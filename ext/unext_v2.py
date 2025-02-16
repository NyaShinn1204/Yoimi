import os
import re
import yaml
import time
import shutil
import json
import logging
from datetime import datetime
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

from ext.utils import unext

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{COLOR_BLUE}{record.service_name}{COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        )
        
        return log_message

def set_variable(session, LOG_LEVEL):
    global logger, config, unixtime
    
    unixtime = str(int(time.time()))
    
    logger = logging.getLogger('YoimiLogger')
    if LOG_LEVEL == "DEBUG":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    formatter = CustomFormatter(
        '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def check_proxie(session):
    logger.info("Checking Proxie...", extra={"service_name": "Yoimi"})
    try:
        start = time.time()
        #
        _ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        _ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        
        response = session.get(
            _ENDPOINT_CHALLENG_ID.format(
                state="ma68aiLyo4LhQkOVHGctEN7jH7PGmRIhRVOmzgK8f5y",
                nonce="ArnY3qesx6DVqiMIXYxEnJG2KzHhMe9l4bzZLOaLnZw"
            )
        )
        script_tag = BeautifulSoup(response.text, "lxml").find("script", {"id": "__NEXT_DATA__"})
        json_data = json.loads(script_tag.string)
        challenge_id = json_data.get("props", {}).get("challengeId")
    
        payload_ = {
            "id": "example@example.com",
            "password": "example123",
            "challenge_id": challenge_id,
            "device_code": "920",
            "scope": ["offline", "unext"],
        }
        auth_response = session.post(_ENDPOINT_RES, json=payload_).json()
        #    
        #
        end = time.time()
        time_elapsed = end - start
        time_elapsed = time_elapsed * 1000
        
        try:
            if auth_response["error_hint"] == "GAW0500003":
                logger.error(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
                logger.error(f"However, this proxy is not located in Japan. You will not be able to use it.", extra={"service_name": "Yoimi"})
                exit(1)
        except Exception as e:
            pass
        
        logger.info(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
    except IOError:
        logger.error(f"Connection error of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)
    except:
        logger.error(f"Failed Check Proxies of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        global media_code, playtoken
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        #additional_info = [__version__, use_rd, use_gnc, use_odc, write_thumbnail, write_description, embed_thumbnail, embed_metadata, embed_subs, embed_chapters]
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
        if session.proxies != {}:
            check_proxie(session)
        
        unext_downloader = unext.Unext_downloader(session, config)
        
        if config["authorization"]["use_token"]:
            if config["authorization"]["token"] != "":
                status, message = unext_downloader.check_token(config["authorization"]["token"])
                if status == False:
                    logger.error(message, extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    account_point = str(message["points"])
                    session.headers.update({"Authorization": config["authorization"]["token"]})
                    logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": "U-Next"})
                    logger.info("Loggined Account", extra={"service_name": "U-Next"})
                    logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                    logger.info(" + Point: "+account_point, extra={"service_name": "U-Next"})
            else:
                logger.error("Please input token", extra={"service_name": "U-Next"})
                exit(1)
        else:
            status, message = unext_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "U-Next"})
            except:
                logger.info("Failed to login", extra={"service_name": "U-Next"})
            if status == False:
                logger.error(message, extra={"service_name": "U-Next"})
                exit(1)
            else:
                account_point = str(message["points"])
                logger.info("Loggined Account", extra={"service_name": "U-Next"})
                logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                logger.info(" + Point: "+account_point, extra={"service_name": "U-Next"})
            
        status, meta_response = unext_downloader.get_title_metadata(url)
        if status == False:
            logger.error("Failed to Get Series Json", extra={"service_name": "U-Next"})
            exit(1)
        else:
            title_name = meta_response["titleName"]
            
        status = unext.Unext_utils.check_single_episode(url)
        logger.info("Get Video Type for URL", extra={"service_name": "U-Next"})
        status_id, id_type = unext_downloader.get_id_type(url)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": "U-Next"})
        productionYear = id_type[3]
        copyright = id_type[4]
        if status == False:
            logger.info("Get Title for Season", extra={"service_name": "U-Next"})
            status, messages = unext_downloader.get_title_parse_all(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
                exit(1)
                
            if additional_info[4]: 
                logger.info("Downloading All Episode Thumbnails...", extra={"service_name": "U-Next"})
                unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
                
            for message in messages:
                if id_type[2] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("displayNo", ""),
                        "episodename": message.get("episodeName", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[2] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("displayNo", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("displayNo", ""),
                            "episodename": message.get("episodeName", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
            for message in messages:
                if id_type[2] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("displayNo", ""),
                        "episodename": message.get("episodeName", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[2] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("displayNo", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("displayNo", ""),
                            "episodename": message.get("episodeName", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                
                if additional_info[2]:        
                    sate = {}
                    sate["info"] = {
                        "work_title": title_name,
                        "episode_title": f"{message.get("displayNo", "")} {message.get("episodeName", "")}",
                    #    "duration": 1479,
                        "raw_text": f"{title_name} {message.get("displayNo", "")} {message.get("episodeName", "")}",
                        "series_title": title_name,
                        "episode_text": message.get("displayNo", ""),
                        "episode_number": 1,
                        "subtitle": message.get("episodeName", ""),
                    }
                    
                    def get_niconico_info(stage, data):
                        if stage == 1:
                            querystring = {
                                "q": data,
                                "_sort": "-startTime",
                                "_context": "NCOverlay/3.23.0/Mod For Yoimi",
                                "targets": "title,description",
                                "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
                                "filters[commentCounter][gt]": 0,
                                "filters[genre.keyword][0]": "アニメ",
                                "_offset": 0,
                                "_limit": 20,
                            }
                            
                            result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
                            return result
                        elif stage == 2:
                            result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
                            return result
                        elif stage == 3:
                            payload = {
                                "params":{
                                    "targets": data[1],
                                    "language":"ja-jp"},
                                "threadKey": data[0],
                                "additionals":{}
                            }
                            headers = {
                              "X-Frontend-Id": "6",
                              "X-Frontend-Version": "0",
                              "Content-Type": "application/json"
                            }
                            result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
                            return result
                        
                    logger.info(f"Getting Niconico Comment", extra={"service_name": "U-Next"})
                    return_meta = get_niconico_info(1, sate["info"]["raw_text"])
                    
                    base_content_id = return_meta["data"][0]["contentId"]
                    
                    total_comment = 0
                    total_comment_json = []
                    total_tv = []
                    
                    for index in return_meta["data"]:
                        return_meta = get_niconico_info(2, index["contentId"])
                            
                        filtered_data = [
                            {"id": str(item["id"]), "fork": item["forkLabel"]}
                            for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
                        ]
                        
                        return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
                        for i in return_meta["data"]["globalComments"]:
                            total_comment = total_comment + i["count"]
                        for i in return_meta["data"]["threads"]:
                            for i in i["comments"]:
                                total_comment_json.append(i)
                        if index["tags"].__contains__("dアニメストア"):
                            total_tv.append("dアニメ")
                        else:
                            total_tv.append("公式")
                    
                    def generate_xml(json_data):
                        root = ET.Element("packet", version="20061206")
                        
                        for item in json_data:
                            chat = ET.SubElement(root, "chat")
                            chat.set("no", str(item["no"]))
                            chat.set("vpos", str(item["vposMs"] // 10))
                            timestamp = datetime.fromisoformat(item["postedAt"]).timestamp()
                            chat.set("date", str(int(timestamp)))
                            chat.set("date_usec", "0")
                            chat.set("user_id", item["userId"])
                            
                            chat.set("mail", " ".join(item["commands"]))
                            
                            chat.set("premium", "1" if item["isPremium"] else "0")
                            chat.set("anonymity", "0")
                            chat.text = item["body"]
                        
                        return ET.ElementTree(root)
                    
                    def save_xml_to_file(tree, base_filename="output.xml"):
                        directory = os.path.dirname(base_filename)
                        if directory and not os.path.exists(directory):
                            os.makedirs(directory)
                        
                        filename = base_filename
                        counter = 1
                        while os.path.exists(filename):
                            filename = f"{os.path.splitext(base_filename)[0]}_{counter}.xml"
                            counter += 1
                    
                        root = tree.getroot()
                        ET.indent(tree, space="  ", level=0)
                        
                        tree.write(filename, encoding="utf-8", xml_declaration=True)
                        return filename
                    
                    tree = generate_xml(total_comment_json)
                    
                    logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": "U-Next"})
                    logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": "U-Next"})
                    
                    saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
                    
                    logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": "U-Next"})
                    
                    if additional_info[3]:
                        continue
                        
                if message["minimumPrice"] != -1:
                    logger.info(f" ! {title_name_logger} require {message["minimumPrice"]} point", extra={"service_name": "U-Next"})
                    if int(message["minimumPrice"]) > int(account_point):
                        logger.info(f" ! ポイントが足りません", extra={"service_name": "U-Next"})
                        pass
                    else:
                        is_buyed = unext_downloader.check_buyed(url)
                        if is_buyed == True:
                            logger.info(f" ! {title_name_logger} have already been purchased.", extra={"service_name": "U-Next"})
                        else:
                            check_downlaod = input(COLOR_GREEN+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+COLOR_RESET+" "+f"[{COLOR_GRAY}INFO{COLOR_RESET}]"+" "+f"{COLOR_BLUE}U-Next{COLOR_RESET}"+" : "+f" ! Do you want to buy {title_name_logger}?"+" | "+"y/n"+" ")
                            logger.info(f"Coming soon", extra={"service_name": "U-Next"})
                            return
                    
                status, playtoken, media_code, additional_meta = unext_downloader.get_playtoken(message["id"])
                if status == False:
                    logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    if additional_info[6] or additional_info[8]:
                        unext_downloader.create_ffmetadata(productionYear, title_name_logger, unixtime, additional_meta, message.get("displayNo", ""), message["duration"], message["introduction"], copyright, additional_info)
                    
                    logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
                    status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
                    if status == False:
                        logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                        logger.error(f"Reason: {mpd_content}", extra={"service_name": "U-Next"})
                        session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                        session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
                        exit(1)
                    mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
        
                    logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
                    logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
                    
                    license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
                    
                    logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "U-Next"})
                    
                    logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                    logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                                        
                    logger.info("Checking resolution...", extra={"service_name": "U-Next"})
                    resolution_s = unext.mpd_parse.get_resolutions(mpd_content)
                    logger.info("Found resolution", extra={"service_name": "U-Next"})
                    for resolution_one in resolution_s:
                        logger.info(" + "+resolution_one, extra={"service_name": "U-Next"})
                    
                    logger.info("Video, Audio Content Link", extra={"service_name": "U-Next"})
                    video_url = unext.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
                    audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                    logger.info(" + Video_URL: "+video_url, extra={"service_name": "U-Next"})
                    logger.info(" + Audio_URL: "+audio_url, extra={"service_name": "U-Next"})
                    
                    def sanitize_filename(filename):
                        filename = filename.replace(":", "：").replace("?", "？")
                        return re.sub(r'[<>"/\\|*]', "_", filename)
                    
                    if additional_info[1]:
                        random_string = str(int(time.time() * 1000))
                        title_name_logger_video = random_string+"_video_encrypted.mp4"
                        title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                    else:
                        title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
                        title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                    
                    logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                    
                    video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
                    audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)                    

                    logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                    
                    unext.Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": "U-Next"})
                    
                    result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, sanitize_filename(title_name), int(message["duration"]), title_name_logger, message.get("displayNo", ""), additional_info)
                        
                    dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                    
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        for filename in os.listdir(dir_path):
                            if filename == "metadata":
                                continue
                            
                            file_path = os.path.join(dir_path, filename)
                            try:
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                                elif os.path.isdir(file_path):
                                    shutil.rmtree(file_path)
                            except Exception as e:
                                print(f"削除エラー: {e}")
                    else:
                        print(f"指定されたディレクトリは存在しません: {dir_path}")
                    
                    logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "U-Next"})
                                           
                    
                    session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                    session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
            logger.info("Finished download Series: {}".format(title_name), extra={"service_name": "U-Next"})
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": "U-Next"})
            status, message, point = unext_downloader.get_title_parse_single(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
                exit(1)
            
            if id_type[2] == "ノーマルアニメ":
                format_string = config["format"]["anime"]
                values = {
                    "seriesname": title_name,
                    "titlename": message.get("displayNo", ""),
                    "episodename": message.get("episodeName", "")
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type[2] == "劇場":
                format_string = config["format"]["movie"]
                if message.get("displayNo", "") == "":
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_name,
                    }
                else:
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("displayNo", ""),
                        "episodename": message.get("episodeName", "")
                    }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
            
            if additional_info[2]:        
                sate = {}
                sate["info"] = {
                    "work_title": title_name,
                    "episode_title": f"{message.get("displayNo", "")} {message.get("episodeName", "")}",
                    "raw_text": f"{title_name} {message.get("displayNo", "")} {message.get("episodeName", "")}",
                    "series_title": title_name,
                    "episode_text": message.get("displayNo", ""),
                    "episode_number": 1,
                    "subtitle": message.get("episodeName", ""),
                }
                
                def get_niconico_info(stage, data):
                    if stage == 1:
                        querystring = {
                            "q": data,
                            "_sort": "-startTime",
                            "_context": "NCOverlay/3.23.0/Mod For Yoimi",
                            "targets": "title,description",
                            "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
                            "filters[commentCounter][gt]": 0,
                            "filters[genre.keyword][0]": "アニメ",
                            "_offset": 0,
                            "_limit": 20,
                        }
                        
                        result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
                        return result
                    elif stage == 2:
                        result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
                        return result
                    elif stage == 3:
                        payload = {
                            "params":{
                                "targets": data[1],
                                "language":"ja-jp"},
                            "threadKey": data[0],
                            "additionals":{}
                        }
                        headers = {
                          "X-Frontend-Id": "6",
                          "X-Frontend-Version": "0",
                          "Content-Type": "application/json"
                        }
                        result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
                        return result
                    
                logger.info(f"Getting Niconico Comment", extra={"service_name": "U-Next"})
                return_meta = get_niconico_info(1, sate["info"]["raw_text"])
                
                base_content_id = return_meta["data"][0]["contentId"]
                
                total_comment = 0
                total_comment_json = []
                total_tv = []
                
                for index in return_meta["data"]:
                    return_meta = get_niconico_info(2, index["contentId"])
                        
                    filtered_data = [
                        {"id": str(item["id"]), "fork": item["forkLabel"]}
                        for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
                    ]
                    
                    return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
                    for i in return_meta["data"]["globalComments"]:
                        total_comment = total_comment + i["count"]
                    for i in return_meta["data"]["threads"]:
                        for i in i["comments"]:
                            total_comment_json.append(i)
                    if index["tags"].__contains__("dアニメストア"):
                        total_tv.append("dアニメ")
                    else:
                        total_tv.append("公式")
                
                def generate_xml(json_data):
                    root = ET.Element("packet", version="20061206")
                    
                    for item in json_data:
                        chat = ET.SubElement(root, "chat")
                        chat.set("no", str(item["no"]))
                        chat.set("vpos", str(item["vposMs"] // 10))
                        timestamp = datetime.fromisoformat(item["postedAt"]).timestamp()
                        chat.set("date", str(int(timestamp)))
                        chat.set("date_usec", "0")
                        chat.set("user_id", item["userId"])
                        
                        chat.set("mail", " ".join(item["commands"]))
                        
                        chat.set("premium", "1" if item["isPremium"] else "0")
                        chat.set("anonymity", "0")
                        chat.text = item["body"]
                    
                    return ET.ElementTree(root)
                
                def save_xml_to_file(tree, base_filename="output.xml"):
                    directory = os.path.dirname(base_filename)
                    if directory and not os.path.exists(directory):
                        os.makedirs(directory)
                    
                    filename = base_filename
                    counter = 1
                    while os.path.exists(filename):
                        filename = f"{os.path.splitext(base_filename)[0]}_{counter}.xml"
                        counter += 1
                
                    root = tree.getroot()
                    ET.indent(tree, space="  ", level=0)
                    
                    tree.write(filename, encoding="utf-8", xml_declaration=True)
                    return filename
                
                tree = generate_xml(total_comment_json)
                
                logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": "U-Next"})
                logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": "U-Next"})
                
                saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
                
                logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": "U-Next"})
                
                if additional_info[3]:
                    return

            if point != -1:
                logger.info(f" ! {title_name_logger} require {point} point", extra={"service_name": "U-Next"})
                if int(point) > int(account_point):
                    logger.info(f" ! ポイントが足りません", extra={"service_name": "U-Next"})
                    pass
                else:
                    is_buyed = unext_downloader.check_buyed(url)
                    if is_buyed == True:
                        logger.info(f" ! {title_name_logger} have already been purchased.", extra={"service_name": "U-Next"})
                    else:
                        check_downlaod = input(COLOR_GREEN+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+COLOR_RESET+" "+f"[{COLOR_GRAY}INFO{COLOR_RESET}]"+" "+f"{COLOR_BLUE}U-Next{COLOR_RESET}"+" : "+f" ! Do you want to buy {title_name_logger}?"+" | "+"y/n"+" ")
                        logger.info(f"Coming soon", extra={"service_name": "U-Next"})
                        return
            
            status, playtoken, media_code, additional_meta = unext_downloader.get_playtoken(message["id"])
            if status == False:
                logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
                exit(1)
            else:
                if additional_info[6] or additional_info[8]:
                    unext_downloader.create_ffmetadata(productionYear, title_name_logger, unixtime, additional_meta, message.get("displayNo", ""), message["duration"], message["introduction"], copyright, additional_info)
                logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
                status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
                if status == False:
                    logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                    session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                    session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
                mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
    
                logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
                logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
                
                license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
                
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "U-Next"})
                
                logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                
                logger.info("Checking resolution...", extra={"service_name": "U-Next"})
                resolution_s = unext.mpd_parse.get_resolutions(mpd_content)
                logger.info("Found resolution", extra={"service_name": "U-Next"})
                for resolution_one in resolution_s:
                    logger.info(" + "+resolution_one, extra={"service_name": "U-Next"})
                
                logger.info("Video, Audio Content Link", extra={"service_name": "U-Next"})
                video_url = unext.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
                audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                logger.info(" + Video_URL: "+video_url, extra={"service_name": "U-Next"})
                logger.info(" + Audio_URL: "+audio_url, extra={"service_name": "U-Next"})
                
                def sanitize_filename(filename):
                    filename = filename.replace(":", "：").replace("?", "？")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                
                if additional_info[1]:
                    random_string = str(int(time.time() * 1000))
                    title_name_logger_video = random_string+"_video_encrypted.mp4"
                    title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                else:
                    title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
                    title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                
                if additional_info[4]: 
                    logger.info("Downloading All Episode Thumbnails...", extra={"service_name": "U-Next"})
                    unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
                
                logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                
                video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
                audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)
                
                logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                
                unext.Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                logger.info("Muxing Episode...", extra={"service_name": "U-Next"})
                
                result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(message["duration"]), title_name_logger, message.get("displayNo", ""), additional_info)
                
                dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    for filename in os.listdir(dir_path):
                        file_path = os.path.join(dir_path, filename)
                        try:
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                        except Exception as e:
                            print(f"削除エラー: {e}")
                else:
                    print(f"指定されたディレクトリは存在しません: {dir_path}")
                
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "U-Next"})
                                       
                
                session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(v)
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))
        session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")