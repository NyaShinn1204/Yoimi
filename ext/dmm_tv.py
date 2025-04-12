import os
import yaml
import json
import time
import shutil
import logging
import xml.etree.ElementTree as ET

from datetime import datetime
from rich.console import Console

from ext.utils import dmm_tv

console = Console()

__service_name__ = "Dmm-TV"

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

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #global media_code, playtoken
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema, Dmm-TV Content for Everyone", extra={"service_name": "Yoimi"})
        
        dmm_tv_downloader = dmm_tv.Dmm_TV_downloader(session)
        
        if email and password != "":
            status, message = dmm_tv_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
                plan_status = message["planStatus"]["planType"]
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+message["id"], extra={"service_name": __service_name__})
                logger.info(" + PlanType: "+plan_status, extra={"service_name": __service_name__})
        else:
            plan_status = "No Logined"
        
        status, season_id, content_id = dmm_tv.Dmm_TV_utils.parse_url(url)
                
        status_check = dmm_tv_downloader.check_free(season_id, content_id)
        if content_id == None:
            if any(item['status'] == 'false' for item in status_check) and plan_status != "STANDARD":
                logger.warning("This content require subscribe plan", extra={"service_name": __service_name__})
                pass
                #exit(1)
            elif any(item['status'] == 'false' for item in status_check) and plan_status == "STANDARD":
                #if "false" in status_check:
                #    print("lol")
                logger.warning("This content is all require subscribe", extra={"service_name": __service_name__})
            else:
                logger.warning("This content is free!", extra={"service_name": __service_name__})
        else:
            if status_check["status"] == 'false' and plan_status != "STANDARD":
                logger.warning("This content require subscribe plan", extra={"service_name": __service_name__})
                pass
                #exit(1)
            elif status_check["status"] == 'false' and plan_status == "STANDARD":
                #if "false" in status_check:
                #    print("lol")
                logger.warning("This content is all require subscribe", extra={"service_name": __service_name__})
            else:
                logger.warning("This content is free!", extra={"service_name": __service_name__})
                
        status, meta_response = dmm_tv_downloader.get_title_metadata(season_id)
        if status == False:
            logger.error("Failed to Get Series Json", extra={"service_name": __service_name__})
            exit(1)
        else:
            title_name = meta_response["titleName"]
            
        logger.info("Get Video Type for URL", extra={"service_name": __service_name__})
        status_id, id_type = dmm_tv_downloader.get_id_type(season_id)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": __service_name__})

        if type(status_check) == list:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            status, messages = dmm_tv_downloader.get_title_parse_all(season_id)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
            i = 0
            for message in messages:
                if id_type[0] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message["node"]["episodeNumberName"],
                        "episodename": message["node"]["episodeTitle"]
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[0] == "劇場":
                    format_string = config["format"]["movie"]
                    if message["node"]["episodeNumberName"] == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message["node"]["episodeNumberName"],
                            "episodename": message["node"]["episodeTitle"]
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                content_type = status_check[i]["status"]
                if content_type == "true":
                    content_type = "FREE   "
                    content_status_lol = f" | END FREE {status_check[i]["end_at"]}"
                else:
                    content_type = "PREMIUM"
                    content_status_lol = ""
                logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": __service_name__})
                
                i=i+1
            for i, message in enumerate(messages):
                content_id = message["node"]["id"]
                status, message = dmm_tv_downloader.get_title_parse_single(season_id, content_id)
                if status == False:
                    logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                    exit(1)
                if id_type[0] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message["node"]["episodeNumberName"],
                        "episodename": message["node"]["episodeTitle"]
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[0] == "劇場":
                    format_string = config["format"]["movie"]
                    if message["node"]["episodeNumberName"] == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message["node"]["episodeNumberName"],
                            "episodename": message["node"]["episodeTitle"]
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
                        "episode_title": f"{message["node"]["episodeNumberName"]} {message["node"]["episodeTitle"]}",
                    #    "duration": 1479,
                        "raw_text": f"{title_name} {message["node"]["episodeNumberName"]} {message["node"]["episodeTitle"]}",
                        "series_title": title_name,
                        "episode_text": message["node"]["episodeTitle"],
                        "episode_number": 1,
                        "subtitle": message["node"]["episodeTitle"],
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
                #print(status_check[i])
                if plan_status == "OTHER":
                    status_real = status_check[i]
                    #print(status_check[i])
                    if status_real["status"] == "false":
                        logger.warning("This episode is require PREMIUM. Skipping...", extra={"service_name": __service_name__})
                        continue
                video_duration = message["node"]["playInfo"]["duration"]
                
                #content_type = status_check["status"]
                #if content_type == "true":
                #    content_type = "FREE   "
                #    content_status_lol = f" | END FREE {status_check["end_at"]}"
                #else:
                #    content_type = "PREMIUM"
                #    content_status_lol = ""
                #logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": __service_name__})
                
                status, links = dmm_tv_downloader.get_mpd_link(content_id)
                logger.debug(f"{status},{links}", extra={"service_name": __service_name__})
                
                logger.debug(f"Parse links", extra={"service_name": __service_name__})
                
                hd_link = dmm_tv_downloader.parse_quality(links)
                logger.debug(f" + HD MPD: {hd_link}", extra={"service_name": __service_name__})
                
                logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
                status, mpd_content, hd_link_base = dmm_tv_downloader.get_mpd_content(hd_link)
                
                mpd_lic = dmm_tv.Dmm_TV_utils.parse_mpd_logic(mpd_content)
                            
                logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
                
                license_key = dmm_tv.Dmm_TV__license.license_vd_ad(mpd_lic["pssh"][1], session)
                            
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                
                logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                
                logger.info("Checking resolution...", extra={"service_name": __service_name__})
                logger.info("Found resolution", extra={"service_name": __service_name__})
                for resolution_one in links:
                    if resolution_one["quality_name"] == "auto":
                        pixel_d = "Unknown"
                    elif resolution_one["quality_name"] == "hd":
                        pixel_d = "1920x1080"
                    elif resolution_one["quality_name"] == "sd":
                        pixel_d = "1280x720"
                    logger.info(" + {reso} {pixel}".format(reso=resolution_one["quality_name"], pixel=pixel_d), extra={"service_name": __service_name__})
                    
                logger.debug("Get Segment URL", extra={"service_name": __service_name__})
                segemnt_content = dmm_tv.Dmm_TV_utils.parse_mpd_content(mpd_content)
                #print(segemnt_content)
                #print(segemnt_content)
                
                #print(hd_link_base)
                
                mpd_base = hd_link_base.replace("manifest.mpd", "")
                
                segment_list_video = dmm_tv.Dmm_TV_utils.get_segment_link_list(mpd_content, segemnt_content["video_list"][1]["name"], mpd_base)
                #print(segment_list_video)
                for i in segment_list_video["segments"]:
                    logger.debug(" + Video Segment URL "+i, extra={"service_name": __service_name__})
                
                segment_list_audio = dmm_tv.Dmm_TV_utils.get_segment_link_list(mpd_content, segemnt_content["audio_list"][1]["name"], mpd_base)
                #print(segment_list_audio)
                for i in segment_list_audio["segments"]:
                    logger.debug(" + Audio Segment URL "+i, extra={"service_name": __service_name__})
                
                logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": __service_name__})
                logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": __service_name__})
    
                
                logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                downloaded_files_video = dmm_tv_downloader.download_segment(segment_list_video["all"], config, unixtime)
                downloaded_files_audio = dmm_tv_downloader.download_segment(segment_list_audio["all"], config, unixtime)
                #print(downloaded_files)
                
                logger.info("Merging encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                dmm_tv_downloader.merge_m4s_files(downloaded_files_video, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"))
                dmm_tv_downloader.merge_m4s_files(downloaded_files_audio, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"))
                
                logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
    
                dmm_tv.DMM_TV_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
                dmm_tv.DMM_TV_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                
                dmm_tv.DMM_TV_decrypt.decrypt_all_content(license_key["video_key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["audio_key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                
                result = dmm_tv_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(video_duration))
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
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
            # forかなんかで取り出して、実行
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            status, message = dmm_tv_downloader.get_title_parse_single(season_id, content_id)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
            if id_type[0] == "ノーマルアニメ":
                format_string = config["format"]["anime"]
                values = {
                    "seriesname": title_name,
                    "titlename": message["node"]["episodeNumberName"],
                    "episodename": message["node"]["episodeTitle"]
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type[0] == "劇場":
                format_string = config["format"]["movie"]
                if message["node"]["episodeNumberName"] == "":
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_name,
                    }
                else:
                    values = {
                        "seriesname": title_name,
                        "titlename": message["node"]["episodeNumberName"],
                        "episodename": message["node"]["episodeTitle"]
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
                    "episode_title": f"{message["node"]["episodeNumberName"]} {message["node"]["episodeTitle"]}",
                #    "duration": 1479,
                    "raw_text": f"{title_name} {message["node"]["episodeNumberName"]} {message["node"]["episodeTitle"]}",
                    "series_title": title_name,
                    "episode_text": message["node"]["episodeNumberName"],
                    "episode_number": 1,
                    "subtitle": message["node"]["episodeTitle"],
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
            
            video_duration = message["node"]["playInfo"]["duration"]
            
            content_type = status_check["status"]
            if content_type == "true":
                content_type = "FREE   "
                content_status_lol = f" | END FREE {status_check["end_at"]}"
            else:
                content_type = "PREMIUM"
                content_status_lol = ""
            logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": __service_name__})
            
            status, links = dmm_tv_downloader.get_mpd_link(content_id)
            logger.debug(f"{status},{links}", extra={"service_name": __service_name__})
            
            logger.debug(f"Parse links", extra={"service_name": __service_name__})
            
            hd_link = dmm_tv_downloader.parse_quality(links)
            logger.debug(f" + HD MPD: {hd_link}", extra={"service_name": __service_name__})
            
            logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
            status, mpd_content, hd_link_base = dmm_tv_downloader.get_mpd_content(hd_link)
            
            mpd_lic = dmm_tv.Dmm_TV_utils.parse_mpd_logic(mpd_content)
                        
            logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
            
            license_key = dmm_tv.Dmm_TV__license.license_vd_ad(mpd_lic["pssh"][1], session)
                        
            logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
            
            logger.info("Checking resolution...", extra={"service_name": __service_name__})
            logger.info("Found resolution", extra={"service_name": __service_name__})
            for resolution_one in links:
                if resolution_one["quality_name"] == "auto":
                    pixel_d = "Unknown"
                elif resolution_one["quality_name"] == "hd":
                    pixel_d = "1920x1080"
                elif resolution_one["quality_name"] == "sd":
                    pixel_d = "1280x720"
                logger.info(" + {reso} {pixel}".format(reso=resolution_one["quality_name"], pixel=pixel_d), extra={"service_name": __service_name__})
                
            logger.debug("Get Segment URL", extra={"service_name": __service_name__})
            segemnt_content = dmm_tv.Dmm_TV_utils.parse_mpd_content(mpd_content)
            #print(segemnt_content)
            #print(segemnt_content)
            
            #print(hd_link_base)
            
            mpd_base = hd_link_base.replace("manifest.mpd", "")
            
            segment_list_video = dmm_tv.Dmm_TV_utils.get_segment_link_list(mpd_content, segemnt_content["video_list"][1]["name"], mpd_base)
            #print(segment_list_video)
            for i in segment_list_video["segments"]:
                logger.debug(" + Video Segment URL "+i, extra={"service_name": __service_name__})
            
            segment_list_audio = dmm_tv.Dmm_TV_utils.get_segment_link_list(mpd_content, segemnt_content["audio_list"][1]["name"], mpd_base)
            #print(segment_list_audio)
            for i in segment_list_audio["segments"]:
                logger.debug(" + Audio Segment URL "+i, extra={"service_name": __service_name__})
            
            logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
            logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": __service_name__})
            logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": __service_name__})

            
            logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            downloaded_files_video = dmm_tv_downloader.download_segment(segment_list_video["all"], config, unixtime)
            downloaded_files_audio = dmm_tv_downloader.download_segment(segment_list_audio["all"], config, unixtime)
            #print(downloaded_files)
            
            logger.info("Merging encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            dmm_tv_downloader.merge_m4s_files(downloaded_files_video, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"))
            dmm_tv_downloader.merge_m4s_files(downloaded_files_audio, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"))
            
            logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})

            dmm_tv.DMM_TV_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
            dmm_tv.DMM_TV_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            result = dmm_tv_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(video_duration))
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
            logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
                        
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")