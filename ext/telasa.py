import os
import re
import time
import yaml
import logging
import shutil
from urllib.parse import urljoin
from rich.console import Console

import ext.global_func.parser as parser

from ext.utils import telasa

console = Console()

__service_name__ = "Telasa"

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
    
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        #additional_info = [__version__, use_rd, use_gnc, use_odc, write_thumbnail, write_description, embed_thumbnail, embed_metadata, embed_subs, embed_chapters]
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Encrypte Content for Everyone", extra={"service_name": "Yoimi"})
        
        telasa_downloader = telasa.Telasa_downloader(session)
        
        if email and password != None:
            if config["authorization"]["use_token"]:
                if config["authorization"]["token"] != "":
                    status, message, response_user = telasa_downloader.check_token(config["authorization"]["token"])
                    if status == False:
                        logger.error(message, extra={"service_name": __service_name__})
                        exit(1)
                    else:
                        session.headers.update({"Authorization": config["authorization"]["token"]})
                        subscribed_plan = response_user["had_subscribed"]
                        logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": __service_name__})
                        logger.info("Loggined Account", extra={"service_name": __service_name__})
                        logger.info(" + ID: "+str(response_user["id"]), extra={"service_name": __service_name__})
                        logger.info(" + Subscribed: "+str(response_user["had_subscribed"]), extra={"service_name": __service_name__})
                        login_status = True
                else:
                    logger.error("Please input token", extra={"service_name": __service_name__})
                    exit(1)
            else:
                status, message, response_user = telasa_downloader.authorize(email, password)
                try:
                    logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
                except:
                    logger.info("Failed to login", extra={"service_name": __service_name__})
                if status == False:
                    logger.error(message, extra={"service_name": __service_name__})
                    exit(1)
                else:
                    subscribed_plan = response_user["had_subscribed"]
                    logger.info("Loggined Account", extra={"service_name": __service_name__})
                    logger.info(" + ID: "+str(response_user["id"]), extra={"service_name": __service_name__})
                    logger.info(" + Subscribed: "+str(response_user["had_subscribed"]), extra={"service_name": __service_name__})
                    login_status = True
        else:
            login_status = False
            
        if url.__contains__("videos"):
            # single episode mode
            logger.info("Get Video Type for URL", extra={"service_name": __service_name__})
            status_id, id_type, more_info = telasa_downloader.get_id_type(url)
            if status_id == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
            logger.info(f" + Video Type: {id_type[0]} Info: {more_info}", extra={"service_name": __service_name__})
            production_year = more_info[0]
            copyright = more_info[1]
            
            
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            status, message = telasa_downloader.get_title_parse_single(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
            
            title_name = re.sub(r"\s*第\d+話", "", message["data"]["name"])
                
            if id_type[0] == "ノーマルアニメ":
                format_string = config["format"]["anime"].replace("_{titlename}", "")
                values = {
                    "seriesname": title_name,
                    "episodename": message["data"].get("subtitle", "")
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type[0] == "劇場":
                format_string = config["format"]["movie"]
                if message["data"].get("subtitle", "") == None:
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_name,
                    }
                else:
                    values = {
                        "seriesname": title_name,
                        "episodename": message["data"].get("subtitle", "")
                    }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            logger.info(f" + {title_name_logger} | Status: {more_info[2]}", extra={"service_name": __service_name__})
            
            if more_info[2] == "PREMIUM" and subscribed_plan != False:
                logger.warning("This episode require: SUBSCRIBE, Skipping...", extra={"service_name": __service_name__})
                return
            
            logger.info("Get playback token", extra={"service_name": __service_name__})
            token = telasa_downloader.get_playback_token(message["data"]["id"])
            logger.info(" + "+token[:12]+"....", extra={"service_name": __service_name__})
            logger.debug(" + "+token, extra={"service_name": __service_name__})
            
            logger.info("Get streaming link", extra={"service_name": __service_name__})
            manifest_list = telasa_downloader.get_streaming_link(message["data"]["id"], token)
            dash_manifest = next((m for m in manifest_list["data"]["manifests"] if m["protocol"] == "dash"), None)
            hd_url = next((item["url"] for item in dash_manifest["items"] if item["name"] == "hd"), None) if dash_manifest else None
            logger.info(" + "+hd_url[:70]+"....", extra={"service_name": __service_name__})
            logger.debug(" + "+hd_url, extra={"service_name": __service_name__})
            
            logger.info(f"Parse MPD file", extra={"service_name": __service_name__})
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(session.get(hd_url).text)
            
            logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
            license_key = telasa.Telasa_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, token, config)

            logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                    
            
            logger.info(f"Get Video, Audio Tracks:", extra={"service_name": __service_name__})
            logger.debug(f" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
            track_data = Tracks.print_tracks(transformed_data)
            
            print(track_data)
            
            get_best_track = Tracks.select_best_tracks(transformed_data)
            
            logger.debug(f" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
            logger.info(f"Selected Best Track:", extra={"service_name": __service_name__})
            logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
            logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
            
            logger.debug(f"Calculate about Manifest...", extra={"service_name": __service_name__})
            episode_duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
            logger.debug(f" + Episode Duration: "+str(int(episode_duration)), extra={"service_name": __service_name__})
            
            logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
            video_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
            logger.info(f" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
            audio_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
            
            logger.info(f" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
            video_segment_links = []
            audio_segment_links = []
            video_segment_links.append(hd_url.rsplit("/", 1)[0] + "/"+get_best_track["video"]["url"].replace("$RepresentationID$", get_best_track["video"]["id"]))
            audio_segment_links.append(hd_url.rsplit("/", 1)[0] + "/"+get_best_track["audio"]["url"].replace("$RepresentationID$", get_best_track["audio"]["id"]))
            
            for single_segment in range(video_segment_list):
                temp_segment_link = get_best_track["video"]["url_segment_base"].split("/", 1)[-1]
                temp_link = (
                    hd_url.rsplit("/", 1)[0] + "/"
                    +
                    get_best_track["video"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["video"]["id"]}/")
                    +
                    temp_segment_link.replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                video_segment_links.append(temp_link)
            for single_segment in range(audio_segment_list):
                temp_segment_link = get_best_track["audio"]["url_segment_base"].split("/", 1)[-1]
                temp_link = (
                    hd_url.rsplit("/", 1)[0] + "/"
                    +
                    get_best_track["audio"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["audio"]["id"]}/")
                    +
                    temp_segment_link.replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                audio_segment_links.append(temp_link)
            
            logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            telasa_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
            telasa_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
            
            logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            telasa.Telasa_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
            telasa.Telasa_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            telasa.Telasa_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            result = telasa_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(episode_duration))
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
            logger.info('Finished download: {}'.format(title_name), extra={"service_name": __service_name__})
            
            if login_status:
                send_stop = session.put("https://api-videopass.kddi-video.com/v1/users/me/videos/played/"+str(message["data"]["id"])+"/1")
                #print(a.json())
        elif url.__contains__("series"):
            logger.error("I dont have telasa premium account. so this option is coming soon", extra={"service_name": __service_name__})
            
            logger.info("Hehe now ongoing", extra={"service_name": __service_name__})
            
            match = re.search(r'/series/(\d+)', url)
            
            if match:
                series_id = match.group(1)
                #print(series_id)  # 出力: 15662
                
            metadata = telasa_downloader.get_series_info(series_id)
            
            title_name = metadata['name']
            episode_ids = metadata.get('episode_ids', [])
            copyright = metadata.get('copyright', "")
            
            episodes_metadata = telasa_downloader.get_episodes_info(episode_ids)
            
            logger.info("Get title for season", extra={"service_name": __service_name__})
            for single in episodes_metadata:
                format_string = config["format"]["anime"].replace("_{titlename}", "")
                values = {
                    "seriesname": title_name,
                    "episodename": single[0]
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
                logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            
            # season episode mode
            return
        else:
            logger.error("Unknown Pattern. Exiting...", extra={"service_name": __service_name__})
            # IDK WTF
            return
            
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")