import os
import re
import time
import json
import yaml
import shutil
import logging
import hashlib
import ext.global_func.parser as parser

from urllib.parse import urlparse, parse_qs
from rich.console import Console

from ext.utils import fanza

console = Console()

#__service_name__ = "Hulu-jp"

fanza_secret_key = "hp2Y944L"
fanza_vr_secret_key = "X1H8kJ9L2n7G5eF3"

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

def check_session(service_name):
    service_name = service_name.lower()
    session_path = os.path.join("cache", "session", service_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
        return False
    current_time = int(time.time())
    closest_file = None
    closest_diff = float('inf')

    for filename in os.listdir(session_path):
        if filename.startswith("session_") and filename.endswith(".json"):
            try:
                # 'session_1234567890.json' -> '1234567890'
                timestamp_str = filename[len("session_"):-len(".json")]
                session_time = int(timestamp_str)
                diff = abs(current_time - session_time)
                if diff < closest_diff:
                    closest_diff = diff
                    closest_file = filename
            except ValueError:
                continue
    if not closest_file == None:
        return os.path.join(session_path, closest_file)
    else:
        return False
def load_session(json_path):
    with open(json_path, 'r', encoding='utf-8-sig') as f:
        data = f.read()
        if data.strip() == "":
            return False
        return json.loads(data)

class Fanza:
    __service_name__ = "Fanza"
    def main_command(session, url, email, password, LOG_LEVEL, additional_info):
        try:
            set_variable(session, LOG_LEVEL)
            fanza_downloader = fanza.Fanza_downloader(session, config)
            
            status = check_session(Fanza.__service_name__)
            session_data = None
            session_status = False
            if not status == False:
                session_data = load_session(status)
                if session_data != False:
                    if email and password != None:
                        if (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["password"] == hashlib.sha256(password.encode()).hexdigest()):
                            token_status, special_text = fanza_downloader.check_token(session_data["access_token"])
                            if token_status == False:
                                logger.error("Session is Invalid. Please re-login", extra={"service_name": Fanza.__service_name__})
                            else:
                                session_status = True
                        else:
                            logger.info("Email and password is no match. re-login", extra={"service_name": Fanza.__service_name__})
                            status, message, session_data = fanza_downloader.authorize(email, password)
                            if status == False:
                                logger.error(message, extra={"service_name": Fanza.__service_name__})
                                exit(1)
                            else:
                                with open(os.path.join("cache", "session", Fanza.__service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
                    else:
                        token_status, special_text = fanza_downloader.check_token(session_data["access_token"])
                        if token_status == False:
                            logger.error("Session is Invalid. Please re-login", extra={"service_name": Fanza.__service_name__})
                        else:
                            session_status = True
            if session_status == False and (email and password != None):
                status, message, session_data = fanza_downloader.authorize(email, password)
                if status == False:
                    logger.error(message, extra={"service_name": Fanza.__service_name__})
                    exit(1)
                else:
                    with open(os.path.join("cache", "session", Fanza.__service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                        json.dump(session_data, f, ensure_ascii=False, indent=4)      
            elif session_status == False and (email and password == None):
                special_text = None
                logger.info("This content is require account login", extra={"service_name": Fanza.__service_name__})
            
            if session_status == False and (email and password != None):
                fanza_userid = message["id"]
            elif session_data != False:
                fanza_userid = special_text
            
            status, bought_list = fanza_downloader.get_title()
            
            match = re.search(r"parent_product_id=([^/]+)", url)
            if match or "tv.dmm.com/vod/" in url:
                if "tv.dmm.com/vod/" in url:
                    parsed = urlparse(url)
                    query_params = parse_qs(parsed.query)
                    search_content_id = query_params.get("season", [None])[0]
                else:
                    search_content_id = match.group(1)
                part_match = re.search(r"part=([^/]+)", url)
                if part_match:
                    part = str(part_match.group(1))
                else:
                    part = "1"
                    
                found_item = False
                
                for single in bought_list:
                    if single["product_id"] == search_content_id:
                        found_item = True
                        
                        logger.info("Download 1 Content", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["title"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["quality_name"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["viewing_text"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["product_id"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + str(single["mylibrary_id"]), extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Get License ID", extra={"service_name": Fanza.__service_name__})
                        status, license_uid = fanza_downloader.get_license_uid(fanza_userid)
                        if status == False:
                            logger.info("Failed to get License UID", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + "+license_uid, extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Send License Request", extra={"service_name": Fanza.__service_name__})
                        status, license, license_payload = fanza_downloader.get_license(fanza_userid, single, license_uid, fanza_secret_key, part)
                        logger.info(" + KEY: "+license["data"]["cookie"][0]["value"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + UID: "+license_payload["authkey"], extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Get Streaming m3u8", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + "+license["data"]["redirect"][:20], extra={"service_name": Fanza.__service_name__})
                        
                        status, resolution_list = fanza_downloader.get_resolution(single["shop_name"], single["product_id"], fanza_secret_key)
                        
                        m3u8_1 = session.get(license["data"]["redirect"], allow_redirects=False)
                        m3u8_2 = session.get(m3u8_1.headers["Location"])
                        
                        global_parser = parser.global_parser()
                        tracks = global_parser.hls_parser(m3u8_2.text)
                        p_to_resolution = {
                            "240p": "426x240",
                            "360p": "640x360",
                            "480p": "854x480",
                            "720p": "1280x720",
                            "1080p": "1920x1080"
                        }
                        bitrate_to_resolution = {}
                        
                        for item in resolution_list["data"]["result2"]:
                            bitrate = int(item["bitrate"])
                            match = re.search(r"\((\d+p)\)", item["quality_display_name"])
                            if match:
                                p_quality = match.group(1)
                                resolution = p_to_resolution.get(p_quality)
                                if resolution:
                                    bitrate_to_resolution[bitrate] = resolution
                        
                        for track in tracks["video_track"]:
                            bitrate = track["bitrate"]
                            if bitrate in bitrate_to_resolution:
                                track["resolution"] = bitrate_to_resolution[bitrate]
                        track_data = global_parser.print_tracks(tracks)
                        print(track_data)
                                                
                        get_best_track = global_parser.select_best_tracks(tracks)
                        
                        logger.info("Selected Best Track:", extra={"service_name": Fanza.__service_name__})
                        logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": Fanza.__service_name__})
                        
                        content_link = m3u8_1.headers["Location"].replace(
                            "playlist.m3u8", "chunklist_b" + str(get_best_track["video"]["bandwidth"]) + ".m3u8"
                        )
                        base_link = content_link.rsplit("/", 1)[0] + "/"
                        
                        logger.debug(content_link, extra={"service_name": Fanza.__service_name__})
                        logger.debug(base_link, extra={"service_name": Fanza.__service_name__})
                        
                        files, iv, key = fanza.Fanza_util.parse_m3u8(content_link, base_link, license_uid, Fanza.__service_name__)
                        
                        dl_list = fanza.Fanza_util.download_chunk(files, iv, key, unixtime, config, Fanza.__service_name__)
                        
                        unixtime_temp = str(int(time.time()))
                        output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                        fanza.Fanza_util.merge_video(dl_list, output_path, Fanza.__service_name__)
                        
                        real_output = os.path.join(config["directorys"]["Downloads"], single["title"]+"_part"+str(part)+".mp4")
                        fanza.Fanza_util.mux_video(output_path, real_output, Fanza.__service_name__, config)
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
                        logger.info('Finished download: {}'.format(single["title"]), extra={"service_name": Fanza.__service_name__})
                    else:
                        continue
                    
                if found_item == False:
                    logger.error("No matches found. Here is a list of contents", extra={"service_name": Fanza.__service_name__})
                    for single in bought_list:
                        logger.info(f" + ID: {single["product_id"]} TITLE: {single["title"]}", extra={"service_name": Fanza.__service_name__})
            else:
                # download all title
                part = "1"
                for single in bought_list:
                    if single["content_type"] == "vr":
                        #logger.info("VR Downloader is now ongoing. please wait")
                        continue
                    else:
                        logger.info("Download 1 Content", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["title"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["quality_name"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["viewing_text"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + single["product_id"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + " + str(single["mylibrary_id"]), extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Get License ID", extra={"service_name": Fanza.__service_name__})
                        status, license_uid = fanza_downloader.get_license_uid(fanza_userid)
                        if status == False:
                            logger.info("Failed to get License UID", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + "+license_uid, extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Send License Request", extra={"service_name": Fanza.__service_name__})
                        status, license, license_payload = fanza_downloader.get_license(fanza_userid, single, license_uid, fanza_secret_key, part)
                        logger.info(" + KEY: "+license["data"]["cookie"][0]["value"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + UID: "+license_payload["authkey"], extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Get Streaming m3u8", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + "+license["data"]["redirect"][:20], extra={"service_name": Fanza.__service_name__})
                        
                        status, resolution_list = fanza_downloader.get_resolution(single["shop_name"], single["product_id"], fanza_secret_key)
                        
                        global_parser = parser.global_parser()
                        tracks = global_parser.hls_parser(m3u8_2.text)
                        p_to_resolution = {
                            "240p": "426x240",
                            "360p": "640x360",
                            "480p": "854x480",
                            "720p": "1280x720",
                            "1080p": "1920x1080"
                        }
                        bitrate_to_resolution = {}
                        
                        for item in resolution_list["data"]["result2"]:
                            bitrate = int(item["bitrate"])
                            match = re.search(r"\((\d+p)\)", item["quality_display_name"])
                            if match:
                                p_quality = match.group(1)
                                resolution = p_to_resolution.get(p_quality)
                                if resolution:
                                    bitrate_to_resolution[bitrate] = resolution
                        
                        for track in tracks["video_track"]:
                            bitrate = track["bitrate"]
                            if bitrate in bitrate_to_resolution:
                                track["resolution"] = bitrate_to_resolution[bitrate]
                        track_data = global_parser.print_tracks(tracks)
                        print(track_data)
                        
                        get_best_track = global_parser.select_best_tracks(tracks)
                        
                        logger.info("Selected Best Track:", extra={"service_name": Fanza.__service_name__})
                        logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": Fanza.__service_name__})
                        
                        content_link = m3u8_1.headers["Location"].replace(
                            "playlist.m3u8", "chunklist_b" + str(get_best_track["video"]["bandwidth"]) + ".m3u8"
                        )
                        base_link = content_link.rsplit("/", 1)[0] + "/"
                        
                        logger.debug(content_link, extra={"service_name": Fanza.__service_name__})
                        logger.debug(base_link, extra={"service_name": Fanza.__service_name__})
                        
                        files, iv, key = fanza.Fanza_util.parse_m3u8(content_link, base_link, license_uid, Fanza.__service_name__)
                        
                        dl_list = fanza.Fanza_util.download_chunk(files, iv, key, unixtime, config, Fanza.__service_name__)
                        
                        unixtime_temp = str(int(time.time()))
                        output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                        fanza.Fanza_util.merge_video(dl_list, output_path, Fanza.__service_name__)
                        
                        real_output = os.path.join(config["directorys"]["Downloads"], single["title"]+"_part"+str(part)+".mp4")
                        fanza.Fanza_util.mux_video(output_path, real_output, Fanza.__service_name__, config)
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
                        logger.info('Finished download: {}'.format(single["title"]), extra={"service_name": Fanza.__service_name__})
             
                
        except Exception:
            logger.error("Traceback has occurred", extra={"service_name": Fanza.__service_name__})
            print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
            print("\n----ERROR LOG----")
            console.print_exception()
            print("Service: "+Fanza.__service_name__)
            print("Version: "+additional_info[0])
            print("----END ERROR LOG----")
class Fanza_VR:
    __service_name__ = "Fanza_VR"
    def main_command(session, url, email, password, LOG_LEVEL, additional_info):
        try:
            set_variable(session, LOG_LEVEL)
            fanza_downloader = fanza.Fanza_VR_downloader(session, config)
            
            status = check_session(Fanza_VR.__service_name__)
            session_data = None
            session_status = False
            if not status == False:
                session_data = load_session(status)
                if session_data != False:
                    if email and password != None:
                        if (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["password"] == hashlib.sha256(password.encode()).hexdigest()):
                            token_status, special_text = fanza_downloader.check_token(session_data["access_token"])
                            if token_status == False:
                                logger.error("Session is Invalid. Please re-login", extra={"service_name": Fanza_VR.__service_name__})
                            else:
                                session_status = True
                        else:
                            logger.info("Email and password is no match. re-login", extra={"service_name": Fanza_VR.__service_name__})
                            status, message, session_data = fanza_downloader.authorize(email, password)
                            if status == False:
                                logger.error(message, extra={"service_name": Fanza_VR.__service_name__})
                                exit(1)
                            else:
                                with open(os.path.join("cache", "session", Fanza_VR.__service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
                    else:
                        token_status, special_text = fanza_downloader.check_token(session_data["access_token"])
                        if token_status == False:
                            logger.error("Session is Invalid. Please re-login", extra={"service_name": Fanza_VR.__service_name__})
                        else:
                            session_status = True
                
            if session_status == False and (email and password != None):
                status, message, session_data = fanza_downloader.authorize(email, password)
                if status == False:
                    logger.error(message, extra={"service_name": Fanza_VR.__service_name__})
                    exit(1)
                else:
                    with open(os.path.join("cache", "session", Fanza_VR.__service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                        json.dump(session_data, f, ensure_ascii=False, indent=4)      
            
            if session_status == False and (email and password != None):
                fanza_userid = message["id"]
            elif session_status == False and (email and password == None):
                fanza_userid = special_text
            
            status, bought_list = fanza_downloader.get_title()
                                    
            match = re.search(r"product_id=([^&]+)", url)
            if match or "tv.dmm.com/vod/" in url:
                if "tv.dmm.com/vod/" in url:
                    parsed = urlparse(url)
                    query_params = parse_qs(parsed.query)
                    search_content_id = query_params.get("season", [None])[0]
                else:
                    search_content_id = match.group(1)
                part_match = re.search(r"part=([^/]+)", url)
                if part_match:
                    part = str(part_match.group(1))
                else:
                    part = "1"
                
                found_item = False
                    
                for single in bought_list:
                    if single["content_id"] == search_content_id:
                        found_item = True
                        
                        logger.warning("This tool is not support 8k. if you want to download 8k, You should buy FantaVR", extra={"service_name": Fanza_VR.__service_name__})
                        
                        logger.info("Download 1 Content", extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + " + single["title"], extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + " + single["purchased_quality_group"], extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + " + single["expire"], extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + " + single["content_id"], extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + " + str(single["mylibrary_id"]), extra={"service_name": Fanza_VR.__service_name__})
                        
                        logger.info("Get License UID & Streaming m3u8", extra={"service_name": Fanza_VR.__service_name__})
                        
                        if single["purchased_quality_group"] == "8k":
                            quality_name = "high"
                        else:
                            quality_name = single["purchased_quality_group"]
                        
                        status, license_uid, streaming_m3u8 = fanza_downloader.get_license_uid(single["mylibrary_id"], quality_name, part, fanza_vr_secret_key)
                        if status == False:
                            logger.info("Failed to get License UID", extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + "+license_uid, extra={"service_name": Fanza_VR.__service_name__})
                        
                        logger.info("Get Streaming m3u8", extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(" + "+streaming_m3u8[:20], extra={"service_name": Fanza_VR.__service_name__})
                        
                        m3u8_1 = session.get(streaming_m3u8, allow_redirects=False)
                        m3u8_2 = session.get(m3u8_1.headers["Location"])
                        
                        global_parser = parser.global_parser()
                        tracks = global_parser.hls_parser(m3u8_2.text)
                        track_data = global_parser.print_tracks(tracks)
                        print(track_data)
                        
                        get_best_track = global_parser.select_best_tracks(tracks)
                        
                        logger.info("Selected Best Track:", extra={"service_name": Fanza_VR.__service_name__})
                        logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": Fanza_VR.__service_name__})
                        
                        content_link = m3u8_1.headers["Location"].replace(
                            "playlist.m3u8", "chunklist_b" + str(get_best_track["video"]["bandwidth"]) + ".m3u8"
                        )
                        base_link = content_link.rsplit("/", 1)[0] + "/"
                        
                        logger.debug(content_link, extra={"service_name": Fanza_VR.__service_name__})
                        logger.debug(base_link, extra={"service_name": Fanza_VR.__service_name__})
                        
                        files, iv, key = fanza.Fanza_util.parse_m3u8(content_link, base_link, license_uid, Fanza_VR.__service_name__)
                        
                        dl_list = fanza.Fanza_util.download_chunk(files, iv, key, unixtime, config, Fanza_VR.__service_name__)
                        
                        unixtime_temp = str(int(time.time()))
                        output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                        fanza.Fanza_util.merge_video(dl_list, output_path, Fanza_VR.__service_name__)
                        
                        real_output = os.path.join(config["directorys"]["Downloads"], single["title"]+"_part"+str(part)+".mp4")
                        fanza.Fanza_util.mux_video(output_path, real_output, Fanza_VR.__service_name__, config)
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
                        logger.info('Finished download: {}'.format(single["title"]), extra={"service_name": Fanza_VR.__service_name__})
                    else:
                        continue
                if found_item == False:
                    logger.error("No matches found. Here is a list of contents", extra={"service_name": Fanza_VR.__service_name__})
                    for single in bought_list:
                        logger.info(f" + ID: {single["product_id"]} TITLE: {single["title"]}", extra={"service_name": Fanza_VR.__service_name__})
            else:
                # download all title
                part = "1"
                for single in bought_list:
                    logger.warning("This tool is not support 8k. if you want to download 8k, You should buy FantaVR", extra={"service_name": Fanza_VR.__service_name__})
                    
                    logger.info("Download 1 Content", extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + " + single["title"], extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + " + single["purchased_quality_group"], extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + " + single["expire"], extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + " + single["content_id"], extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + " + str(single["mylibrary_id"]), extra={"service_name": Fanza_VR.__service_name__})
                    
                    logger.info("Get License UID & Streaming m3u8", extra={"service_name": Fanza_VR.__service_name__})
                    
                    if single["purchased_quality_group"] == "8k":
                        quality_name = "high"
                    else:
                        quality_name = single["purchased_quality_group"]
                    
                    status, license_uid, streaming_m3u8 = fanza_downloader.get_license_uid(single["mylibrary_id"], quality_name, part, fanza_vr_secret_key)
                    if status == False:
                        logger.info("Failed to get License UID", extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + "+license_uid, extra={"service_name": Fanza_VR.__service_name__})
                    
                    logger.info("Get Streaming m3u8", extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(" + "+streaming_m3u8[:20], extra={"service_name": Fanza_VR.__service_name__})
                    
                    m3u8_1 = session.get(streaming_m3u8, allow_redirects=False)
                    m3u8_2 = session.get(m3u8_1.headers["Location"])
                    
                    global_parser = parser.global_parser()
                    tracks = global_parser.hls_parser(m3u8_2.text)
                    track_data = global_parser.print_tracks(tracks)
                    print(track_data)
                    
                    get_best_track = global_parser.select_best_tracks(tracks)
                    
                    logger.info("Selected Best Track:", extra={"service_name": Fanza_VR.__service_name__})
                    logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": Fanza_VR.__service_name__})
                    
                    content_link = m3u8_1.headers["Location"].replace(
                        "playlist.m3u8", "chunklist_b" + str(get_best_track["video"]["bandwidth"]) + ".m3u8"
                    )
                    base_link = content_link.rsplit("/", 1)[0] + "/"
                    
                    logger.debug(content_link, extra={"service_name": Fanza_VR.__service_name__})
                    logger.debug(base_link, extra={"service_name": Fanza_VR.__service_name__})
                    
                    files, iv, key = fanza.Fanza_util.parse_m3u8(content_link, base_link, license_uid, Fanza_VR.__service_name__)
                    
                    dl_list = fanza.Fanza_util.download_chunk(files, iv, key, unixtime, config, Fanza_VR.__service_name__)
                    
                    unixtime_temp = str(int(time.time()))
                    output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                    fanza.Fanza_util.merge_video(dl_list, output_path, Fanza_VR.__service_name__)
                    
                    real_output = os.path.join(config["directorys"]["Downloads"], single["title"]+"_part"+str(part)+".mp4")
                    fanza.Fanza_util.mux_video(output_path, real_output, Fanza_VR.__service_name__, config)
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
                    logger.info('Finished download: {}'.format(single["title"]), extra={"service_name": Fanza_VR.__service_name__})
             
                
        except Exception:
            logger.error("Traceback has occurred", extra={"service_name": Fanza.__service_name__})
            print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
            print("\n----ERROR LOG----")
            console.print_exception()
            print("Service: "+Fanza.__service_name__)
            print("Version: "+additional_info[0])
            print("----END ERROR LOG----")