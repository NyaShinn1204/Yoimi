import os
import re
import yaml
import json
import time
import shutil
import hashlib
import logging

import ext.global_func.parser as parser

from rich.console import Console
from urllib.parse import urlparse

from ext.utils import hiyahtv

console = Console()

__service_name__ = "Hi-YAH!"

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
        
    session.headers.update({"User-Agent": "Hi-YAH!/8.402.1(Google AOSP TV on x86, Android 16 (API 36))"})

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


def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://www.hiyahtv.com/masked-avengers"
        #url = "https://www.hiyahtv.com/creation-of-the-gods-kingdom-of-storms/videos/creation-of-the-gods-kingdom-of-storms"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        hi_yah_downloader = hiyahtv.HI_YAH_downloader(session, config)
        


        status = check_session(__service_name__)
        session_data = None
        session_status = False
        if not status == False:
            session_data = load_session(status)
            if session_data != False:
                if email and password != None:
                    if (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["password"] == hashlib.sha256(password.encode()).hexdigest() and session_data["method"] == "NORMAL"):
                        token_status, message = hi_yah_downloader.check_token(session_data["access_token"])
                        if token_status == False:
                            logger.info("Session is Invalid. Refresing...", extra={"service_name": __service_name__})
                            hi_yah_downloader.refresh_token(session_data["refresh_token"], session_data)
                            status, message = hi_yah_downloader.get_userinfo()
                            if status:
                                with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
                                session_status = True
                            else:
                                logger.error("Refresh failed. Please re-login", extra={"service_name": __service_name__})
                        else:
                            session_status = True
                    elif (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["method"] == "QR_LOGIN"):
                        token_status, message = hi_yah_downloader.check_token(session_data["access_token"])
                        if token_status == False:
                            logger.info("Session is Invalid. Refresing...", extra={"service_name": __service_name__})
                            hi_yah_downloader.refresh_token(session_data["refresh_token"], session_data)
                            status, message = hi_yah_downloader.get_userinfo()
                            if status:
                                with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
                                session_status = True
                            else:
                                logger.error("Refresh failed. Please re-login", extra={"service_name": __service_name__})
                        else:
                            session_status = True
                    else:
                        logger.info("Email and password is no match. re-login", extra={"service_name": __service_name__})
                        status, message, login_status, session_data = hi_yah_downloader.authorize(email, password)
                        if status == False:
                            logger.error(message, extra={"service_name": __service_name__})
                            exit(1)
                        else:
                            session_status = True
                            with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                json.dump(session_data, f, ensure_ascii=False, indent=4)      
                else:
                    token_status, message = hi_yah_downloader.check_token(session_data["access_token"])
                    if token_status == False:
                        logger.info("Session is Invalid. Refresing...", extra={"service_name": __service_name__})
                        hi_yah_downloader.refresh_token(session_data["refresh_token"], session_data)
                        status, message = hi_yah_downloader.get_userinfo()
                        if status:
                            with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                json.dump(session_data, f, ensure_ascii=False, indent=4)      
                            session_status = True
                        else:
                            logger.error("Refresh failed. Please re-login", extra={"service_name": __service_name__})
                    else:
                        session_status = True
            
        if session_status == False and (email and password != None):
            status, message, login_status, session_data = hi_yah_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
        
        if session_status == False and (email and password != None):
            account_logined = True
            account_id = str(message["id"])
            logger.info("Loggined Account", extra={"service_name": __service_name__})
            logger.info(" + id: "+account_id, extra={"service_name": __service_name__})
        elif session_status == False and (email and password == None):
            account_point = 0
            account_logined = False
            logger.info("Using Temp Account", extra={"service_name": __service_name__})
        elif session_status == True:
            account_logined = True
            account_id = str(message["id"])
            logger.info("Loggined Account", extra={"service_name": __service_name__})
            logger.info(" + id: "+account_id, extra={"service_name": __service_name__})
            
        if not re.match(r'^https?://(?:www\.)?hiyahtv\.com/.*/videos/[\w\-]+', url): # Season
            # Get Content id
            content_id = hi_yah_downloader.get_contentid_page(url)["PROPERTIES"]["COLLECTION_ID"]
            status, metadata = hi_yah_downloader.get_content_info(content_id)
            if metadata["items_count"] != 0:
                logger.info("Get Title for Season", extra={"service_name": __service_name__})
                item_list = hi_yah_downloader.get_item_list(content_id)
                for single in item_list["items"]:
                    title_name_logger = single["entity"]["title"]
                    logger.info(" + "+title_name_logger, extra={"service_name": __service_name__})
                for single in item_list["items"]:
                    logger.info("Checking Content Info", extra={"service_name": __service_name__})
                    logger.info(f"Support 5.1ch?: {single["entity"]["audio_5_1"]}", extra={"service_name": __service_name__})
                    
                    episode_id = str(single["entity"]["id"])
                    
                    logger.info("Getting Content Stream", extra={"service_name": __service_name__})
                    mpd_list = hi_yah_downloader.get_mpd_list(logger, __service_name__, episode_id)
                    if mpd_list == None:
                        logger.error("Can't found MP4 Stream", extra={"service_name": __service_name__})
                        
                    widevine_url = mpd_list["drm"]["schemes"]["widevine"]["license_url"]
                    playready_url = mpd_list["drm"]["schemes"]["widevine"]["license_url"]
                    logger.debug("Widevine URL: {}".format(widevine_url), extra={"service_name": __service_name__})
                    logger.debug("PlayReady URL: {}".format(playready_url), extra={"service_name": __service_name__})
                    
                    main_mpd_url = mpd_list["url"]
                    logger.debug("MPD URL: {}".format(main_mpd_url), extra={"service_name": __service_name__})
                    logger.info("Parse MPD file", extra={"service_name": __service_name__})
                    Tracks = parser.global_parser()
                    mpd_request = session.get(main_mpd_url)
                    base_link_temp = mpd_request.url
                    transformed_data = Tracks.mpd_parser(mpd_request.text)
                    logger.debug("Tracks Data: {}".format(transformed_data), extra={"service_name": __service_name__})
                    
                    logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                    license_key = hiyahtv.Hi_YAH_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, config)
                    
                    logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                    logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})        
                    
                    logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                    logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                    track_data = Tracks.print_tracks(transformed_data)
                    
                    print(track_data)

                    get_best_track = Tracks.select_best_tracks(transformed_data)
                    
                    logger.debug(" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                    logger.info("Selected Best Track:", extra={"service_name": __service_name__})
                    logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    
                    logger.debug("Calculate about Manifest...", extra={"service_name": __service_name__})
                    duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                    logger.debug(" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})
                    
                    logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                    video_segment_list = get_best_track["video"]["segment_count"]
                    audio_segment_list = get_best_track["audio"]["segment_count"]
                    logger.info(" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
                    logger.info(" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
                    
                    video_segment_links = []
                    audio_segment_links = []
                    
                    parsed = urlparse(base_link_temp)
                    real_base_url = parsed.path.split('/')
                    if 'v2' in real_base_url:
                        v2_index = real_base_url.index('v2')
                        base_path = '/'.join(real_base_url[:v2_index + 1]) + '/'
                        segment_base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
                    
                    video_segment_links.append(segment_base_url+get_best_track["video"]["url"])
                    audio_segment_links.append(segment_base_url+get_best_track["audio"]["url"])
                    
                    for single_segment in range(video_segment_list):
                        temp_link = segment_base_url+get_best_track["video"]["url_base"]+get_best_track["video"]["url_segment_base"].split('/', 1)[1].replace("$Number$", str(single_segment))
                        video_segment_links.append(temp_link)
                    for single_segment in range(audio_segment_list):
                        temp_link = segment_base_url+get_best_track["audio"]["url_base"]+get_best_track["audio"]["url_segment_base"].split('/', 1)[1].replace("$Number$", str(single_segment))
                        audio_segment_links.append(temp_link)
                    
                    logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    hi_yah_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
                    hi_yah_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
                    
                    logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    hiyahtv.Hi_YAH_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4")
                    
                    result = hi_yah_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", output_path, config, unixtime, None, int(duration))
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
            else:
                logger.error("Item not found", extra={"service_name": __service_name__})
                
        else: # Single
            # Get Content id
            content_id = hi_yah_downloader.get_contentid_page(url)["PROPERTIES"]["COLLECTION_ID"]
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")