import re
import os
import yaml
import json
import uuid
import time
import shutil
import hashlib
import logging

import ext.global_func.parser as parser
from ext.global_func.util.other_util import sanitize_filename

from rich.console import Console

from ext.utils import fod_v2

console = Console()

__service_name__ = "FOD"

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
        
    session.headers.update({"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)"})

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
        #url = "https://fod.fujitv.co.jp/title/8068/8068810008/"
        #url = "https://fod.fujitv.co.jp/title/8068/"
        #url = "https://fod.fujitv.co.jp/title/8068/?genre=drama&shelf=category_JD1000"
        #url = "https://fod.fujitv.co.jp/title/b0i0/?genre=anime&shelf=category_AN1000"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        fod_downloader = fod_v2.FOD_downloader(session, config)
        


        status = check_session(__service_name__)
        session_data = None
        session_status = False
        if not status == False:
            session_data = load_session(status)
            if session_data != False:
                if email != None and password != None:
                    if (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["password"] == hashlib.sha256(password.encode()).hexdigest() and session_data["method"] == "NORMAL"):
                        token_status, message = fod_downloader.check_token(session_data["access_token"], session_data["method"])
                        if token_status == False:
                            logger.error("Session is Invalid. Please re-login", extra={"service_name": __service_name__})
                        else:
                            session_status = True
                    elif (session_data["email"] == hashlib.sha256(email.encode()).hexdigest()) and (session_data["method"] == "QR_LOGIN"):
                        token_status, message = fod_downloader.check_token(session_data["access_token"], session_data["method"])
                        if token_status == False:
                            logger.error("Session is Invalid. Please re-login", extra={"service_name": __service_name__})
                        else:
                            session_status = True
                    else:
                        logger.info("Email and password is no match. re-login", extra={"service_name": __service_name__})
                        status, message, uuid_cookie, login_status, session_data = fod_downloader.authorize(email, password)
                        if status == False:
                            logger.error(message, extra={"service_name": __service_name__})
                            exit(1)
                        else:
                            session_status = True
                            with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                                json.dump(session_data, f, ensure_ascii=False, indent=4)      
                else:
                    token_status, message = fod_downloader.check_token(session_data["access_token"], session_data["method"])
                    if token_status == False:
                        logger.error("Session is Invalid. Please re-login", extra={"service_name": __service_name__})
                    else:
                        session_status = True
            
        if session_status == False and (email != None and password != None):
            status, message, uuid_cookie, login_status, session_data = fod_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                with open(os.path.join("cache", "session", __service_name__.lower(), "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                    json.dump(session_data, f, ensure_ascii=False, indent=4)      
        
        print(session_status, email, password)
        
        if session_status == False and (email != None and password != None):
            account_logined = True
            account_coin = str(message["user_coin"])
            account_point = str(message["user_point"])
            logger.info("Loggined Account", extra={"service_name": __service_name__})
            logger.info(" + Coin: "+account_coin, extra={"service_name": __service_name__})
            logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
            
            if fod_downloader.has_active_courses(message):
                plan_status = True
                logger.info(" + Plan Status: Yes premium", extra={"service_name": __service_name__})
            else:
                plan_status = False
                logger.info(" + Plan Status: Not found", extra={"service_name": __service_name__})
        elif session_status == False and (email == None and password == None):
            account_point = 0
            plan_status = True
            account_logined = False
            logger.info("Using Temp Account", extra={"service_name": __service_name__})
            status, message, login_status = fod_downloader.gen_temptoken()
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
        elif session_status == True:
            account_logined = True
            account_coin = str(message["user_coin"])
            account_point = str(message["user_point"])
            logger.info("Loggined Account", extra={"service_name": __service_name__})
            logger.info(" + Coin: "+account_coin, extra={"service_name": __service_name__})
            logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
            
            if fod_downloader.has_active_courses(message):
                plan_status = True
                logger.info(" + Plan Status: Yes premium", extra={"service_name": __service_name__})
            else:
                plan_status = False
                logger.info(" + Plan Status: Not found", extra={"service_name": __service_name__})
                
        check_single = fod_downloader.check_single_episode(url)
        
        status, episode_list, title_detail = fod_downloader.get_title_parse_all(url)
        
        if "アニメ" in title_detail["attribute"]:
            id_type = "ノーマルアニメ"
        elif "ドラマ" in title_detail["attribute"]:
            id_type = "ノーマルドラマ"
        elif "映画" in title_detail["attribute"]:
            id_type = "映画"
        else:
            id_type = "映画"
        
                    
        season_title = title_detail["lu_title"]
        
        
        logger.info(f" + Video Type: {id_type}", extra={"service_name": __service_name__})
        
        if not check_single:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            
            for single_episode in episode_list:
                ep_title_name = single_episode["ep_title"].replace(single_episode["disp_ep_no"]+" ", "")
                ep_title_num = single_episode["disp_ep_no"]
                
                free_download = False
                
                if single_episode["sales_type"][0] == "free":
                    free_download = True
                    
                if single_episode["purchase_end"] == "":
                    status_purchase = [True, None]
                else:
                    status_purchase = [False, single_episode["purchase_end"]]
                    #status_purchase = single_episode["purchase_end"]
                    
                title_name_logger = fod_downloader.create_titlename_logger(id_type, len(episode_list), season_title, ep_title_num, ep_title_name)
                if free_download:
                    title_name_logger = "FREE    | "+title_name_logger
                else:
                    title_name_logger = "PREMIUM | "+title_name_logger
                if status_purchase[0] == False:
                    title_name_logger = f"END STREAMING: {status_purchase[1][:19]} | "+title_name_logger
                logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            for single_episode in episode_list:
                if plan_status == False:
                    if single_episode["sales_type"][0] == "free":
                        pass
                    else:
                        logger.info("This episode reuqire PREMIUM", extra={"service_name": __service_name__})
                        continue
                
                ep_id = single_episode["ep_id"]
                ep_uuid = str(uuid.uuid4())
                ep_title_name = single_episode["ep_title"].replace(single_episode["disp_ep_no"]+" ", "")
                ep_title_num = single_episode["disp_ep_no"]
                title_name_logger = fod_downloader.create_titlename_logger(id_type, len(episode_list), season_title, ep_title_num, ep_title_name)
                
                episode_metadata = fod_downloader.get_episode_metadata(ep_id, ep_uuid)
                if episode_metadata == None:
                    logger.error("Failed to get Episode Content", extra={"service_name": __service_name__})
                    exit(1)
                    
                if ".mpd" in episode_metadata["url"]:
                    logger.info("Getting information from MPD", extra={"service_name": __service_name__})
                    Tracks = parser.global_parser()
                    transformed_data = Tracks.mpd_parser(session.get(episode_metadata["url"]).text)
                    duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                            
                    logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                    license_key = fod_v2.FOD_license.license_vd_ad(transformed_data["pssh_list"]["widevine"],  episode_metadata["ticket"], session, config)
                    
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
                    
                    if additional_info[1]:
                        random_string = str(int(time.time() * 1000))
                        title_name_logger_video = random_string+"_video_encrypted.mp4"
                        title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                    else:
                        title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4", True)
                        title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4", True)
                    
                    logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                    
                    video_status, video_downloaded = fod_downloader.aria2c(get_best_track["video"]["url"], title_name_logger_video, config, unixtime)
                    audio_status, audio_downloaded = fod_downloader.aria2c(get_best_track["audio"]["url"], title_name_logger_audio, config, unixtime)
                    
                    if not video_status or not audio_status:
                        #logger.error(f"Error: {video_downloaded, audio_downloaded}", extra={"service_name": __service_name__})
                        logger.error("Error: Download failed with error", extra={"service_name": __service_name__})
                        
                        logger.error("---Video Download Error---", extra={"service_name": __service_name__})
                        print("".join(video_downloaded).strip())
                        logger.error("--------------------------", extra={"service_name": __service_name__})
                        logger.error("---Audio Download Error---", extra={"service_name": __service_name__})
                        print("".join(audio_downloaded).strip())
                        logger.error("--------------------------", extra={"service_name": __service_name__})
                        raise Exception("DOWNLOAD ERROR | ARIA2C EXCEPTION")
                    
                    logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                    
                    fod_v2.FOD_decrypt.decrypt_all_content(license_key["key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    season_title = sanitize_filename(season_title, False)
                    title_name_logger = sanitize_filename(title_name_logger, False)             
                    result = fod_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], season_title, title_name_logger+".mp4"), config, unixtime, season_title, int(duration))
                        
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
                    if account_logined != False:
                        fod_downloader.send_stop_signal(episode_metadata, ep_uuid, get_best_track["audio"]["bitrate"], duration)
                if "meta.m3u8" in episode_metadata["url"]:
                    logger.info("Getting information from HLS", extra={"service_name": __service_name__})
                    Tracks = parser.global_parser()
                    transformed_data = Tracks.hls_parser(session.get(episode_metadata["url"]).text)
                    logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                    logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                    track_data = Tracks.print_tracks(transformed_data)
                    
                    print(track_data)
                    
                    get_best_track = Tracks.select_best_tracks(transformed_data)
                    
                    logger.debug(" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                    logger.info("Selected Best Track:", extra={"service_name": __service_name__})
                    logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    
                    files, duration, iv, key = fod_v2.FOD_utils.parse_m3u8(get_best_track["video"]["url"])
                    
                    dl_list = fod_v2.FOD_utils.download_chunk(files, iv, key, unixtime, config, __service_name__)
                    
                    unixtime_temp = str(int(time.time()))
                    output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                    fod_v2.FOD_utils.merge_video(dl_list, output_path, __service_name__)
                    
                    season_title = sanitize_filename(season_title, False)
                    title_name_logger = sanitize_filename(title_name_logger, False)
                    real_output = os.path.join(config["directorys"]["Downloads"], season_title, title_name_logger+".mp4")
                    fod_v2.FOD_utils.mux_video(output_path, season_title, real_output, duration, __service_name__, config)
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
                    if account_logined != False:
                        fod_downloader.send_stop_signal_hls(episode_metadata, ep_uuid, get_best_track["video"]["bitrate"], duration)
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            status, single_episode = fod_downloader.get_title_parse_single(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)

            ep_title_name = single_episode["ep_title"].replace(single_episode["disp_ep_no"]+" ", "")
            ep_title_num = single_episode["disp_ep_no"]
            
            free_download = False
            
            if single_episode["sales_type"][0] == "free":
                free_download = True
                
            if single_episode["purchase_end"] == "":
                status_purchase = [True, None]
            else:
                status_purchase = [False, single_episode["purchase_end"]]
                #status_purchase = single_episode["purchase_end"]
                
            title_name_logger = fod_downloader.create_titlename_logger(id_type, len(episode_list), season_title, ep_title_num, ep_title_name)
            if free_download:
                title_name_logger = "FREE    | "+title_name_logger
            else:
                title_name_logger = "PREMIUM | "+title_name_logger
            if status_purchase[0] == False:
                title_name_logger = f"END STREAMING: {status_purchase[1][:19]} | "+title_name_logger
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
        
            if plan_status == False:
                if single_episode["sales_type"][0] == "free":
                    pass
                else:
                    logger.info("This episode reuqire PREMIUM", extra={"service_name": __service_name__})
                    exit(1)
            
            ep_id = single_episode["ep_id"]
            ep_uuid = str(uuid.uuid4())
            ep_title_name = single_episode["ep_title"].replace(single_episode["disp_ep_no"]+" ", "")
            ep_title_num = single_episode["disp_ep_no"]
            title_name_logger = fod_downloader.create_titlename_logger(id_type, len(episode_list), season_title, ep_title_num, ep_title_name)
            
            episode_metadata = fod_downloader.get_episode_metadata(ep_id, ep_uuid)
            if episode_metadata == None:
                logger.error("Failed to get Episode Content", extra={"service_name": __service_name__})
                exit(1)
                
            if ".mpd" in episode_metadata["url"]:
                logger.info("Getting information from MPD", extra={"service_name": __service_name__})
                Tracks = parser.global_parser()
                transformed_data = Tracks.mpd_parser(session.get(episode_metadata["url"]).text)
                duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                        
                logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                license_key = fod_v2.FOD_license.license_vd_ad(transformed_data["pssh_list"]["widevine"],  episode_metadata["ticket"], session, config)
                
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
                
                if additional_info[1]:
                    random_string = str(int(time.time() * 1000))
                    title_name_logger_video = random_string+"_video_encrypted.mp4"
                    title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                else:
                    title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4", True)
                    title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4", True)
                
                logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
                video_status, video_downloaded = fod_downloader.aria2c(get_best_track["video"]["url"], title_name_logger_video, config, unixtime)
                audio_status, audio_downloaded = fod_downloader.aria2c(get_best_track["audio"]["url"], title_name_logger_audio, config, unixtime)
                
                if not video_status or not audio_status:
                    #logger.error(f"Error: {video_downloaded, audio_downloaded}", extra={"service_name": __service_name__})
                    logger.error("Error: Download failed with error", extra={"service_name": __service_name__})
                    
                    logger.error("---Video Download Error---", extra={"service_name": __service_name__})
                    print("".join(video_downloaded).strip())
                    logger.error("--------------------------", extra={"service_name": __service_name__})
                    logger.error("---Audio Download Error---", extra={"service_name": __service_name__})
                    print("".join(audio_downloaded).strip())
                    logger.error("--------------------------", extra={"service_name": __service_name__})
                    raise Exception("DOWNLOAD ERROR | ARIA2C EXCEPTION")

                
                logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
                fod_v2.FOD_decrypt.decrypt_all_content(license_key["key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                season_title = sanitize_filename(season_title, False)
                title_name_logger = sanitize_filename(title_name_logger, False)           
                result = fod_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], season_title, title_name_logger+".mp4"), config, unixtime, season_title, int(duration))
                    
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
                if account_logined != False:
                    fod_downloader.send_stop_signal(episode_metadata, ep_uuid, get_best_track["audio"]["bitrate"], duration)
            if "meta.m3u8" in episode_metadata["url"]:
                logger.info("Getting information from HLS", extra={"service_name": __service_name__})
                Tracks = parser.global_parser()
                transformed_data = Tracks.hls_parser(session.get(episode_metadata["url"]).text)
                logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                track_data = Tracks.print_tracks(transformed_data)
                
                print(track_data)
                
                get_best_track = Tracks.select_best_tracks(transformed_data)
                
                logger.debug(" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                logger.info("Selected Best Track:", extra={"service_name": __service_name__})
                logger.info(f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                
                files, duration, iv, key = fod_v2.FOD_utils.parse_m3u8(get_best_track["video"]["url"])
                
                dl_list = fod_v2.FOD_utils.download_chunk(files, iv, key, unixtime, config, __service_name__)
                
                unixtime_temp = str(int(time.time()))
                output_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, unixtime_temp+"_nomux_"+".mp4")
                fod_v2.FOD_utils.merge_video(dl_list, output_path, __service_name__)
                season_title = sanitize_filename(season_title, False)
                title_name_logger = sanitize_filename(title_name_logger, False)
                real_output = os.path.join(config["directorys"]["Downloads"], season_title, title_name_logger+".mp4")
                fod_v2.FOD_utils.mux_video(output_path, season_title, real_output, duration, __service_name__, config)
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
                if account_logined != False:
                    fod_downloader.send_stop_signal_hls(episode_metadata, ep_uuid, get_best_track["video"]["bitrate"], duration)
        
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")