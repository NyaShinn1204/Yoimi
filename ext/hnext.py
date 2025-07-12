import os
import re
import yaml
import json
import time
import shutil
import base64
import logging

import ext.global_func.parser as parser

from rich.console import Console
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote

from ext.utils import hnext

from ext.global_func.util.mux_util import main_mux
from ext.global_func.util.download_util import aria2c_downloader
from ext.global_func.util.decrypt_util import main_decrypt
from ext.global_func.util.session_util import session_util
from ext.global_func.util.license_util import license_util

console = Console()

__service_name__ = "H-Next"

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
        
    session.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 japanview/1.0.6"})
    
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
        #url = "https://video.hnext.jp/play/AID0257926/AED0248798?rev=20250307104645" # single
        #url = "https://video.hnext.jp/title/AID0257926"                              # batch
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        hnext_downloader = hnext.Hnext_downloader(session, config)
        


        status = check_session(__service_name__)
        session_logic = session_util(logger=logger, service_name=__service_name__, service_util=hnext_downloader)
        session_data = None
        session_status = False
        
        if status:
            session_data = load_session(status)
            if session_data:
                token_status, message = hnext_downloader.check_token(session_data["access_token"])
                if not token_status:
                    logger.info("Session is Invalid. Please re-login.", extra={"service_name": __service_name__})
                    if email == "QR_LOGIN":
                        method = "qr"
                    else:
                        method = "normal"
                    session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method=method)
                else:
                    session_status = True
            
        if not session_status and email and password:
            if email == "QR_LOGIN":
                method = "qr"
            else:
                method = "normal"
            session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method=method)
        
        if session_status:
            profile_id = message["cuid"]
            logger.info("Logged-in Account", extra={"service_name": __service_name__})
            logger.info(" + id: " + profile_id, extra={"service_name": __service_name__})
            
        logger.info("Analyzing URL", extra={"service_name": __service_name__})
        
        
        # DOWNLOAD LOGIC
        def single_download_logic(url, from_mutli=False, title_name_logger=None, title_name=None):
            aid_id = re.search(r"(AID\d+)", url).group(1)
            
            if "/title/" in url:
                aed_id = title_name
                title_name = None
            else: 
                aed_id = re.search(r"(AED\d+)", url).group(1)
            
            content_info = hnext_downloader.get_content_info(aid=aid_id)
            
            logger.info("Get Title, Catch for 1 Episode", extra={"service_name": __service_name__})

            title_name_logger = content_info["title_name"]
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            logger.info(f" + {content_info["title_comment"]}", extra={"service_name": __service_name__})
            
            logger.info("Getting information from MPD", extra={"service_name": __service_name__})
            
            play_token, content_list = hnext_downloader.get_mpd_info(aed_id=aed_id)
            dash_profile = content_list["movie_profile"].get("dash")
            mpd_link = dash_profile["playlist_url"]
            mpd_text = session.get(mpd_link+f"&play_token={play_token}").text
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(mpd_text)
            duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                    
            logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
            widevine_headers = {
                "content-type": "application/octet-stream",
                "user-agent": "Beautiful_Japan_TV_Android/1.0.6 (Linux;Android 10) ExoPlayerLib/2.12.0",
                "accept-encoding": "gzip",
                "host": "wvproxy.unext.jp",
                "connection": "Keep-Alive"
            }
            license_key = license_util.widevine_license(transformed_data["pssh_list"]["widevine"], dash_profile["license_url_list"]["widevine"]+f"?play_token={play_token}", widevine_headers, session, config)
            
            hnext_downloader.send_stop_signal(play_token=play_token, media_code=content_list["code"])
            
            logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})        
            
            logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
            logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
            track_data = Tracks.print_tracks(transformed_data)
            
            print(track_data) 
            
            get_best_track = Tracks.select_best_tracks(transformed_data)
            
            logger.info("Selected Best Track:", extra={"service_name": __service_name__})
            logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {str(int(int(get_best_track["video"]["bitrate"]) /1000))} kbps", extra={"service_name": __service_name__})
            logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {str(int(int(get_best_track["audio"]["bitrate"]) /1000))} kbps", extra={"service_name": __service_name__})
                          
            duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
            logger.debug(" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})           
            
            logger.info("Downloading Encrypted Video, Audio...", extra={"service_name": __service_name__})
            
            video_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4")
            audio_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4")
            
            downloader = aria2c_downloader()
            
            status, result = downloader.download(get_best_track["video"]["url"], "download_encrypt_video.mp4", config, unixtime, __service_name__)
            status, result = downloader.download(get_best_track["audio"]["url"], "download_encrypt_audio.mp4", config, unixtime, __service_name__)
            
            logger.info("Decrypting Encrypted Video, Audio...", extra={"service_name": __service_name__})
            
            decryptor = main_decrypt(logger)
            
            video_decrypt_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4")
            audio_decrypt_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4")
            
            decryptor.decrypt(license_keys=license_key, input_path=[video_output, audio_output], output_path=[video_decrypt_output, audio_decrypt_output], config=config, service_name=__service_name__)
                        
            def sanitize_filename(filename: str) -> str:
                """
                Fucking idiot Windows filename convert to nice string 
                """
                replacements = {
                    '<': '＜',
                    '>': '＞',
                    ':': '：',
                    '"': '”',
                    '/': '／',
                    '\\': '＼',
                    '|': '｜',
                    '?': '？',
                    '*': '＊'
                }
                for bad_char, safe_char in replacements.items():
                    filename = filename.replace(bad_char, safe_char)
                return filename
            
            if title_name != None:
                if os.name == "nt":
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name, sanitize_filename(os.path.join(title_name_logger+".mp4")))
                else:
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
            else:
                if os.name == "nt":
                    output_path = os.path.join(config["directorys"]["Downloads"], sanitize_filename(os.path.join(title_name_logger+".mp4")))
                else:
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4")
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            muxer = main_mux(logger)
            
            muxer.mux_content(video_input=video_decrypt_output, audio_input=audio_decrypt_output, output_path=output_path, duration=int(duration), service_name=__service_name__)
            
            if LOG_LEVEL != "DEBUG":
                dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                try:
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        shutil.rmtree(dir_path)
                    else:
                        print(f"Folder is not found: {dir_path}")
                except Exception as e:
                    print(f"Delete folder errro: {e}")
            
            logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
            
        def season_download_logic(url):
            aid_id = re.search(r"(AID\d+)", url).group(1)
            content_json = hnext_downloader.get_content_info(aid_id)            
            logger.info("Get Info for Season", extra={"service_name": __service_name__})
            logger.info(f" + Title: {content_json["title_name"]}", extra={"service_name": __service_name__})
            
            single_download_logic(url, from_mutli=True, title_name_logger=content_json["title_name"], title_name=content_json["episode_code"])
                
            logger.info("Finished download Season: {}".format(content_json["title_name"]), extra={"service_name": __service_name__})
        
        if "/title/" in url:
            season_download_logic(url)
        elif "/play/" in url:
            single_download_logic(url)
        else:
            logger.error("Unknown contetn strcuture", extra={"service_name": __service_name__})
        return
    
        logger.error("Unsupported Type URL", extra={"service_name": __service_name__})
            
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")