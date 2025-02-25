import os
import re
import time
import json
import yaml
import shutil
import logging
import xml.etree.ElementTree as ET

from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console

from global_util import Global_utils
from ext.utils import jff_theater

console = Console()

__service_name__ = "Jff-Theater"

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
        global media_code, playtoken
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        #additional_info = [__version__, use_rd, use_gnc, use_odc, write_thumbnail, write_description, embed_thumbnail, embed_metadata, embed_subs, embed_chapters]
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
        
        jff_downloader = jff_theater.Jff_downloader(session, config)
        
        if email and password != None:
            status, message = jff_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+"Bearer "+temp_token, extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
        else:
            status, message, temp_token = jff_downloader.create_temp_account()
            session.headers.update({"Authorization": "Bearer "+ temp_token})
        if status == False:
            logger.info(message, extra={"service_name": __service_name__})
            exit(1)
        else:
            if email and password != None:
                account_id = message["data"]["accountCode"]
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + AC: "+account_id[:10]+"*****", extra={"service_name": __service_name__})
                logger.info(" + RG: "+message["data"]["country"], extra={"service_name": __service_name__})
            else:
                account_id = message["data"]["accountCode"]
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
                logger.info(" + AC: "+account_id[:10]+"*****", extra={"service_name": __service_name__})
                logger.info(" + RG: "+message["data"]["country"], extra={"service_name": __service_name__})
                temp_account = True
            

        logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
        status, message = jff_downloader.get_content_info(url)
        if status == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
            exit(1)
        
        mpd_link = message["streamname"]
        
        you_lang = "jp"
        if you_lang == "jp":
            title_name_logger = message["contentsTitle"]
        else:
            title_name_logger = message["contentsTitleEn"]
        
        logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
        
        #Global_utils.download_niconico_comment(logger, additional_info, title_name, message.get("displayNo", ""), message.get("displayNo", "").replace("第", "").replace("話", ""), config, title_name_logger, service_type="U-Next")
        
        logger.info(f"Checking {title_name_logger} is playable...", extra={"service_name": __service_name__})
        
        status, message = jff_downloader.check_play_ep(message["contentsCode"])
        if status == False:
            if message == "Region Lock":
                logger.error("Region Locked. Please use Proxie/VPN", extra={"service_name": __service_name__})
                exit(1)
            else:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
        else:
            drm_key = message["data"]["drmKey"]
            mpd_content = session.get("https://www.jff.jpf.go.jp/jff-vod/_definst_/"+mpd_link+"/manifest.mpd").text
            
            # dmm mpd parser
            
        logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
        
        mpd_lic = jff_theater.Jff_utils.parse_mpd_logic(mpd_content)
        
        logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
        
        license_key = jff_theater.Jff_license.license_vd_ad(mpd_lic["pssh"][1], session, drm_key)
                    
        logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
        
        logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
        exit(1)
        status, playtoken, media_code, additional_meta = unext_downloader.get_playtoken(message["id"])
        if status == False:
            logger.error("Failed to Get Episode Playtoken", extra={"service_name": __service_name__})
            exit(1)
        else:
            if additional_info[6] or additional_info[8]:
                unext_downloader.create_ffmetadata(productionYear, [id_type, title_name, message.get("displayNo", ""), message.get("episodeName", "")], unixtime, additional_meta, message.get("displayNo", ""), message["duration"], message["introduction"], copyright, additional_info)
            logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
            status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
            if status == False:
                logger.error("Failed to Get Episode MPD_Content", extra={"service_name": __service_name__})
                session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
            mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)

            logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": __service_name__})
            logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": __service_name__})
            
            license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
            
            logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            
            logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
            logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
            
            logger.info("Checking resolution...", extra={"service_name": __service_name__})
            resolution_s = unext.mpd_parse.get_resolutions(mpd_content)
            logger.info("Found resolution", extra={"service_name": __service_name__})
            for resolution_one in resolution_s:
                logger.info(" + "+resolution_one, extra={"service_name": __service_name__})
            
            logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
            video_url = unext.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
            audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
            logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
            logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
            
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
                logger.info("Downloading All Episode Thumbnails...", extra={"service_name": __service_name__})
                unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
            
            logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
            
            video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
            audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)
            
            logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
            
            unext.Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
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
            
            logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")