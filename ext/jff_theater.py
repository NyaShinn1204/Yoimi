import os
import time
import yaml
import shutil
import logging

from rich.console import Console

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
            
        logger.info("Get License for 1 Episode", extra={"service_name": __service_name__})
        
        mpd_lic = jff_theater.Jff_utils.parse_mpd_logic(mpd_content)
        
        logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
        
        license_key = jff_theater.Jff_license.license_vd_ad(mpd_lic["pssh"][1], session, drm_key, config)
                    
        logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
        
        logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})

        logger.debug("Get Segment URL", extra={"service_name": __service_name__})
        segemnt_content = jff_theater.Jff_utils.parse_mpd_content(mpd_content)
        #print(segemnt_content)
        #print(segemnt_content)
        
        #print(hd_link_base)
        
        mpd_base = "https://www.jff.jpf.go.jp/jff-vod/_definst_/"+mpd_link+"/"
        
        segment_list_video = jff_theater.Jff_utils.get_segment_link_list(mpd_content, segemnt_content["video_list"][0]["name"], mpd_base)
        #print(segment_list_video)
        for i in segment_list_video["segments"]:
            logger.debug(" + Video Segment URL "+i, extra={"service_name": __service_name__})
        
        segment_list_audio = jff_theater.Jff_utils.get_segment_link_list(mpd_content, segemnt_content["audio_list"][0]["name"], mpd_base)
        #print(segment_list_audio)
        for i in segment_list_audio["segments"]:
            logger.debug(" + Audio Segment URL "+i, extra={"service_name": __service_name__})
        
        logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
        logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": __service_name__})
        logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": __service_name__})


        logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
        
        downloaded_files_video = jff_downloader.download_segment(segment_list_video["all"], config, unixtime, "download_encrypt_video.mp4")
        downloaded_files_audio = jff_downloader.download_segment(segment_list_audio["all"], config, unixtime, "download_encrypt_audio.mp4")
        #print(downloaded_files)
        print(segment_list_video["total_duration"])
        
        logger.info("Merging encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
        
        #jff_downloader.merge_m4s_files(downloaded_files_video, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"))
        #jff_downloader.merge_m4s_files(downloaded_files_audio, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"))
        
        logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
        jff_theater.Jff_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
        jff_theater.Jff_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
        
        logger.info("Muxing Episode...", extra={"service_name": __service_name__})
        
        result = jff_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4"), config, unixtime, None, title_name_logger, None, additional_info)
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
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")