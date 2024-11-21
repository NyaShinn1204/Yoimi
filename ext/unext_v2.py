import os
import yaml
import time
import shutil
import logging

from ext.utils import unext

class CustomFormatter(logging.Formatter):
    COLOR_GREEN = "\033[92m"
    COLOR_GRAY = "\033[90m"
    COLOR_RESET = "\033[0m"
    COLOR_BLUE = "\033[94m"

    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{self.COLOR_BLUE}{record.service_name}{self.COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{self.COLOR_GREEN}{record.asctime}{self.COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{self.COLOR_GRAY}{record.levelname}{self.COLOR_RESET}"
        )
        
        return log_message

def set_variable(session):
    global logger, config, unixtime
    
    unixtime = str(int(time.time()))
    
    logger = logging.getLogger('YoimiLogger')
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

def main_command(session, url, email, password):
    try:
        global media_code, playtoken
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        set_variable(session)
        logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
        
        unext_downloader = unext.Unext_downloader(session)
        
        if config["authorization"]["use_token"]:
            if config["authorization"]["token"] != "":
                status, message = unext_downloader.check_token(config["authorization"]["token"])
                if status == False:
                    logger.error(message, extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    session.headers.update({"Authorization": config["authorization"]["token"]})
                    logger.info("Loggined Account", extra={"service_name": "U-Next"})
                    logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                    logger.info(" + Point: "+str(message["points"]), extra={"service_name": "U-Next"})
            else:
                logger.error("Please input token", extra={"service_name": "U-Next"})
                exit(1)
        else:
            status, message = unext_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": "U-Next"})
                exit(1)
            else:
                logger.info("Loggined Account", extra={"service_name": "U-Next"})
                logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                logger.info(" + Point: "+str(message["points"]), extra={"service_name": "U-Next"})
            
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
        if status == False:
            logger.info("Get Title for Season", extra={"service_name": "U-Next"})
            status, messages = unext_downloader.get_title_parse_all(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
                exit(1)
            for message in messages:
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
                logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
            for message in messages:
                status, playtoken, media_code = unext_downloader.get_playtoken(message["id"])
                if status == False:
                    logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
                    status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
                    if status == False:
                        logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                        exit(1)
                    mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
        
                    logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
                    logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
                    
                    license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
                    
                    logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "U-Next"})
                    
                    logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                    logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                                        
                    logger.info("Video, Audio Content Link", extra={"service_name": "U-Next"})
                    video_url = unext.mpd_parse.extract_video_info(mpd_content, "1920x1080 mp4 avc1.4d4028")["base_url"]
                    audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                    logger.info(" + Video_URL: "+video_url, extra={"service_name": "U-Next"})
                    logger.info(" + Audio_URL: "+audio_url, extra={"service_name": "U-Next"})
                    
                    title_name_logger_video = title_name_logger+"_video_encrypted.mp4"
                    title_name_logger_audio = title_name_logger+"_audio_encrypted.mp4"
                    
                    logger.info("Downloading Encrypted Video, Audio Files..", extra={"service_name": "U-Next"})
                    
                    video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video.replace(":", ""), config, unixtime)
                    audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio.replace(":", ""), config, unixtime)
                    
                    logger.info("Decrypting encrypted Video, Audio Files..", extra={"service_name": "U-Next"})
                    
                    unext.Unext_decrypt.decrypt_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), config)
                    unext.Unext_decrypt.decrypt_content(license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                    
                    result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name)
                        
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
                    
                    logger.info('Finished downloading: {}'.format(title_name_logger), extra={"service_name": "U-Next"})
                                           
                    
                    session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                    session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": "U-Next"})
            status, message = unext_downloader.get_title_parse_single(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
                exit(1)
            
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
            logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
            
            status, playtoken, media_code = unext_downloader.get_playtoken(message["id"])
            if status == False:
                logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
                exit(1)
            else:
                logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
                status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
                if status == False:
                    logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                    exit(1)
                mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
    
                logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
                logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
                
                license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
                
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "U-Next"})
                
                logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                
                logger.info("Video, Audio Content Link", extra={"service_name": "U-Next"})
                video_url = unext.mpd_parse.extract_video_info(mpd_content, "1920x1080 mp4 avc1.4d4028")["base_url"]
                audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                logger.info(" + Video_URL: "+video_url, extra={"service_name": "U-Next"})
                logger.info(" + Audio_URL: "+audio_url, extra={"service_name": "U-Next"})
                
                title_name_logger_video = title_name_logger+"_video_encrypted.mp4"
                title_name_logger_audio = title_name_logger+"_audio_encrypted.mp4"
                
                logger.info("Downloading Encrypted Video, Audio Files..", extra={"service_name": "U-Next"})
                
                video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video.replace(":", ""), config, unixtime)
                audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio.replace(":", ""), config, unixtime)
                
                logger.info("Decrypting encrypted Video, Audio Files..", extra={"service_name": "U-Next"})
                
                unext.Unext_decrypt.decrypt_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), config)
                unext.Unext_decrypt.decrypt_content(license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name)
                    
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
                
                logger.info('Finished downloading: {}'.format(title_name_logger), extra={"service_name": "U-Next"})
                                       
                
                session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))
        session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")