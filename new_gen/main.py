import yaml
import requests
import logging

from utils import unext

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

def set_variable():
    global logger, config, session
    
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
        
    session = requests.Session()
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def main_command():
    #url = "https://video.unext.jp/title/SID0104147"
    url = "https://video.unext.jp/play/SID0104147/ED00570917"
    set_variable()
    logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
    
    unext_downloader = unext.Unext_downloader(session)
    
    status, message = unext_downloader.authorize(config["authorization"]["Email"], config["authorization"]["Password"])
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
        #print(meta_response["titleName"])
        
    status = unext.Unext_utils.check_single_episode(url)
    if status == False:
        logger.info("Get Title for Season", extra={"service_name": "U-Next"})
        status, messages = unext_downloader.get_title_parse_all(url)
        if status == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
            exit(1)
        for message in messages:
            logger.info(f" + {config["format"]["anime"].format(seriesname=title_name,titlename=message["displayNo"],episodename=message["episodeName"])}", extra={"service_name": "U-Next"})
    else:
        logger.info("Get Title for 1 Episode", extra={"service_name": "U-Next"})
        status, message = unext_downloader.get_title_parse_single(url)
        if status == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
            exit(1)
        logger.info(f" + {config["format"]["anime"].format(seriesname=title_name,titlename=message["displayNo"],episodename=message["episodeName"])}", extra={"service_name": "U-Next"})
        status, playtoken, media_code = unext_downloader.get_playtoken(message["id"])
        if status == False:
            logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
            exit(1)
        else:
            logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
            #print(playtoken, media_code)
            status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
            if status == False:
                logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                exit(1)
            #print(mpd_content)
            mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
            #video_info = unext.mpd_parse.extract_video_info(mpd_content, "1920x1080 mp4 avc1.4d4028")
            ##print(video_info)
            logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
            #audio_info = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")
            logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
            ##print(audio_info)
            
            license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
            
            logger.info(f" + Decrypt Video License: {license_key["video_key"]}", extra={"service_name": "U-Next"})
            logger.info(f" + Decrypt Audio License: {license_key["audio_key"]}", extra={"service_name": "U-Next"})
            #print(license_key)
            
            session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
            session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        
    # get license, decryt license
    #status, playtoken = unext_downloader.get_playtoken()
main_command()
