import os
import yaml
import time
import shutil
import logging
from datetime import datetime

from ext.utils import dmm_tv

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

def main_command(session, url, email, password, LOG_LEVEL):
    try:
        #global media_code, playtoken
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema, Dmm-TV Content for Everyone", extra={"service_name": "Yoimi"})
        
        dmm_tv_downloader = dmm_tv.Dmm_TV_downloader(session)
        
        if email and password != "":
            status, message = dmm_tv_downloader.authorize(email, password)
            logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "Dmm-TV"})
            if status == False:
                logger.error(message, extra={"service_name": "Dmm-TV"})
                exit(1)
            else:
                logger.info("Loggined Account", extra={"service_name": "Dmm-TV"})
                logger.info(" + ID: "+message["id"], extra={"service_name": "Dmm-TV"})
                logger.info(" + PlanType: "+message["planStatus"]["planType"], extra={"service_name": "Dmm-TV"})
        
        status, season_id, content_id = dmm_tv.Dmm_TV_utils.parse_url(url)
                
        status_check = dmm_tv_downloader.check_free(season_id, content_id)
        if "false" in status_check:
            logger.warning("This content require subscribe plan", extra={"service_name": "Dmm-TV"})
            pass
            #exit(1)
        else:
            logger.warning("This content is free!", extra={"service_name": "Dmm-TV"})
                
        status, meta_response = dmm_tv_downloader.get_title_metadata(season_id)
        if status == False:
            logger.error("Failed to Get Series Json", extra={"service_name": "Dmm-tv"})
            exit(1)
        else:
            title_name = meta_response["titleName"]
            
        logger.info("Get Video Type for URL", extra={"service_name": "Dmm-TV"})
        status_id, id_type = dmm_tv_downloader.get_id_type(season_id)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "Dmm-TV"})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": "Dmm-TV"})

        if type(status_check) == list:
            logger.info("Get Title for Season", extra={"service_name": "Dmm-TV"})
            status, messages = dmm_tv_downloader.get_title_parse_all(season_id)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "Dmm-TV"})
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
                content_type = status_check[i]
                if content_type == "true":
                    content_type = "FREE   "
                else:
                    content_type = "PREMIUM"
                logger.info(f" + {content_type} | {title_name_logger}", extra={"service_name": "Dmm-TV"})
                
                i=i+1
            # forかなんかで取り出して、実行
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": "Dmm-TV"})
            status, message = dmm_tv_downloader.get_title_parse_single(season_id, content_id)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "Dmm-TV"})
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
            content_type = status_check
            if content_type == "true":
                content_type = "FREE   "
            else:
                content_type = "PREMIUM"
            logger.info(f" + {content_type} | {title_name_logger}", extra={"service_name": "Dmm-TV"})
            
            status, links = dmm_tv_downloader.get_mpd_link(content_id)
            logger.debug(f"{status},{links}", extra={"service_name": "Dmm-TV"})
            
            logger.debug(f"Parse links", extra={"service_name": "Dmm-TV"})
            
            hd_link = dmm_tv_downloader.parse_quality(links)
            logger.debug(f" + HD MPD: {hd_link}", extra={"service_name": "Dmm-TV"})
            
            logger.info(f"Get License for 1 Episode", extra={"service_name": "Dmm-TV"})
            status, mpd_content = dmm_tv_downloader.get_mpd_content(hd_link)
            
            mpd_lic = dmm_tv.Dmm_TV_utils.parse_mpd_logic(mpd_content)
                        
            logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": "Dmm-TV"})
            
            license_key = dmm_tv.Dmm_TV__license.license_vd_ad(mpd_lic["pssh"][1], session)
            
            logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "Dmm-TV"})
            
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": "Dmm-TV"})
            
            logger.info("Checking resolution...", extra={"service_name": "Dmm-TV"})
            logger.info("Found resolution", extra={"service_name": "Dmm-TV"})
            for resolution_one in links:
                logger.info(" + "+resolution_one["quality_name"], extra={"service_name": "Dmm-TV"})
            
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))