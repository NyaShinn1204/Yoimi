import re
import os
import yaml
import time
import logging
import shutil
from rich.console import Console

from ext.utils import videomarket

__service_name__ = "VideoMarket"

console = Console()

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
        
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"})
    
def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://www.crunchyroll.com/series/G9VHN9QXQ/unnamed-memory"
        #url = "https://www.crunchyroll.com/watch/GG1U2JW3V/cursed-words-and-the-azure-tower"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        videomarket_downloader = videomarket.VideoMarket_downloader(session, config)
        
        if email and password != None:
            status, message = videomarket_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
        else:
            status, message, id_token, refresh_token = videomarket_downloader.get_temp_token()
            session.headers.update({"Authorization": "Bearer "+ id_token})
        if status == False:
            logger.info(message, extra={"service_name": __service_name__})
            exit(1)
        else:
            if email and password != None:
                account_id = str(message["userId"])
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+account_id[:3]+"*****", extra={"service_name": __service_name__})
            else:
                account_id = str(message["userId"])
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+account_id, extra={"service_name": __service_name__})
                
        status = videomarket_downloader.check_single(url)
        
        if status == False:
            logger.info("Get Title For Season", extra={"service_name": __service_name__})
            
            status, message, id_type, title_summary = videomarket_downloader.get_title_parse_all(url)
            
            for single in message:
                if single["groupType"] == "SINGLE_CHOICE":
                    pass
                else:
                    continue
                
                if "アニメ" in id_type and "邦画" not in id_type:
                    format_string = config["format"]["anime"].replace("_{episodename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                        "titlename": single.get("packName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                elif "邦画" in id_type:
                    format_string = config["format"]["movie"]
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if single["price"] == 0:
                    content_type = "FREE   "
                    content_status_lol = ""
                else:
                    content_type = "PREMIUM"
                    content_status_lol = f"| PRICE {str(single["price"])}"
                logger.info(f" + {content_type} {content_status_lol}| {title_name_logger}", extra={"service_name": __service_name__})
            for single in message:
                if single["groupType"] == "SINGLE_CHOICE":
                    pass
                else:
                    continue
                
                if "アニメ" in id_type and "邦画" not in id_type:
                    format_string = config["format"]["anime"].replace("_{episodename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                        "titlename": single.get("packName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                elif "邦画" in id_type:
                    format_string = config["format"]["movie"]
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if single["price"] == 0:
                    content_type = "FREE   "
                    content_status_lol = ""
                else:
                    content_type = "PREMIUM"
                    content_status_lol = f"| PRICE {str(single["price"])}"
                    
                if content_type == "PREMIUM":
                    logger.warning("This episode is require PREMIUM. Skipping...", extra={"service_name": __service_name__})
                    continue
                
                logger.info("Get Playing Access Token", extra={"service_name": __service_name__})
                status, playing_access_token = videomarket_downloader.get_playing_access_token()
                logger.info(" + Playing Access Token (Temp): "+playing_access_token[:10]+"*****", extra={"service_name": __service_name__})
                
                logger.info("Get Playing Token", extra={"service_name": __service_name__})
                
                status, playing_token = videomarket_downloader.get_playing_token(single["packs"][0]["stories"][0]["fullStoryId"], single["packs"][0]["fullPackId"], playing_access_token)
                logger.info(" + Playing Token (Temp): "+playing_token[:10]+"*****", extra={"service_name": __service_name__})
                
                logger.info("Get Streaming Data", extra={"service_name": __service_name__})
                status, streaming_data = videomarket_downloader.get_streaming_info(single["packs"][0]["stories"][0]["fullStoryId"], playing_token, account_id)
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")