import os
import re
import sys
import time
import json
import yaml
import shutil
import logging
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
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

class Fanza:
    __service_name__ = "Fanza"
    def main_command(session, url, email, password, LOG_LEVEL, additional_info):
        try:
            fanza_downloader = fanza.Fanza_downloader(session, config)
            
            status = check_session(Fanza.__service_name__)
            session_data = None
            session_status = False
            if not status == False:
                session_data = load_session(status)
                
                token_status = fanza_downloader.check_token(session_data["access_token"])
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
                    with open(os.path.join("cache", "session", Fanza.__service_name__, "session_"+str(int(time.time()))+".json"), "w", encoding="utf-8") as f:
                        json.dump(session_data, f, ensure_ascii=False, indent=4)      
            
            
            fanza_userid = message
            
            status, bought_list = fanza_downloader.get_title()
            
            match = re.search(r"parent_product_id=([^/]+)", url)
            if match:
                # download single title
                
                for single in bought_list:
                    if single["product_id"] == match.group(1):
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
                        status, license, license_payload = fanza_downloader.get_license(fanza_userid, single, license_uid, fanza_secret_key)
                        logger.info(" + KEY: "+license["data"]["cookie"][0]["value"], extra={"service_name": Fanza.__service_name__})
                        logger.info(" + UID: "+license_payload["authkey"], extra={"service_name": Fanza.__service_name__})
                        
                        logger.info("Get Streaming m3u8", extra={"service_name": Fanza.__service_name__})
                        logger.info(" + "+license["data"]["redirect"][:20], extra={"service_name": Fanza.__service_name__})
                        
                    else:
                        continue
            else:
                # download all title
                print(" fuck you bro")
             
                
        except Exception as error:
            logger.error("Traceback has occurred", extra={"service_name": Fanza.__service_name__})
            print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
            print("\n----ERROR LOG----")
            console.print_exception()
            print("Service: "+Fanza.__service_name__)
            print("Version: "+additional_info[0])
            print("----END ERROR LOG----")
class Fanza_VR:
    __service_name__ = "Fanza_VR"