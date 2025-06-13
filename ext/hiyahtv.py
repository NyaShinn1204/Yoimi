import os
import re
import yaml
import json
import time
import hashlib
import logging

from rich.console import Console

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