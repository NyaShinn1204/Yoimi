import os
import re
import yaml
import json
import time
import shutil
import hashlib
import logging

import ext.global_func.parser as parser

from rich.console import Console
from urllib.parse import urlparse

from ext.utils import lemino
from ext.global_func.session_util import session_util

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
        
    session.headers.update({"User-Agent": "Lemino/7.2.2(71) A7S;AndroidTV;10"})
    
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
        #url = "https://lemino.docomo.ne.jp/contents/Y3JpZDovL3BsYWxhLmlwdHZmLmpwL3ZvZC/xxxxx"    # single
        #url = "https://lemino.docomo.ne.jp/search/word/XXXXXX?crid=Y3JpZDovL3BsYWxh..."          # search
        #url = "https://lemino.docomo.ne.jp/contents/Y3JpZDovL3BsYWxhLmlwdHZmLmpwL2dyb3Vw/xxxxx." # batch
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        lemino_downloader = lemino.Lemino_downloader(session, config)
        


        status = check_session(__service_name__)
        session_logic = session_util(logger=logger, service_name=__service_name__, service_util=lemino_downloader)
        session_data = None
        session_status = False
        
        if status:
            session_data = load_session(status)
            if session_data:
                token_status, message = lemino_downloader.check_token(session_data["access_token"])
                if not token_status:
                    logger.info("Session is Invalid. Please re-login.", extra={"service_name": __service_name__})
                    session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method="qr")
                else:
                    session_status = True
            
        if not session_status and email and password:
            session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method="qr")
    
        if session_status:
            account_logined = True
            profile_id = message["profile"]["profile_id"]
            logger.info("Logged-in Account", extra={"service_name": __service_name__})
            logger.info(" + id: " + profile_id, extra={"service_name": __service_name__})
        else:
            account_logined = False
            lemino_downloader.use_temptoken_flug()
            logger.info("Using Temp Account", extra={"service_name": __service_name__})

            
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")