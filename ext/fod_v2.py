import re
import os
import yaml
import json
import time
import logging
import shutil
import ext.global_func.niconico as comment

import ext.global_func.parser as parser

from rich.console import Console

from ext.utils import fod_v2

console = Console()

__service_name__ = "FOD"

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
        
    session.headers.update({"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)"})

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://fod.fujitv.co.jp/title/8068/8068810008/"
        #url = "https://fod.fujitv.co.jp/title/8068/"
        #url = "https://fod.fujitv.co.jp/title/8068/?genre=drama&shelf=category_JD1000"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        fod_downloader = fod_v2.FOD_downloader(session)
        
        if email and password != None:
            status, message, uuid_cookie, login_status = fod_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["x-authorization"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                account_coin = str(message["user_coin"])
                account_point = str(message["user_point"])
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + Coin: "+account_coin, extra={"service_name": __service_name__})
                logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
                
                if fod_downloader.has_active_courses(message):
                    plan_status = True
                    logger.info(" + Plan Status: Yes premium")
                else:
                    plan_status = False
                    logger.info(" + Plan Status: Not found")
        else:
            status, message, login_status = fod_downloader.gen_temptoken()
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                account_point = 0
                plan_status = True
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
        
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")