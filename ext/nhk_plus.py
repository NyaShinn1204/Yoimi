# ok analyze is done
# これだけ無駄にコード綺麗に書いてやろうかな
import sys
import yaml
import time
import logging
import requests
import traceback

from ext.utils import nhk_plus

__service_name__ = "NHK+"

def set_variable(session, LOG_LEVEL):
    global logger, config, unixtime

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
    session.headers.update({"Accept": "application/json, text/plain, */*"})

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        nhkplus_downloader = nhk_plus.NHKplus_downloader(session)
        
        if email and password != "":
            status, message = nhkplus_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": "NHK+"})
                exit(1)
            else:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "NHK+"})
                plan_status = message["planStatus"]["planType"]
                logger.info("Loggined Account", extra={"service_name": "NHK+"})
                logger.info(" + ID: "+message["id"], extra={"service_name": "NHK+"})
                logger.info(" + PlanType: "+plan_status, extra={"service_name": "NHK+"})
        else:
            plan_status = "No Logined"
        
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        #print(traceback.format_exc())
        #print("\n")
        type_, value, _ = sys.exc_info()
        #print(type_)
        #print(value)
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        print("ENative:\n"+traceback.format_exc())
        print("EType:\n"+str(type_))
        print("EValue:\n"+str(value))
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")