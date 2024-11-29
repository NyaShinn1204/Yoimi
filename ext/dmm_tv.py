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
                
        status = dmm_tv_downloader.check_free(season_id, content_id)
        if "false" in status:
            logger.error("This content require subscribe plan", extra={"service_name": "Dmm-TV"})
            exit(1)
        else:
            logger.debug("This content is free!", extra={"service_name": "Dmm-TV"})

        if type(status) == list:
            logger.info("Get Title for Season", extra={"service_name": "Dmm-TV"})
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": "Dmm-TV"})
            
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))