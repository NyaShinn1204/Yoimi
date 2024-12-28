import os
import yaml
import time
import logging
import hashlib
from enum import Enum

from ext.utils import amazon

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

def main_command(session, url, email, password, LOG_LEVEL, quality, vrange):
    try:
        #global media_code, playtoken
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        amazon_downloader = amazon.Amazon_downloader(session)
        
        profile = "default"
        vcodec = "H265"
        vrange = vrange
        vquality = ""
        device_id = None
        device_token = None
        
        if 0 < quality <= 576 and vrange == "SDR":
            logger.info(f"Setting manifest quality to SD", extra={"service_name": "Amazon"})
            vquality = "SD"
            
        if quality > 1080:
            logger.info(f"Setting manifest quality to UHD to be able to get 2160p video track", extra={"service_name": "Amazon"})
            vquality = "UHD"
            
        vquality = vquality or "HD"
                        
        cookies = amazon_downloader.parse_cookie(profile)
        if not cookies:
            logger.error(f"Profile {profile} has no cookies", extra={"service_name": "Amazon"})
            logger.error(f"Please Cookies to /cookies/amazon/default.txt (Netescape format)", extra={"service_name": "Amazon"})
            raise
        else:
            logger.debug(f"Get cookies: {len(cookies)}", extra={"service_name": "Amazon"})
            
        logger.info("Getting Account Region", extra={"service_name": "Amazon"})
        get_region, error_msg = amazon_downloader.get_region()
        if not get_region:
            logger.error("Failed to get Amazon Account Region", extra={"service_name": "Amazon"})
            logger.error(error_msg, extra={"service_name": "Amazon"})
            raise
        
        logger.info(f" + Region: {get_region['code']}", extra={"service_name": "Amazon"})
        
        # Update Region, Endpoints
        endpoints = amazon_downloader.prepare_endpoints(get_region)
        
        session.headers.update({
            "Origin": f"https://{get_region['base']}"
        })
        
        device = amazon_downloader.get_device(profile)
        #if not device:
        #    logger.debug("Device not set. using other option...", extra={"service_name": "Amazon"})
        #logger.debug(f"Device: {device}", extra={"service_name": "Amazon"})

        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        device_cdm = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device_cdm)
        #print(cdm.device_type)
        
        class Types(Enum):
            CHROME = 1
            ANDROID = 2
            PLAYREADY = 3
        
        if (quality > 1080 or vrange != "SDR") and vcodec == "H265" and cdm.device_type == Types.CHROME:
            logger.info(f"Using device to Get UHD manifests", extra={"service_name": "Amazon"})
            device_id, device_token = amazon_downloader.register_device(session, profile, logger)
        elif not device or cdm.device_type == Types.CHROME or vquality == "SD":
            # falling back to browser-based device ID
            if not device:
                logger.warning(f"No Device information was provided for {profile}, using browser device...", extra={"service_name": "Amazon"})
            device_id = hashlib.sha224(
                ("CustomerID" + session.headers["User-Agent"]).encode("utf-8")
            ).hexdigest()
            device = {"device_type": "AOAGZA014O5RE"}
        else:
            logger.debug("Device not set. using other option...", extra={"service_name": "Amazon"})
            device_id, device_token = amazon_downloader.register_device(session, profile, logger)
    
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))