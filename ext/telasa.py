import time
import yaml
import logging
from rich.console import Console

from ext.utils import telasa

console = Console()

__service_name__ = "Telasa"

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

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        #additional_info = [__version__, use_rd, use_gnc, use_odc, write_thumbnail, write_description, embed_thumbnail, embed_metadata, embed_subs, embed_chapters]
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Encrypte Content for Everyone", extra={"service_name": "Yoimi"})
        
        unext_downloader = telasa.Telasa_downloader(session)
        
        if email and password != None:
            if config["authorization"]["use_token"]:
                if config["authorization"]["token"] != "":
                    status, message, response_user = unext_downloader.check_token(config["authorization"]["token"])
                    if status == False:
                        logger.error(message, extra={"service_name": __service_name__})
                        exit(1)
                    else:
                        session.headers.update({"Authorization": config["authorization"]["token"]})
                        logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": __service_name__})
                        logger.info("Loggined Account", extra={"service_name": __service_name__})
                        logger.info(" + ID: "+str(response_user["id"]), extra={"service_name": __service_name__})
                        logger.info(" + Subscribed: "+str(response_user["had_subscribed"]), extra={"service_name": __service_name__})
                        login_status = True
                else:
                    logger.error("Please input token", extra={"service_name": __service_name__})
                    exit(1)
            else:
                status, message, response_user = unext_downloader.authorize(email, password)
                try:
                    logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
                except:
                    logger.info("Failed to login", extra={"service_name": __service_name__})
                if status == False:
                    logger.error(message, extra={"service_name": __service_name__})
                    exit(1)
                else:
                    logger.info("Loggined Account", extra={"service_name": __service_name__})
                    logger.info(" + ID: "+str(response_user["id"]), extra={"service_name": __service_name__})
                    logger.info(" + Subscribed: "+str(response_user["had_subscribed"]), extra={"service_name": __service_name__})
                    login_status = True
        else:
            login_status = False
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")