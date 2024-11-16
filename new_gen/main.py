import yaml
import requests
import logging

from utils import unext

class CustomFormatter(logging.Formatter):
    COLOR_GREEN = "\033[92m"
    COLOR_GRAY = "\033[90m"
    COLOR_RESET = "\033[0m"
    COLOR_BLUE = "\033[94m"

    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{self.COLOR_BLUE}{record.service_name}{self.COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{self.COLOR_GREEN}{record.asctime}{self.COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{self.COLOR_GRAY}{record.levelname}{self.COLOR_RESET}"
        )
        
        return log_message

def set_variable():
    global logger, config, session
    
    logger = logging.getLogger('YoimiLogger')
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
        
    session = requests.Session()
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def main_command():
    set_variable()
    logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
    
    unext_downloader = unext.Unext_downloader(session)
    
    status, message = unext_downloader.authorize(config["authorization"]["Email"], config["authorization"]["Password"])
    if status == False:
        logger.error(message, extra={"service_name": "U-Next"})
    else:
        logger.info("Loggined Account", extra={"service_name": "U-Next"})
        logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
        logger.info(" + Point: "+str(message["points"]), extra={"service_name": "U-Next"})

main_command()
