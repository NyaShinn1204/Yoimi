import yaml
import time
import logging

from ext.utils import fod

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
    
def main_command(session, url, email, password, LOG_LEVEL):
    try:
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        fod_downloader = fod.FOD_downloader(session)
        
        status, message, uuid_cookie = fod_downloader.authorize(email, password)
        try:
            logger.debug("Get Token: "+session.headers["x-authorization"], extra={"service_name": "FOD"})
        except:
            logger.info("Failed to login", extra={"service_name": "FOD"})
        if status == False:
            logger.error(message, extra={"service_name": "FOD"})
            exit(1)
        else:
            account_coin = str(message["user_coin"])
            account_point = str(message["user_point"])
            logger.info("Loggined Account", extra={"service_name": "FOD"})
            logger.info(" + ID: "+message["member_id"], extra={"service_name": "FOD"})
            logger.info(" + Coin: "+account_coin, extra={"service_name": "FOD"})
            logger.info(" + Point: "+account_point, extra={"service_name": "FOD"})        
        #episode_id = "70v8110012"
        #unixtime = str(int(time.time() * 1000))
        #uuid_here = uuid_cookie
        #test = session.get(f"https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={episode_id}&qa=auto&uuid={uuid_here}&starttime=0&is_pt=false&dt=&_={unixtime}")
        #print(test.json()["ticket"])        
        status_id, id_type = fod_downloader.get_id_type(url)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "FOD"})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": "FOD"})
        
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))