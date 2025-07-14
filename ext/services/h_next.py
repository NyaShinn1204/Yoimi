from ext.util import Logger

__service_name__ = "H-Next"
__user_agent__ = "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 japanview/1.0.6"

def main_command(email, password, url, command_list):    
    ## SERVICE INFO
    ## name: H-Next
    ## require_account: Yes
    ## cache_session: Yes
    ## support_url: 
    ##    https://video.hnext.jp/title/xxx
    ##    https://video.hnext.jp/play/xxx/xxx
    
    logger = Logger.create_logger(service_name=__service_name__, LOG_LEVEL=command_list["verbose"])
    
    if not email or not password:
        logger.error(f"{__service_name__} is require account login.")
    
    pass