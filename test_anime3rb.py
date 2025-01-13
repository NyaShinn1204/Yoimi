import re
import sys
import time
import yaml
import logging
import requests
import traceback
from urllib.parse import urlparse, parse_qs

import ongoing.anime3rb.anime3rb as anime3rb

__service_name__ = "Anime3rb"

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
        
        anime3rb_downloader = anime3rb.Anime3rb_downloader(session)
        
        # No require login for this site
        
        if url.__contains__("search?q="):            
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            re_search_query = query_params.get('q', [None])[0]
            
            result, links = anime3rb_downloader.search(re_search_query)
        
            logger.info("[+] Get Result: {search_name}".format(search_name=re_search_query),extra={"service_name": __service_name__})
            for i, result_sig  in enumerate(result):
                logger.info(f"[+] {i}: {result_sig.get_text()}",extra={"service_name": __service_name__})
                
            download_title_s = int(input("What do you want to download? (ex: 7): "))
            if download_title_s >= len(result):
                print("ok value is invalid")
                return
            
            anime_name, anime_link_episode_num = anime3rb_downloader.get_info(links[download_title_s])
            
        elif url.__contains__("titles/"):
            anime_name, anime_link_episode_num = anime3rb_downloader.get_info(url)
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            for i in range(int(anime_link_episode_num[1])):
                episode_number = i+1
                def sanitize_filename(filename):
                    filename = filename.replace(":", "：").replace("?", "？")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                
                title_name_logger = sanitize_filename(anime_name[1]+"_"+"#"+str(episode_number).zfill(2)+".mp4")
                logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            for i in range(int(anime_link_episode_num[1])):
                episode_number = i+1
                
                real_url = anime_link_episode_num[0]
                if not url.endswith('/'):
                    url += '/'
                
                url = re.sub(r'/episode/(.*?)/\d+', r'/titles/\1/', real_url)
                url = f"{url}{episode_number}".replace("titles", "episode")
                
                # ok single episode
                logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
                
                player_url = anime3rb_downloader.get_player_info(url).replace('\\u0026', "&")
                player_info = anime3rb_downloader.get_player_meta(player_url)
                
                #print(player_info)
                logger.info("Found resolution", extra={"service_name": __service_name__})
                for info in player_info:
                    logger.info(f"+ {info["label"]}", extra={"service_name": __service_name__})
                    
                # select best resolution
                best_quality_url = player_info[0]["src"]
                
                logger.info("Video Content Link", extra={"service_name": __service_name__})
                logger.info(" + Video_URL: "+best_quality_url, extra={"service_name": __service_name__})
                
                logger.info("Downloading Episode...", extra={"service_name": __service_name__})
                
                def sanitize_filename(filename):
                    filename = filename.replace(":", "：").replace("?", "？")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                
                title_name_logger = sanitize_filename(anime_name[1]+"_"+"#"+str(episode_number).zfill(2)+".mp4")
                            
                video_downloaded = anime3rb_downloader.aria2c(best_quality_url, title_name_logger, config, unixtime, anime_name[1])
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
                
            logger.info('Finished ownload series: {}'.format(title_name_logger), extra={"service_name": __service_name__})
            
        if url.__contains__("episode/"):
            episode_number = re.search(r'/(\d+)$', url).group(1)
            temp_url = re.sub(r'/episode/(.*?)/\d+', r'/titles/\1/', url)
            anime_name, anime_link_episode_num = anime3rb_downloader.get_info(temp_url)
            
            # ok single episode
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            
            player_url = anime3rb_downloader.get_player_info(url).replace('\\u0026', "&")
            player_info = anime3rb_downloader.get_player_meta(player_url)
            
            #print(player_info)
            logger.info("Found resolution", extra={"service_name": __service_name__})
            for info in player_info:
                logger.info(f"+ {info["label"]}", extra={"service_name": __service_name__})
                
            # select best resolution
            best_quality_url = player_info[0]["src"]
            
            logger.info("Video Content Link", extra={"service_name": __service_name__})
            logger.info(" + Video_URL: "+best_quality_url, extra={"service_name": __service_name__})
            
            logger.info("Downloading Episode...", extra={"service_name": __service_name__})
            
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            
            title_name_logger = sanitize_filename(anime_name[1]+"_"+"#"+episode_number.zfill(2)+".mp4")
                        
            video_downloaded = anime3rb_downloader.aria2c(best_quality_url, title_name_logger, config, unixtime, anime_name[1])
            
            logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
        
        #print(anime_name, anime_link_episode_num)
            
        
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
        print("Version: "+additional_info[1])
        print("----END ERROR LOG----")

main_command(requests.Session(),"https://anime3rb.com/titles/isekai-wa-smartphone-to-tomo-ni/","","","",[False,"0.9.0"])