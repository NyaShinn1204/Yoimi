import os
import re
import time
import json
import yaml
import shutil
import logging
import ext.global_func.niconico as comment

from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console

from ext.utils import bandai_ch

console = Console()

__service_name__ = "Bandai-Ch"

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
        logger.info("Decrypt Encrypt Content for Everyone", extra={"service_name": "Yoimi"})

        bch_downloader = bandai_ch.Bandai_ch_downloader(session, config)
        
        if email and password != None:
            status, b_session, message, plan_name = bch_downloader.authorize(email, password)
            
            # update session to logined cookie
            session = b_session
            
            try:
                logger.debug("Get Session Key: "+session.cookies["BCHWWW"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + Nickname: "+message["nickname"], extra={"service_name": __service_name__})
                logger.info(" + Level: "+message["lv"], extra={"service_name": __service_name__})
                login_status = True
        else:
            login_status = False
            plan_name = "guest"
            
        global_title_name = bch_downloader.get_title_name(url)
        global_title_id = bch_downloader.get_title_id(url)
            
        status = bch_downloader.check_single_episode(url)
        
        global_title_json = bch_downloader.get_title_data(global_title_id)

        if status == False:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            title_json, episode_id = bch_downloader.get_signle_title_json(url)
            processed_string = re.sub(r'"resolution": "([^"]+)",', r'"resolution": "\1"', title_json)
            single_vod_status = json.loads(processed_string)
            
            #print(episode_id)
            episode_select_json = global_title_json[int(episode_id)-1]
            #print(episode_select_json)
            
            if episode_select_json["strysu_txt"] and episode_select_json["strytitle_txt"] == " ":
                id_genere_type = "劇場"
            else:
                id_genere_type = "ノーマルアニメ"
            id_type = [id_genere_type]
            
            if id_type[0] == "ノーマルアニメ":
                format_string = config["format"]["anime"]
                values = {
                    "seriesname": global_title_name,
                    "titlename": episode_select_json["strysu_txt"],
                    "episodename": episode_select_json["strytitle_txt"]
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type[0] == "劇場":
                format_string = config["format"]["movie"]
                if episode_select_json["strysu_txt"] == "":
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": global_title_name,
                    }
                else:
                    values = {
                        "seriesname": global_title_name,
                        "titlename": episode_select_json["strysu_txt"],
                        "episodename": episode_select_json["strytitle_txt"]
                    }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            
            logger.info("Checking Can download...", extra={"service_name": __service_name__})
            can_download = False
            
            episode_display = ""
            if episode_select_json["prod"][0]["free_f"] == "1":
                can_download = True
                episode_display = "FREE"
            elif episode_select_json["prod"][0]["mbauth_f"] == "1" and login_status:
                if login_status:
                    can_download = True
                episode_display = "MEMBER_FREE"
            elif episode_select_json["prod"][0]["free_f"] == "0" and episode_select_json["prod"][0]["mbauth_f"] == "0":
                if plan_name == "monthly" and login_status:
                    can_download = True
                episode_display = "PAID_OR_MONTHLY"
            
            logger.info("This episode is can download?: "+str(can_download), extra={"service_name": __service_name__})
            if can_download != True:
                logger.error("This episode require: "+str(episode_display), extra={"service_name": __service_name__})
                return
            
            #if episode_display not in ["FREE", "MEMBER_FREE"]:
            #    logger.info(f"This content require: {episode_display}", extra={"service_name": __service_name__})
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")