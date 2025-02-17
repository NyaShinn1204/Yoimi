import re
import os
import yaml
import json
import time
import logging
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime

from ext.utils import crunchyroll

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
    
def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        crunchyroll_downloader = crunchyroll.Crunchyroll_downloader(session)
        
        status, message = crunchyroll_downloader.authorize(email, password)
        try:
            logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "Crunchyroll"})
        except:
            logger.info("Failed to login", extra={"service_name": "Crunchyroll"})
        if status == False:
            logger.info(message, extra={"service_name": "Crunchyroll"})
            exit(1)
        else:
            account_id = message["account_id"]
            logger.info("Loggined Account", extra={"service_name": "Crunchyroll"})
            logger.info(" + ID: "+account_id[:10]+"*****", extra={"service_name": "Crunchyroll"})
            
        status, message = crunchyroll_downloader.login_check()
        if status == False:
            logger.info(message, extra={"service_name": "Crunchyroll"})
            exit(1)
            
        language = "ja-JP"
        
        season_id_info = crunchyroll_downloader.get_info("https://www.crunchyroll.com/series/G1XHJV0XM/alya-sometimes-hides-her-feelings-in-russian")
        logger.info(f"Total Episode: {season_id_info["total"]}", extra={"service_name": "Crunchyroll"})
        for i in season_id_info["data"]:
            #season_number episode_number
            logger.info(i["season_title"] + " " + "S" + str(i["season_number"]).zfill(2) + "E" + str(i["episode_number"]).zfill(2) + " - " + i["title"] + " " + f"[{language}_ID: {i["id"]}]", extra={"service_name": "Crunchyroll"})
        for meta_i in season_id_info["data"]:
            try:
                #season_number episode_number
                logger.info("Downloading 1 episode", extra={"service_name": "Crunchyroll"})
                #print(i["season_title"] + " " + "S" + str(i["season_number"]).zfill(2) + "E" + str(i["episode_number"]).zfill(2) + " - " + i["title"] + " " + f"[{self.language}_ID: {i["id"]}]")
                player_info = session.get(f"https://www.crunchyroll.com/playback/v2/{meta_i["id"]}/web/chrome/play").json()
                #print(player_info)
                mpd_content = session.get(player_info["url"]).text
                #payload = {
                #    "content_id": meta_i["id"],
                #    "playhead": 1
                #}
                headers = {
                    "Content-Type": "application/json"
                }
                #self.session.post(f"https://www.crunchyroll.com/content/v2/{account_id}/playheads?preferred_audio_language=en-US&locale=en-US", json=payload, headers=headers)
                
                
                mpd_lic = crunchyroll.Crunchyroll_utils.parse_mpd_logic(mpd_content)
                logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": "Crunchyroll"})
                
                license_key = crunchyroll.Crunchyroll_license.license_vd_ad(mpd_lic["pssh"][1], session, player_info["token"], meta_i["id"])
                session.delete(f"https://www.crunchyroll.com/playback/v1/token/{meta_i["id"]}/{player_info["token"]}", json={}, headers=headers)
                            
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "Crunchyroll"})
                
                logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": "Crunchyroll"})
                
                logger.info("Get Segment URL", extra={"service_name": "Crunchyroll"})
                segemnt_content = crunchyroll.Crunchyroll_utils.parse_mpd_content(mpd_content)
                #logger.info(segemnt_content)
                #logger.info(segemnt_content)
                
                #logger.info(hd_link_base)
                
                #mpd_base = player_info["url"].replace("manifest.mpd", "")
                
                segment_list_video = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["video"]["name"], segemnt_content["video"]["base_url"])
                #logger.info(segment_list_video)
                for i in segment_list_video["segments"]:
                    logger.debug(" + Video Segment URL "+i, extra={"service_name": "Crunchyroll"})
                
                segment_list_audio = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["audio"]["name"], segemnt_content["audio"]["base_url"])
                #logger.debug(segment_list_audio)
                for i in segment_list_audio["segments"]:
                    logger.debug(" + Audio Segment URL "+i, extra={"service_name": "Crunchyroll"})
                
                logger.info("Video, Audio Content Segment Link", extra={"service_name": "Crunchyroll"})
                logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": "Crunchyroll"})
                logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": "Crunchyroll"})
                logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": "Crunchyroll"})
                
                #print(segemnt_content["video"]["base_url"])
                #print(segment_list_video)
                #print(segment_list_video["all"])
                
                crunchyroll_downloader.download_segment(segment_list_video["all"], config, unixtime, "download_encrypt_video.mp4")
                crunchyroll_downloader.download_segment(segment_list_audio["all"], config, unixtime, "download_encrypt_audio.m4s")
                #exit(1)
                #crunchyroll_downloader.merge_m4s_files(downloaded_files_video, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"))
                #
                crunchyroll.Crunchyroll_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.m4s"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.m4s"), config)
                
                logger.info("Muxing Episode...", extra={"service_name": "Dmm-TV"})
                
                title_name = meta_i["season_title"]
                
                video_duration = meta_i["duration_ms"] / 1000
                
                title_name_logger = meta_i["season_title"] + " " + "S" + str(meta_i["season_number"]).zfill(2) + "E" + str(meta_i["episode_number"]).zfill(2) + " - " + meta_i["title"] + " " + f"[{language}_ID: {meta_i["id"]}]"
                
                result = crunchyroll_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.m4s", os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(video_duration))
                dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    for filename in os.listdir(dir_path):
                        file_path = os.path.join(dir_path, filename)
                        try:
                            if os.path.isfile(file_path):
                                os.remove(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                        except Exception as e:
                            print(f"削除エラー: {e}")
                else:
                    print(f"指定されたディレクトリは存在しません: {dir_path}")
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "Dmm-TV"})
            except Exception as e:
                import sys, traceback
                type_, value, _ = sys.exc_info()
                #print(type_)
                #print(value)
                print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
                print("\n----ERROR LOG----")
                print("ENative:\n"+traceback.format_exc())
                print("EType:\n"+str(type_))
                print("EValue:\n"+str(value))
                session.delete(f"https://www.crunchyroll.com/playback/v1/token/{i["id"]}/{player_info["token"]}", json={}, headers=headers)
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))