import re
import os
import yaml
import time
import logging
import shutil
from rich.console import Console

from ext.utils import crunchyroll

__service_name__ = "Crunchyroll"

console = Console()

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
    
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"})
    
def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://www.crunchyroll.com/series/G9VHN9QXQ/unnamed-memory"
        #url = "https://www.crunchyroll.com/watch/GG1U2JW3V/cursed-words-and-the-azure-tower"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        crunchyroll_downloader = crunchyroll.Crunchyroll_downloader(session)
        
        if email and password != None:
            status, message = crunchyroll_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
        else:
            status, message = crunchyroll_downloader.generate_random_token()
            session.headers.update({"Authorization": "Bearer "+ message["access_token"]})
        if status == False:
            logger.info(message, extra={"service_name": __service_name__})
            exit(1)
        else:
            if email and password != None:
                account_id = message["account_id"]
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+account_id[:10]+"*****", extra={"service_name": __service_name__})
            else:
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
                logger.info(" + Expire: "+str(message["expires_in"]), extra={"service_name": __service_name__})
            
        status, message = crunchyroll_downloader.login_check()
        if status == False:
            logger.info(message, extra={"service_name": __service_name__})
            exit(1)
            
        language = "ja-JP" # Default Language
                
        if url.__contains__("watch"):
            match = re.search(r'"?https?://www\.crunchyroll\.com/(?:series|watch)/([^/"]+)', url)
            content_id =  match.group(1) if match else None
            single_info = crunchyroll_downloader.get_single_info(content_id)["data"][0]
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            language = crunchyroll.Crunchyroll_utils.find_locale_by_guid(single_info["episode_metadata"]["versions"], content_id)
            logger.info(single_info["episode_metadata"]["season_title"] + " " + "S" + str(single_info["episode_metadata"]["season_number"]).zfill(2) + "E" + str(single_info["episode_metadata"]["episode_number"]).zfill(2) + " - " + single_info["title"] + " " + f"[{language}_ID: {single_info["id"]}]", extra={"service_name": __service_name__})
            try:
                logger.info("Downloading 1 episode", extra={"service_name": __service_name__})
                player_info = session.get(f"https://www.crunchyroll.com/playback/v2/{single_info["id"]}/tv/android_tv/play").json()
                try:
                    if player_info["errro"] == "the current subscription does not have access to this content":
                        logger.error("Require subscription account", extra={"service_name": __service_name__})
                        exit(1)
                except:
                    pass
                mpd_content = session.get(player_info["url"]).text
                headers = {
                    "Content-Type": "application/json"
                }                
                
                mpd_lic = crunchyroll.Crunchyroll_utils.parse_mpd_logic(mpd_content)
                logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
                
                license_key = crunchyroll.Crunchyroll_license.license_vd_ad(mpd_lic["pssh"][1], session, player_info["token"], single_info["id"], config)
                session.delete(f"https://www.crunchyroll.com/playback/v1/token/{single_info["id"]}/{player_info["token"]}", json={}, headers=headers)
                            
                logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                
                logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                
                #if (additional_info[8] or additional_info[7]) and not transformed_data["text_track"] == []: # if get, or embed = true
                #    print("on going")
                
                logger.info("Get Segment URL", extra={"service_name": __service_name__})
                segemnt_content = crunchyroll.Crunchyroll_utils.parse_mpd_content(mpd_content)
                
                segment_list_video = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["video"]["name"], segemnt_content["video"]["base_url"])
                for i in segment_list_video["segments"]:
                    logger.debug(" + Video Segment URL "+i, extra={"service_name": __service_name__})
                
                segment_list_audio = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["audio"]["name"], segemnt_content["audio"]["base_url"])
                
                for i in segment_list_audio["segments"]:
                    logger.debug(" + Audio Segment URL "+i, extra={"service_name": __service_name__})
                
                logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": __service_name__})
                logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": __service_name__})
                logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                crunchyroll_downloader.download_segment(segment_list_video["all"], config, unixtime, "download_encrypt_video.mp4")
                crunchyroll_downloader.download_segment(segment_list_audio["all"], config, unixtime, "download_encrypt_audio.m4s")
                
                logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                crunchyroll.Crunchyroll_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.m4s"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.m4s"), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                
                def sanitize_filename(filename):
                    filename = filename.replace(":", " ").replace("?", " ")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                
                title_name = sanitize_filename(single_info["episode_metadata"]["season_title"])
                
                video_duration = single_info["episode_metadata"]["duration_ms"] / 1000
                
                title_name_logger = sanitize_filename(single_info["episode_metadata"]["season_title"] + " " + "S" + str(single_info["episode_metadata"]["season_number"]).zfill(2) + "E" + str(single_info["episode_metadata"]["episode_number"]).zfill(2) + " - " + single_info["title"])
                
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
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
            except Exception:
                logger.error("Traceback has occurred", extra={"service_name": __service_name__})
                print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
                print("\n----ERROR LOG----")
                console.print_exception()
                print("Service: "+__service_name__)
                print("Version: "+additional_info[0])
                print("----END ERROR LOG----")
                session.delete(f"https://www.crunchyroll.com/playback/v1/token/{i["id"]}/{player_info["token"]}", json={}, headers=headers)
        else:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            season_id_info, default_info = crunchyroll_downloader.get_info(url)
            for i in season_id_info["data"]:
                logger.info(i["season_title"] + " " + "S" + str(i["season_number"]).zfill(2) + "E" + str(i["episode_number"]).zfill(2) + " - " + i["title"] + " " + f"[{language}_ID: {i["id"]}]", extra={"service_name": __service_name__})
            for meta_i in season_id_info["data"]:
                try:
                    logger.info("Downloading 1 episode", extra={"service_name": __service_name__})
                    player_info = session.get(f"https://www.crunchyroll.com/playback/v2/{meta_i["id"]}/tv/android_tv/play").json()
                    try:
                        if player_info["errro"] == "the current subscription does not have access to this content":
                            logger.error("Require subscription account", extra={"service_name": __service_name__})
                            exit(1)
                    except:
                        pass
                    mpd_content = session.get(player_info["url"]).text

                    headers = {
                        "Content-Type": "application/json"
                    }                    
                    
                    mpd_lic = crunchyroll.Crunchyroll_utils.parse_mpd_logic(mpd_content)
                    logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
                    
                    license_key = crunchyroll.Crunchyroll_license.license_vd_ad(mpd_lic["pssh"][1], session, player_info["token"], meta_i["id"], config)
                    session.delete(f"https://www.crunchyroll.com/playback/v1/token/{meta_i["id"]}/{player_info["token"]}", json={}, headers=headers)
                                
                    logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                    
                    logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                    
                    logger.info("Get Segment URL", extra={"service_name": __service_name__})
                    segemnt_content = crunchyroll.Crunchyroll_utils.parse_mpd_content(mpd_content)
                    
                    segment_list_video = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["video"]["name"], segemnt_content["video"]["base_url"])
                    for i in segment_list_video["segments"]:
                        logger.debug(" + Video Segment URL "+i, extra={"service_name": __service_name__})
                    
                    segment_list_audio = crunchyroll.Crunchyroll_utils.get_segment_link_list(mpd_content, segemnt_content["audio"]["name"], segemnt_content["audio"]["base_url"])
                    for i in segment_list_audio["segments"]:
                        logger.debug(" + Audio Segment URL "+i, extra={"service_name": __service_name__})
                    
                    logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                    logger.info(" + Video_Segment: "+str(len(segment_list_video["segments"])), extra={"service_name": __service_name__})
                    logger.info(" + Audio_Segment: "+str(len(segment_list_audio["segments"])), extra={"service_name": __service_name__})
                    logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    crunchyroll_downloader.download_segment(segment_list_video["all"], config, unixtime, "download_encrypt_video.mp4")
                    crunchyroll_downloader.download_segment(segment_list_audio["all"], config, unixtime, "download_encrypt_audio.m4s")
                    
                    logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    crunchyroll.Crunchyroll_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.m4s"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.m4s"), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    
                    def sanitize_filename(filename):
                        filename = filename.replace(":", " ").replace("?", " ")
                        return re.sub(r'[<>"/\\|*]', "_", filename)
                    
                    title_name = sanitize_filename(meta_i["season_title"])
                    
                    video_duration = meta_i["duration_ms"] / 1000
                    
                    title_name_logger = sanitize_filename(meta_i["season_title"] + " " + "S" + str(meta_i["season_number"]).zfill(2) + "E" + str(meta_i["episode_number"]).zfill(2) + " - " + meta_i["title"])
                    
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
                    
                    # Token expire bypass. lol crunchyroll
                    #update_token = crunchyroll_downloader.update_token()
                    #session.headers.update({"Authorization": "Bearer "+update_token})
                    
                    logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
                except Exception:
                    logger.error("Traceback has occurred", extra={"service_name": __service_name__})
                    print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
                    print("\n----ERROR LOG----")
                    console.print_exception()
                    print("Service: "+__service_name__)
                    print("Version: "+additional_info[0])
                    print("----END ERROR LOG----")
                    session.delete(f"https://www.crunchyroll.com/playback/v1/token/{i["id"]}/{player_info["token"]}", json={}, headers=headers)
            logger.info("Finished download Series: {}".format(default_info["data"][0]["title"]), extra={"service_name": __service_name__})
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")