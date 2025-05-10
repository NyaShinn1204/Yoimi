import re
import os
import yaml
import json
import time
import logging
import shutil
import ext.global_func.niconico as comment

import ext.global_func.parser as parser

from rich.console import Console

from ext.utils import fod

console = Console()

__service_name__ = "FOD"

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
        
        fod_downloader = fod.FOD_downloader(session)
        
        if email and password != None:
            status, message, uuid_cookie = fod_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["x-authorization"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                account_coin = str(message["user_coin"])
                account_point = str(message["user_point"])
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                #logger.info(" + ID: "+message["member_id"], extra={"service_name": __service_name__})
                logger.info(" + Coin: "+account_coin, extra={"service_name": __service_name__})
                logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
                login_status = True  
        else:
            status, message = fod_downloader.gen_temptoken()
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                login_status = False
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
        #episode_id = "70v8110012"
        #unixtime = str(int(time.time() * 1000))
        #uuid_here = uuid_cookie
        #test = session.get(f"https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={episode_id}&qa=auto&uuid={uuid_here}&starttime=0&is_pt=false&dt=&_={unixtime}")
        #print(test.json()["ticket"])        
        status = fod.FOD_utils.check_single_episode(url)
        status_id, id_type = fod_downloader.get_id_type(url)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": __service_name__})
        if status == False:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            status, messages, detail = fod_downloader.get_title_parse_all(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
            title_name = detail["lu_title"]
            for message in messages:
                if id_type[1] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("disp_ep_no", ""),
                        "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[1] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("disp_ep_no", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("disp_ep_no", ""),
                            "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            for message in messages:
                if id_type[1] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("disp_ep_no", ""),
                        "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[1] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("disp_ep_no", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("disp_ep_no", ""),
                            "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                global_comment = comment.global_comment()
                global_comment.download_niconico_comment(logger, additional_info, title_name, f"{message.get("disp_ep_no", "")} {message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")}", message.get("disp_ep_no", "").replace("第", "").replace("話", ""), config, title_name_logger, service_type="FOD")                        
                
                if message["price"] != 0:
                    logger.info(f" ! {title_name_logger} require {message["price"]}", extra={"service_name": __service_name__})
                    if int(message["price"]) > int(account_point):
                        logger.info(f" ! ポイントが足りません", extra={"service_name": __service_name__})
                        pass
                    else:
                        logger.info(f" ! {title_name_logger} require BUY or RENTAL", extra={"service_name": __service_name__})
                
                logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
                uuid = session.cookies.get("uuid")
                ut = session.cookies.get("UT")
                #print(ut)
                #print(uuid)
                url = f"https://fod.fujitv.co.jp/title/{detail["lu_id"]}/{message["ep_id"]}/"
                #print(ep_id)
                status, custom_data, mpd_content = fod_downloader.get_mpd_content(uuid, url, ut)
                if status == False:
                    logger.error("Failed to Get Episode MPD_Content", extra={"service_name": __service_name__})
                #print(custom_data, mpd_content)
                mpd_lic = fod.FOD_utils.parse_mpd_logic(mpd_content)
    
                logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
                       
                license_key = fod.FOD_license.license_vd_ad(mpd_lic["pssh"][1], custom_data, session, config)
                    
                logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                       
                #logger.info("Checking resolution...", extra={"service_name": __service_name__})
                resolution_s, bandwidth_list = fod.mpd_parse.get_resolutions(mpd_content)
                #logger.info("Found resolution", extra={"service_name": __service_name__})
                #for resolution_one in resolution_s:
                #    logger.info(" + "+resolution_one, extra={"service_name": __service_name__})
                #for bandwidth_one in bandwidth_list:
                #    logger.debug(" + "+bandwidth_one, extra={"service_name": __service_name__})
                duration = fod.mpd_parse.get_duration(mpd_content)
                #logger.debug("+ duration: "+duration, extra={"service_name": __service_name__})
                if login_status != False:
                    fod_downloader.sent_start_stop_signal(bandwidth_list[-1], url, duration)
                #    
                #logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
                #video_url = fod.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
                #audio_url = fod.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                #logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
                #logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
                
                Tracks = parser.global_parser()
                transformed_data = Tracks.mpd_parser(mpd_content)
                
                logger.info("Get Tracks", extra={"service_name": __service_name__})
                track_data = Tracks.print_tracks(transformed_data)
                print(track_data)
                get_best_track = Tracks.select_best_tracks(transformed_data)
                logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
                video_url = get_best_track["video"]["url"]
                audio_url = get_best_track["audio"]["url"]
                logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
                logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
                
                def sanitize_filename(filename):
                    filename = filename.replace(":", "：").replace("?", "？")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                
                if additional_info[1]:
                    random_string = str(int(time.time() * 1000))
                    title_name_logger_video = random_string+"_video_encrypted.mp4"
                    title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                else:
                    title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
                    title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                
                logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
                video_downloaded = fod_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
                audio_downloaded = fod_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)
                
                logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
                fod.FOD_decrypt.decrypt_all_content(license_key["key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                                 
                result = fod_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(duration))
                    
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
                if login_status != False:
                    fod_downloader.sent_start_stop_signal(bandwidth_list[-1], url, duration)
            logger.info("Finished download Series: {}".format(title_name), extra={"service_name": __service_name__})
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            status, message, point = fod_downloader.get_title_parse_single(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
                exit(1)
                
            title_name = message["lu_title"]
            
            if id_type[1] == "ノーマルアニメ":
                format_string = config["format"]["anime"]
                values = {
                    "seriesname": title_name,
                    "titlename": message.get("disp_ep_no", ""),
                    "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type[1] == "劇場":
                format_string = config["format"]["movie"]
                if message.get("disp_ep_no", "") == "":
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_name,
                    }
                else:
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("disp_ep_no", ""),
                        "episodename": message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")
                    }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            global_comment = comment.global_comment()
            global_comment.download_niconico_comment(logger, additional_info, title_name, f"{message.get("disp_ep_no", "")} {message.get("ep_title", "").replace(message.get("disp_ep_no", "")+" ", "")}", message.get("disp_ep_no", "").replace("第", "").replace("話", ""), config, title_name_logger, service_type="FOD")                        
            
            if point[1] != 0:
                logger.info(f" ! {title_name_logger} require {point[1]}", extra={"service_name": __service_name__})
                if int(point[1]) > int(account_point):
                    logger.info(f" ! ポイントが足りません", extra={"service_name": __service_name__})
                    pass
                else:
                    logger.info(f" ! {title_name_logger} require BUY or RENTAL", extra={"service_name": __service_name__})
                    
            logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
            uuid = session.cookies.get("uuid")
            ut = session.cookies.get("UT")
            #print(ut)
            #print(uuid)
            #print(ep_id)
            status, custom_data, mpd_content = fod_downloader.get_mpd_content(uuid, url, ut)
            if status == False:
                logger.error("Failed to Get Episode MPD_Content", extra={"service_name": __service_name__})
            #print(custom_data, mpd_content)
            mpd_lic = fod.FOD_utils.parse_mpd_logic(mpd_content)

            logger.info(f" + Video, Audio PSSH: {mpd_lic["pssh"][1]}", extra={"service_name": __service_name__})
                   
            license_key = fod.FOD_license.license_vd_ad(mpd_lic["pssh"][1], custom_data, session, config)
                
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                   
            #logger.info("Checking resolution...", extra={"service_name": __service_name__})
            resolution_s, bandwidth_list = fod.mpd_parse.get_resolutions(mpd_content)
            #logger.info("Found resolution", extra={"service_name": __service_name__})
            #for resolution_one in resolution_s:
            #    logger.info(" + "+resolution_one, extra={"service_name": __service_name__})
            #for bandwidth_one in bandwidth_list:
            #    logger.debug(" + "+bandwidth_one, extra={"service_name": __service_name__})
            duration = fod.mpd_parse.get_duration(mpd_content)
            #logger.debug("+ duration: "+duration, extra={"service_name": __service_name__})
            if login_status != False:
                fod_downloader.sent_start_stop_signal(bandwidth_list[-1], url, duration)
            #    
            #logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
            #video_url = fod.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
            #audio_url = fod.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
            #logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
            #logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
            
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(mpd_content)
            
            logger.info("Get Tracks", extra={"service_name": __service_name__})
            track_data = Tracks.print_tracks(transformed_data)
            print(track_data)
            get_best_track = Tracks.select_best_tracks(transformed_data)
            logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
            video_url = get_best_track["video"]["url"]
            audio_url = get_best_track["audio"]["url"]
            logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
            logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
            
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            
            if additional_info[1]:
                random_string = str(int(time.time() * 1000))
                title_name_logger_video = random_string+"_video_encrypted.mp4"
                title_name_logger_audio = random_string+"_audio_encrypted.mp4"
            else:
                title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
                title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
            
            logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
            
            video_downloaded = fod_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
            audio_downloaded = fod_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)
            
            logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
            
            fod.FOD_decrypt.decrypt_all_content(license_key["key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                             
            result = fod_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(duration))
                
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
            if login_status != False:
                fod_downloader.sent_start_stop_signal(bandwidth_list[-1], url, duration)
            #session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
            #session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
            #mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
#
            #logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
            #logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
            #
            #license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
        
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")