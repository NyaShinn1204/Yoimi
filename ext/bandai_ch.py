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

import ext.global_func.parser as parser

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
    
    if not logger.handlers:
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
            
        status = bch_downloader.check_single_episode(url)
            
        global_title_name = bch_downloader.get_title_name(url, status)
        global_title_id = bch_downloader.get_title_id(url)
        
        global_title_json = bch_downloader.get_title_data(global_title_id)

        if status == False:
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            #title_json, episode_id = bch_downloader.get_signle_title_json(url)
            #processed_string = re.sub(r'"resolution": "([^"]+)",', r'"resolution": "\1"', title_json)
            #single_vod_status = json.loads(processed_string)
            
            #print(episode_id)
            for episode_select_json in global_title_json:
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
            for episode_id, episode_select_json in enumerate(global_title_json):
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
                
                title_name = title_name_logger.replace(global_title_name+"_", "")
                #logger.info("Checking Can download...", extra={"service_name": __service_name__})
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
                
                #logger.info("This episode is can download?: "+str(can_download), extra={"service_name": __service_name__})
                if can_download != True:
                    logger.warning("This episode require: "+str(episode_display)+", Skipping...", extra={"service_name": __service_name__})
                    continue
                
                logger.debug("Get Video Data Auth Key", extra={"service_name": __service_name__})
                soup = BeautifulSoup(session.get(f"https://www.b-ch.com/titles/{global_title_id}/{str(episode_id+1).zfill(3)}").content, 'html.parser')
                video_tag = soup.select_one('section.bch-l-hero div.bch-p-hero div#bchplayer-box video-js')
                if video_tag:
                    data_auth = video_tag.get('data-auth')
                    data_auth = data_auth.replace("\n", "")
                    logger.debug("Data Auth Key: "+data_auth, extra={"service_name": __service_name__})
                else:
                    logger.error("Failed to get Data Auth Key", extra={"service_name": __service_name__})
                    
                device_list = {
                    "PC": 70,
                    "Android": 80,
                    "iPad": 81,
                    "FireTablet": 82,
                    "iOS": 99
                }
                
                status, manifest_list = bch_downloader.get_manifest_list(global_title_id, episode_id+1, device_list["PC"], login_status, data_auth)
                if status != True:
                    logger.error("Failed to get Manifest List", extra={"service_name": __service_name__})
                
                logger.info("Get License Auth Key:", extra={"service_name": __service_name__})
                license_authkey = manifest_list["bch"]["pas_token"]
                logger.info("Token: "+license_authkey[:15], extra={"service_name": __service_name__})
                logger.debug("Token: "+license_authkey, extra={"service_name": __service_name__})
                
                
                if manifest_list["bc"]["text_tracks"] != []:
                    logger.info("Found text track(sub, cc), but this version is no supported. lol", extra={"service_name": __service_name__})
                    logger.info("If you want download (cc, sub), please create issues.", extra={"service_name": __service_name__})
                    
                episode_duration = int(manifest_list["bc"]["duration"] / 1000)
                urls = []
                for source in manifest_list["bc"]["sources"]:
                    if "key_systems" in source and "manifest.mpd" in source["src"] and "https" in source["src"]:
                        urls.append(source["src"])
                        if source["key_systems"]:
                            widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                            playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                        #else:
                        #    widevine_url = None
                        #    playready_url = None
                #print("[+] うお！暗号化リンクゲット！")
                #print(urls[0])
                logger.debug("Get Manifest link: "+urls[0], extra={"service_name": __service_name__})
                logger.info(f"Get Manifest link: {urls[0][:15]+"*****"}", extra={"service_name": __service_name__})
                
                logger.info(f"Parse MPD file", extra={"service_name": __service_name__})
                Tracks = parser.global_parser()
                transformed_data = Tracks.mpd_parser(session.get(urls[0]).text)
                            
                logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                license_key = bandai_ch.Bandai_ch_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, license_authkey, config)
                
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                        
                
                logger.info(f"Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                logger.debug(f" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                track_data = Tracks.print_tracks(transformed_data)
                
                print(track_data)
                
                get_best_track = Tracks.select_best_tracks(transformed_data)
                
                logger.debug(f" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                logger.info(f"Selected Best Track:", extra={"service_name": __service_name__})
                logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                
                logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                video_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
                logger.info(f" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
                audio_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
                
                logger.info(f" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
                video_segment_links = []
                audio_segment_links = []
                video_segment_links.append(get_best_track["video"]["url"].replace("$RepresentationID$", get_best_track["video"]["id"]))
                audio_segment_links.append(get_best_track["audio"]["url"].replace("$RepresentationID$", get_best_track["audio"]["id"]))
                
                for single_segment in range(video_segment_list):
                    temp_link = (
                        get_best_track["video"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["video"]["id"]}/")
                        +
                        get_best_track["video"]["url_segment_base"].replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                    video_segment_links.append(temp_link)
                for single_segment in range(audio_segment_list):
                    temp_link = (
                        get_best_track["audio"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["audio"]["id"]}/")
                        +
                        get_best_track["audio"]["url_segment_base"].replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                    audio_segment_links.append(temp_link)
                
                logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                #print(video_segment_links)
                
                bch_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
                bch_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
                
                logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                
                bandai_ch.Bandai_ch_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
                bandai_ch.Bandai_ch_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                
                bandai_ch.Bandai_ch_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                
                result = bch_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], global_title_name, title_name_logger+".mp4"), config, unixtime, global_title_name, int(episode_duration))
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
            logger.info("Finished download Series: {}".format(global_title_name), extra={"service_name": __service_name__})
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
            
            title_name = title_name_logger.replace(global_title_name+"_", "")
            
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
            
            logger.debug("Get Video Data Auth Key", extra={"service_name": __service_name__})
            soup = BeautifulSoup(session.get(f"https://www.b-ch.com/titles/{global_title_id}/{str(episode_id).zfill(3)}").content, 'html.parser')
            video_tag = soup.select_one('section.bch-l-hero div.bch-p-hero div#bchplayer-box video-js')
            if video_tag:
                data_auth = video_tag.get('data-auth')
                data_auth = data_auth.replace("\n", "")
                logger.debug("Data Auth Key: "+data_auth, extra={"service_name": __service_name__})
            else:
                logger.error("Failed to get Data Auth Key", extra={"service_name": __service_name__})
                
            device_list = {
                "PC": 70,
                "Android": 80,
                "iPad": 81,
                "FireTablet": 82,
                "iOS": 99
            }
            
            status, manifest_list = bch_downloader.get_manifest_list(global_title_id, episode_id, device_list["PC"], login_status, data_auth)
            if status != True:
                logger.error("Failed to get Manifest List", extra={"service_name": __service_name__})
            
            logger.info("Get License Auth Key:", extra={"service_name": __service_name__})
            license_authkey = manifest_list["bch"]["pas_token"]
            logger.info("Token: "+license_authkey[:15], extra={"service_name": __service_name__})
            logger.debug("Token: "+license_authkey, extra={"service_name": __service_name__})
            
            
            if manifest_list["bc"]["text_tracks"] != []:
                logger.info("Found text track(sub, cc), but this version is no supported. lol", extra={"service_name": __service_name__})
                logger.info("If you want download (cc, sub), please create issues.", extra={"service_name": __service_name__})
                
            episode_duration = int(manifest_list["bc"]["duration"] / 1000)
            urls = []
            for source in manifest_list["bc"]["sources"]:
                if "key_systems" in source and "manifest.mpd" in source["src"] and "https" in source["src"]:
                    urls.append(source["src"])
                    if source["key_systems"]:
                        widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                        playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                    #else:
                    #    widevine_url = None
                    #    playready_url = None
            #print("[+] うお！暗号化リンクゲット！")
            #print(urls[0])
            logger.debug("Get Manifest link: "+urls[0], extra={"service_name": __service_name__})
            logger.info(f"Get Manifest link: {urls[0][:15]+"*****"}", extra={"service_name": __service_name__})
            
            logger.info(f"Parse MPD file", extra={"service_name": __service_name__})
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(session.get(urls[0]).text)
                        
            logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
            license_key = bandai_ch.Bandai_ch_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, license_authkey, config)
            
            logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                    
            
            logger.info(f"Get Video, Audio Tracks:", extra={"service_name": __service_name__})
            logger.debug(f" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
            track_data = Tracks.print_tracks(transformed_data)
            
            print(track_data)
            
            get_best_track = Tracks.select_best_tracks(transformed_data)
            
            logger.debug(f" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
            logger.info(f"Selected Best Track:", extra={"service_name": __service_name__})
            logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
            logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
            
            logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
            video_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
            logger.info(f" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
            audio_segment_list = Tracks.calculate_segments(episode_duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
            
            logger.info(f" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
            video_segment_links = []
            audio_segment_links = []
            video_segment_links.append(get_best_track["video"]["url"].replace("$RepresentationID$", get_best_track["video"]["id"]))
            audio_segment_links.append(get_best_track["audio"]["url"].replace("$RepresentationID$", get_best_track["audio"]["id"]))
            
            for single_segment in range(video_segment_list):
                temp_link = (
                    get_best_track["video"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["video"]["id"]}/")
                    +
                    get_best_track["video"]["url_segment_base"].replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                video_segment_links.append(temp_link)
            for single_segment in range(audio_segment_list):
                temp_link = (
                    get_best_track["audio"]["url_base"].replace("/$RepresentationID$/", f"/{get_best_track["audio"]["id"]}/")
                    +
                    get_best_track["audio"]["url_segment_base"].replace("$Number$", str(single_segment)).replace("$RepresentationID$/",""))
                audio_segment_links.append(temp_link)
            
            logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            #print(video_segment_links)
            
            bch_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
            bch_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
            
            logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            bandai_ch.Bandai_ch_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
            bandai_ch.Bandai_ch_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            bandai_ch.Bandai_ch_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            result = bch_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], global_title_name, title_name_logger+".mp4"), config, unixtime, global_title_name, int(episode_duration))
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
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")