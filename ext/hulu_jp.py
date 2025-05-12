import os
import re
import time
import json
import yaml
import shutil
import logging
import ext.global_func.parser as parser
import ext.global_func.niconico as comment

from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console

from ext.utils import hulu_jp

console = Console()

__service_name__ = "Hulu-jp"

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
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Encrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        hulu_jp_downloader = hulu_jp.Hulu_jp_downloader(session, config)
        
        #if config["authorization"]["use_token"]:
        #    if config["authorization"]["token"] != "":
        #        status, message = unext_downloader.check_token(config["authorization"]["token"])
        #        if status == False:
        #            logger.error(message, extra={"service_name": __service_name__})
        #            exit(1)
        #        else:
        #            account_point = str(message["points"])
        #            session.headers.update({"Authorization": config["authorization"]["token"]})
        #            logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": __service_name__})
        #            logger.info("Loggined Account", extra={"service_name": __service_name__})
        #            logger.info(" + ID: "+message["id"], extra={"service_name": __service_name__})
        #            logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
        #    else:
        #        logger.error("Please input token", extra={"service_name": __service_name__})
        #        exit(1)
        #else:
        status, message = hulu_jp_downloader.authorize(email, password)
        #try:
        #    logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
        #except:
        #    logger.info("Failed to login", extra={"service_name": __service_name__})
        if status == False:
            logger.error(message, extra={"service_name": __service_name__})
            exit(1)
        else:
            logger.info("Get Profile list", extra={"service_name": __service_name__})
            for idx, one_profile in enumerate(message, 1):
                logger.info(f" + {str(idx)}: Has pin: {one_profile[1]} | {one_profile[0]} ", extra={"service_name": __service_name__})
                
            profile_num = int(input("Please enter the number of the profile you want to use >> ")) -1
            
            select_profile_uuid = message[profile_num][2]
            if message[profile_num][1] == "Yes":
                pin = input("Profile PIN >> ")
            else:
                pin = ""
            #print(select_profile_uuid)
            
            status, message = hulu_jp_downloader.select_profile(select_profile_uuid, pin=pin)
            
            if status != True:
                logger.error(message, extra={"service_name": __service_name__})
            
            logger.info("Success change profile", extra={"service_name": __service_name__})
            logger.info(" + Nickname: "+message["profile"]["nickname"], extra={"service_name": __service_name__})
            
        
        print("getting episode info")
        match = re.search(r'/watch/(\d+)', url)

        if match:
            episode_id = match.group(1)
        
        status, metadata = hulu_jp_downloader.playback_auth(episode_id)
        print(status, metadata)
        
        print("get video ovp_video_id")
        print(metadata["media"]["ovp_video_id"])
        print("get playback sessionid")
        print(metadata["playback_session_id"])
        
        #title_name = metadata["media"]["name"].replace(episode_id+":", "")
        #print(title_name)
        #407078
        status, url_metadata = hulu_jp_downloader.get_title_info(metadata["log_params"]["meta_id"])
        print("get episode metadata")
        
        if url_metadata["season_id"] == None:
            season_title = None
            title_name = url_metadata["name"]
        else:
            season_title = url_metadata["season_number_title"]
            title_name = url_metadata["name"]
        
        print("try to open play session....")
        
        status, playdata = hulu_jp_downloader.open_playback_session(metadata["media"]["ovp_video_id"], metadata["playback_session_id"], episode_id)
        
        status, message = hulu_jp_downloader.close_playback_session(metadata["playback_session_id"])
        print(status, message)
        
        print(playdata["name"], playdata["duration"])
        
        urls = []
        
        widevine_url = None
        playready_url = None
        
        for source in playdata["sources"]:
            if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                urls.append(source["src"])
                if source["key_systems"]:
                    widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                    playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
        
        print("have subtitle?")
        found_sub = False
        for single in playdata["tracks"]:
            if single["kind"] == "subtitles":
                found_sub = True
        print(found_sub)
        print("get hd mpd")
        hd_link = urls[0]
        print(hd_link)
        print("get license url")
        print(widevine_url)
        
        logger.info(f"Parse MPD file", extra={"service_name": __service_name__})
        Tracks = parser.global_parser()
        transformed_data = Tracks.mpd_parser(session.get(hd_link).text)
                
        logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
        license_key = hulu_jp.Hulu_jp_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, config)
        
        logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
        logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
    
        #wod_downloader.send_stop_signal(video_access_token, session_id)
        
        
        logger.info(f"Get Video, Audio Tracks:", extra={"service_name": __service_name__})
        logger.debug(f" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
        track_data = Tracks.print_tracks(transformed_data)
        
        print(track_data)
        
        get_best_track = Tracks.select_best_tracks(transformed_data)
        
        logger.debug(f" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
        logger.info(f"Selected Best Track:", extra={"service_name": __service_name__})
        logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
        logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
        
        logger.debug(f"Calculate about Manifest...", extra={"service_name": __service_name__})
        #print(transformed_data["info"]["mediaPresentationDuration"])
        duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
        #print(duration)
        logger.debug(f" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})
        
        logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
        #print(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
        video_segment_list = Tracks.calculate_segments(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
        logger.info(f" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
        audio_segment_list = Tracks.calculate_segments(duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
        logger.info(f" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
        
        video_segment_links = []
        audio_segment_links = []
        video_segment_links.append(get_best_track["video"]["url"])
        audio_segment_links.append(get_best_track["audio"]["url"])
        
        for single_segment in range(video_segment_list):
            temp_link = get_best_track["video"]["url_base"]+get_best_track["video"]["url_segment_base"].replace("$Number$", str(single_segment))
            video_segment_links.append(temp_link)
        for single_segment in range(audio_segment_list):
            temp_link = get_best_track["audio"]["url_base"]+get_best_track["audio"]["url_segment_base"].replace("$Number$", str(single_segment))
            audio_segment_links.append(temp_link)
        
        logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
        
        hulu_jp_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
        hulu_jp_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
        
        logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
        
        #hulu_jp.Hulu_jp_decrypt.decrypt_content_shaka(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
        #hulu_jp.Hulu_jp_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
        
        hulu_jp.Hulu_jp_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
        
        logger.info("Muxing Episode...", extra={"service_name": __service_name__})
        
        if season_title != None:
            output_path = os.path.join(config["directorys"]["Downloads"], season_title, title_name+".mp4")
        else:
            output_path = os.path.join(config["directorys"]["Downloads"], title_name+".mp4")
        
        result = hulu_jp_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", output_path, config, unixtime, season_title, int(duration))
        #dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        #if os.path.exists(dir_path) and os.path.isdir(dir_path):
        #    for filename in os.listdir(dir_path):
        #        file_path = os.path.join(dir_path, filename)
        #        try:
        #            if os.path.isfile(file_path):
        #                os.remove(file_path)
        #            elif os.path.isdir(file_path):
        #                shutil.rmtree(file_path)
        #        except Exception as e:
        #            print(f"削除エラー: {e}")
        #else:
        #    print(f"指定されたディレクトリは存在しません: {dir_path}")
        logger.info('Finished download: {}'.format(title_name), extra={"service_name": __service_name__})
            #account_point = str(message["points"])
            #logger.info("Loggined Account", extra={"service_name": __service_name__})
            #logger.info(" + ID: "+message["id"], extra={"service_name": __service_name__})
            #logger.info(" + Point: "+account_point, extra={"service_name": __service_name__})
            
        # status, meta_response = unext_downloader.get_title_metadata(url)
        # if status == False:
        #     logger.error("Failed to Get Series Json", extra={"service_name": __service_name__})
        #     exit(1)
        # else:
        #     title_name = meta_response["titleName"]
            
        # status = unext.Unext_utils.check_single_episode(url)
        # logger.info("Get Video Type for URL", extra={"service_name": __service_name__})
        # status_id, id_type = unext_downloader.get_id_type(url)
        # if status_id == False:
        #     logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
        #     exit(1)
        # logger.info(f" + Video Type: {id_type}", extra={"service_name": __service_name__})
        # productionYear = id_type[3]
        # copyright = id_type[4]
        # if status == False:
        #     logger.info("Get Title for Season", extra={"service_name": __service_name__})
        #     status, messages = unext_downloader.get_title_parse_all(url)
        #     if status == False:
        #         logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
        #         exit(1)
                
        #     if additional_info[4]: 
        #         logger.info("Downloading All Episode Thumbnails...", extra={"service_name": __service_name__})
        #         unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
                
        #     for message in messages:
        #         if id_type[2] == "ノーマルアニメ":
        #             format_string = config["format"]["anime"]
        #             values = {
        #                 "seriesname": title_name,
        #                 "titlename": message.get("displayNo", ""),
        #                 "episodename": message.get("episodeName", "")
        #             }
        #             try:
        #                 title_name_logger = format_string.format(**values)
        #             except KeyError as e:
        #                 missing_key = e.args[0]
        #                 values[missing_key] = ""
        #                 title_name_logger = format_string.format(**values)
        #         if id_type[2] == "劇場":
        #             format_string = config["format"]["movie"]
        #             if message.get("displayNo", "") == "":
        #                 format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #                 values = {
        #                     "seriesname": title_name,
        #                 }
        #             else:
        #                 values = {
        #                     "seriesname": title_name,
        #                     "titlename": message.get("displayNo", ""),
        #                     "episodename": message.get("episodeName", "")
        #                 }
        #             try:
        #                 title_name_logger = format_string.format(**values)
        #             except KeyError as e:
        #                 missing_key = e.args[0]
        #                 values[missing_key] = ""
        #                 title_name_logger = format_string.format(**values)
        #         logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
        #     for message in messages:
        #         if id_type[2] == "ノーマルアニメ":
        #             format_string = config["format"]["anime"]
        #             values = {
        #                 "seriesname": title_name,
        #                 "titlename": message.get("displayNo", ""),
        #                 "episodename": message.get("episodeName", "")
        #             }
        #             try:
        #                 title_name_logger = format_string.format(**values)
        #             except KeyError as e:
        #                 missing_key = e.args[0]
        #                 values[missing_key] = ""
        #                 title_name_logger = format_string.format(**values)
        #         if id_type[2] == "劇場":
        #             format_string = config["format"]["movie"]
        #             if message.get("displayNo", "") == "":
        #                 format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #                 values = {
        #                     "seriesname": title_name,
        #                 }
        #             else:
        #                 values = {
        #                     "seriesname": title_name,
        #                     "titlename": message.get("displayNo", ""),
        #                     "episodename": message.get("episodeName", "")
        #                 }
        #             try:
        #                 title_name_logger = format_string.format(**values)
        #             except KeyError as e:
        #                 missing_key = e.args[0]
        #                 values[missing_key] = ""
        #                 title_name_logger = format_string.format(**values)
                
        #         global_comment = comment.global_comment()
        #         global_comment.download_niconico_comment(logger, additional_info, title_name, message.get("displayNo", ""), message.get("displayNo", "").replace("第", "").replace("話", ""), config, title_name_logger, service_type="U-Next")
        #         if message["minimumPrice"] != -1:
        #             logger.info(f" ! {title_name_logger} require {message["minimumPrice"]} point", extra={"service_name": __service_name__})
        #             if int(message["minimumPrice"]) > int(account_point):
        #                 logger.info(f" ! ポイントが足りません", extra={"service_name": __service_name__})
        #                 pass
        #             else:
        #                 is_buyed = unext_downloader.check_buyed(url)
        #                 if is_buyed == True:
        #                     logger.info(f" ! {title_name_logger} have already been purchased.", extra={"service_name": __service_name__})
        #                 else:
        #                     check_downlaod = input(COLOR_GREEN+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+COLOR_RESET+" "+f"[{COLOR_GRAY}INFO{COLOR_RESET}]"+" "+f"{COLOR_BLUE}U-Next{COLOR_RESET}"+" : "+f" ! Do you want to buy {title_name_logger}?"+" | "+"y/n"+" ")
        #                     logger.info(f"Coming soon", extra={"service_name": __service_name__})
        #                     return
                    
        #         status, playtoken, media_code, additional_meta = unext_downloader.get_playtoken(message["id"])
        #         if status == False:
        #             logger.error("Failed to Get Episode Playtoken", extra={"service_name": __service_name__})
        #             exit(1)
        #         else:
        #             if additional_info[6] or additional_info[9]:
        #                 unext_downloader.create_ffmetadata(productionYear, [id_type, title_name, message.get("displayNo", ""), message.get("episodeName", "")], unixtime, additional_meta, message.get("displayNo", ""), message["duration"], message["introduction"], copyright, additional_info)
                    
        #             logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
        #             status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
        #             if status == False:
        #                 logger.error("Failed to Get Episode MPD_Content", extra={"service_name": __service_name__})
        #                 logger.error(f"Reason: {mpd_content}", extra={"service_name": __service_name__})
        #                 session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        #                 session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        #                 exit(1)
        #             mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
        
        #             logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": __service_name__})
        #             logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": __service_name__})
                    
        #             license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session, config)
                    
        #             logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                    
        #             logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
        #             logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                                        
        #             logger.info("Checking resolution...", extra={"service_name": __service_name__})
        #             resolution_s = unext.mpd_parse.get_resolutions(mpd_content)
        #             logger.info("Found resolution", extra={"service_name": __service_name__})
        #             for resolution_one in resolution_s:
        #                 logger.info(" + "+resolution_one, extra={"service_name": __service_name__})
                    
        #             logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
        #             video_url = unext.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
        #             audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
        #             logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
        #             logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
                    
        #             def sanitize_filename(filename):
        #                 filename = filename.replace(":", "：").replace("?", "？")
        #                 return re.sub(r'[<>"/\\|*]', "_", filename)
                    
        #             if additional_info[1]:
        #                 random_string = str(int(time.time() * 1000))
        #                 title_name_logger_video = random_string+"_video_encrypted.mp4"
        #                 title_name_logger_audio = random_string+"_audio_encrypted.mp4"
        #             else:
        #                 title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
        #                 title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                    
        #             logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                    
        #             video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
        #             audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)                    

        #             logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                    
        #             unext.Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                    
        #             logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    
        #             result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, sanitize_filename(title_name), int(message["duration"]), title_name_logger, message.get("displayNo", ""), additional_info)
                    
        #             if additional_info[4] and additional_info[5]:
        #                 result = unext_downloader.apply_thumbnail(message.get("displayNo", ""), title_name, title_name_logger, unixtime, config)
        #                 if result != True:
        #                     logger.error("Failed Apply Thumbnail. LOL", extra={"service_name": __service_name__})
                    
        #             dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                    
        #             if os.path.exists(dir_path) and os.path.isdir(dir_path):
        #                 for filename in os.listdir(dir_path):
        #                     if filename == "metadata":
        #                         continue
                            
        #                     file_path = os.path.join(dir_path, filename)
        #                     try:
        #                         if os.path.isfile(file_path):
        #                             os.remove(file_path)
        #                         elif os.path.isdir(file_path):
        #                             shutil.rmtree(file_path)
        #                     except Exception as e:
        #                         print(f"削除エラー: {e}")
        #             else:
        #                 print(f"指定されたディレクトリは存在しません: {dir_path}")
                    
        #             logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
                                           
                    
        #             session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        #             session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        #     logger.info("Finished download Series: {}".format(title_name), extra={"service_name": __service_name__})
        # else:
        #     logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
        #     status, message, point = unext_downloader.get_title_parse_single(url)
        #     if status == False:
        #         logger.error("Failed to Get Episode Json", extra={"service_name": __service_name__})
        #         exit(1)
            
        #     if id_type[2] == "ノーマルアニメ":
        #         format_string = config["format"]["anime"]
        #         values = {
        #             "seriesname": title_name,
        #             "titlename": message.get("displayNo", ""),
        #             "episodename": message.get("episodeName", "")
        #         }
        #         try:
        #             title_name_logger = format_string.format(**values)
        #         except KeyError as e:
        #             missing_key = e.args[0]
        #             values[missing_key] = ""
        #             title_name_logger = format_string.format(**values)
        #     if id_type[2] == "劇場":
        #         format_string = config["format"]["movie"]
        #         if message.get("displayNo", "") == "":
        #             format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #             values = {
        #                 "seriesname": title_name,
        #             }
        #         else:
        #             values = {
        #                 "seriesname": title_name,
        #                 "titlename": message.get("displayNo", ""),
        #                 "episodename": message.get("episodeName", "")
        #             }
        #         try:
        #             title_name_logger = format_string.format(**values)
        #         except KeyError as e:
        #             missing_key = e.args[0]
        #             values[missing_key] = ""
        #             title_name_logger = format_string.format(**values)
        #     logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            
        #     global_comment = comment.global_comment()
        #     global_comment.download_niconico_comment(logger, additional_info, title_name, message.get("displayNo", ""), message.get("displayNo", "").replace("第", "").replace("話", ""), config, title_name_logger, service_type="U-Next")
            
        #     if point != -1:
        #         logger.info(f" ! {title_name_logger} require {point} point", extra={"service_name": __service_name__})
        #         if int(point) > int(account_point):
        #             logger.info(f" ! ポイントが足りません", extra={"service_name": __service_name__})
        #             pass
        #         else:
        #             is_buyed = unext_downloader.check_buyed(url)
        #             if is_buyed == True:
        #                 logger.info(f" ! {title_name_logger} have already been purchased.", extra={"service_name": __service_name__})
        #             else:
        #                 check_downlaod = input(COLOR_GREEN+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+COLOR_RESET+" "+f"[{COLOR_GRAY}INFO{COLOR_RESET}]"+" "+f"{COLOR_BLUE}U-Next{COLOR_RESET}"+" : "+f" ! Do you want to buy {title_name_logger}?"+" | "+"y/n"+" ")
        #                 logger.info(f"Coming soon", extra={"service_name": __service_name__})
        #                 return
            
        #     status, playtoken, media_code, additional_meta = unext_downloader.get_playtoken(message["id"])
        #     if status == False:
        #         logger.error("Failed to Get Episode Playtoken", extra={"service_name": __service_name__})
        #         exit(1)
        #     else:
        #         if additional_info[6] or additional_info[9]:
        #             unext_downloader.create_ffmetadata(productionYear, [id_type, title_name, message.get("displayNo", ""), message.get("episodeName", "")], unixtime, additional_meta, message.get("displayNo", ""), message["duration"], message["introduction"], copyright, additional_info)
        #         logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
        #         status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
        #         if status == False:
        #             logger.error("Failed to Get Episode MPD_Content", extra={"service_name": __service_name__})
        #             session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        #             session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        #         mpd_lic = unext.Unext_utils.parse_mpd_logic(mpd_content)
    
        #         logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": __service_name__})
        #         logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": __service_name__})
                
        #         license_key = unext.Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session, config)
                
        #         logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                
        #         logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
        #         logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                
        #         logger.info("Checking resolution...", extra={"service_name": __service_name__})
        #         resolution_s = unext.mpd_parse.get_resolutions(mpd_content)
        #         logger.info("Found resolution", extra={"service_name": __service_name__})
        #         for resolution_one in resolution_s:
        #             logger.info(" + "+resolution_one, extra={"service_name": __service_name__})
                
        #         logger.info("Video, Audio Content Link", extra={"service_name": __service_name__})
        #         video_url = unext.mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
        #         audio_url = unext.mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
        #         logger.info(" + Video_URL: "+video_url, extra={"service_name": __service_name__})
        #         logger.info(" + Audio_URL: "+audio_url, extra={"service_name": __service_name__})
                
        #         def sanitize_filename(filename):
        #             filename = filename.replace(":", "：").replace("?", "？")
        #             return re.sub(r'[<>"/\\|*]', "_", filename)
                
        #         if additional_info[1]:
        #             random_string = str(int(time.time() * 1000))
        #             title_name_logger_video = random_string+"_video_encrypted.mp4"
        #             title_name_logger_audio = random_string+"_audio_encrypted.mp4"
        #         else:
        #             title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
        #             title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                
        #         if additional_info[4]: 
        #             logger.info("Downloading All Episode Thumbnails...", extra={"service_name": __service_name__})
        #             unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
                
        #         logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
        #         video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
        #         audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)
                
        #         logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                
        #         unext.Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
        #         logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                
        #         result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(message["duration"]), title_name_logger, message.get("displayNo", ""), additional_info)
                
        #         if additional_info[4] and additional_info[5]:
        #             result = unext_downloader.apply_thumbnail(message.get("displayNo", ""), title_name, title_name_logger, unixtime, config)
        #             if result != True:
        #                 logger.error("Failed Apply Thumbnail. LOL", extra={"service_name": __service_name__})
                
        #         dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                
        #         if os.path.exists(dir_path) and os.path.isdir(dir_path):
        #             for filename in os.listdir(dir_path):
        #                 file_path = os.path.join(dir_path, filename)
        #                 try:
        #                     if os.path.isfile(file_path):
        #                         os.remove(file_path)
        #                     elif os.path.isdir(file_path):
        #                         shutil.rmtree(file_path)
        #                 except Exception as e:
        #                     print(f"削除エラー: {e}")
        #         else:
        #             print(f"指定されたディレクトリは存在しません: {dir_path}")
                
        #         logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
                                       
        #         session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        #         session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception(show_locals=True)
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")
        #session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        #session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")