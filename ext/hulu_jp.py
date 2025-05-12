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
        
        status, message = hulu_jp_downloader.authorize(email, password)

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
            
            status, message = hulu_jp_downloader.select_profile(select_profile_uuid, pin=pin)
            
            if status != True:
                logger.error(message, extra={"service_name": __service_name__})
            
            logger.info("Success change profile", extra={"service_name": __service_name__})
            logger.info(" + Nickname: "+message["profile"]["nickname"], extra={"service_name": __service_name__})
            
        
        
        #print("getting episode info")
        match = re.search(r'/watch/(\d+)', url)
        if match: ## single episode
            episode_id = match.group(1)
            
            logger.info("Creating Video Sesson...", extra={"service_name": __service_name__})
            status, metadata = hulu_jp_downloader.playback_auth(episode_id)
            logger.info(" + Session Token: "+metadata["playback_session_id"][:10]+"*****", extra={"service_name": __service_name__})
            #print(status, metadata)
            #
            #print("get video ovp_video_id")
            #print(metadata["media"]["ovp_video_id"])
            #print("get playback sessionid")
            #print(metadata["playback_session_id"])
            
            #407078
            status, url_metadata = hulu_jp_downloader.get_title_info(metadata["log_params"]["meta_id"])
            #print("get episode metadata")
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            if url_metadata["season_id"] == None:
                season_title = None
                format_string = config["format"]["movie"]
                #title_name = url_metadata["name"]
                format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                values = {
                    "seriesname": url_metadata["name"],
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            else:
                format_string = config["format"]["anime"]
                values = {
                    "seriesname": url_metadata["season_number_title"],
                    "titlename": url_metadata["video_categories"][0]["name"],
                    "episodename": url_metadata["header"].replace(url_metadata["video_categories"][0]["name"]+" ", "")
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
                    
                season_title = url_metadata["season_number_title"]
                #title_name = url_metadata["name"]
                
            #def find_4k_videos(data):
            #    result = []
            #    for media in data.get("medias", []):
            #        values = media.get("values", {})
            #        if values.get("file_type") == "video/4k":
            #            result.append(media)
            #    return result
            #
            #result = find_4k_videos(url_metadata["medias"])
            #print(result)
            #exit(1)
            found4k = hulu_jp_downloader.find_4k(metadata["log_params"]["meta_id"])
            #print(data)
            #exit(1)
            if found4k != []:
                status, message = hulu_jp_downloader.close_playback_session(metadata["playback_session_id"])
                logger.info("Close Video Session", extra={"service_name": __service_name__})
                ovp_video_id = found4k[0]["ovp_video_id"]
                media_id = found4k[0]["media_id"]
                logger.info("Creating Video Sesson 4K...", extra={"service_name": __service_name__})
                status, metadata = hulu_jp_downloader.playback_auth(episode_id, uhd=True, media_id=media_id)
                logger.info(" + Session Token: "+metadata["playback_session_id"][:10]+"*****", extra={"service_name": __service_name__})
            else:
                ovp_video_id= metadata["media"]["ovp_video_id"]
            
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            #print("try to open play session....")
            
            status, playdata = hulu_jp_downloader.open_playback_session(ovp_video_id, metadata["playback_session_id"], episode_id)
            
            status, message = hulu_jp_downloader.close_playback_session(metadata["playback_session_id"])
            logger.info("Close Video Session", extra={"service_name": __service_name__})
            #print(status, message)
            #
            #print(playdata["name"], playdata["duration"])
            if found4k != []:
                logger.info("Got 4k Link", extra={"service_name": __service_name__})
                urls = []
                widevine_url = None
                playready_url = None
                for source in playdata["sources"]:
                    if source["resolution"] == "3840x2160" and "manifest.mpd" in source["src"]:
                        urls.append(source["src"])
                        if source["key_systems"]:
                            widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                            playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                hd_link = urls[0]
                logger.info(f" + 4K_link: {hd_link[:15]+"*****"}", extra={"service_name": __service_name__})
            else:
                logger.info("Got HD Link", extra={"service_name": __service_name__})
                urls = []
                widevine_url = None
                playready_url = None
                for source in playdata["sources"]:
                    if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                        urls.append(source["src"])
                        if source["key_systems"]:
                            widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                            playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                hd_link = urls[0]
                logger.info(f" + HD_link: {hd_link[:15]+"*****"}", extra={"service_name": __service_name__})
            
            logger.info("Checking Subtitle...", extra={"service_name": __service_name__})
            #print("have subtitle?")
            found_sub = False
            for single in playdata["tracks"]:
                if single["kind"] == "subtitles":
                    found_sub = True
            logger.info(" + Have Subtitle?: "+str(found_sub), extra={"service_name": __service_name__})
            #print(found_sub)
            #print("get hd mpd")
            #hd_link = urls[0]
            #print(hd_link)
            #print("get license url")
            #print(widevine_url)
            
            logger.info(f"Parse MPD file", extra={"service_name": __service_name__})
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(session.get(hd_link).text)
                    
            logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
            license_key = hulu_jp.Hulu_jp_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, config)
            
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
            
            logger.debug(f"Calculate about Manifest...", extra={"service_name": __service_name__})
            duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
            logger.debug(f" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})
            
            logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
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
            
            hulu_jp.Hulu_jp_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            if season_title != None:
                output_path = os.path.join(config["directorys"]["Downloads"], season_title, title_name_logger+".mp4")
            else:
                output_path = os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4")
            
            result = hulu_jp_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", output_path, config, unixtime, season_title, int(duration))
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
        elif re.search(r'/watchssss/(\d+)', url): ## season download
            print("ongoing")
            # curnchyrollから撮ってくる
            
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