# ok analyze is done
# これだけ無駄にコード綺麗に書いてやろうかな
import os
import yaml
import time
import shutil
import logging
from rich.console import Console
from urllib.parse import urlparse, parse_qs
import ext.global_func.parser as parser

from ext.utils import wowow

console = Console()

__service_name__ = "WOD-WOWOW"

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
    
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        wod_downloader = wowow.WOD_downloader(session, logger)
        
        if email and password != "":
            status, message = wod_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": __service_name__})
                exit(1)
            else:
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+str(message["user"]["id"]), extra={"service_name": __service_name__})
                login_status = True
        else:
            login_status = False
            logger.error("WOWOW Require Login Account", extra={"service_name": __service_name__})
        
        logger.info("Fetching URL...", extra={"service_name": __service_name__})
        
        # https://wod.wowow.co.jp/program/203640
        # https://wod.wowow.co.jp/program/203640?season_id=152140
        # こいつらをサポート (↑They are supported)
        
        if url.__contains__("program/") and not url.__contains__("season_id="):
            total_season, all_season_json = wod_downloader.get_all_season_id(url)
            
            logger.info(f"Fetching {total_season} season Meta...", extra={"service_name": __service_name__})
            
            for single_season in all_season_json:
                logger.info(f"Get Title for {single_season["name"]}", extra={"service_name": __service_name__})
                episode_list = wod_downloader.get_season_episode_title(single_season["meta_id"])
                for single in episode_list:
                    logger.info(f"+ {single_season["name"]}_{single["shortest_name"]}_{single["short_name"]} [ID:{single["ep_id"]}, RID:{single["refId"]}]", extra={"service_name": __service_name__})
                for single in episode_list:
                    title_name = f"{single_season["name"]}_{single["shortest_name"]}_{single["short_name"]}"
                    season_title = single_season["name"]
                    logger.info("Creating Video Sesson...", extra={"service_name": __service_name__})
                    status, response = wod_downloader.create_video_session()
                    if status != True:
                        pass
                    logger.info(" + Session Token: "+response["token"][:10]+"*****", extra={"service_name": __service_name__})
                    if login_status == False:
                        logger.error("Get manifest is require login account. but You'r is not logined. exiting...", extra={"service_name": __service_name__})
                        exit(1)
                    wod_downloader.check_token()
                    status, session_id, video_access_token, ovp_video_id = wod_downloader.create_playback_session(single["ep_id"])
                    if status != True:
                        pass
                    duration, sources = wod_downloader.get_episode_prod_info(ovp_video_id, video_access_token, session_id)
                    logger.info("Close Video Session", extra={"service_name": __service_name__})
                    
                    logger.info("Got HD Link", extra={"service_name": __service_name__})
                    urls = []
                    
                    widevine_url = None
                    playready_url = None
                    
                    for source in sources:
                        if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                            urls.append(source["src"])
                            if source["key_systems"]:
                                widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                                playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                            #else:
                            #    widevine_url = None
                            #    playready_url = None
                    hd_link = urls[0].replace("jp/v4", "jp/v6")
                    logger.info(f" + HD_link: {hd_link[:15]+"*****"}", extra={"service_name": __service_name__})
                    
                    logger.info("Parse MPD file", extra={"service_name": __service_name__})
                    Tracks = parser.global_parser()
                    transformed_data = Tracks.mpd_parser(session.get(hd_link).text)
                    
                    
                    logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                    license_key = wowow.WOD_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, config)
                    
                    logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                    logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                
                    wod_downloader.send_stop_signal(video_access_token, session_id)
                    
                    
                    logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                    logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                    track_data = Tracks.print_tracks(transformed_data)
                    
                    print(track_data)
                    
                    get_best_track = Tracks.select_best_tracks(transformed_data)
                    
                    logger.debug(" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                    logger.info("Selected Best Track:", extra={"service_name": __service_name__})
                    logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    
                    logger.debug("Calculate about Manifest...", extra={"service_name": __service_name__})
                    duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                    logger.debug(" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})
                    
                    logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                    video_segment_list = Tracks.calculate_segments(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
                    logger.info(" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
                    audio_segment_list = Tracks.calculate_segments(duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
                    logger.info(" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
                    
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
                    
                    wod_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
                    wod_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
                    
                    logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    wowow.WOD_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
                    wowow.WOD_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                    
                    wowow.WOD_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    
                    result = wod_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], season_title, title_name+".mp4"), config, unixtime, season_title, int(duration))
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
                    logger.info('Finished download: {}'.format(title_name), extra={"service_name": __service_name__})
        elif url.__contains__("season_id="):
            url_select_id = parse_qs(urlparse(url).query).get("season_id", [None])[0]
            
            total_season, all_season_json = wod_downloader.get_all_season_id(url)
                        
            for single_season in all_season_json:

                if single_season["id"] != int(url_select_id):
                    continue
                logger.info(f"Get Title for {single_season["name"]}", extra={"service_name": __service_name__})
                episode_list = wod_downloader.get_season_episode_title(single_season["meta_id"])

                for single in episode_list:
                    logger.info(f"+ {single_season["name"]}_{single["shortest_name"]}_{single["short_name"]} [ID:{single["ep_id"]}, RID:{single["refId"]}]", extra={"service_name": __service_name__})
                for single in episode_list:
                    title_name = f"{single_season["name"]}_{single["shortest_name"]}_{single["short_name"]}"
                    season_title = single_season["name"]
                    logger.info("Creating Video Sesson...", extra={"service_name": __service_name__})
                    status, response = wod_downloader.create_video_session()
                    if status != True:
                        pass
                    logger.info(" + Session Token: "+response["token"][:10]+"*****", extra={"service_name": __service_name__})
                    if login_status == False:
                        logger.error("Get manifest is require login account. but You'r is not logined. exiting...", extra={"service_name": __service_name__})
                        exit(1)
                    wod_downloader.check_token()
                    status, session_id, video_access_token, ovp_video_id = wod_downloader.create_playback_session(single["ep_id"])
                    if status != True:
                        pass
                    duration, sources = wod_downloader.get_episode_prod_info(ovp_video_id, video_access_token, session_id)
                    logger.info("Close Video Session", extra={"service_name": __service_name__})
                    
                    logger.info("Got HD Link", extra={"service_name": __service_name__})
                    urls = []
                    
                    widevine_url = None
                    playready_url = None
                    
                    for source in sources:
                        if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                            urls.append(source["src"])
                            if source["key_systems"]:
                                widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                                playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                            #else:
                            #    widevine_url = None
                            #    playready_url = None
                    hd_link = urls[0].replace("jp/v4", "jp/v6")
                    logger.info(f" + HD_link: {hd_link[:15]+"*****"}", extra={"service_name": __service_name__})
                    
                    logger.info("Parse MPD file", extra={"service_name": __service_name__})
                    Tracks = parser.global_parser()
                    transformed_data = Tracks.mpd_parser(session.get(hd_link).text)
                    
                    
                    logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                    license_key = wowow.WOD_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, widevine_url, config)
                    
                    logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                    logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})
                
                    wod_downloader.send_stop_signal(video_access_token, session_id)
                    
                    
                    logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
                    logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
                    track_data = Tracks.print_tracks(transformed_data)
                    
                    print(track_data)
                    
                    get_best_track = Tracks.select_best_tracks(transformed_data)
                    
                    logger.debug(" + Track Json: "+str(get_best_track), extra={"service_name": __service_name__})
                    logger.info("Selected Best Track:", extra={"service_name": __service_name__})
                    logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps", extra={"service_name": __service_name__})
                    
                    logger.debug("Calculate about Manifest...", extra={"service_name": __service_name__})
                    #print(transformed_data["info"]["mediaPresentationDuration"])
                    duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                    #print(duration)
                    logger.debug(" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})
                    
                    logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
                    #print(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
                    video_segment_list = Tracks.calculate_segments(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
                    logger.info(" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})                 
                    audio_segment_list = Tracks.calculate_segments(duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
                    logger.info(" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
                    
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
                    
                    wod_downloader.download_segment(video_segment_links, config, unixtime, "download_encrypt_video.mp4")
                    wod_downloader.download_segment(audio_segment_links, config, unixtime, "download_encrypt_audio.mp4")
                    
                    logger.info("Decrypting encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
                    
                    wowow.WOD_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), config)
                    wowow.WOD_decrypt.decrypt_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                    
                    wowow.WOD_decrypt.decrypt_all_content(license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4"), os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4"), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                    
                    result = wod_downloader.mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", os.path.join(config["directorys"]["Downloads"], season_title, title_name+".mp4"), config, unixtime, season_title, int(duration))
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
                    logger.info('Finished download: {}'.format(title_name), extra={"service_name": __service_name__})
        else:
            print("unsupported")
    except Exception:
        try:
            wod_downloader.send_stop_signal(video_access_token, session_id)
        except:
            pass
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")