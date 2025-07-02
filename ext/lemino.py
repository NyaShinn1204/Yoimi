import os
import re
import yaml
import json
import time
import shutil
import base64
import logging

import ext.global_func.parser as parser

from rich.console import Console
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote

from ext.utils import lemino

from ext.global_func.util.mux_util import main_mux
from ext.global_func.util.download_util import segment_downloader
from ext.global_func.util.decrypt_util import main_decrypt
from ext.global_func.util.session_util import session_util
from ext.global_func.util.license_util import license_util

console = Console()

__service_name__ = "Lemino"

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
        
    session.headers.update({"User-Agent": "Lemino/7.2.2(71) A7S;AndroidTV;10"})
    
def check_session(service_name):
    service_name = service_name.lower()
    session_path = os.path.join("cache", "session", service_name)
    if not os.path.exists(session_path):
        os.makedirs(session_path)
        return False
    current_time = int(time.time())
    closest_file = None
    closest_diff = float('inf')

    for filename in os.listdir(session_path):
        if filename.startswith("session_") and filename.endswith(".json"):
            try:
                timestamp_str = filename[len("session_"):-len(".json")]
                session_time = int(timestamp_str)
                diff = abs(current_time - session_time)
                if diff < closest_diff:
                    closest_diff = diff
                    closest_file = filename
            except ValueError:
                continue
    if not closest_file == None:
        return os.path.join(session_path, closest_file)
    else:
        return False
def load_session(json_path):
    with open(json_path, 'r', encoding='utf-8-sig') as f:
        data = f.read()
        if data.strip() == "":
            return False
        return json.loads(data)
    
def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = "https://lemino.docomo.ne.jp/contents/Y3JpZDovL3BsYWxhLmlwdHZmLmpwL3ZvZC/xxxxx"    # single
        #url = "https://lemino.docomo.ne.jp/search/word/XXXXXX?crid=Y3JpZDovL3BsYWxh..."          # search
        #url = "https://lemino.docomo.ne.jp/contents/Y3JpZDovL3BsYWxhLmlwdHZmLmpwL2dyb3Vw/xxxxx." # batch
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        lemino_downloader = lemino.Lemino_downloader(session, config)
        


        status = check_session(__service_name__)
        session_logic = session_util(logger=logger, service_name=__service_name__, service_util=lemino_downloader)
        session_data = None
        session_status = False
        
        if status:
            session_data = load_session(status)
            if session_data:
                token_status, message = lemino_downloader.check_token(session_data["access_token"])
                if not token_status:
                    logger.info("Session is Invalid. Please re-login.", extra={"service_name": __service_name__})
                    session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method="qr")
                else:
                    session_status = True
            
        if not session_status and email and password:
            session_status, message, session_data = session_logic.login_with_credentials(email, password, login_method="qr")
        
        if session_status:
            account_logined = True
            profile_id = message["profile"]["profile_id"]
            logger.info("Logged-in Account", extra={"service_name": __service_name__})
            logger.info(" + id: " + profile_id, extra={"service_name": __service_name__})
        else:
            account_logined = False
            lemino_downloader.use_temptoken_flag()
            logger.info("Using Temp Account", extra={"service_name": __service_name__})
            
        logger.info("Analyzing URL", extra={"service_name": __service_name__})
        
        
        # DOWNLOAD LOGIC
        def single_download_logic(content_crid, from_mutli=False, title_name_logger=None, title_name=None):
            content_info = lemino_downloader.get_content_info(crid=content_crid)
            
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            
            genre_list = []
            for genre_s in content_info["meta_list"][0]["genre_list"]["vod"]:
                genre_list.append(genre_s["id"])
            
            result_genre, print_genre, only_genre_id_list = lemino_downloader.analyze_genre(genre_list)
            logger.info(f" + Video Type: {print_genre}", extra={"service_name": __service_name__})
            
            # try:
            #     content_list = lemino_downloader.get_content_list(content_info["meta_list"][0]["member_of"][0])
            # except:
            #     content_list = 1
            # if from_mutli:
            #     title_name = title_name
            # else:
            #     title_name = content_info["meta_list"][0]["title"].replace(content_info["meta_list"][0]["title_sub"], "")
            # episode_num = 1
            # match = re.search(r'(\d+)', content_info["meta_list"][0]["play_button_name"])
            # if match:
            #     episode_num = int(match.group(1))
                    
            # if from_mutli:
            #     title_name_logger = title_name_logger
            # else:
            #     title = content_info["meta_list"][0]["title"].strip()
            #     title_sub = content_info["meta_list"][0]["title_sub"].strip()
            #     subtitle = title_sub 
            #     for part in title.split():
            #         if part and part in subtitle:
            #             subtitle = subtitle.replace(part, "").strip()
            #     episode_number = content_info["meta_list"][0]["play_button_name"]
            #     title_name_logger = lemino_downloader.create_titlename_logger(only_genre_id_list, content_list, title_name, episode_number, subtitle)
            # logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            if content_info["meta_list"][0]["member_of"] != []:
                season_title, content_count, season_info = lemino_downloader.get_content_list(content_info["meta_list"][0]["member_of"][0])        
                single = content_info["meta_list"][0]
                title = single["title"].strip()
                title_sub = single["title_sub"].strip()
                
                if title_sub.startswith(title):
                    subtitle = title_sub[len(title):].strip()
                else:
                    subtitle = title_sub
                    for part in title.split():
                        if part and part in subtitle:
                            subtitle = subtitle.replace(part, "").strip()
                            
                episode_number = single["play_button_name"]
                title_name_logger = lemino_downloader.create_titlename_logger(only_genre_id_list, content_count, season_title, episode_number, subtitle)
            else:
                try:
                    content_list = lemino_downloader.get_content_list(content_info["meta_list"][0]["member_of"][0])
                except:
                    content_list = 1
                if from_mutli:
                    title_name = title_name
                else:
                    title_name = content_info["meta_list"][0]["title"].replace(content_info["meta_list"][0]["title_sub"], "")
                episode_num = 1
                match = re.search(r'(\d+)', content_info["meta_list"][0]["play_button_name"])
                if match:
                    episode_num = int(match.group(1))
                        
                if from_mutli:
                    title_name_logger = title_name_logger
                else:
                    title = content_info["meta_list"][0]["title"].strip()
                    title_sub = content_info["meta_list"][0]["title_sub"].strip()
                    subtitle = title_sub 
                    for part in title.split():
                        if part and part in subtitle:
                            subtitle = subtitle.replace(part, "").strip()
                    episode_number = content_info["meta_list"][0]["play_button_name"]
                    title_name_logger = lemino_downloader.create_titlename_logger(only_genre_id_list, content_list, title_name, episode_number, subtitle)
            logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})

            
            cid = content_info["meta_list"][0]["cid_obj"][0]["cid"]
            
            
            license_list = content_info["meta_list"][0]["license_list"]
            now = datetime.now(timezone(timedelta(hours=9)))  # JST (UTC+9)
            lid = None
            
            logger.debug("Fetching VOD Type", extra={"service_name": __service_name__})
            
            # if sale_type == avod, and sale_end_date is not invalid
            for license in license_list:
                if license.get("sale_type") == "avod":
                    logger.debug(" + Found AVOD(Ad Video Ondemand)", extra={"service_name": __service_name__})
                    sale_start = datetime.fromisoformat(license["sale_start_date"])
                    sale_end = datetime.fromisoformat(license["sale_end_date"])
                    if sale_start <= now < sale_end:
                        logger.debug(" + AVOD is Valid. juse use AVOD", extra={"service_name": __service_name__})
                        lid = license["license_id"]
                        break
                    else:
                        logger.debug(" + AVOD is not start, or expired. just use another", extra={"service_name": __service_name__})
            # if sale_type == free, and sale_start_date <= now < sale_end_date
            for license in license_list:
                if license.get("sale_type") == "free":
                    logger.debug(" + Found Free", extra={"service_name": __service_name__})
                    sale_start = datetime.fromisoformat(license["sale_start_date"])
                    sale_end = datetime.fromisoformat(license["sale_end_date"])
                    if sale_start <= now < sale_end:
                        logger.debug(" + Free is Valid. jsue use Free", extra={"service_name": __service_name__})
                        lid = license["license_id"]
                        break
                    else:
                        logger.debug(" + Free is not start, or expired. just use another", extra={"service_name": __service_name__})
                    
            # if not found, juse use first svod lid
            if lid is None:
                for license in license_list:
                    if license.get("sale_type") == "svod":
                        logger.debug(" + Found SVOD(Subscribe Video Ondemand)", extra={"service_name": __service_name__})
                        lid = license["license_id"]
                        break
            
            
            
            logger.info("Getting information from MPD", extra={"service_name": __service_name__})
            
            play_token, content_list = lemino_downloader.get_mpd_info(cid=cid, lid=lid, crid=content_info["meta_list"][0]["crid"])
            mpd_link = content_list[0]["play_url"]
            mpd_text = session.get(mpd_link).text
            Tracks = parser.global_parser()
            transformed_data = Tracks.mpd_parser(mpd_text, real_bitrate=True)
            duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                    
            logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
            widevine_headers = {
                "acquirelicenseassertion": content_list[0]["custom_data"],
                "user-agent": "inidrmagent/2.0 (Android 10; jp.ne.docomo.lemino.androidtv)",
                "content-type": "application/octet-stream",
                "host": "drm.lemino.docomo.ne.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip"
            }
            license_key = license_util.widevine_license(transformed_data["pssh_list"]["widevine"], content_list[0]["la_url"], widevine_headers, session, config)
            
            lemino_downloader.send_stop_signal(play_token, content_info["meta_list"][0]["duration_sec"])
            
            logger.info("Decrypt License for 1 Episode", extra={"service_name": __service_name__})
            logger.info(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}", extra={"service_name": __service_name__})        
            
            logger.info("Get Video, Audio Tracks:", extra={"service_name": __service_name__})
            logger.debug(" + Meta Info: "+str(transformed_data["info"]), extra={"service_name": __service_name__})
            track_data = Tracks.print_tracks(transformed_data, real_bitrate=True)
            
            print(track_data) 
            
            get_best_track = Tracks.select_best_tracks(transformed_data)
            
            logger.info("Selected Best Track:", extra={"service_name": __service_name__})
            logger.info(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {str(int(int(get_best_track["video"]["bitrate"]) /1000))} kbps", extra={"service_name": __service_name__})
            logger.info(f" + Audio: [{get_best_track["audio"]["codec"]}] | {str(int(int(get_best_track["audio"]["bitrate"]) /1000))} kbps", extra={"service_name": __service_name__})
                          
            duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
            logger.debug(" + Episode Duration: "+str(int(duration)), extra={"service_name": __service_name__})           
            
            logger.info("Video, Audio Content Segment Link", extra={"service_name": __service_name__})
            video_segment_list = Tracks.calculate_segments(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
            logger.info(" + Video Segments: "+str(int(video_segment_list)), extra={"service_name": __service_name__})               
            audio_segment_list = Tracks.calculate_segments(duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
            logger.info(" + Audio Segments: "+str(int(audio_segment_list)), extra={"service_name": __service_name__})
            
            parsed = urlparse(mpd_link)
            base_path = parsed.path.rsplit('/', 1)[0] + '/'
            base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
            
            video_segments = Tracks.get_segment_link_list(mpd_text, get_best_track["video"]["id"], base_url)
            video_segment_links = [item.replace("$Bandwidth$", get_best_track["video"]["bitrate"]) for item in video_segments["all"]]
            audio_segments = Tracks.get_segment_link_list(mpd_text, get_best_track["audio"]["id"], base_url)
            audio_segment_links = [item.replace("$Bandwidth$", get_best_track["audio"]["bitrate"]) for item in audio_segments["all"]]
            
            logger.info("Downloading Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            video_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_video.mp4")
            audio_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4")
            
            downloader = segment_downloader()
            
            status, result = downloader.download(video_segment_links, "download_encrypt_video.mp4", config, unixtime, __service_name__)
            status, result = downloader.download(audio_segment_links, "download_encrypt_audio.mp4", config, unixtime, __service_name__)
            
            logger.info("Decrypting Encrypted Video, Audio Segments...", extra={"service_name": __service_name__})
            
            decryptor = main_decrypt(logger)
            
            video_decrypt_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_video.mp4")
            audio_decrypt_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4")
            
            decryptor.decrypt(license_keys=license_key, input_path=[video_output, audio_output], output_path=[video_decrypt_output, audio_decrypt_output], config=config, service_name=__service_name__)
                        
            def sanitize_filename(filename: str) -> str:
                """
                Fucking idiot Windows filename convert to nice string 
                """
                replacements = {
                    '<': '＜',
                    '>': '＞',
                    ':': '：',
                    '"': '”',
                    '/': '／',
                    '\\': '＼',
                    '|': '｜',
                    '?': '？',
                    '*': '＊'
                }
                for bad_char, safe_char in replacements.items():
                    filename = filename.replace(bad_char, safe_char)
                return filename
            
            if title_name != None:
                if os.name == "nt":
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name, sanitize_filename(os.path.join(title_name_logger+".mp4")))
                else:
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
            else:
                if os.name == "nt":
                    output_path = os.path.join(config["directorys"]["Downloads"], sanitize_filename(os.path.join(title_name_logger+".mp4")))
                else:
                    output_path = os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4")
            
            logger.info("Muxing Episode...", extra={"service_name": __service_name__})
            
            muxer = main_mux(logger)
            
            muxer.mux_content(video_input=video_decrypt_output, audio_input=audio_decrypt_output, output_path=output_path, duration=int(duration), service_name=__service_name__)
            
            if LOG_LEVEL != "DEBUG":
                dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                try:
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        shutil.rmtree(dir_path)
                    else:
                        print(f"Folder is not found: {dir_path}")
                except Exception as e:
                    print(f"Delete folder errro: {e}")
            
            logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
            
        def season_download_logic(content_crid):
            season_title, content_count, season_info = lemino_downloader.get_content_list(content_crid)            
            logger.info("Get Info for Season", extra={"service_name": __service_name__})
            logger.info(f" + Title: {season_title}", extra={"service_name": __service_name__})
            logger.info(f" + Episode Count: {content_count}", extra={"service_name": __service_name__})

            genre_list = []
            for genre_s in season_info["genre_list"]["vod"]:
                genre_list.append(genre_s["id"])
            
            result_genre, print_genre, only_genre_id_list = lemino_downloader.analyze_genre(genre_list)
            logger.info(f" + Video Type: {print_genre}", extra={"service_name": __service_name__})
            
            logger.info("Get Title for Season", extra={"service_name": __service_name__})
            
            for single in season_info["child_list"]:
                title = single["title"].strip()
                title_sub = single["title_sub"].strip()
                
                if title_sub.startswith(title):
                    subtitle = title_sub[len(title):].strip()
                else:
                    subtitle = title_sub
                    for part in title.split():
                        if part and part in subtitle:
                            subtitle = subtitle.replace(part, "").strip()
                            
                episode_number = single["play_button_name"]
                title_name_logger = lemino_downloader.create_titlename_logger(only_genre_id_list, content_count, season_title, episode_number, subtitle)
                logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
                
            for single in season_info["child_list"]:
                title = single["title"].strip()
                title_sub = single["title_sub"].strip()
                
                if title_sub.startswith(title):
                    subtitle = title_sub[len(title):].strip()
                else:
                    subtitle = title_sub
                    for part in title.split():
                        if part and part in subtitle:
                            subtitle = subtitle.replace(part, "").strip()
                            
                episode_number = single["play_button_name"]
                title_name_logger = lemino_downloader.create_titlename_logger(only_genre_id_list, content_count, season_title, episode_number, subtitle)
                single_download_logic(single["crid"], from_mutli=True, title_name_logger=title_name_logger, title_name=season_title)
                
            logger.info("Finished download Season: {}".format(season_title), extra={"service_name": __service_name__})
        # URL LOGIC HERE
        def safe_b64decode(data: str) -> str:
            # nice decode base64 to crid :)
            data += '=' * (-len(data) % 4)
            return base64.b64decode(data).decode('utf-8')
    
        parsed = urlparse(url)
        
        # --- search URL ---
        if "search/word" in url:
            query = parse_qs(parsed.query)
            crid_encoded = query.get("crid", [None])[0]
            if crid_encoded:
                crid_decoded = safe_b64decode(unquote(crid_encoded))
                if "group" in crid_decoded:
                    season_download_logic(crid_decoded)
                else:
                    single_download_logic(crid_decoded)
                return
    
        # --- contents URL ---
        match = re.search(r'/contents/([^/?#]+)', parsed.path)
        if match:
            crid_encoded = match.group(1)
            crid_decoded = safe_b64decode(unquote(crid_encoded))
    
            if "/vod/" in crid_decoded:
                single_download_logic(crid_decoded)
            elif "/group/" in crid_decoded:
                season_download_logic(crid_decoded)
            else:
                logger.error("Unknown contetn strcuture", extra={"service_name": __service_name__})
            return
    
        logger.error("Unsupported Type URL", extra={"service_name": __service_name__})
        logger.error("Now support:", extra={"service_name": __service_name__})
        logger.error("https://lemino.docomo.ne.jp/contents/xxx... (single)", extra={"service_name": __service_name__})
        logger.error("https://lemino.docomo.ne.jp/search/word/xxx...?crid=xxx... (single)", extra={"service_name": __service_name__})
        logger.error("https://lemino.docomo.ne.jp/contents/xxx... (batch)", extra={"service_name": __service_name__})
            
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")