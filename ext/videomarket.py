import re
import os
import yaml
import time
import logging
import shutil
from rich.console import Console
from urllib.parse import urlparse

import ext.global_func.parser as parser

from ext.utils import videomarket

__service_name__ = "VideoMarket"

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
        
        videomarket_downloader = videomarket.VideoMarket_downloader(session, config)
        
        if email and password != None:
            status, message = videomarket_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": __service_name__})
            except:
                logger.info("Failed to login", extra={"service_name": __service_name__})
        else:
            status, message, id_token, refresh_token = videomarket_downloader.get_temp_token()
            session.headers.update({"Authorization": "Bearer "+ id_token})
        if status == False:
            logger.info(message, extra={"service_name": __service_name__})
            exit(1)
        else:
            if email and password != None:
                account_id = str(message["userId"])
                logger.info("Loggined Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+account_id[:3]+"*****", extra={"service_name": __service_name__})
            else:
                account_id = str(message["userId"])
                logger.info("Using Temp Account", extra={"service_name": __service_name__})
                logger.info(" + ID: "+account_id, extra={"service_name": __service_name__})
                
        status = videomarket_downloader.check_single(url)
        
        if status == False:
            logger.info("Get Title For Season", extra={"service_name": __service_name__})
            
            status, message, id_type, title_summary = videomarket_downloader.get_title_parse_all(url)
            
            for single in message:
                if single["groupType"] == "SINGLE_CHOICE":
                    pass
                else:
                    continue
                
                if "アニメ" in id_type and "邦画" not in id_type:
                    format_string = config["format"]["anime"].replace("_{episodename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                        "titlename": single.get("packName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                elif "邦画" in id_type:
                    format_string = config["format"]["movie"]
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if single["price"] == 0:
                    content_type = "FREE   "
                    content_status_lol = ""
                else:
                    content_type = "PREMIUM"
                    content_status_lol = f"| PRICE {str(single["price"])}"
                logger.info(f" + {content_type} {content_status_lol}| {title_name_logger}", extra={"service_name": __service_name__})
            for single in message:
                if single["groupType"] == "SINGLE_CHOICE":
                    pass
                else:
                    continue
                
                if "アニメ" in id_type and "邦画" not in id_type:
                    format_string = config["format"]["anime"].replace("_{episodename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                        "titlename": single.get("packName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                elif "邦画" in id_type:
                    format_string = config["format"]["movie"]
                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                    values = {
                        "seriesname": title_summary.get("titleName", ""),
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                
                series_title = title_summary.get("titleName", "")
                #print(series_title)
                if single["price"] == 0:
                    content_type = "FREE   "
                    content_status_lol = ""
                else:
                    content_type = "PREMIUM"
                    content_status_lol = f"| PRICE {str(single["price"])}"
                    
                if content_type == "PREMIUM":
                    logger.warning("This episode is require PREMIUM. Skipping...", extra={"service_name": __service_name__})
                    continue
                
                logger.info("Get Playing Access Token", extra={"service_name": __service_name__})
                status, playing_access_token = videomarket_downloader.get_playing_access_token()
                logger.info(" + Playing Access Token (Temp): "+playing_access_token[:10]+"*****", extra={"service_name": __service_name__})
                
                logger.info("Get Playing Token", extra={"service_name": __service_name__})
                
                status, playing_token = videomarket_downloader.get_playing_token(single["packs"][0]["stories"][0]["fullStoryId"], single["packs"][0]["fullPackId"], playing_access_token)
                logger.info(" + Playing Token (Temp): "+playing_token[:10]+"*****", extra={"service_name": __service_name__})
                
                logger.info("Get Streaming Data", extra={"service_name": __service_name__})
                status, streaming_data = videomarket_downloader.get_streaming_info(single["packs"][0]["stories"][0]["fullStoryId"], playing_token, account_id, playing_access_token)
                #print(streaming_data)
                
                logger.debug("Get Codecs Info", extra={"service_name": __service_name__})
                for s_codec_info in streaming_data["codecInfo"]:
                    logger.debug(" + "+s_codec_info+" : "+str(streaming_data["codecInfo"][s_codec_info]), extra={"service_name": __service_name__})
                
                logger.info(f"Get Best Streaming URL:", extra={"service_name": __service_name__})
                
                
                # lowFhdの辞書を取得
                low_fhd = streaming_data["videoInfo"]["abr"]["avc"]["lowFhd"]
                
                ## 要素を取得
                #file_type = last_entry["fileType"]
                #play_url = last_entry["playUrl"]
                #quality = last_entry["quality"]
                
                #print("fileType:", file_type)
                #print("playUrl:", play_url)
                #print("quality:", quality)
                #print(low_fhd["playUrl"])
                
                logger.info(" + Quality:"+low_fhd["quality"]+" Type:"+low_fhd["fileType"], extra={"service_name": __service_name__})
                
                logger.info("Parse Best MPD file", extra={"service_name": __service_name__})
                
                Tracks = parser.global_parser()
                transformed_data = Tracks.mpd_parser(session.get(low_fhd["playUrl"]).text)
                                
                logger.info(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}", extra={"service_name": __service_name__})
                license_key = videomarket.VideoMarket_license.license_vd_ad(transformed_data["pssh_list"]["widevine"], session, streaming_data["drmInfo"]["lowFhd"]["licenseUrl"], config)
                
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

                parsed = urlparse(low_fhd["playUrl"])
                base_path = parsed.path.rsplit('/', 1)[0]
                base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/"
                                
                video_url = base_url+get_best_track["video"]["url"]
                audio_url = base_url+get_best_track["audio"]["url"]
                logger.debug(" + Video: "+video_url, extra={"service_name": __service_name__})
                logger.debug(" + Audio: "+audio_url, extra={"service_name": __service_name__})
                
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
                
                series_title = sanitize_filename(series_title)
                
                logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                    
                video_downloaded = videomarket_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
                audio_downloaded = videomarket_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)                    
                logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                                
                videomarket.VideoMarket_decrypt.decrypt_all_content(license_key["key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                
                result = videomarket_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], series_title, title_name_logger+".mp4"), config, unixtime, sanitize_filename(series_title), int(int(single["playTime"]) / 1000), title_name_logger, None, additional_info)
                
                dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    for filename in os.listdir(dir_path):
                        if filename == "metadata":
                            continue
                        
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
        else:
            logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")