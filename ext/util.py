import re
import os
import cv2
import json
import time
import shutil
import logging
import colorama
import requests
import tls_client
from typing import Iterator
from datetime import datetime
from rich.console import Console
from importlib import import_module
from urllib.parse import urlparse, parse_qs


import ext.utils.parser_util as parser_util

from ext.utils.download_util import (aria2c_downloader, segment_downloader, live_downloader)
from ext.utils.decrypt_util import main_decrypt
from ext.utils.mux_util import main_mux

from ext.utils.license_util import license_logic
from ext.utils.session_util import session_logic
from ext.utils.titlename_util import (titlename_logic, filename_logic)
from ext.utils.zzz_other_util import other_util

colorama.init()
console = Console()

def path_check(input_path):
    invalid_chars = r'[<>:"|?*]'
    if re.search(invalid_chars, input_path):
        return False

    if not input_path.strip():
        return False

    has_extension = bool(os.path.splitext(input_path)[1])
    looks_like_path = '/' in input_path or '\\' in input_path

    return has_extension or looks_like_path
def update_config(obj, config_dict):
    for key, value in config_dict.items():
        setattr(obj, key, value)

def check_dmm_content_type(season_id):
    try:
        res = requests.post("https://api.tv.dmm.com/graphql", json={
            "operationName": "FetchVideoContent",
            "variables": {
                "id": season_id,
                "playDevice": "BROWSER",
                "isLoggedIn": False
            },
            "query": "query FetchVideoContent($id: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!) {\n  videoContent(id: $id) {\n    contentType\n  }\n}"
        })
        if res.status_code == 200:
            return res.json()["data"]["videoContent"]["contentType"]
    except Exception:
        return None

def get_parser(url):
    patterns = [
        # パターン, 条件, モジュール名, ラベル名
        (re.compile(r'^https?://abema\.tv/.+'), lambda u: "-v1" in u, 'ext.services.abematv', 'abemav1'),
        (re.compile(r'^https?://abema\.tv/.+'), None, 'ext.services.abematv_v2', 'abema'),
        (re.compile(r'^https?://gyao\.yahoo\.co\.jp/.+'), None, 'ext.services.gyao', 'gyao'),
        (re.compile(r'^https?://(?:www\.)?aniplus-asia\.com/episode/.+'), None, 'ext.services.aniplus', 'aniplus'),
        (re.compile(r'^https?://(?:video|video-share)\.unext\.jp/.+(SID\d+|ED\d+|LIV\d+)', re.IGNORECASE), None, 'ext.services.u_next', 'U-Next'),
        (re.compile(r'^https?://video\.hnext\.jp/(?:play|title)/(AID\d+|AED\d+)'), None, 'ext.services.h_next', 'H-Next'),
        (re.compile(r'^https?://tv\.dmm\.com/.+season=([^&]+).*(content=([^&]+))?'), lambda u: check_dmm_content_type(parse_qs(urlparse(u).query).get("season", [None])[0]) == "VOD_VR", 'ext.services.fanza.vr', 'Fanza-VR'),
        (re.compile(r'^https?://tv\.dmm\.com/.+season=([^&]+)'), None, 'ext.services.dmm_tv', 'dmm_tv'),
        (re.compile(r'^https?://www\.brainshark\.com/.+pi=([^&]+)'), None, 'ext.services.brainshark', 'brainshark'),
        (re.compile(r'^https?://fod\.fujitv\.co\.jp/title/[0-9a-z]+'), None, 'ext.services.fod_v2', 'fod'),
        (re.compile(r'^https?://anime3rb\.com/.+'), None, 'ext.services.anime3rb', 'anime3rb'),
        (re.compile(r'^https?://www\.crunchyroll\.com/(series|watch)/.+'), None, 'ext.services.crunchyroll', 'Crunchyroll'),
        (re.compile(r'^https?://www\.b-ch\.com/titles/\d+'), None, 'ext.services.bandai_ch', 'Bandai-Ch'),
        (re.compile(r'^https?://(?:www\.)?telasa\.jp/.+'), None, 'ext.services.telasa', 'Telasa'),
        (re.compile(r'^https?://(?:www\.)?videomarket\.jp/.+'), None, 'ext.services.videomarket', 'VideoMarket'),
        (re.compile(r'^https?://(?:www\.)?hulu\.jp/.+'), None, 'ext.services.hulu_jp', 'Hulu-jp'),
        (re.compile(r'^https?://www\.dmm\.(?:com|co\.jp)/digital/-/player/=/.+'), None, 'ext.services.fanza.normal', 'Fanza'),
        (re.compile(r'^https?://tv\.dmm\.com/vod/restrict/.+season=([^&]+)'), lambda u: check_dmm_content_type(re.match(r'.*season=([^&]+)', u).group(1)) == "VOD_VR", 'ext.services.fanza.vr', 'Fanza-VR'),
        (re.compile(r'^https?://tv\.dmm\.com/vod/restrict/.+season=([^&]+)'), lambda u: check_dmm_content_type(re.match(r'.*season=([^&]+)', u).group(1)) == "VOD_2D", 'ext.services.fanza.normal', 'Fanza'),
        (re.compile(r'^https?://(?:www\.)?hiyahtv\.com/.+'), None, 'ext.services.hiyahtv', 'Hi-YAH!'),
        (re.compile(r'^https?://lemino\.docomo\.ne\.jp/.+'), None, 'ext.services.lemino', 'Lemino'),
        (re.compile(r'^https?://tv\.rakuten\.co\.jp/content/\d+/?'), None, 'ext.services.rakutentv_jp', 'RakutenTV-JP'),
    ]

    for pattern, condition, module_name, label in patterns:
        if pattern.match(url):
            if condition is None or condition(url):
                module = import_module(module_name)
                return module, label

    if "plus.nhk.jp" in url:
        from ext.services import nhk_plus
        return nhk_plus, "NHK+"
    elif "jff.jpf.go.jp" in url:
        from ext.services import jff_theater
        return jff_theater, "Jff Theater"
    elif "wod.wowow.co.jp" in url:
        from ext.services import wowow_ondemand
        return wowow_ondemand, "WOWOW-Ondemand"
    elif "dmmvrplayerstreaming" in url or "vr-sample-player" in url or ".wsdcf" in url:
        from ext.services import fanza
        return fanza.Fanza_VR, "Fanza-VR"

    return None, None

class Logger:
    COLOR_GREEN = "\033[92m"
    COLOR_GRAY = "\033[90m"
    COLOR_RESET = "\033[0m"
    COLOR_BLUE = "\033[94m"
    class CustomFormatter(logging.Formatter):
        def format(self, record):
            service_name = getattr(record, "service_name", "")
            levelname = record.levelname
            record.color_service_name = f"{Logger.COLOR_BLUE}{service_name}{Logger.COLOR_RESET}" if service_name else ""
            record.color_levelname = f"{Logger.COLOR_GRAY}{levelname}{Logger.COLOR_RESET}"
            
            if not hasattr(record, "asctime"):
                record.asctime = self.formatTime(record, self.datefmt)
            record.color_asctime = f"{Logger.COLOR_GREEN}{record.asctime}{Logger.COLOR_RESET}"
    
            self._style._fmt = (
                "%(color_asctime)s [%(color_levelname)s] %(color_service_name)s : %(message)s"
            )
            return super().format(record)
    
    class ServiceLoggerAdapter(logging.LoggerAdapter):
        def process(self, msg, kwargs):
            kwargs.setdefault('extra', {})
            kwargs['extra'].setdefault('service_name', self.extra['service_name'])
            return msg, kwargs
    
    def create_logger(service_name: str, LOG_LEVEL: bool):
        base_logger = logging.getLogger('YoimiLogger')
        if LOG_LEVEL:
            base_logger.setLevel(logging.DEBUG)
        else:
            base_logger.setLevel(logging.INFO)
    
        formatter = Logger.CustomFormatter(
            '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
    
        if not base_logger.handlers:
            base_logger.addHandler(console_handler)
        
        logger = Logger.ServiceLoggerAdapter(base_logger, {'service_name': service_name})
        return logger

def download_command(input: str, command_list: Iterator):
    try:
        enable_verbose = command_list["verbose"]
                
        module_service, module_label = get_parser(input)
        service_config = module_service.__service_config__
        service_label = service_config["service_name"]
        service_logger = Logger.create_logger(service_label, LOG_LEVEL=enable_verbose)
        yoimi_logger = Logger.create_logger("Yoimi", LOG_LEVEL=enable_verbose)
        
        email, password = command_list["email"], command_list["password"]
        
        ### load config file
        loaded_config = other_util.load_config()
        
        ### check cdm config
        return_cdms = other_util.cdms_check(loaded_config)
        if return_cdms == None:
            return None
        
        ### check decryptor found
        return_decryptor = other_util.decryptor_check(loaded_config)
        if not return_decryptor["shaka_path"] and not return_decryptor["mp4_path"]:
            binary_folder = loaded_config["directories"]["Binaries"]
            yoimi_logger.error("Decryptor not found. Please check.")

            paths = {
                "Windows": {
                    "Mp4_decryptor": "mp4decrypt.exe",
                    "Shaka_packager": "shaka_packager_win.exe"
                },
                "Linux": {
                    "Mp4_decryptor": "mp4decrypt",
                    "Shaka_packager": "shaka_packager_linux"
                }
            }

            for os_name, tools in paths.items():
                yoimi_logger.error(f"{os_name}:")
                for name, filename in tools.items():
                    yoimi_logger.error(f" + {name}: {os.path.join(binary_folder, filename)}")

            return None
        ### define, init service
        if service_config["use_tls"]:
            session = tls_client.Session(client_identifier="chrome139",random_tls_extension_order=True)
        else:
            session = requests.Session()
        proxy = command_list["proxy"]
        if proxy:
            session.proxies = {'http': proxy, 'https': proxy}
        titlename_manager = titlename_logic(config=loaded_config)
            
        service_downloader = module_service.downloader(session=session, logger=service_logger)
        
        ### check session
        if service_config["cache_session"] and loaded_config["authorization"]["use_cache"]:
            session_manager = session_logic(logger=service_logger, service_name=service_label, service_util=service_downloader)
            
            availiable_cache = session_manager.check_session(service_label)
            
            session_data, session_status = None, False
            
            if availiable_cache:
                yoimi_logger.info("Load cache")
                session_data = session_manager.load_session(availiable_cache)
                if session_data:
                    update_config(service_downloader, session_data["additional_info"])
                    token_status, user_info = service_downloader.check_token(session_data["access_token"])
                    if token_status:
                        session_status = True
                    else:
                        service_logger.info("Session is Expired.")
                        if service_config["enable_refresh"]:
                            refresh_status, user_info = session_manager.refresh_session(session_data["refresh_token"], session_data)
                            session_status = refresh_status
                        else:
                            service_logger.info("Please re-login.")
            
            # if invalid cache or not found, just re-login
            if not session_status and (email != None and password != None):
                if email == "QR_LOGIN":
                    if service_config["support_qr"]:
                        method = "qr"
                    else:
                        service_logger.error("This service doesn't support qr login")
                        return None
                else:
                    if service_config["support_normal"]:
                        method = "normal"
                    else:
                        service_logger.error("This service doesn't support normal login")
                        return None
                login_status, user_info, session_data = session_manager.login_with_credentials(email, password, login_method=method)
                if login_status == False:
                    service_logger.error(user_info)
                    return None
        if service_config["require_account"]:
            if session_status:
                pass
            else:
                if not email or not password:
                    yoimi_logger.error(f"{service_label} is require account login.")
                    return None
                else:
                    if email == "QR_LOGIN":
                        if service_config["support_qr"]:
                            method = "qr"
                        else:
                            service_logger.error("This service doesn't support qr login")
                            return None
                    else:
                        if service_config["support_normal"]:
                            method = "normal"
                        else:
                            service_logger.error("This service doesn't support normal login")
                            return None
                    login_status, user_info, session_data = session_manager.login_with_credentials(email, password, login_method=method)
                    if login_status == False:
                        service_logger.error(user_info)
                        return None
        
        if user_info == None:
            return None
        
        service_downloader.show_userinfo(user_info)
        
        watchtype = service_downloader.judgment_watchtype(input)
        
        def single_dl(input, video_info = None, season_title = None):
            service_logger.info("Fetching 1 Episode")
            
            unixtime = str(int(datetime.now().timestamp()))
            
            if video_info == None:
                video_info = service_downloader.parse_input(input)
            
            if video_info == "unexception_type_content":
                service_logger.error("Please report content url!")
                if input != None:
                    service_logger.error("URL: "+input)
                return None
            
            if video_info == "not_availiable_content":
                service_logger.error("Please check content url can playable")
                if input != None:
                    service_logger.error("URL: "+input)
                return None
            if video_info == "special":
               service_downloader.special_logic(input)
               return
                        
            service_logger.info("Creating Content filename...") 
            if video_info["content_type"] == "special":
                output_titlename = video_info["output_titlename"]
                video_info["content_type"] = "movie"
            elif video_info["content_type"] == "live":
                output_titlename = video_info["output_titlename"]
            else:
                output_titlename = titlename_manager.create_titlename_logger(content_type=video_info["content_type"], episode_count=video_info["episode_count"], title_name=video_info["title_name"], episode_num=video_info["episode_num"], episode_name=video_info["episode_name"])
            service_logger.info(" + "+output_titlename)
            
            deliviery_type, manifest_response, manifest_link, manifest_info, license_header = service_downloader.open_session_get_dl(video_info)
            
            Tracks = parser_util.global_parser()
            dl_type = Tracks.determine_mpd_type(manifest_response)
            transformed_data = Tracks.mpd_parser(manifest_response, debug=enable_verbose)
            
            yoimi_logger.debug("Get Manifest Dl Type")
            yoimi_logger.debug(" + "+dl_type)
            
            yoimi_logger.info("Parsing MPD file")
            
            track_data = Tracks.print_tracks(transformed_data)
            print(track_data)
            
            if command_list["show_resolution"]:
                service_downloader.decrypt_done()
                return
            
            
            if command_list["resolution"] == "best":
                select_track = Tracks.select_best_tracks(transformed_data)
            if command_list["resolution"] == "worst":
                select_track = Tracks.select_worst_tracks(transformed_data)
            if "p" in command_list["resolution"]: # select user track
                select_track = Tracks.select_special_week(command_list["resolution"], transformed_data)
            
            yoimi_logger.info("Selected Track:")
            yoimi_logger.info(f" + Video: [{select_track["video"]["codec"]}] [{select_track["video"]["resolution"]}] | {select_track["video"]["bitrate"]} kbps")
            yoimi_logger.info(f" + Audio: [{select_track["audio"]["codec"]}] | {select_track["audio"]["bitrate"]} kbps")
            
            if service_config["is_drm"]:
                yoimi_logger.info("Get Video, Audio PSSH")
                if transformed_data["pssh_list"].get("widevine"):
                    yoimi_logger.info(" + Widevine: "+ transformed_data["pssh_list"]["widevine"][:35]+"...")
                if transformed_data["pssh_list"].get("playready"):
                    yoimi_logger.info(" + Playready: "+ transformed_data["pssh_list"]["playready"][:35]+"...")
                
                yoimi_logger.info("Decrypting License")
                license_return = license_logic.decrypt_license(transformed_data, manifest_info, license_header, session, loaded_config, yoimi_logger, debug=enable_verbose)
                if license_return["type"] == "widevine":
                    yoimi_logger.info(f"Decrypt License (Widevine):")
                    for license_key in license_return["key"]:
                        if license_key["type"] == "CONTENT":
                            yoimi_logger.info(" + "+license_key['kid_hex']+":"+license_key['key_hex']) 
                elif license_return["type"] == "playready":
                    yoimi_logger.info(f"Decrypt License (PlayReady):")
                    for license_key in license_return["key"]:
                        yoimi_logger.info(" + "+license_key) 
            
            service_downloader.decrypt_done()
            
            yoimi_logger.info("Setting output filename")
            
            output_filename, output_path = titlename_manager.create_output_filename(video_info, command_list, season_title, output_titlename)
            
            yoimi_logger.info(" + " + str(output_path))
            
            if dl_type == "segment":                
                yoimi_logger.info("Calculate about Manifest")
                duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                
                yoimi_logger.debug(" + Episode Duration: "+str(int(duration)))
                
                have_timeline, timeline_dict = Tracks.is_have_timeline(manifest_response)
                
                yoimi_logger.info("Video, Audio Segment Count")
                video_segment_list = Tracks.calculate_segments(duration, int(select_track["video"]["seg_duration"]), int(select_track["video"]["seg_timescale"]))
                yoimi_logger.info(" + Video Segments: "+str(int(video_segment_list)))                 
                audio_segment_list = Tracks.calculate_segments(duration, int(select_track["audio"]["seg_duration"]), int(select_track["audio"]["seg_timescale"]))
                yoimi_logger.info(" + Audio Segments: "+str(int(audio_segment_list)))
                                
                audio_segment_links, video_segment_links = service_downloader.create_segment_links(select_track, manifest_link, video_segment_list, audio_segment_list, timeline_dict)
                
                yoimi_logger.info("Downloading Segments...")
                downloader = segment_downloader(yoimi_logger)
                success, video_output = downloader.download(video_segment_links, "download_encrypt_video.mp4", loaded_config, unixtime, "Yoimi")
                success, audio_output = downloader.download(audio_segment_links, "download_encrypt_audio.mp4", loaded_config, unixtime, "Yoimi")
                
                if service_config["is_drm"]:
                    yoimi_logger.info("Decrypting Segments...")
                    decryptor = main_decrypt(yoimi_logger)
                    video_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_video.mp4")
                    audio_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4")
                                    
                    decryptor.decrypt(license_keys=license_return, input_path=[video_output, audio_output], output_path=[video_decrypt_output, audio_decrypt_output], config=loaded_config, service_name="Yoimi")
            
            elif dl_type == "single":
                yoimi_logger.info("Calculate about Manifest")
                duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
                
                yoimi_logger.info("Downloading Files...")
                
                video_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_encrypt_video.mp4")
                audio_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4")
                
                downloader = aria2c_downloader()
                
                status, result = downloader.download(select_track["video"]["url"], "download_encrypt_video.mp4", loaded_config, unixtime, "Yoimi")
                status, result = downloader.download(select_track["audio"]["url"], "download_encrypt_audio.mp4", loaded_config, unixtime, "Yoimi")
                
                if service_config["is_drm"]:
                    yoimi_logger.info("Decrypting Files...")
                    decryptor = main_decrypt(yoimi_logger)
                    video_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_video.mp4")
                    audio_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4")
                                    
                    decryptor.decrypt(license_keys=license_return, input_path=[video_output, audio_output], output_path=[video_decrypt_output, audio_decrypt_output], config=loaded_config, service_name="Yoimi")
            elif dl_type == "live":
                # WTF THIS OPTION SO SICKKKKKKK
                # FUCKING SHIT BRUH MOMENT BRUUUUUUHHHHHH
                yoimi_logger.info("Checking manifest...")
                seg_info = {}
                base_url = manifest_link.replace("manifest.mpd", "")
                
                seg_info["video"] = transformed_data["video_track"][0]
                seg_info["audio"] = transformed_data["audio_track"][0]
                seg_info["video"]["url_base"] = base_url
                seg_info["audio"]["url_base"] = base_url
            
                video_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_encrypt_video.mp4")
                audio_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_encrypt_audio.mp4")
                
                downloader = live_downloader(yoimi_logger)
                
                status = downloader.download(manifest_link, seg_info, loaded_config, unixtime, "Yoimi")
                
                ## Get Video Duration
                video = cv2.VideoCapture(video_output)
                fps = video.get(cv2.CAP_PROP_FPS)
                frame_count = video.get(cv2.CAP_PROP_FRAME_COUNT)
                duration = duration = frame_count / fps
                            
                if service_config["is_drm"]:
                    yoimi_logger.info("Decrypting Files...")
                    decryptor = main_decrypt(yoimi_logger)
                    video_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_video.mp4")
                    audio_decrypt_output = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime, "download_decrypt_audio.mp4")
                                    
                    decryptor.decrypt(license_keys=license_return, input_path=[video_output, audio_output], output_path=[video_decrypt_output, audio_decrypt_output], config=loaded_config, service_name="Yoimi")
 
            
            yoimi_logger.info("Muxing Content")
            muxer = main_mux(yoimi_logger)
            muxer.mux_content(video_input=video_decrypt_output, audio_input=audio_decrypt_output, output_path=output_path, duration=int(duration), service_name="Yoimi")
                
            if command_list["keep"] or enable_verbose:
                yoimi_logger.warn("Enable Keep temp flag")
            else:
                dir_path = os.path.join(loaded_config["directories"]["Temp"], "content", unixtime)
                try:
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        shutil.rmtree(dir_path)
                    else:
                        yoimi_logger.error(f"Folder is not found: {dir_path}")
                except Exception as e:
                    yoimi_logger.error(f"Delete folder error: {e}")
            
            if output_filename != None:
                yoimi_logger.info('Finished download: {}'.format(output_filename))
            else:
                yoimi_logger.info('Finished download: {}'.format(output_titlename))
                
        
        if watchtype == "single":
            single_dl(input)
        elif watchtype == "season":
            service_logger.info("Fetching Sesaon")
            
            season_title, season_output, video_info = service_downloader.parse_input_season(input)
            
            for single in video_info["episode_list"]["metas"]:
                single_video_info = service_downloader.parse_input(url_input=None, id=str(single["id_in_schema"]))
                single_dl(None, video_info=single_video_info, season_title=season_title)
                
            yoimi_logger.info("Finished download season: {}".format(season_output))
    except:
        print("Traceback has occurred")
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception(show_locals=enable_verbose)
        print("Service: "+service_label)
        print("Version: "+command_list["version"])
        print("----END ERROR LOG----")