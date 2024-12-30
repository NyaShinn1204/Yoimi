import re
import os
import yaml
import time
import logging
import hashlib
from enum import Enum
from langcodes import Language
from collections import defaultdict
from click.core import ParameterSource

from ext.utils import amazon

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
    
def main_command(session, url, email, password, LOG_LEVEL, quality, vrange):
    try:
        #global media_code, playtoken
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        match = re.search(r"/detail/([^/]+)/", url)
        if match:
            title = match.group(1)
            #print(title)
            if len(title) > 10:
                pv = True
            else:
                pv = False
        
        amazon_downloader = amazon.Amazon_downloader(session, pv)
        
        profile = "default"
        vcodec = "H265" # default
        amanifest = vcodec
        aquality = "SD"
        bitrate = "CBR" # default
        single = False # Force single episode/season instead of getting series ASIN,
        atmos = False
        vrange = vrange
        vquality = None
        device_id = None
        device_token = None
                
        vquality_source = ParameterSource.DEFAULT
        bitrate_source = ParameterSource.DEFAULT
        
        if vquality_source != ParameterSource.COMMANDLINE:
            if 0 < quality <= 576 and vrange == "SDR":
                logger.info(f" + Setting manifest quality to SD", extra={"service_name": "Amazon"})
                vquality = "SD"

            if quality > 1080:
                logger.info(f" + Setting manifest quality to UHD to be able to get 2160p video track", extra={"service_name": "Amazon"})
                vquality = "UHD"

        vquality = vquality or "HD"

        if bitrate_source != ParameterSource.COMMANDLINE:
            if vcodec == "H265" and vrange == "SDR" and bitrate != "CVBR+CBR":
                bitrate = "CVBR+CBR"
                logger.info(" + Changed bitrate mode to CVBR+CBR to be able to get H.265 SDR video track", extra={"service_name": "Amazon"})

            if vquality == "UHD" and vrange != "SDR" and bitrate != "CBR":
                bitrate = "CBR"
                logger.info(f" + Changed bitrate mode to CBR to be able to get highest quality UHD {vrange} video track", extra={"service_name": "Amazon"})

        orig_bitrate = bitrate
        
        amazon_downloader.update_variable("vcodec", vcodec)
        amazon_downloader.update_variable("orig_bitrate", orig_bitrate)
        amazon_downloader.update_variable("vquality", vquality)
        amazon_downloader.update_variable("vrange", vrange)
        
        cookies = amazon_downloader.parse_cookie(profile)
        if not cookies:
            logger.error(f"Profile {profile} has no cookies", extra={"service_name": "Amazon"})
            logger.error(f"Please Cookies to /cookies/amazon/default.txt (Netescape format)", extra={"service_name": "Amazon"})
            raise
        else:
            logger.debug(f"Get cookies: {len(cookies)}", extra={"service_name": "Amazon"})
            
        logger.info("Getting Account Region", extra={"service_name": "Amazon"})
        get_region, error_msg, cookies = amazon_downloader.get_region()
        if not get_region:
            logger.error("Failed to get Amazon Account Region", extra={"service_name": "Amazon"})
            logger.error(error_msg, extra={"service_name": "Amazon"})
            raise
        
        logger.info(f" + Region: {get_region['code']}", extra={"service_name": "Amazon"})
        
        logger.info("Update Session", extra={"service_name": "Amazon"})
        session.headers.update({"User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0'})
        session.cookies.update(cookies or {})
                
        # Update Region, Endpoints
        endpoints = amazon_downloader.prepare_endpoints(get_region)
                
        session.headers.update({
            "Origin": f"https://{get_region['base']}"
        })
        
        device = amazon_downloader.get_device(profile, endpoints)
        #if not device:
        #    logger.debug("Device not set. using other option...", extra={"service_name": "Amazon"})
        logger.debug(f"Device: {device}", extra={"service_name": "Amazon"})

        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        device_cdm = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device_cdm)
        #print(cdm.device_type)
        
        class Types(Enum):
            CHROME = 1
            ANDROID = 2
            PLAYREADY = 3
        
        device_types = {
            "default": {
                "browser": "AOAGZA014O5RE"
            }
        }
            
        logger.debug(f"DLOG: {device}", extra={"service_name": "Amazon"})
        logger.debug(f"DLOG: {vquality}", extra={"service_name": "Amazon"})
        logger.debug(f"DLOG: {cdm.device_type}", extra={"service_name": "Amazon"})
        
        if (quality > 1080 or vrange != "SDR") and vcodec == "H265" and cdm.device_type == Types.CHROME:
            logger.info(f"Using device to Get UHD manifests", extra={"service_name": "Amazon"})
            device_id, device_token = amazon_downloader.register_device(session, profile, logger)
        elif not device or vquality != "UHD" or cdm.device_type == Types.CHROME:
            # falling back to browser-based device ID
            if not device:
                logger.warning(f"No Device information was provided for {profile}, using browser device...", extra={"service_name": "Amazon"})
            device_id = hashlib.sha224(
                ("CustomerID" + session.headers["User-Agent"]).encode("utf-8")
            ).hexdigest()
            amazon_downloader.update_variable("device_id", device_id)
            device = {"device_type": device_types[profile]["browser"]}
        else:
            logger.debug("Device not set. using other option...", extra={"service_name": "Amazon"})
            device_id, device_token = amazon_downloader.register_device(session, profile, logger)
            
        #print(device_id, device_token)
        logger.debug("Logined", extra={"service_name": "Amazon"})
        logger.debug(f"Device_id: {device_id}", extra={"service_name": "Amazon"})
        logger.debug(f"Device_token: {device_token}", extra={"service_name": "Amazon"})
        #logger.error("Failed to get Title Metadata, Episode Type Data | Reason: Authorization is invalid", extra={"service_name": "Amazon"})
    
        meta_response = amazon_downloader.get_titles(session, title, single, vcodec, bitrate, vquality)
        #title_name = meta_response["titleName"]
        logger.info("Get Title for Season", extra={"service_name": "Amazon"})
        logger.debug(f"Titles_json: {meta_response}", extra={"service_name": "Amazon"})
        logger.debug(f"Episode_count: {len(meta_response)}", extra={"service_name": "Amazon"})
        
        logger.info("Title: {}".format(meta_response[0]["name"]), extra={"service_name": "Amazon"})
        logger.info("Total Episode: {}".format(str(len(meta_response))), extra={"service_name": "Amazon"})
        logger.info("By Season: {season} ({len_episode})".format(season=str(meta_response[0]["season"]),len_episode=str(len(meta_response))), extra={"service_name": "Amazon"})
        
        for title in meta_response:
            if title["type"] == "TV":
                #logger.info(" + {tv_title}_S{season:02}{episode_name}".format(tv_title=title["name"],season=title["season"] or 0, episode=title["episode"] or 0, episode_name=f" - {title["episode_name"]}" if title["episode_name"] else ""), extra={"service_name": "Amazon"})
                logger.info(" + Allow Download: {allow_download:<3} | {title} S{season:02}E{episode:02}{name} [{id}]".format(
                    allow_download="Yes" if not title["deny_download"] else "No",
                    title=title["name"],
                    season=title["season"] or 0,
                    episode=title["episode"] or 0,
                    name=f" - {title['episode_name']}" if title["episode_name"] else "",
                    id=title["id"],
                ), extra={"service_name": "Amazon"})
                #print(title["deny_download"])
            else:
                # ここにmovie typeのloggerを書く
                logger.info("coming soon", extra={"service_name": "Amazon"})
        logger.info("Checking Free or playable Type Video", extra={"service_name": "Amazon"})
        for title in meta_response:
            try:
                #print(title["free"])
                # ここにtracksとchapterを取得するコードを書く
                if title["deny_download"]:
                    logger.info("This episode can't download | {title} S{season:02}E{episode:02}{name} [{id}]".format(
                        title=title["name"],
                        season=title["season"] or 0,
                        episode=title["episode"] or 0,
                        name=f" - {title['episode_name']}" if title["episode_name"] else "",
                        id=title["id"],
                    ), extra={"service_name": "Amazon"})
                    continue
                if title["free"]:
                    logger.info("This episode is Free! | {title} S{season:02}E{episode:02}{name} [{id}]".format(
                        title=title["name"],
                        season=title["season"] or 0,
                        episode=title["episode"] or 0,
                        name=f" - {title['episode_name']}" if title["episode_name"] else "",
                        id=title["id"],
                    ), extra={"service_name": "Amazon"})
               # print("device: ", device)
                logger.debug("+ Use Device: "+str(device), extra={"service_name": "Amazon"})
                title_tracks, chosen_manifest, manifest = amazon_downloader.get_tracks(title, device)
                #print(title_tracks)
                #print(amazon_downloader.get_print_track(title_tracks))
                need_separate_audio = (
                    (aquality or vquality) != vquality or
                    amanifest == "CVBR" and (vcodec, bitrate) != ("H264", "CVBR") or
                    amanifest == "CBR" and (vcodec, bitrate) != ("H264", "CBR") or
                    amanifest == "H265" and vcodec != "H265" or
                    amanifest != "H265" and vcodec == "H265"
                )
                #print("nsa: "+str(need_separate_audio))
                logger.info("+ Nsa: "+str(need_separate_audio), extra={"service_name": "Amazon"})
                if not need_separate_audio:
                    language_audio_map = defaultdict(list)
                    
                    # 言語ごとにオーディオトラックを分類
                    for audio_track in title_tracks["audio_tracks"]:
                        language = audio_track.get("language")  # 辞書から "language" を取得
                        if language:  # "language" が存在する場合のみ処理
                            language_audio_map[language].append(audio_track)
                    
                    # 言語ごとにビットレートをチェック
                    for language, audio_tracks in language_audio_map.items():
                        if all((track.get("bitrate", 0) or 0) < 640000 for track in audio_tracks):
                            need_separate_audio = True
                            break
                        
                if need_separate_audio and not atmos:
                    manifest_type = amanifest or "H265"
                    logger.info(f"Getting audio from {manifest_type} manifest for potential higher bitrate or better codec", extra={"service_name": "Amazon"})
                    audio_manifest = amazon_downloader.get_manifest(
                        title=title,
                        video_codec="H265" if manifest_type == "H265" else "H264",
                        bitrate_mode="CVBR" if manifest_type != "CBR" else "CBR",
                        quality=aquality or vquality,
                        hdr=None,
                        ignore_errors=True
                    )
                    if not audio_manifest:
                        logger.warning(f" - Unable to get {manifest_type} audio manifests, skipping", extra={"service_name": "Amazon"})
                    elif not (chosen_audio_manifest := amazon_downloader.choose_manifest(audio_manifest, cdn=None)):
                        logger.warning(f" - No {manifest_type} audio manifests available, skipping", extra={"service_name": "Amazon"})
                    else:
                        audio_mpd_url = amazon_downloader.clean_mpd_url(chosen_audio_manifest["avUrlInfoList"][0]["url"], optimise=False)
                        logger.debug(audio_mpd_url, extra={"service_name": "Amazon"})
                        logger.info(" + Downloading HEVC manifest", extra={"service_name": "Amazon"})
        
                        try:
                            title_tracks_temp = amazon_downloader.Mpd_parse.get_mpd_content(
                                url=audio_mpd_url,
                                session=session,
                                source="AMZN"
                            )
                            title_tracks["audio_track"] = title_tracks_temp["audio_track"]
                            #print("\n\n\n\n")
                            #print(title_tracks_temp)
                            #print("\n\n\n\n")
                        except KeyError:
                            logger.warning(f" - Title has no {amanifest} stream, cannot get higher quality audio", extra={"service_name": "Amazon"})
                        else:
                            #print("get new version mpd content", title_tracks)
                            logger.info("Use get new version mpd content to parse", extra={"service_name": "Amazon"})
                need_uhd_audio = atmos
                if not amanifest and ((aquality == "UHD" and vquality != "UHD") or not aquality):
                    language_audio_map = defaultdict(list)
                    
                    # 言語ごとにオーディオトラックを分類
                    for audio_track in title_tracks["audio_track"]:
                        language = audio_track.get("language")  # 辞書から "language" を取得
                        if language:  # "language" が存在する場合のみ処理
                            language_audio_map[language].append(audio_track)
                    
                    # 言語ごとにビットレートをチェック
                    for language, audio_tracks in language_audio_map.items():
                        if all((track.get("bitrate", 0) or 0) < 640000 for track in audio_tracks):
                            need_separate_audio = True
                            break
        
                if need_uhd_audio:
                    logger.info("Getting audio from UHD manifest for potential higher bitrate or better codec",extra={"service_name": "Amazon"})
                    temp_device_json = {
                      "device": {
                        "default": {
                          "domain": "Device",
                          "app_name": "AIV",
                          "app_version": "3.12.0",
                          "device_model": "SHIELD Android TV",
                          "os_version": "28",
                          "device_type": "A1KAXIG6VXSG8Y",
                          "device_serial": "13f5b56b4a17de5d136f0e4c28236109",
                          "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Shield TV",
                          "software_version": "248"
                        }
                      }
                    }

                    temp_device = temp_device_json["device"]["default"]
                    temp_device_token = temp_device_json["device"]["default"]["device_token"]
                    temp_device_id = temp_device_json["device"]["default"]["device_id"]
                    uhd_audio_manifest = None
        
                    try:
                        if cdm.device_type == Types.CHROME and quality < 2160:
                            logger.info(f" + Switching to device to get UHD manifest", extra={"service_name": "Amazon"})
                            amazon_downloader.register_device(session, profile, logger)
        
                        uhd_audio_manifest = amazon_downloader.get_manifest(
                            title=title,
                            video_codec="H265",
                            bitrate_mode="CVBR+CBR",
                            quality="UHD",
                            hdr="DV",  # Needed for 576kbps Atmos sometimes
                            ignore_errors=True
                        )
                    except:
                        pass
                    
                    device = temp_device
                    device_token = temp_device_token
                    device_id = temp_device_id
        
                    if not uhd_audio_manifest:
                        logger.warning(f" - Unable to get UHD manifests, skipping", extra={"service_name": "Amazon"})
                    elif not (chosen_uhd_audio_manifest := amazon_downloader.choose_manifest(uhd_audio_manifest, cdn=None)):
                        logger.warning(f" - No UHD manifests available, skipping", extra={"service_name": "Amazon"})
                    else:
                        uhd_audio_mpd_url = amazon_downloader.clean_mpd_url(chosen_uhd_audio_manifest["avUrlInfoList"][0]["url"], optimise=False)
                        logger.debug(uhd_audio_mpd_url, extra={"service_name": "Amazon"})
                        logger.info(" + Downloading UHD manifest", extra={"service_name": "Amazon"})
        
                        try:
                            uhd_audio_mpd = amazon_downloader.Mpd_parse.get_mpd_content(
                                url=uhd_audio_mpd_url,
                                session=session,
                                source="AMZN"
                            )
                        except KeyError:
                            logger.warning(f" - Title has no UHD stream, cannot get higher quality audio", extra={"service_name": "Amazon"})
                        else:
                            # replace the audio tracks with DV manifest version if atmos is present
                            if any(x for x in uhd_audio_mpd["audio_track"] if x["atmos"]):
                                title_tracks["audio_track"] = uhd_audio_mpd["title_tracks"]
        
                for video in title_tracks["video_track"]:
                    video["hdr10"] = chosen_manifest["hdrFormat"] == "Hdr10"
                    video["dv"] = chosen_manifest["hdrFormat"] == "DolbyVision"
        
                for audio in title_tracks["audio_track"]:
                    audio["descriptive"] = audio["extra"][1].get("audioTrackSubtype") == "descriptive"
                    # Amazon @lang is just the lang code, no dialect, @audioTrackId has it.
                    audio_track_id = audio["extra"][1].get("audioTrackId")
                    if audio_track_id:
                        audio["language"] = Language.get(audio_track_id.split("_")[0])  # e.g. es-419_ec3_blabla
        
                for sub in manifest.get("subtitleUrls", []) + manifest.get("forcedNarratives", []):
                    temp_json = {
                        "content_type": "text",
                        "id_": sub.get(
                            "timedTextTrackId",
                            f"{sub['languageCode']}_{sub['type']}_{sub['subtype']}_{sub['index']}"
                        ),
                        "source": "AMAZN",
                        "url": os.path.splitext(sub["url"])[0] + ".srt",  # DFXP -> SRT forcefully seems to work fine
                        # metadata
                        "codec": "srt",  # sub["format"].lower(),
                        "language": sub["languageCode"],
                        "forced": "forced" in sub["displayName"],
                        "sdh": sub["type"].lower() == "sdh",  # TODO: what other sub types? cc? forced?
                    }
                    title_tracks["text_track"].append(temp_json)
        
                final_title_tracks = title_tracks
                #print(final_title_tracks)
                logger.info("Get Episode Tracks:", extra={"service_name": "Amazon"})
                print_track = amazon_downloader.get_print_track(final_title_tracks)
                print(print_track)
                #amazon_downloader.get_chapters(title)
            except Exception as error:
                print(error)
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))