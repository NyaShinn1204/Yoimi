# ok analyze is done
# これだけ無駄にコード綺麗に書いてやろうかな
import os
import re
import yaml
import time
import shutil
import base64
import logging
from rich.console import Console
from urllib.parse import urlparse, parse_qs

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
        
        if url.__contains__("program/") and not url.__contains__("season_id="):
            total_season, all_season_json = wod_downloader.get_all_season_id(url)
            
            logger.info(f"Fetching {total_season} season Meta...", extra={"service_name": __service_name__})
            
            for single_season in all_season_json:
                logger.info(f"Get Title for {single_season["name"]}", extra={"service_name": __service_name__})
                episode_list = wod_downloader.get_season_episode_title(single_season["meta_id"])
                for single in episode_list:
                    #print(single)
                    logger.info(f"+ {single_season["name"]}_{single["shortest_name"]}_{single["short_name"]} [ID:{single["ep_id"]}, RID:{single["refId"]}]", extra={"service_name": __service_name__})
        elif url.__contains__("season_id="):
            url_select_id = parse_qs(urlparse(url).query).get("season_id", [None])[0]
            
            
            total_season, all_season_json = wod_downloader.get_all_season_id(url)
            
            # logger.info(f"Fetching {total_season} season Meta...", extra={"service_name": __service_name__})
            
            for single_season in all_season_json:
                # print(single_season["id"], url_select_id)
                if single_season["id"] != int(url_select_id):
                    continue
                logger.info(f"Get Title for {single_season["name"]}", extra={"service_name": __service_name__})
                episode_list = wod_downloader.get_season_episode_title(single_season["meta_id"])
                #media_id = single_season["oap"]["media_id"]
                #print(media_id)
                for single in episode_list:
                    #print(single)
                    logger.info(f"+ {single_season["name"]}_{single["shortest_name"]}_{single["short_name"]} [ID:{single["ep_id"]}, RID:{single["refId"]}]", extra={"service_name": __service_name__})
                for single in episode_list:
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
                    # print(duration, sources)
                    wod_downloader.send_stop_signal(video_access_token, session_id)
                    logger.info("Close Video Session", extra={"service_name": __service_name__})
                    
                    logger.info("Got HD Link", extra={"service_name": __service_name__})
                    urls = []
                    for source in sources:
                        if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                            urls.append(source["src"])
                    hd_link = urls[0].replace("jp/v4", "jp/v6")
                    logger.info(f" + HD_link: {hd_link}", extra={"service_name": __service_name__})
        # https://wod.wowow.co.jp/program/203639
        
        # status, video_session = wod_downloader.create_video_session()
        # if status != True:
            # pass        
        # status, playback_session_id, access_token = wod_downloader.create_playback_session(meta_id, media_id)
        # if status != True:
            # pass
        # duration, sources = wod_downloader.get_episode_prod_info(media_uuid, access_token, playback_session_id)
        # 
        # logger.info("Get 1080p NOD Link", extra={"service_name": __service_name__})
        # urls = []
        # for source in sources:
            # if source["resolution"] == "1920x1080" and "manifest.mpd" in source["src"]:
                # urls.append(source["src"])
        # hd_link = urls[0].replace("jp/v4", "jp/v6")
        # logger.info(f" + HD Link: {hd_link}", extra={"service_name": __service_name__})
        # wod_downloader.send_stop_signal(access_token, playback_session_id)
        #logger.info("Get or Gen Video Access Token...", extra={"service_name": __service_name__})
        #if email and password != "":
        #   status, video_access_token = nhkplus_downloader.create_video_session(email, password)
        #else:
        #   video_access_token = nhkplus_downloader.gen_access_token()
        #
        #logger.debug("Get VAT_TEMP: "+video_access_token, extra={"service_name": __service_name__})
        #
        #logger.info("Got Video Access Token For Temp", extra={"service_name": __service_name__})
        #logger.info("+ Video Access Token (Temp): "+video_access_token[:10]+"*****", extra={"service_name": __service_name__})
        #
        #logger.debug("Open Get access key", extra={"service_name": __service_name__})
        #
        #drm_token = nhkplus_downloader.get_drm_token(video_access_token)
        #logger.info("Got Drm Token", extra={"service_name": __service_name__})
        #logger.info("+ Drm Token: "+drm_token[:10]+"*****", extra={"service_name": __service_name__})
        # 
        # Tracks = nhk_plus.NHKplus_tracks()
        # 
        # if url.__contains__("playlist_id"):
            # st_id, playlist_id = nhk_plus.NHKplus_utils.extract_nhk_ids(url)
            # 
            # status, metadata = nhkplus_downloader.get_playlist_info(st_id, playlist_id)
            # if status == False:
                # logger.info("Failed to Get Video Info. Reason: Playlist id not found", extra={"service_name": __service_name__})
                # return
            # 
            # logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            # title_name_logger = metadata["stream_type"]["program"]["pl"]["title"]
            # logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            # 
            # if login_status:
                # video_info = session.get(metadata["stream_type"]["program"]["hsk"]["video_descriptor"]).json()
            # else:
                # temp_vi_url = metadata["stream_type"]["program"]["hsk"]["video_descriptor"]
                # vi_url = re.sub(r"(https://.+/)([^/]+)(/videoinfo-.+\.json)", r"\1\2_1min\3", temp_vi_url)
                # video_info = session.get(vi_url).json()
            # 
            #Get Duration from json
            # duration_temp = metadata["stream_type"]["program"]["hsk"]["passed_length"]
            # h, m, s = map(int, duration_temp.split(':'))
            # duration_second = h * 3600 + m * 60 + s
            ## 
            #print("[+] Get Video Info:")
            #print(" + allow_multispeed: "+str(video_info["allow_multispeed"]))
            #print(" + need_L1_hd: "+str(video_info["need_L1_hd"]))
            #print(" + total manifests: "+str(len(video_info["manifests"])))
            #print("[+] Convert Video Info...")
            ## transformed_data = Tracks.transform_metadata(video_info["manifests"])
            #print("[+] Convert Video Info")
            #print(json.dumps(transformed_data, indent=4))
            #print("[+] Select Highest birate manifest")
            ## highest_bitrate_manifest = Tracks.get_highest_bitrate_manifest(video_info["manifests"])
            #print(json.dumps(highest_bitrate_manifest, indent=4))
            #print("[+] Get m3u8")
            # 
            # logger.info(f"Get best birtate m3u8", extra={"service_name": __service_name__})
            # 
            # m3u8_data = session.get(highest_bitrate_manifest["url"]).text
            # tracks = Tracks.parse_m3u8(m3u8_data)
            # logger.info(f"Get Video, Audio, Sub Tracks:", extra={"service_name": __service_name__})
            # track_data = Tracks.print_tracks(tracks)
            # 
            # print(track_data)
            # 
            # get_best_track = Tracks.select_tracks(tracks)
            # 
            # logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
            # 
            # temp_video_meta = session.get(get_best_track["video"]["url"]).text
            # temp_audio_meta = session.get(get_best_track["audio"]["url"]).text
            # 
            # video_url = re.search(r'#EXT-X-MAP:URI="([^"]+)"', temp_video_meta).group(1)
            # 
            # if login_status == False:
                # video_url = get_best_track["video"]["url"].replace("playlist.m3u8", "")+video_url 
            # 
            # moov_box = Tracks.find_moov_box(session.get(video_url).content)
            # 
            # pssh_box = ""
            # count = 0
            # if moov_box:
                # sub_boxes = Tracks.parse_box(moov_box)
                # for box in sub_boxes:
                    # if box["type"] == "pssh":
                        # if count == 0:
                            # pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            # pssh_box = pssh_temp.replace("==", "")
            #                pssh_box = pssh_temp // なぜかこれでもdecryptできる。謎
                        # else:
                            # pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            # pssh_box = pssh_box + pssh_temp.replace("==", "====")
                        # count += 1
            # 
            # 
            # if pssh_box == "":
            #    print("[-] おい！psshどこやねん！殺すぞ！！！")
                # logger.error(f"!Can not found pssh!", extra={"service_name": __service_name__})
                # return
            # else:
                # logger.info(f" + Video, Audio PSSH: {pssh_box}", extra={"service_name": __service_name__})
                # 
                # logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                # 
                # keys = nhk_plus.NHKplus_license.license_vd_ad(pssh_box, session, drm_token)
                # 
                # logger.info(f"Decrypt Video, Audio License", extra={"service_name": __service_name__})
                # 
                # pssh_list = ""
                # pssh_dics = []
                # for key in keys["key"]:
                    # if key["type"] == "CONTENT":
                        # pssh_list = pssh_list + " --key {}:{}".format(key["kid_hex"], key["key_hex"])
                        # pssh_dics.append(["{}:{}".format(key["kid_hex"], key["key_hex"])])
                        # logger.info(f" + {key["kid_hex"]}:{key["key_hex"]}", extra={"service_name": __service_name__})
                # 
                # logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                # 
                # random_string = str(int(time.time() * 1000))
                # title_name_logger_video = random_string+"_video_encrypted.mp4"
                # title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                # 
                # video_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_video_meta, login_status, get_best_track["video"]["url"].replace("playlist.m3u8", ""), title_name_logger_video, config, unixtime)
                # audio_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_audio_meta, login_status, get_best_track["audio"]["url"].replace("playlist.m3u8", ""), title_name_logger_audio, config, unixtime)
                # 
                # logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                # 
                # nhk_plus.NHKplus_decrypt.decrypt_all_content(pssh_dics, video_downloaded, video_downloaded.replace("_encrypted", ""), audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                # 
                # logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                # 
                # result = nhkplus_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4"), config, unixtime, int(duration_second), title_name_logger, None, additional_info)
                # 
                # dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                # 
                # if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    # for filename in os.listdir(dir_path):
                        # file_path = os.path.join(dir_path, filename)
                        # try:
                            # if os.path.isfile(file_path):
                                # os.remove(file_path)
                            # elif os.path.isdir(file_path):
                                # shutil.rmtree(file_path)
                        # except Exception as e:
                            # print(f"削除エラー: {e}")
                # else:
                    # print(f"指定されたディレクトリは存在しません: {dir_path}")
                # 
                # logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
        # else:
            # st_id = nhk_plus.NHKplus_utils.extract_nhk_id(url)
            # 
            # status, metadata = nhkplus_downloader.get_playlist_info(st_id, None)
            # if status == False:
                # logger.info("Failed to Get Video Info. Reason: Playlist id not found", extra={"service_name": __service_name__})
                # return
            # 
            # logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            # title_name_logger = metadata["stream_type"]["program"]["title"]
            # logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            # 
            # logger.info("Get Title for 1 Episode", extra={"service_name": __service_name__})
            # title_name_logger = metadata["stream_type"]["program"]["title"]
            # logger.info(f" + {title_name_logger}", extra={"service_name": __service_name__})
            # 
            # if login_status:
                # video_info = session.get(metadata["stream_type"]["program"]["hsk"]["video_descriptor"]).json()
            # else:
                # temp_vi_url = metadata["stream_type"]["program"]["hsk"]["video_descriptor"]
                # vi_url = re.sub(r"(https://.+/)([^/]+)(/videoinfo-.+\.json)", r"\1\2_1min\3", temp_vi_url)
                # video_info = session.get(vi_url).json()
            # 
            #Get Duration from json
            ## duration_temp = metadata["stream_type"]["program"]["hsk"]["passed_length"]
            ## h, m, s = map(int, duration_temp.split(':'))
            ## duration_second = h * 3600 + m * 60 + s
            ## 
            #print("[+] Get Video Info:")
            #print(" + allow_multispeed: "+str(video_info["allow_multispeed"]))
            #print(" + need_L1_hd: "+str(video_info["need_L1_hd"]))
            #print(" + total manifests: "+str(len(video_info["manifests"])))
            #print("[+] Convert Video Info...")
            ## transformed_data = Tracks.transform_metadata(video_info["manifests"])
            #print("[+] Convert Video Info")
            #print(json.dumps(transformed_data, indent=4))
            #print("[+] Select Highest birate manifest")
            ## highest_bitrate_manifest = Tracks.get_highest_bitrate_manifest(video_info["manifests"])
            #print(json.dumps(highest_bitrate_manifest, indent=4))
            #print("[+] Get m3u8")
            # 
            # logger.info(f"Get best birtate m3u8", extra={"service_name": __service_name__})
            # 
            # m3u8_data = session.get(highest_bitrate_manifest["url"]).text
            # tracks = Tracks.parse_m3u8(m3u8_data)
            # logger.info(f"Get Video, Audio, Sub Tracks:", extra={"service_name": __service_name__})
            # track_data = Tracks.print_tracks(tracks)
            # 
            # print(track_data)
            # 
            # get_best_track = Tracks.select_tracks(tracks)
            # 
            # logger.info(f"Get License for 1 Episode", extra={"service_name": __service_name__})
            # 
            # temp_video_meta = session.get(get_best_track["video"]["url"]).text
            # temp_audio_meta = session.get(get_best_track["audio"]["url"]).text
            # 
            # video_url = re.search(r'#EXT-X-MAP:URI="([^"]+)"', temp_video_meta).group(1)
            # 
            # if login_status == False:
                # video_url = get_best_track["video"]["url"].replace("playlist.m3u8", "")+video_url 
            # 
            # moov_box = Tracks.find_moov_box(session.get(video_url).content)
            # 
            # pssh_box = ""
            # count = 0
            # if moov_box:
                # sub_boxes = Tracks.parse_box(moov_box)
                # for box in sub_boxes:
                    # if box["type"] == "pssh":
                        # if count == 0:
                            # pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            # pssh_box = pssh_temp.replace("==", "")
            #               pssh_box = pssh_temp // なぜかこれでもdecryptできる。謎
                        # else:
                            # pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            # pssh_box = pssh_box + pssh_temp.replace("==", "====")
                        # count += 1
            # 
            # 
            # if pssh_box == "":
            #    print("[-] おい！psshどこやねん！殺すぞ！！！")
                # logger.error(f"!Can not found pssh!", extra={"service_name": __service_name__})
                # return
            # else:
                # logger.info(f" + Video, Audio PSSH: {pssh_box}", extra={"service_name": __service_name__})
                # 
                # logger.info(f"Decrypt License for 1 Episode", extra={"service_name": __service_name__})
                # 
                # keys = nhk_plus.NHKplus_license.license_vd_ad(pssh_box, session, drm_token)
                # 
                # logger.info(f"Decrypt Video, Audio License", extra={"service_name": __service_name__})
                # 
                # pssh_list = ""
                # pssh_dics = []
                # for key in keys["key"]:
                    # if key["type"] == "CONTENT":
                        # pssh_list = pssh_list + " --key {}:{}".format(key["kid_hex"], key["key_hex"])
                        # pssh_dics.append(["{}:{}".format(key["kid_hex"], key["key_hex"])])
                        # logger.info(f" + {key["kid_hex"]}:{key["key_hex"]}", extra={"service_name": __service_name__})
                # 
                # logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                # 
                # random_string = str(int(time.time() * 1000))
                # title_name_logger_video = random_string+"_video_encrypted.mp4"
                # title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                # 
                # video_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_video_meta, login_status, get_best_track["video"]["url"].replace("playlist.m3u8", ""), title_name_logger_video, config, unixtime)
                # audio_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_audio_meta, login_status, get_best_track["audio"]["url"].replace("playlist.m3u8", ""), title_name_logger_audio, config, unixtime)
                # 
                # logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": __service_name__})
                # 
                # nhk_plus.NHKplus_decrypt.decrypt_all_content(pssh_dics, video_downloaded, video_downloaded.replace("_encrypted", ""), audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                # 
                # logger.info("Muxing Episode...", extra={"service_name": __service_name__})
                # 
                # result = nhkplus_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4"), config, unixtime, int(duration_second), title_name_logger, None, additional_info)
                # 
                # dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                # 
                # if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    # for filename in os.listdir(dir_path):
                        # file_path = os.path.join(dir_path, filename)
                        # try:
                            # if os.path.isfile(file_path):
                                # os.remove(file_path)
                            # elif os.path.isdir(file_path):
                                # shutil.rmtree(file_path)
                        # except Exception as e:
                            # print(f"削除エラー: {e}")
                # else:
                    # print(f"指定されたディレクトリは存在しません: {dir_path}")
                # 
                # logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": __service_name__})
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        console.print_exception()
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")