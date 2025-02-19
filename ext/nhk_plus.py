# ok analyze is done
# これだけ無駄にコード綺麗に書いてやろうかな
import os
import sys
import yaml
import time
import shutil
import logging
import traceback

from ext.utils import nhk_plus

__service_name__ = "NHK+"

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
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})
    session.headers.update({"Accept": "application/json, text/plain, */*"})

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        
        nhkplus_downloader = nhk_plus.NHKplus_downloader(session, logger)
        
        if email and password != "":
            status, message = nhkplus_downloader.authorize(email, password)
            if status == False:
                logger.error(message, extra={"service_name": "NHK+"})
                exit(1)
            else:
                logger.info("Loggined Account", extra={"service_name": "NHK+"})
                logger.info(" + ID: "+message["disp_login_id"], extra={"service_name": "NHK+"})
                logger.info(" + Member Type: "+str(message["member_type"]), extra={"service_name": "NHK+"})
        else:
            plan_status = "No Logined"
            
        #logger.info("Get or Gen Video Access Token...", extra={"service_name": "NHK+"})
        if email and password != "":
            status, video_access_token = nhkplus_downloader.create_access_token(email, password)
        else:
            video_access_token = nhkplus_downloader.gen_access_token()
        
        logger.debug("Get VAT_TEMP: "+video_access_token, extra={"service_name": "NHK+"})
        
        logger.info("Got Video Access Token For Temp", extra={"service_name": "NHK+"})
        logger.info("+ Video Access Token (Temp): "+video_access_token[:10]+"*****", extra={"service_name": "NHK+"})
        
        logger.debug("Open Get access key", extra={"service_name": "NHK+"})
        
        drm_token = nhkplus_downloader.get_drm_token(video_access_token)
        logger.info("Got Drm Token", extra={"service_name": "NHK+"})
        logger.info("+ Drm Token: "+drm_token[:10]+"*****", extra={"service_name": "NHK+"})
        
        if url.__contains__("playlist_id"):
            st_id, playlist_id = nhk_plus.NHKplus_utils.extract_nhk_ids(url)
            
            status, metadata = nhkplus_downloader.get_playlist_info(st_id, playlist_id)
            if status == False:
                logger.info("Failed to Get Video Info. Reason: Playlist id not found", extra={"service_name": "NHK+"})
                return
            
            #video_info = session.get(metadata["stream_type"]["program"]["hsk"]["video_descriptor"])
            logger.info("Get Title for 1 Episode", extra={"service_name": "NHK+"})
            title_name_logger = metadata["stream_type"]["program"]["pl"]["title"]
            logger.info(f" + {title_name_logger}", extra={"service_name": "NHK+"})
            
            video_info = session.get(metadata["stream_type"]["program"]["hsk"]["video_descriptor"]).json()
            duration_temp = metadata["stream_type"]["program"]["hsk"]["passed_length"]
            h, m, s = map(int, duration_temp.split(':'))
            duration_second = h * 3600 + m * 60 + s

            import struct
            import base64
            import re
            def find_moov_box(mp4_data):
                """MP4バイナリデータからmoovボックスをうあーする"""
                f = mp4_data
                i = 0
                while i < len(f):
                    box_size, box_type = struct.unpack('>I4s', f[i:i+8])
                    i += 8
            
                    if box_type == b'moov':
                        return f[i:i+box_size-8]
            
                    i += box_size - 8
            
                return None
            
            def parse_box(data, index=0):
                """指定されたデータからボックスをうあーして返す"""
                boxes = []
                while index < len(data):
                    box_size, box_type = struct.unpack('>I4s', data[index:index+8])
                    index += 8
            
                    box = {
                        'size': box_size,
                        'type': box_type.decode('utf-8'),
                        'data': data[index:index+box_size-8]
                    }
            
                    boxes.append(box)
            
                    index += box_size - 8
                return boxes
            
            def remove_duplicates_and_count(tracks):
                # ここでダブってるやつをぶっ飛ばす
                unique_tracks = {}
                duplicates_count = 0
            
                for track in tracks:
                    try:
                        if track["content_type"] == "video":
                            track_key = (
                                track.get("url"),
                                track.get("bitrate"),
                            )
                        elif track["content_type"] == "audio":
                            track_key = (
                                track.get("url"),
                                track.get("bitrate"),
                            )
                        elif track["content_type"] == "text":
                            track_key = (
                                track.get("language"),
                            )
                        else:
                            print("wtf", str(track))
                
                        if track_key in unique_tracks:
                            duplicates_count += 1  # 重複カウント
                        else:
                            unique_tracks[track_key] = track
                    except:
                        print("wtf", str(track))
            
                unique_track_list = list(unique_tracks.values())
            
                return unique_track_list
            
            def select_tracks(tracks):
                # ここでビットレートが一番高いやつを盗んでreturnで殴る
                highest_bitrate_video = max(tracks["video_track"], key=lambda x: x["bitrate"])
            
                # オーディオトラックのnameがmainのやつを引っ張る。 mainっていうのは主音声、subは副音声優先のやつらしい
                main_audio = next((audio for audio in tracks["audio_track"] if audio["name"] == "main"), None)
            
                return {
                    "video": highest_bitrate_video,
                    "audio": main_audio
                }
            
            
            def parse_m3u8(file_content):
                video_tracks = []
                audio_tracks = []
                text_tracks = []
                
                CODEC_MAP = {
                    "avc1": "H.264",
                    "mp4a": "AAC",
                }
                
                lines = file_content.splitlines()
                
                for i, line in enumerate(lines):
                    if line.startswith("#EXT-X-STREAM-INF"):
                        attributes = re.findall(r'([A-Z0-9\-]+)=("[^"]+"|[^,]+)', line)
                        attr_dict = {key: value.strip('"') for key, value in attributes}
                        bitrate = int(attr_dict.get("BANDWIDTH", 0)) // 1000  # bps to kbpsに変換
                        codec = attr_dict.get("CODECS", "").split(",")[1]
                        
                        # なぜかvideoのやつだけurlが次の行に書かれてるので仕方なくやります。
                        video_url = lines[i + 1] if i + 1 < len(lines) else "unknown"
                        
                        video_tracks.append({
                            "content_type": "video",
                            "bitrate": bitrate,
                            "codec": CODEC_MAP.get(codec.split(".")[0], codec),
                            "url": video_url,
                        })
                    elif line.startswith("#EXT-X-MEDIA"):
                        attributes = re.findall(r'([A-Z0-9\-]+)=("[^"]+"|[^,]+)', line)
                        attr_dict = {key: value.strip('"') for key, value in attributes}
                        if attr_dict.get("TYPE") == "AUDIO":
                            audio_tracks.append({
                                "content_type": "audio",
                                "language": attr_dict.get("LANGUAGE", "unknown"),
                                "name": attr_dict.get("NAME", "unknown"),
                                "url": attr_dict.get("URI", "unknown"),
                            })
                        elif attr_dict.get("TYPE") == "SUBTITLES":
                            text_tracks.append({
                                "content_type": "text",
                                "language": attr_dict.get("LANGUAGE", "unknown"),
                                "name": attr_dict.get("NAME", "unknown"),
                                "url": attr_dict.get("URI", "unknown"),
                            })
            
                return {
                    "video_track": video_tracks,
                    "audio_track": remove_duplicates_and_count(audio_tracks),  # 重複してるうやつをどか～ん
                    "text_track": text_tracks,
                }
            
            def print_tracks(tracks):
                output = ""
                # Video tracks まぁvideoやな
                output += f"{len(tracks['video_track'])} Video Tracks:\n"
                for i, video in enumerate(tracks["video_track"]):
                    output += f"├─ VID | [{video['codec']}] | {video['bitrate']} kbps\n"
                
                # Audio tracks まぁaudioやな
                output += f"\n{len(tracks['audio_track'])} Audio Tracks:\n"
                for i, audio in enumerate(tracks["audio_track"]):
                    output += f"├─ AUD | {audio['language']} | {audio['name']}\n"
            
                # Text tracks まぁsubやな
                output += f"\n{len(tracks['text_track'])} Text Tracks:\n"
                for i, text in enumerate(tracks["text_track"]):
                    output += f"├─ SUB | [VTT] | {text['language']} | {text['name']}\n"
                
                print(output)
            
            
            
            def transform_metadata(manifests):
                transformed = []
            
                for manifest in manifests:
                    drm_type = manifest.get("drm_type", "")
                    bitrate_limit_type = manifest.get("bitrate_limit_type", "")
                    url = manifest.get("url", "")
                    video_codec = manifest.get("video_codec", "H.264")
                    dynamic_range = manifest.get("dynamic_range", "SDR")
            
                    # birtareの文字の最初にmがついてればMulti、泣ければSingleらしい。
                    bitrate_type = "Multi" if bitrate_limit_type.startswith("m") else "Single"
                    bitrate_limit = int(bitrate_limit_type[1:]) if bitrate_limit_type[1:].isdigit() else 0
            
                    # 取得したデータを整形
                    transformed_manifest = {
                        "drmType": drm_type,
                        "bitrateLimit": bitrate_limit,
                        "bitrateType": bitrate_type,
                        "url": url,
                        "videoCodec": "H.265" if video_codec == "H.265" else "H.264",
                        "dynamicRange": "HDR" if dynamic_range == "HDR" else "SDR",
                    }
            
                    transformed.append(transformed_manifest)
            
                return transformed
            
            def get_highest_bitrate_manifest(manifests):
                transformed = transform_metadata(manifests)
                if not transformed:
                    return None
                return max(transformed, key=lambda x: x["bitrateLimit"])
            
            #print("[+] Get Video Info:")
            #print(" + allow_multispeed: "+str(video_info["allow_multispeed"]))
            #print(" + need_L1_hd: "+str(video_info["need_L1_hd"]))
            #print(" + total manifests: "+str(len(video_info["manifests"])))
            #print("[+] Convert Video Info...")
            transformed_data = transform_metadata(video_info["manifests"])
            #print("[+] Convert Video Info")
            #print(json.dumps(transformed_data, indent=4))
            #print("[+] Select Highest birate manifest")
            highest_bitrate_manifest = get_highest_bitrate_manifest(video_info["manifests"])
            #print(json.dumps(highest_bitrate_manifest, indent=4))
            #print("[+] Get m3u8")
            
            logger.info(f"Get best birtate m3u8", extra={"service_name": "NHK+"})
            
            m3u8_data = session.get(highest_bitrate_manifest["url"]).text
            tracks = parse_m3u8(m3u8_data)
            logger.info(f"Get Video, Audio, Sub Tracks:", extra={"service_name": "NHK+"})
            print_tracks(tracks)
            
            get_best_track = select_tracks(tracks)
            
            logger.info(f"Get License for 1 Episode", extra={"service_name": "NHK+"})
            
            #print("[+] Finding pssh...")
            temp_video_meta = session.get(get_best_track["video"]["url"]).text
            temp_audio_meta = session.get(get_best_track["audio"]["url"]).text
            
            video_url = re.search(r'#EXT-X-MAP:URI="(https?://[^"]+)"', temp_video_meta).group(1)
            
            response = session.get(video_url)
            
            video_data = response.content # バイナリデータをうあーする
            moov_box = find_moov_box(video_data)
            
            pssh_box = ""
            count = 0
            if moov_box:
                sub_boxes = parse_box(moov_box)
                for box in sub_boxes:
                    if box["type"] == "pssh":
                        if count == 0:
                            pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            pssh_box = pssh_temp.replace("==", "")
                            #pssh_box = pssh_temp // なぜかこれでもdecryptできる。謎
                        else:
                            pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            pssh_box = pssh_box + pssh_temp.replace("==", "====")
                        count += 1
            
            
            if pssh_box == "":
                # print("[-] おい！psshどこやねん！殺すぞ！！！")
                logger.error(f"!Can not found pssh!", extra={"service_name": "NHK+"})
                return
            else:
                #print("[+] GET PSSH: {}".format(pssh_box))
                logger.info(f" + Video, Audio PSSH: {pssh_box}", extra={"service_name": "NHK+"})
                
                logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "NHK+"})
                
                keys = nhk_plus.NHKplus_license.license_vd_ad(pssh_box, session, drm_token)
                
                logger.info(f"Decrypt Video, Audio License", extra={"service_name": "NHK+"})
                
                #print("[+] Get Widevine Key:")
                pssh_list = ""
                pssh_dics = []
                for key in keys["key"]:
                    if key["type"] == "CONTENT":
                        pssh_list = pssh_list + " --key {}:{}".format(key["kid_hex"], key["key_hex"])
                        pssh_dics.append(["{}:{}".format(key["kid_hex"], key["key_hex"])])
                        #print("[+] DECRYPT KEY: {}:{}".format(key["kid_hex"], key["key_hex"]))
                        logger.info(f" + {key["kid_hex"]}:{key["key_hex"]}", extra={"service_name": "NHK+"})
                
                logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": "NHK+"})
                
                random_string = str(int(time.time() * 1000))
                title_name_logger_video = random_string+"_video_encrypted.mp4"
                title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                
                video_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_video_meta, title_name_logger_video, config, unixtime)
                audio_downloaded = nhkplus_downloader.m3u8_downlaoder(temp_audio_meta, title_name_logger_audio, config, unixtime)
                
                logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": "NHK+"})
                
                nhk_plus.NHKplus_decrypt.decrypt_all_content(pssh_dics, video_downloaded, video_downloaded.replace("_encrypted", ""), audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                
                logger.info("Muxing Episode...", extra={"service_name": "NHK+"})
                
                result = nhkplus_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4"), config, unixtime, int(duration_second), title_name_logger, message.get("displayNo", ""), additional_info)
                
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
                
                logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "NHK+"})
        
    except Exception as error:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        #print(traceback.format_exc())
        #print("\n")
        type_, value, _ = sys.exc_info()
        #print(type_)
        #print(value)
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        print("ENative:\n"+traceback.format_exc())
        print("EType:\n"+str(type_))
        print("EValue:\n"+str(value))
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")