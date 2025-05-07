import os
import re
import subprocess
from tqdm import tqdm
from datetime import datetime

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class VideoMarket_license:
    def license_vd_ad(pssh, session, url, config):
        _WVPROXY = url
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge))
        response.raise_for_status()
    
        cdm.parse_license(session_id, response.content)
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]
    
        cdm.close(session_id)
                
        keys = {
            "key": keys,
        }
        
        return keys

class VideoMarket_decrypt:
    def mp4decrypt(keys, config):
        if os.name == 'nt':
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
        
        mp4decrypt_path = os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe" if os.name == 'nt' else "mp4decrypt")
        
        if not os.access(mp4decrypt_path, os.X_OK):
            try:
                os.chmod(mp4decrypt_path, 0o755)
            except Exception as e:
                raise PermissionError(f"Failed to set executable permissions on {mp4decrypt_path}: {e}")
            
        for key in keys:
            if key["type"] == "CONTENT":
                mp4decrypt_command.extend(
                    [
                        "--show-progress",
                        "--key",
                        "{}:{}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return mp4decrypt_command
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="VideoMarket"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            VideoMarket_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            VideoMarket_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="VideoMarket"):
        mp4decrypt_command = VideoMarket_decrypt.mp4decrypt(keys, config)
        mp4decrypt_command.extend([input_file, output_file])
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
            with subprocess.Popen(mp4decrypt_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:
                for line in process.stdout:
                    match = re.search(r"(ｲ+)", line)  # 進捗解析
                    if match:
                        progress_count = len(match.group(1))
                        inner_pbar.n = progress_count
                        inner_pbar.refresh()
                
                process.wait()
                if process.returncode == 0:
                    inner_pbar.n = 100
                    inner_pbar.refresh()

class VideoMarket_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.tv_headers = {
            "accept": "multipart/mixed; deferSpec=20220824, application/json",
            "app-version": "tv.4.1.14",
            "content-type": "application/json",
            "host": "bff.videomarket.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0"
        }
        self.hd_headers = {
            "accept": "application/json",
            "vm-device-info": "{\"model\":\"AOSP TV on x86\",\"deviceCode\":\"generic_x86_arm\",\"brand\":\"google\",\"platform\":\"Android TV OS\",\"platformVer\":\"13\",\"sdkVer\":33,\"hdcpVer\":1}",
            "vm-app-info": "{\"ver\":\"tv.4.1.14\"}",
            "vm-codec-info": "{\"isHdr\":false,\"isDdp\":false,\"isAtmos\":false,\"isUhd\":false,\"isHevc\":false}", # false...? trueだとなぜか最初のリクエストが飛ばない。謎
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 13; AOSP TV on x86 Build/TTT5.221206.003)",
            "host": "pf-api.videomarket.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
    def authorize(self, email, password):
        _ENDPOINT_CC = 'https://bff.videomarket.jp/graphql'
        
        status, message, temp_id_token, temp_refresh_token = self.get_temp_token()
        
        payload = {
          "id_token": temp_id_token,
          "password": password,
          "login_id": email
        }
        
        response = self.session.post("https://www.videomarket.jp/login", json=payload)
        
        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            return False, 'Wrong Email or password combination'
        
        auth_response = response.json()
        self.session.headers.update({"Authorization": "Bearer "+auth_response["id_token"]})
        
        user_info_query = {
            "query": "{     user {       isTester       userId       email     }   }"
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["user"]
    def get_temp_token(self):
        _ENDPOINT_CC = 'https://bff.videomarket.jp/graphql'
        _AUTH_DEVICE_URL = "https://auth.videomarket.jp/v1/authorize/device"
        
        payload = {
            "api_key": "43510DE69546794606805E74F797CA84FB8C0938",
            "site_type": 7 # 3 = android, 7 = androidTV
        }    
        headers = {
            "user-agent": "okhttp/4.12.0",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "host": "auth.videomarket.jp"
        }
        
        response = self.session.post(_AUTH_DEVICE_URL, json=payload, headers=headers)
        
        id_token = response.json()["id_token"]
        refrest_token = response.json()["refresh_token"]
        self.session.headers.update({"Authorization": "Bearer "+id_token})
        user_info_query = {
            "query": "{     user {       isTester       userId       email     }   }"
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["user"], id_token, refrest_token
    
    def check_single(self, url):
        pattern = r"https://www\.videomarket\.jp/(player|title)/[A-Z0-9]+/[A-Z0-9]+"
        return bool(re.match(pattern, url))
    
    def get_title_parse_all(self, url):
        match = re.match(r"https://www\.videomarket\.jp/(player|title)/([A-Z0-9]+)", url)
        title_id = match.group(2)
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "Title",
            "variables": {
                "fullTitleId": title_id,
                "limit": 1000
            },
           "query": "query Title($fullTitleId: String!, $limit: Int!) { title(fullTitleId: $fullTitleId, limit: $limit) { titleSummary { __typename ...titleSummary } titleDetail { copyright introduction outline highlight rating subtitleDubType year countries audioType isFavorite isDolbyVision } casts { castId castName roleName additionalInformation } staff { staffName staffRole } series { seriesId seriesName } repPacks { __typename ...repPack } genres { __typename ...genre } contentId } relatedTitleSummaries(fullTitleId: $fullTitleId, limit: $limit) { __typename ...titleSummary } quickPlay(fullTitleId: $fullTitleId) { __typename ...repPack } user { userId } }  fragment titleSummary on TitleSummary { fullTitleId titleName titleImageUrl16x9 courseIds hasFreePack hasEstPack hasDownloadablePack isCouponTarget couponDiscountRate }  fragment story on Story { fullStoryId subtitleDubType encodeVersion isDownloadable isBonusMaterial }  fragment repPack on RepPack { repFullPackId groupType packName fullTitleId titleName storyImageUrl16x9 playTime subtitleDubType outlines courseIds price couponPrice couponDiscountRate discountRate rentalDays viewDays deliveryExpiredAt salesType status { hasBeenPlayed isCourseRegistered isEstPurchased isNowPlaying isPlayable isRented playExpiredAt playableQualityType rentalExpiredAt } packs { canPurchase fullPackId subGroupType fullTitleId qualityConsentType courseIds price couponPrice discountRate couponDiscountRate rentalDays viewDays deliveryExpiredAt salesType stories { __typename ...story } } }  fragment genre on Genre { genreId genreName }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["title"] != None:
                id_type = []
                for single_genre in return_json['data']['title']['genres']:
                    id_type.append(single_genre["genreName"])
                metadata_response_single = return_json['data']['title']['repPacks']
                return True, metadata_response_single, id_type, return_json['data']['title']['titleSummary']
            else:
                return False, None, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
    def get_playing_access_token(self):
        '''Playing Access Tokenを取得するコード'''
        meta_json = {
            "operationName": "PlayingAccessToken",
            "variables": {},
            "query": "query PlayingAccessToken { playingAccessToken }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json, headers=self.tv_headers)
            return_json = metadata_response.json()
            if return_json["data"]["playingAccessToken"] != None:
                return True, return_json['data']['playingAccessToken']
            else:
                return False, None
        except Exception as e:
            print(e)
            return False
        
    def get_playing_token(self, story_id, pack_id, access_token):
        '''Playing Tokenを取得するコード'''
        meta_json = {
            "operationName": "PlayingToken",
            "variables": {
                "fullStoryId": story_id,
                "fullPackId": pack_id,
                "qualityType": 3,
                "token": access_token
            },
            "query": "query PlayingToken($fullStoryId: String!, $fullPackId: String!, $qualityType: Int!, $token: String!) { playingToken(fullStoryId: $fullStoryId, fullPackId: $fullPackId, qualityType: $qualityType, token: $token) }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json, headers=self.tv_headers)
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json['data']['playingToken']
            else:
                return False, None
        except Exception as e:
            print(e)
            return False
        
    def get_streaming_info(self, story_id, play_token, user_id, playing_access_token):
        '''該当エピソードのメディアデータを取得するコード'''
        if user_id == "0":
            user_id = ""
        meta_json = {
            "userId": user_id,
            "playToken": play_token,
            "fullStoryId": story_id
        }
        headers = self.hd_headers.copy()
        headers.update({
            "Authorization": "Bearer "+playing_access_token
        })
        try:
            metadata_response = self.session.post("https://pf-api.videomarket.jp/v1/play/vm/streaming/app/tv", json=meta_json, headers=headers)
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json
            else:
                return False, None
        except Exception as e:
            print(e)
            return False
    def update_progress(self, process, service_name="VideoMarket"):
        total_size = None
        downloaded_size = 0

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if line.startswith("[#") and "ETA:" in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        downloaded_info = parts[1]
                        downloaded, total = downloaded_info.split('/')

                        # 単位を正規表現で取得
                        downloaded_match = re.search(r"([\d.]+)\s*(MiB|GiB)", downloaded)
                        total_match = re.search(r"([\d.]+)\s*(MiB|GiB)", total)

                        if downloaded_match and total_match:
                            downloaded_value = float(downloaded_match.group(1))
                            downloaded_unit = downloaded_match.group(2)
                            total_value = float(total_match.group(1))
                            total_unit = total_match.group(2)

                            # 単位をMiBに揃える
                            if downloaded_unit == "GiB":
                                downloaded_value *= 1024
                            if total_unit == "GiB":
                                total_value *= 1024

                            if total_size is None:
                                total_size = total_value

                            downloaded_size = downloaded_value

                            percentage = (downloaded_size / total_size) * 100
                            bar = f"{percentage:.0f}%|{'#' * int(percentage // 10)}{'-' * (10 - int(percentage // 10))}|"

                            # GBとMBの判定による表示
                            if total_size >= 1024:  # GBの場合
                                size_info = f" {downloaded_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
                            else:  # MBの場合
                                size_info = f" {downloaded_size:.1f}/{total_size:.1f} MiB"

                            log_message = (
                                f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                                f"{bar}{size_info}"
                            )

                            print(f"\r{log_message}", end="", flush=True)

                    except (IndexError, ValueError, AttributeError) as e:
                        print(f"Error parsing line: {line} - {e}")
                else:
                    print(f"Unexpected format in line: {line}")

        if total_size:
            if total_size >= 1024:  # GBの場合
                final_size_info = f" {total_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
            else:  # MBの場合
                final_size_info = f" {total_size:.1f}/{total_size:.1f} MiB"

            print(
                f"\r{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                f"100%|{'#' * 10}|{final_size_info}",
                flush=True
            )
    def aria2c(self, url, output_file_name, config, unixtime):
        output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)

        if not os.path.exists(output_temp_directory):
            os.makedirs(output_temp_directory, exist_ok=True)
        if os.name == 'nt':
            aria2c = os.path.join(config["directorys"]["Binaries"], "aria2c.exe")
        else:
            aria2c = "aria2c"
        
        if os.name == 'nt':
            if not os.path.isfile(aria2c) or not os.access(aria2c, os.X_OK):
                print(f"aria2c binary not found or not executable: {aria2c}")
            
        aria2c_command = [
            aria2c,
            url,
            "-d",
            os.path.join(config["directorys"]["Temp"], "content", unixtime),
            "-j16",
            "-o", output_file_name,
            "-s16",
            "-x16",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "--allow-overwrite=false",
            "--async-dns=false",
            "--auto-file-renaming=false",
            "--console-log-level=warn",
            "--retry-wait=5",
            "--summary-interval=1",
        ]
        
        #print(" ".join(aria2c_command))

        process = subprocess.Popen(
            aria2c_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            encoding='utf-8'
        )

        self.update_progress(process)

        process.wait()

        return os.path.join(config["directorys"]["Temp"], "content", unixtime, output_file_name)
    
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, title_name_logger, episode_number, additional_info, service_name="VideoMarket"):
        if os.name != 'nt':
            os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
        else:
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            os.makedirs(os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name)), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name), sanitize_filename(title_name_logger+".mp4"))
        
        base_command = [
            "ffmpeg",
            "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),  # 動画
            "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),  # 音声
            "-map", "0:v:0",  # 動画ストリームを選択
            "-map", "1:a:0",  # 音声ストリームを選択
            "-c:v", "copy",  # 映像の再エンコードなし
            "-c:a", "copy",  # 音声の再エンコードなし
            "-strict", "experimental",
            "-y",
            "-progress", "pipe:1",  # 進捗を標準出力に出力
            "-nostats",  # 標準出力を進捗情報のみにする
        ]
        
        # メタデータを追加する場合
        if additional_info[6] or additional_info[9]:
            metadata_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, "metadata", f"{episode_number}_metadata.txt")
            base_command.extend(["-i", metadata_path, "-map_metadata", "2"])
        
        ## サムネイルを追加する場合
        #if additional_info[4] or additional_info[5]:
        #    thumbnail_path = os.path.join(config["directorys"]["Temp"], "thumbnail", unixtime, f"thumbnail_{episode_number}.jpg")
        #    base_command.extend(["-i", thumbnail_path, "-map", "2:v:0", "-disposition:v:1", "attached_pic"])  # サムネイルを埋め込み
        
        compile_command = base_command + [output_name]
        
        #print(compile_command)

        #print(" ".join(compile_command))
        # tqdmを使用した進捗表示
        #duration = 1434.93  # 動画全体の長さ（秒）を設定（例: 23分54.93秒）
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as process:
                for line in process.stdout:   
                    #print(line) 
                    # "time=" の進捗情報を解析
                    match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
                    if match:
                        hours = int(match.group(1))
                        minutes = int(match.group(2))
                        seconds = float(match.group(3))
                        current_time = hours * 3600 + minutes * 60 + seconds
    
                        # 進捗率を計算して更新
                        progress = (current_time / duration) * 100
                        pbar.n = int(progress)
                        pbar.refresh()
    
            # プロセスが終了したら進捗率を100%にする
            process.wait()
            if process.returncode == 0:  # 正常終了の場合
                pbar.n = 100
                pbar.refresh()
            pbar.close()