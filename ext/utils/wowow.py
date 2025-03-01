import re
import os
import jwt
import ast
import uuid
import m3u8
import random
import base64
import string
import requests
import subprocess
from tqdm import tqdm
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote, urljoin

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class NHKplus_downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.user_agent = "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 jp.ne.wowow.vod.androidtv/3.7.0"
        self.common_headers = {
            "user-agent": self.user_agent,
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "host": "custom-api.wowow.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
    def authorize(self, email, password):
        try:
            url = "https://custom-api.wowow.co.jp/api/v1/wip/users/auth"
            headers = self.common_headers.copy()
            payload = {
                "online_id": email,
                "password": password,
                "client_id": "wod-tv",
                "app_id": 5,
                "device_code": 8,
                "vuid": uuid.uuid4().hex
            }
            response = self.session.post(url, headers=headers, json=payload, allow_redirects=False).json()
            try:
                if response["error"]:
                    return False, response["error"]["message"]
            except:
                pass
            
            #access_token ="Bearer " + response["wip_access_token"]
            #access_token ="Bearer " + response["access_token"]
            
            return True, response

        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer

    def create_access_token(self, email, password):
        try:
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://agree.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            payload = {
                "scope": "openid SIMUL001",
                "response_type": "id_token token",
                "client_id": "simul",
                "redirect_uri": "https://plus.nhk.jp/auth/login",
                "claims": "{\"id_token\":{\"service_level\":{\"essential\":true}}}",
                "prompt": "login",
                "nonce": str(uuid.uuid4()),
                "state": "/watch/ch/g1",
                "did": str(uuid.uuid4())
            }

            response = self.session.get("https://agree.auth.nhkid.jp/oauth/AuthorizationEndpoint?", params=payload, headers=headers, allow_redirects=False)

            response = self.session.get(response.headers["Location"], headers=headers, allow_redirects=False)
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://login.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            parsed_url = urlparse(response.headers["Location"])
            parameters = parse_qs(parsed_url.query)
            response_parameter = {key: value[0] for key, value in parameters.items()}
            payload = {
                "AUTH_TYPE": "AUTH_OP",
                "SITE_ID": "co_site",
                "MESSAGE_AUTH": response_parameter["MESSAGE_AUTH"],
                "AUTHENTICATED": response_parameter["AUTHENTICATED"],
                "snsid": "undefined",
                "Fingerprint": str(uuid.uuid4())
            }
            response = self.session.post("https://login.auth.nhkid.jp/auth/login", data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 1: {response.status_code}", extra={"service_name": "NHK+"})

            # Step 7: Authentication with Email and Password
            payload = {
                "ORG_ID": "undefined",
                "ID": email,
                "PWD": password,
                "user-agent": self.user_agent,
                "PIN_CODE": "undefined",
                "Fingerprint": str(uuid.uuid4()),
                "lowLevelSessionFlg": "undefined"
            }
            response = self.session.post("https://login.auth.nhkid.jp/auth/login", data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 2: {response.status_code}", extra={"service_name": "NHK+"})

            if response.json()["resultCode"] != "CO-SC0003":
                self.logger.info(f"Login failed: {response.json().get('resultMessage', 'Unknown error')}", extra={"service_name": "NHK+"})
                raise Exception()

            # Step 3 (Corrected): Handle the redirect and extract parameters
            # The 'authenticated' value contains a URL, sometimes relative.
            authenticated_url = response.json()["authenticated"]
            if not authenticated_url.startswith("http"): # Check if the URL is relative
                authenticated_url = urljoin("https://login.auth.nhkid.jp", authenticated_url) # Join relative URL with base URL
            response = self.session.post(authenticated_url, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 3: {response.status_code}", extra={"service_name": "NHK+"})

            parsed_url = urlparse(response.headers["Location"])
            fragment = parsed_url.fragment
            query_params = parse_qs(fragment)
            for key, value in query_params.items():
                self.logger.debug(f"+ {key}: {value[0]}", extra={"service_name": "NHK+"})
            id_token = query_params.get("id_token", [None])[0]

            return True,  "Bearer " + id_token
        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer
    def gen_access_token(self):        
        private_key = NHKplus_utils.parse_private_key()
            
        payload = {
            "iss": "app.nhkplus",
            "sub": "AppToken",
            "aud": "ctl.npd.plus.nhk.jp",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc)
        }
        
        headers = {
            "kid": "008b6857-3801-492c-bc50-48531db4b936",
            "alg": "RS256",
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        
        return  "Bearer " + token
    
    def get_drm_token(self, token):
        accesskey_json = self.session.post("https://ctl.npd.plus.nhk.jp/create-accesskey", json={}, headers={"Authorization": token}).json()
        
        return accesskey_json["drmToken"]
    
    def get_playlist_info(self, st_id, playlist_id):
        if playlist_id:
            meta_response = self.session.get(f"https://api-plus.nhk.jp/d5/pl2/recommend/{playlist_id}.json").json()
            
            for single_meta in meta_response["body"]:
                if single_meta["stream_id"] == st_id:
                   return True, single_meta
            return False, "Not found"
        else:
            meta_response = self.session.get(f"https://api-plus.nhk.jp/r5/pl2/streams/4/{st_id}?area_id=130&is_rounded=false").json()
            
            for single_meta in meta_response["body"]:
                if single_meta["stream_id"] == st_id:
                   return True, single_meta
            return False, "Not found"
        
    def m3u8_downlaoder(self, content_text, login_status, base_url, title_name, config, unixtime, service_name="NHK+"):
        output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)

        if not os.path.exists(output_temp_directory):
            os.makedirs(output_temp_directory, exist_ok=True)
        
            
        output_file = os.path.join(output_temp_directory, title_name)
        download_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        
        # 一時フォルダを作成
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
        
        # m3u8を解析
        m3u8_obj = m3u8.loads(content_text)
                
        video_url = re.search(r'#EXT-X-MAP:URI="([^"]+)"', content_text).group(1)
        
        if login_status == False:
            video_url = video_url
        else:
            base_url = ""
        
        segment_urls = [seg.uri for seg in m3u8_obj.segments]
        segment_urls.insert(0, video_url)
        
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        # 各セグメントをダウンロード
        #print("ダウンロード中...")
        for i, segment_url in enumerate(tqdm(segment_urls, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ")):
            ts_file = os.path.join(download_dir, f"{random_string}_segment_{i}.ts")
            if not os.path.exists(ts_file):
                res = requests.get(base_url+segment_url, stream=True)
                with open(ts_file, "wb") as f:
                    for chunk in res.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
        
        # 結合
        #print("結合中...")
        with open(output_file, "wb") as output:
            for i in tqdm(range(len(segment_urls)), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "):
                ts_file = os.path.join(download_dir, f"{random_string}_segment_{i}.ts")
                with open(ts_file, "rb") as f:
                    output.write(f.read())
        
       # print(f"動画のダウンロードが完了しました： {output_file}")
        return os.path.join(config["directorys"]["Temp"], "content", unixtime, title_name)
    
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, duration, title_name_logger, episode_number, additional_info, service_name="NHK+"):
        if os.name != 'nt':
            output_name = os.path.join(config["directorys"]["Downloads"], title_name_logger+".mp4")
        else:
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            output_name = os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name_logger+".mp4"))
        
        if additional_info[6] or additional_info[8]:
            compile_command = [
                "ffmpeg",
                "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),  # 動画
                "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),  # 音声
                "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, "metadata", episode_number+"_metadata.txt"),  # メタデータ
                "-map", "0:v:0",  # 動画ストリームを選択
                "-map", "1:a:0",  # 音声ストリームを選択
                "-map_metadata", "2",  # メタデータを適用
                "-c:v", "copy",  # 映像の再エンコードなし
                "-c:a", "copy",  # 音声の再エンコードなし
                "-strict", "experimental",
                "-y",
                "-progress", "pipe:1",  # 進捗を標準出力に出力
                "-nostats",  # 標準出力を進捗情報のみにする
                output_name,
            ]
        else:
            compile_command = [
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
                output_name,
            ]
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