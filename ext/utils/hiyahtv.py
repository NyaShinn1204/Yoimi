import re
import os
import time
import json
import hashlib
import requests
import threading
import subprocess

from tqdm import tqdm
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Hi_YAH_decrypt:
    def mp4decrypt(keys, config):
        if os.name == 'nt':
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
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
    def shaka_packager(keys, config):
        if os.name == 'nt':
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "3.4.2_packager-win-x64.exe")]
        else:
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "3.4.2_packager-linux-arm64")]
        for key in keys:
            if key["type"] == "CONTENT":
                shaka_decrypt_command.extend(
                    [
                        "--enable_raw_key_decryption",
                        "--keys",
                        "key_id={}:key={}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return shaka_decrypt_command
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Hi-YAH!"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Hi_YAH_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Hi_YAH_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Hi-YAH!"):
        mp4decrypt_command = Hi_YAH_decrypt.mp4decrypt(keys, config)
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
    def decrypt_content_shaka(keys, input_file, output_file, config, service_name="Hi-YAH!"):
        shaka_command = Hi_YAH_decrypt.shaka_packager(keys, config)
        shaka_command.extend([f"input={input_file},stream=video,output={output_file}"])
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
            with subprocess.Popen(shaka_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:                
                process.wait()
                if process.returncode == 0:
                    inner_pbar.n = 100
                    inner_pbar.refresh()

class Hi_YAH_license:
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

class HI_YAH_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.login_status = False
    def authorize(self, email, password):        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        status, temp_token = self.get_temp_token()
        
        default_headers = {
            "content-type": "application/json",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "Hi-YAH!/8.402.1(Google AOSP TV on x86, Android 16 (API 36))",
            "x-ott-agent": "android-tv site/90901 android-app/8.402.1",
            "ott-client-version": "8.402.1",
            "x-ott-language": "en_US",
            "authorization": "Bearer "+temp_token["access_token"],
        }
        
        self.session.headers.update(default_headers)
        
        if email == "QR_LOGIN":
            """
            Get QR login url
            """
            # default_headers["host"] = "fod-sp.fujitv.co.jp"
            # self.session.headers.update(default_headers)
            get_loginurl = self.session.post("https://api.vhx.tv/oauth/codes/", json={"client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6","client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd"})
            if get_loginurl.status_code != 201:
                return False, "Authentication Failed: Failed to get QR login url", None, None
            else:
                request_login_json = get_loginurl.json()
                print("Login URL:", "https://www.hiyahtv.com/activate")
                print("Code:", request_login_json["code"])
                
                start_time = time.time()
                
                while True:
                    if time.time() - start_time >= request_login_json["expires_in"]:
                        print("Code Expired. Please Re-try")
                        break
                    send_checkping = self.session.get(f"https://api.vhx.tv/oauth/codes/{request_login_json["code"]}", params={"client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6","client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd"})                        
                    if send_checkping.status_code == 404:
                        print("Waiting Login...")
                        time.sleep(5)
                    elif send_checkping.status_code == 200:
                        print("Login Accept")
                        login_success_json = send_checkping.json()
                        self.session.headers.update({"authorization": "Bearer "+login_success_json["access_token"]})
                      
                        status, message = self.get_userinfo()
                        
                        session_json = {
                            "method": "QR_LOGIN",
                            "email": hashlib.sha256(email.encode()).hexdigest(),
                            "password": hashlib.sha256(password.encode()).hexdigest(),
                            "access_token": login_success_json["access_token"],
                            "refresh_token": login_success_json["refresh_token"]
                        }
                        
                        self.login_status = True
                        
                        return True, message, self.login_status, session_json
        
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "Hi-YAH! require email and password", None, None, None
            
        payload = {
            "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
            "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
            "username": email,
            "grant_type": "password",
            "password": password
        }
        
        response = self.session.post("https://auth.vhx.com/v1/oauth/token", headers=default_headers, json=payload)
        response.raise_for_status()
        
        self.session.headers.update({"authorization": "Bearer "+response.json()["access_token"]})
        
        status, message = self.get_userinfo()
        self.login_status = True
        session_json = {
            "method": "NORMAL",
            "email": hashlib.sha256(email.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": response.json()["access_token"],
            "refresh_token": response.json()["refresh_token"]
        }
        return True, message, self.login_status, session_json
    
    def get_temp_token(self):
        self.session.headers.update({"authorization": None})
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "grant_type": "client_credentials",
          "scope": "read write"
        }
        
        temp_token = self.session.post("https://api.vhx.tv/oauth/token/", json=payload)
        if temp_token.status_code == 200:
            return True, temp_token.json()
        else:
            return False, None
    def check_token(self, token):
        self.session.headers.update({
            "authorization": "Bearer " + token
        })
        status, return_json = self.get_userinfo()
        return status, return_json
    def get_userinfo(self):
        url = "https://api.vhx.com/v2/sites/90901/me"
                    
        response = self.session.get(url)
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, None
    def refresh_token(self, refresh_token, old_session_json):
        status, temp_token = self.get_temp_token()
        self.session.headers.update({"authorization": "Bearer "+ temp_token["access_token"]})
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "grant_type": "refresh_token",
          "refresh_token": refresh_token
        }
        refresh_return = self.session.post("https://api.vhx.tv/oauth/token/", json=payload)
        if refresh_return.status_code == 200:
            self.session.headers.update({"authorization": "Bearer " + refresh_return.json()["access_token"]})
            session_json = {
                "method": "NORMAL",
                "email": old_session_json["email"],
                "password": old_session_json["password"],
                "access_token": refresh_return.json()["access_token"],
                "refresh_token": refresh_return.json()["refresh_token"]
            }
            return True, refresh_return.json(), session_json
        else:
            return False, None, None
        
    def revoke_token(self, token):
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "token": token,
        }
        revoke_status = self.session.post("https://api.vhx.tv/oauth/revoke", json=payload)
        if revoke_status.status_code == 200:
            return True
        else:
            return False
        
    
    def get_contentid_page(self, url):
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")
    
            content_id_name = None
            if "videos" in path_parts:
                videos_index = path_parts.index("videos")
                if videos_index + 1 < len(path_parts):
                    content_id_name = path_parts[videos_index + 1]
            else:
                content_id_name = path_parts[-1]
    
            if not content_id_name:
                return None
    
            full_url = urljoin("https://www.hiyahtv.com/", content_id_name)
            response = self.session.get(full_url)
            response.raise_for_status()

            match = re.search(r'window\.Page\s*=\s*({.*?})\s*(?:</script>|$)', response.text, re.DOTALL)
            if match:
                json_text = match.group(1)
                page_data = json.loads(json_text)
                return page_data
            else:
                return None
            return None
    
        except Exception as e:
            print(e)
            return None
        
    def get_content_info(self, content_id):
        try:
            metadata_response = self.session.get(f"https://api.vhx.com/v2/sites/90901/collections/{content_id}?include_events=1")
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json
            else:
                return False, None
        except Exception:
            return False, None
        
    def get_item_list(self, content_id):
        try:
            metadata_response = self.session.get(f"https://api.vhx.com/v2/sites/90901/collections/{content_id}/items?include_products_for=google&include_events=1&page=1&per_page=1000")
            return_json = metadata_response.json()
            if return_json != None:
                return return_json
            else:
                return None
        except Exception:
            return None
        
    def get_mpd_list(self, logger, __service_name__, episode_id):
        try:
            querystring = {
                "offline_license": "0",
                "model": "AOSP TV on x86",
                "max_width": "3840",
                "max_height": "2160",
                "max_fps": "60",
                "codecs": "hevc,avc",
                "os_version": "16"
            }
            metadata_response = self.session.get(f"https://api.vhx.com/v2/sites/90901/videos/{episode_id}/delivery", params=querystring)
            return_json = metadata_response.json()
            if return_json != None:
                logger.debug(f"Found {str(len(return_json["streams"]))} type stream", extra={"service_name": __service_name__})
                for find_mp4 in return_json["streams"]:
                    logger.debug(f" + {find_mp4["segment_format"]} | {find_mp4["method"]}", extra={"service_name": __service_name__})
                    if find_mp4["segment_format"] == "mp4":
                        return find_mp4
                return None
            else:
                return None
        except Exception:
            return None
        
    def download_segment(self, segment_links, config, unixtime, name, service_name="Hi-YAH!"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
    
        stop_flag = threading.Event()  # ← フラグの作成
    
        def fetch_and_save(index_url):
            index, url = index_url
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    response = self.session.get(url.strip(), timeout=10)
                    response.raise_for_status()
                    temp_path = os.path.join(base_temp_dir, f"{index:05d}.ts")
                    with open(temp_path, 'wb') as f:
                        f.write(response.content)
                    return index
                except requests.exceptions.RequestException:
                    retry += 1
                    time.sleep(2)
            if not stop_flag.is_set():
                raise Exception(f"Failed to download segment {index}: {url}")
    
        futures = []
        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(fetch_and_save, (i, url)) for i, url in enumerate(segment_links)]
                with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"Error: {e}")
                        pbar.update(1)
    
            # 結合処理
            output_path = os.path.join(base_temp_dir, name)
            with open(output_path, 'wb') as out_file:
                for i in range(len(segment_links)):
                    temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                    with open(temp_path, 'rb') as f:
                        out_file.write(f.read())
                    os.remove(temp_path)
    
        except KeyboardInterrupt:
            #print("\nダウンロード中断されました。停止信号を送信します...")
            stop_flag.set()  # ← ここで全スレッドに停止を通知
            for future in futures:
                future.cancel()
            # 未完了ファイルの削除
            for i in range(len(segment_links)):
                temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
            raise  # 終了ステータスを再送出

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Hi-YAH!"):        
        if title_name != None:
            os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
    
        compile_command = [
            "ffmpeg",
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),
            "-c:v",
            "copy",               # 映像はコピー
            "-c:a",
            "copy",                # 音声をコピー
            "-b:a",
            "192k",               # 音声ビットレートを設定（192kbpsに調整）
            "-strict",
            "experimental",
            "-y",
            "-progress", "pipe:1",  # 進捗を標準出力に出力
            "-nostats",            # 標準出力を進捗情報のみにする
            output_name,
        ]
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8") as process:
                for line in process.stdout:    
                    match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
                    if match:
                        hours = int(match.group(1))
                        minutes = int(match.group(2))
                        seconds = float(match.group(3))
                        current_time = hours * 3600 + minutes * 60 + seconds
    
                        progress = (current_time / duration) * 100
                        pbar.n = int(progress)
                        pbar.refresh()
    
            # プロセスが終了したら進捗率を100%にする
            process.wait()
            if process.returncode == 0:  # 正常終了の場合
                pbar.n = 100
                pbar.refresh()
            pbar.close()