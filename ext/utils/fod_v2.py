import re
import os
import jwt
import time
import m3u8
import requests
import threading
import subprocess
import dateutil.parser
from tqdm import tqdm
from datetime import datetime
from Crypto.Cipher import AES
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class FOD_license:
    def license_vd_ad(all_pssh, custom_data, session, config):
        _WVPROXY = f"https://cenc.webstream.ne.jp/drmapi/wv/fujitv?custom_data={custom_data}"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(all_pssh))
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

class FOD_decrypt:
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="FOD"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            FOD_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            FOD_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="FOD"):
        mp4decrypt_command = FOD_decrypt.mp4decrypt(keys, config)
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

class FOD_utils:
    def parse_m3u8(m3u8_url):
        headers = {
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        r = requests.get(m3u8_url, headers=headers)
        x = m3u8.loads(r.text)
        files = x.files[1:]

        key_url = x.keys[0].uri
        key = requests.get(key_url, headers=headers).content
        iv = bytes.fromhex("00000000000000000000000000000000")  # バカシステムなのでこれで通ります。:checked:
        parsed_files = []
        for f in files:
            parsed_files.append(f)
        
        duration = int(sum(x.duration for x in x.segments)) # Thanks By elinaldosoft
       
        return parsed_files, duration, iv, key

    # Download logic
    def setup_decryptor(iv, key):
        global _aes, return_iv
        return_iv = iv
        _aes = AES.new(key, AES.MODE_CBC, IV=return_iv)
    def download_chunk(files, iv, key, unixtime, config, service_name):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", str(unixtime))
        os.makedirs(base_temp_dir, exist_ok=True)
    
        FOD_utils.setup_decryptor(iv, key)
        stop_flag = threading.Event()
        downloaded_files = []
    
        def fetch_and_decrypt(ts_url):
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    headers = {
                        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)",
                        "connection": "Keep-Alive",
                        "accept-encoding": "gzip"
                    }
                    response = requests.get(ts_url.strip(), timeout=10, headers=headers)
                    response.raise_for_status()
                    decrypted_data = _aes.decrypt(response.content)
                    output_path = os.path.join(base_temp_dir, os.path.basename(ts_url))
                    with open(output_path, "wb") as f:
                        f.write(decrypted_data)
                    return output_path
                except Exception as e:
                    retry += 1
                    time.sleep(2)
            if not stop_flag.is_set():
                raise Exception(f"Failed to download: {ts_url}")
    
        futures = []
        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(fetch_and_decrypt, url) for url in files]
                with tqdm(total=len(files), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : Downloading", unit="file", ascii=True) as pbar:
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            downloaded_files.append(result)
                        except Exception as err:
                            print(f"Problem occurred\nReason: {err}")
                            stop_flag.set()
                            for f in futures:
                                f.cancel()
                            return None
                        pbar.update(1)
        except KeyboardInterrupt:
            print("User pressed CTRL+C, cleaning up...")
            stop_flag.set()
            for f in futures:
                f.cancel()
            return None
    
        return downloaded_files
    
    def merge_video(path, output, service_name):
        # sort video_path
        def extract_index(filename):
            match = re.search(r'_(\d+)\.ts$', filename)
            return int(match.group(1)) if match else -1
        
        def sort_dl_list(dl_list):
            return sorted(dl_list, key=lambda path: extract_index(os.path.basename(path)))
        list_video_path = sort_dl_list(path)
        with open(output, "wb") as out:
            with tqdm(total=len(list_video_path), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : Merging", ascii=True, unit="file") as pbar:
                for i in list_video_path:
                    out.write(open(i, "rb").read())
                    os.remove(i)
                    pbar.update()
                    
    def mux_video(temp_video_path, title_name, output, duration, service_name, config):    
        os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
        compile_command = [
            "ffmpeg",
            "-i",
            temp_video_path,
            "-c:v",
            "copy",             
            "-strict",
            "experimental",
            "-y",
            "-progress", "pipe:1", 
            "-nostats",         
            output,
        ]
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : Encoding", unit="%") as pbar:
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
    
            process.wait()
            if process.returncode == 0:
                pbar.n = 100
                pbar.refresh()
            pbar.close()

class FOD_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.login_status = None
        self.logined_headers = {}
    def authorize(self, email, password):        
        global fod_user_id
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        temp_token = self.gen_crack_token()
        
        default_headers = {
            "content-type": "application/json",
            # "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0",
            "x-authorization": "Bearer "+temp_token,
        }
        
        self.session.headers.update(default_headers)
        
        if email == "QR_LOGIN":
            """
            Get QR login url
            """
            # default_headers["host"] = "fod-sp.fujitv.co.jp"
            self.session.headers.update(default_headers)
            get_loginurl = self.session.get("https://fod-sp.fujitv.co.jp/apps/api/login/pin/?dv_type=tv")
            if get_loginurl.status_code != 200:
                return False, "Authentication Failed: Failed to get QR login url", None
            else:
                request_login_json = get_loginurl.json()
                print("Login URL:", request_login_json["url"])
                print("Code:", request_login_json["code"])
                
                while True:
                    send_checkping = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_pin/", json={"pin": request_login_json["code"]})                        
                    if send_checkping.status_code == 400:
                        print("Waiting Login...")
                        time.sleep(5)
                    elif send_checkping.status_code == 200:
                        print("Login Accept")
                        login_success_json = send_checkping.json()
                        gen_token = self.gen_login_uid_token(login_success_json["uid"])
                        self.session.headers.update({"x-authorization": "Bearer "+gen_token})
                        
                        status, message, login_uuid = self.get_userinfo()
                        fod_user_id = message.get("member_id")
                        if message == "1012":
                            return False, "Authentication Failed: This account is not subscription", None
                        else:
                            self.logined_headers = self.session.headers
                            self.login_status = [False, True]
                            return True, message, login_uuid, self.login_status
        
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "FOD require email and password", None, None
            
        payload = {
            "mail_address": email,
            "password": password
        }    
        
        response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        response.raise_for_status()
        
        email_verify_hashkey = response.json()["hash_key"]
        mail_auth_code = input("MAIL AUTH CODE : ")
        if mail_auth_code == None:
            return False, "Authentication Failed: Require Mail Auth Code", None, None
        else:
            pass
        
        payload = {
            "auth_code": str(mail_auth_code),
            "hash_key": email_verify_hashkey
        }
        login_status_check = self.session.post("https://id.fod.fujitv.co.jp/api/member/CheckAuthCodeApp", headers=default_headers, json=payload)
        login_status_check.raise_for_status()
        
        fodid_login_token = login_status_check.json()["fodid_login_token"]
        
        # default_headers["host"] = "fod-sp.fujitv.co.jp"
        self.session.headers.update(default_headers)
        
        payload = {
            "fodid_login_token": fodid_login_token
        }
        check_token_status = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_token/", headers=default_headers, json=payload)
        check_token_status.raise_for_status()
        
        uid = check_token_status.json()["uid"]
        
        login_token = self.gen_login_uid_token(uid)
        
        self.session.headers.update({"x-authorization": "Bearer "+login_token})
        
        status, message, login_uuid = self.get_userinfo()
        fod_user_id = message.get("member_id")
        if message == "1012":
            return False, "Authentication Failed: This account is not subscription", None, None
        else:
            self.logined_headers = self.session.headers
            self.login_status = [False, True]
            return True, message, login_uuid, self.login_status

    def gen_crack_token(self):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx" # Haha cracked from AndroidTV APK
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jwt_token
    
    def gen_login_uid_token(self, uid):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx" # Haha cracked from AndroidTV APK
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "uid": uid,
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jwt_token
    
    def get_userinfo(self):
        url = "https://fod-sp.fujitv.co.jp/apps/api/user/status/"
        
        querystring = { "dv_type": "tv" }
            
        response = self.session.get(url, params=querystring)
        if response.status_code == 200:
            return True, response.json(), response.cookies.get("uuid")
        elif response.status_code == 401:
            return False, response.json["code"], None
        
    def gen_temptoken(self):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx"
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        headers_xauth = {
            "content-type": "application/json",
           # "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0",
            "x-authorization": "Bearer "+jwt_token,
        }
        self.session.headers.update({'X-Authorization': 'Bearer ' + jwt_token})
        self.logined_headers = headers_xauth
        self.login_status = [True, True]
        return True, None, self.login_status

    def has_active_courses(self, user_status):
        """
        Check user plan.
        ex):
        1. check courses found
        2. check courses is not expired
        """
        courses = user_status.get("courses", [])
        
        if not courses:
            return False  # Cources not found
    
        now = datetime.now()
    
        for course in courses:
            exp_str = course.get("expiration_date", "")
            if exp_str:
                try:
                    expiration_date = dateutil.parser.parse(exp_str)
                    if expiration_date > now:
                        return True
                except ValueError:
                    continue
            else:
                return True
    
        return False
    
    
    def check_single_episode(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)

        def contains_repeated_identifier(url, identifier):
            pattern = f"({re.escape(identifier)}).*\\1"
            return bool(re.search(pattern, url))
                
        if contains_repeated_identifier(url, matches_url.group("title_id")):
            return True
        else:
            return False
    def get_title_parse_all(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)(?:/(?P<episode_id>[0-9a-z]+))?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=false&is_kids=false&dv_type=tv")

            return_json = metadata_response.json()
            if return_json["episodes"] != None:
                return True, return_json["episodes"], return_json["detail"]
            else:
                return False, None, None
        except Exception as e:
            return False, None, None
        
    def get_episode_metadata(self, ep_id, ep_uuid):
        url = "https://fod-sp.fujitv.co.jp/apps/api/auth/contents/tv_common/"
        
        querystring = {
            "site_id": "fodapp",
            "ep_id": ep_id,
            "qa": "auto",
            "uuid": ep_uuid,
            "starttime": "0",
            "wvsl": "3",
            "dv_type": "tv"
        }
        try:
            metadata_response = self.session.get(url, params=querystring).json()
            return metadata_response
        except Exception as e:
            return None
        
    def create_titlename_logger(self, id_type, episode_count, title_name, episode_num, episode_name):
        def safe_format(format_string, raw_values):
            # フォーマット文字列に使われているキーを抽出
            keys_in_format = set(re.findall(r"{(\w+)}", format_string))
            
            # 存在するキーだけで辞書を作成（不足は除外）
            values = {k: raw_values.get(k, "") for k in keys_in_format if raw_values.get(k)}
            
            # 空文字になるキーがあれば、その "{key}" または "_{key}" を文字列から除去
            for k in keys_in_format:
                if not raw_values.get(k):
                    format_string = re.sub(rf"_?{{{k}}}", "", format_string)
    
            return format_string.format_map(defaultdict(str, values))
    
        # 共通の値（node は引数から取得）
        raw_values = {
            "seriesname": title_name,
            "titlename": episode_num,
            "episodename": episode_name
        }
    
        # ノーマルアニメ・ドラマ
        if id_type in ("ノーマルアニメ", "ノーマルドラマ"):
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values)
    
        # 映画（劇場）
        elif id_type == "映画":
            if episode_count == 1:
                title_name_logger = title_name
            else:
                format_string = self.config["format"]["movie"]
                title_name_logger = safe_format(format_string, raw_values)
            
        return title_name_logger
    
    def update_progress(self, process, service_name="FOD"):
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
        
        #print(aria2c_command)

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
    
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="FOD"):
        # 出力ディレクトリを作成
        os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
    
        # ffmpegコマンド
        compile_command = [
            "ffmpeg",
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),
            "-c:v",
            "copy",               # 映像はコピー
            "-c:a",
            "copy",                # 音声をAAC形式に変換             # 音声ビットレートを設定（192kbpsに調整）
            "-strict",
            "experimental",
            "-y",
            "-progress", "pipe:1",  # 進捗を標準出力に出力
            "-nostats",            # 標準出力を進捗情報のみにする
            output_name,
        ]

        # tqdmを使用した進捗表示
        #duration = 1434.93  # 動画全体の長さ（秒）を設定（例: 23分54.93秒）
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8") as process:
                for line in process.stdout:    
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
            
            
    def send_stop_signal(self, episode_metadata, ep_uuid, audio_bandwidth, duration):
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        if self.login_status[1]:
            foduser_id = fod_user_id
        else:
            foduser_id = ""
        
        querystring = {
            "device_rotate": "landscape",
            "error_id": "",
            "buffering": "56181",
            "device_category": "tv",
            "enq_id": "",
            "duration": duration,
            "episode_id": episode_metadata["samba"],
            "device_ua": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)",
            "device_memory_max": "4015252",
            "stream_type": "VOD-urn:mpeg:dash:mp4protection:2011",
            "subpronum": "0",
            "skip_label": "",
            "fod_episode_id": episode_metadata["mediaid"],
            "current_time": "1", ## CHANGE THIS VALUE
            "device_os_sdk": "36",
            "internet_speed": "10934",
            "ifa": "optout",
            "device_memory_free": "516112",
            "session_id": ep_uuid,
            "season_id": episode_metadata["lu_id"],
            "foduser_id": foduser_id,
            "device_os": "androidtv",
            "play_band": str(int(audio_bandwidth) * 1000),
            "refer": "fodapp",
            "play_speed": "1.0",
            "player_status": "pause",
            "td_write_key": "257/1dbef148fc11ca71d992972db31166af2b5dba41", ## THIS VALUE IS NOT CHANGEABLE
            "device_os_version": "16",
            "contents_type": "SVOD-TVOD"
        }
        
        response = self.session.get(url, params=querystring)
        # nice
        
    def send_stop_signal_hls(self, episode_metadata, ep_uuid, video_bandwidth, duration):
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        if self.login_status[1]:
            foduser_id = fod_user_id
        else:
            foduser_id = ""
        
        querystring = {
            "device_rotate": "landscape",
            "error_id": "",
            "buffering": "56181",
            "device_category": "tv",
            "enq_id": "",
            "duration": duration,
            "episode_id": episode_metadata["samba"],
            "device_ua": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)",
            "device_memory_max": "4015252",
            "stream_type": "AES-128",
            "subpronum": "0",
            "skip_label": "",
            "fod_episode_id": episode_metadata["mediaid"],
            "current_time": "1", ## CHANGE THIS VALUE
            "device_os_sdk": "36",
            "internet_speed": "10934",
            "ifa": "optout",
            "device_memory_free": "516112",
            "session_id": ep_uuid,
            "season_id": episode_metadata["lu_id"],
            "foduser_id": foduser_id,
            "device_os": "androidtv",
            "play_band": str(int(video_bandwidth) * 1000),
            "refer": "fodapp",
            "play_speed": "1.0",
            "player_status": "pause",
            "td_write_key": "257/1dbef148fc11ca71d992972db31166af2b5dba41", ## THIS VALUE IS NOT CHANGEABLE
            "device_os_version": "16",
            "contents_type": "SVOD-TVOD"
        }
        
        response = self.session.get(url, params=querystring)
        # nice