import os
import re
import time
import requests
import subprocess
from tqdm import tqdm
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Bandai_ch_decrypt:
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Bandai-Ch"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Bandai_ch_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Bandai_ch_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Bandai-Ch"):
        mp4decrypt_command = Bandai_ch_decrypt.mp4decrypt(keys, config)
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

class Bandai_ch_license:
    def license_vd_ad(pssh, session, url, license_authkey):
        _WVPROXY = url
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers={"Bcov-Auth": license_authkey})
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

class Bandai_ch_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
    def authorize(self, email, password):
        
        LOGIN_URL = "https://account-api.bandainamcoid.com/v3/login/idpw"
        REDIRECT_URI = "https://www.bandainamcoid.com/v2/oauth2/auth?back=v3&client_id=bnid_b_ch&scope=JpGroupAll&redirect_uri=https://www.b-ch.com/mbr/auth2v3.php?refer=&text="
        
        data = {
            "client_id": "bnid_b_ch",
            "redirect_uri": REDIRECT_URI,
            "customize_id": "",
            "login_id": email,
            "password": password,
            "shortcut": "0",
            "retention": "0",
            "language": "ja",
            "cookie": '{"language":"ja"}',
            "prompt": ""
        }
        
        response = self.session.post(LOGIN_URL, data=data)
        if response.status_code != 200:
            raise Exception("Failed to login")
        
        login_response = response.json()
        redirect_url = login_response.get("redirect")
        if not redirect_url:
            raise Exception("No redirect URL found")
        
        auth_response = self.session.get(redirect_url)
        if auth_response.status_code != 200:
            raise Exception("Failed to authenticate")
                
        url = "https://appsvr.b-ch.com/api/mbauth/ajax_session_check"
        
        payload = "mbssn_key="+self.session.cookies["BCHWWW"]
        headers = {
            "host": "appsvr.b-ch.com",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "accept": "application/json",
            "sec-ch-ua": "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Brave\";v=\"134\"",
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.7",
            "origin": "https://www.b-ch.com",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.b-ch.com/",
            "accept-encoding": "gzip, deflate, br, zstd"
        }
        
        response = self.requests.post(url, data=payload, headers=headers)
        
        plan_name = "guest"
        if response.json()["pom_tc"] == "1" and response.json()["status_c"] == "0":
            plan_name = "monthly"
        else:
            plan_name = "free"
            
        return response, plan_name
    
    def get_title_name(self, url):
        html = self.session.get(url).content # .textだと文字化けする
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.find('span', id='bch-series-title').a.text
        return text
    
    def get_signle_title_json(self, url):        
        html = self.session.get(url).text
        
        soup = BeautifulSoup(html, "html.parser")
        
        script_tags = soup.find_all("script")
        script_content = "\n".join(tag.string for tag in script_tags if tag.string)
        
        match1 = re.search(r'var\s+titleInfo\s*=\s*(\{.*?\});', script_content, re.DOTALL)
        match2 = re.search(r'var\s+_STORY_ID\s*=\s*(\d+);', script_content)
        if match1:
            title_info_json = match1.group(1)
            return title_info_json, match2.group(1)
        
    def check_single_episode(self, url):
        return bool(re.match(r"https://www\.b-ch\.com/titles/\d+/\d+$", url))
        
    def get_title_id(self, url):
        path_parts = urlparse(url).path.strip('/').split('/')
        if len(path_parts) > 1 and path_parts[0] == "titles":
            title_id = path_parts[1]
            #print(title_id)  # 出力: 1202
            return title_id
    
    def get_title_data(self, title_id):
        title_json = self.session.get(f"https://www.b-ch.com/json/titles/{title_id}.json").json()
        return title_json
    
    def get_manifest_list(self, title_id, episode_id, device_code, login_status, data_auth):
        try:
            if login_status:
                metainfo_url = f"https://pbifcd.b-ch.com/v1/playbackinfo/ST/{str(device_code)}/{str(title_id)}/{str(episode_id)}?mbssn_key="+self.session.cookie["BCHWWW"]
            else:
                metainfo_url = f"https://pbifcd.b-ch.com/v1/playbackinfo/ST/{str(device_code)}/{str(title_id)}/{str(episode_id)}?mbssn_key="
                            
            metainfo_json = self.session.get(metainfo_url, headers={"X-API-KEY": data_auth}).json()
            return True, metainfo_json
        except Exception as e:
            return False, None
        
    def download_segment(self, segment_links, config, unixtime, name, service_name="Bandai-Ch"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
        with open(os.path.join(config["directorys"]["Temp"], "content", unixtime, name), 'wb') as out_file:
            with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as progress_bar:
                for url in segment_links:
                    retry = 0
                    while retry < 3:
                        try:
                            response = self.session.get(url.strip(), timeout=10)
                            response.raise_for_status()
                            out_file.write(response.content)
                            progress_bar.update(1)
                            break
                        except requests.exceptions.RequestException as e:
                            retry += 1
                            time.sleep(2)

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Bandai-Ch"):
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
            "aac",                # 音声をAAC形式に変換
            "-b:a",
            "192k",               # 音声ビットレートを設定（192kbpsに調整）
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