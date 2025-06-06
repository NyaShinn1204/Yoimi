import re
import os
import uuid
import time
import random
import base64
import requests
import subprocess
from tqdm import tqdm
from lxml import etree
from datetime import datetime
from urllib.parse import urljoin

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Crunchyroll_utils:
    def find_guid_by_locale(data, locale):
        en_us_guid = None
        
        for version in data["versions"]:
            if version["audio_locale"] == locale:
                return version["guid"]
            if version["audio_locale"] == "en-US":
                en_us_guid = version["guid"]
        
        return en_us_guid
    def find_locale_by_guid(data, guid):
        for version in data:
            if version["guid"] == guid:
                return version["audio_locale"]
        return None
    def parse_mpd_logic(content):
        try:
            # Ensure the content is in bytes
            if isinstance(content, str):
                content = content.encode('utf-8')
    
            # Parse XML
            root = etree.fromstring(content)
            namespaces = {
                'mpd': 'urn:mpeg:dash:schema:mpd:2011',
                'cenc': 'urn:mpeg:cenc:2013'
            }
    
            # Extract video information
            videos = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    videos.append({
                        'resolution': f"{representation.get('width')}x{representation.get('height')}",
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract audio information
            audios = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    audios.append({
                        'audioSamplingRate': representation.get('audioSamplingRate'),
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract PSSH values
            pssh_list = []
            for content_protection in root.findall('.//mpd:ContentProtection', namespaces):
                pssh_element = content_protection.find('cenc:pssh', namespaces)
                if pssh_element is not None:
                    pssh_list.append(pssh_element.text)
    
            # Build the result
            result = {
                "main_content": content.decode('utf-8'),
                "pssh": pssh_list
            }
    
            return result
    
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid MPD content: {e}")
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred: {e}")
    def parse_mpd_content(mpd_content):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        else:
            content = mpd_content
    
        root = etree.fromstring(content)
        namespace = {'ns': 'urn:mpeg:dash:schema:mpd:2011'}
        representations = root.findall(".//ns:Representation", namespace)
        
        video_list = []
        audio_list = []
        
        for elem in representations:
            rep_id = elem.attrib.get('id', '')
            bandwidth = int(elem.attrib.get('bandwidth', 0))
            codecs = elem.attrib.get('codecs', '')
            width = int(elem.attrib.get('width', 0)) if 'width' in elem.attrib else None
            height = int(elem.attrib.get('height', 0)) if 'height' in elem.attrib else None
            base_url_elem = elem.find("ns:BaseURL", namespace)
            base_url = base_url_elem.text.strip() if base_url_elem is not None else None
    
            if "v1" in rep_id:
                video_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "width": width,
                    "height": height,
                    "codecs": codecs,
                    "base_url": base_url
                })
            elif "a1" in rep_id:
                audio_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "codecs": codecs,
                    "base_url": base_url
                })
        
        highest_video = max(video_list, key=lambda x: x['bandwidth'], default=None)
        highest_audio = max(audio_list, key=lambda x: x['bandwidth'], default=None)
        
        return {
            "video": highest_video,
            "audio": highest_audio
        }
    def get_segment_link_list(mpd_content, representation_id, url):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        else:
            content = mpd_content
        """
        MPDコンテンツから指定されたRepresentation IDに対応するSegmentTemplateのリストを取得する。
    
        Args:
            mpd_content (str): MPDファイルのXMLコンテンツ。
            representation_id (str): 抽出したいRepresentation ID。
            url (str) : mpdファイルのURL
    
        Returns:
            dict: セグメントリストのリスト。セグメントリストが見つからない場合は空の辞書を返す。
        """
        try:
            tree = etree.fromstring(content)
            # 名前空間を設定
            ns = {'dash': 'urn:mpeg:dash:schema:mpd:2011'}
    
            # 指定されたRepresentation IDを持つRepresentation要素を探す
            representation = tree.find(f'.//dash:Representation[@id="{representation_id}"]', ns)
            if representation is None:
              return {}
    
            # 親のAdaptationSet要素を見つける
            adaptation_set = representation.find('..')
    
            # そのAdaptationSetの子要素であるSegmentTemplateを探す
            segment_template = adaptation_set.find('dash:SegmentTemplate', ns)
            if segment_template is None:
              return {}
    
            segment_timeline = segment_template.find('dash:SegmentTimeline', ns)
            if segment_timeline is None:
              return {}
    
            media_template = segment_template.get('media')
            init_template = segment_template.get('initialization')
            
            # テンプレート文字列の $RepresentationID$ を実際のIDに置換
            media_template = media_template.replace('$RepresentationID$', representation_id)
            init_template = init_template.replace('$RepresentationID$', representation_id)
            
            # セグメントリストの構築
            segment_list = []
            segment_all = []
            segment_all.append(urljoin(url, init_template))
            current_time = 0
            for segment in segment_timeline.findall('dash:S', ns):
                d_attr = segment.get('d')
                r_attr = segment.get('r')
                if not d_attr:
                    continue
                duration = int(d_attr)
                
                repeat_count = 1
                if r_attr is not None:
                    repeat_count = int(r_attr) + 1
    
                for _ in range(repeat_count):
                    segment_file = media_template.replace('$Time$', str(current_time)).replace('$Number$', str(len(segment_list)+1)) # segmentは0始まりじゃなくて1始まりなのでこれでurlを調整
                    segment_list.append(urljoin(url, segment_file))
                    segment_all.append(urljoin(url, segment_file))
                    current_time += duration
    
    
            init_url = urljoin(url, init_template)
    
    
            return {"init": init_url, "segments": segment_list, "all": segment_all}
    
        except etree.ParseError:
            print("XML解析エラー")
            return {}
        except Exception as e:
            print(f"予期せぬエラーが発生しました: {e}")
            return {}
class Crunchyroll_license:
    def license_vd_ad(pssh, session, token, id, config):
        _WVPROXY = "https://www.crunchyroll.com/license/v1/license/widevine"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        headers = {
            "content-type": "application/octet-stream",
            "origin": "https://static.crunchyroll.com",
            "referer": "https://static.crunchyroll.com/",
            "x-cr-video-token": token,
            "x-cr-content-id": id
        }
        response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers=headers)
        response.raise_for_status()
    
        cdm.parse_license(session_id, base64.b64decode(response.json()["license"]))
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]
    
        cdm.close(session_id)
                
        keys = {
            "key": keys,
        }
        
        return keys
class Crunchyroll_decrypt:
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Crunchyroll"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Crunchyroll_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Crunchyroll_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Crunchyroll"):
        mp4decrypt_command = Crunchyroll_decrypt.mp4decrypt(keys, config)
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
class Crunchyroll_downloader:
    def __init__(self, session):
        self.session = session
        self.language = "ja-JP"
    def authorize(self, email, password):
        retries = 0
        while retries < 3:
            try:
                self.session.headers = {
                    "Connection": "Keep-Alive",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "ETP-Anonymous-ID": str(uuid.uuid4()),
                    "Host": "www.crunchyroll.com",
                    "User-Agent": "Crunchyroll/deviceType: ANDROIDTV; appVersion: defaultUserAgent; osVersion: 16; model: AOSP TV on x86; manufacturer: Google; brand: google",
                    "X-Datadog-Sampling-Priority": "0",
                }
                payload = {
                    "username": email,
                    "password": password,
                    "grant_type": "password",
                    "scope": "offline_access",
                    "device_id": str(uuid.uuid4()),
                    "device_name": "emulator_x86_arm",
                    "device_type": "ANDROIDTV",
                    "client_id": "ty7y4elumwpo9a3fjzx9",
                    "client_secret": "iwI2U1qBCg3cC96e5ZmXDDd0-ioFk26m"
                }
                response = self.session.post('https://www.crunchyroll.com/auth/v1/token', data=payload)
                if response.status_code == 200:
                    token = response.json()["access_token"]
                    if token:
                        self.session.headers["Authorization"] = f"Bearer {token}"
                        user_info = self.get_account_info()
                        return True, user_info
                    return None
                if response.status_code == 401:
                    print(f"Invalid credentials. {response.text}")
                    return None
                if response.status_code == 500:
                    print(f"Internal server error. {response.text}")
                    return None
                
                if response.status_code == 403:
                    print("Flagged IP address.")
                    return None
                
                if response.status_code == 429:
                    retries += 1
                    print(f"Rate limited, retrying with new proxy (Attempt {retries}/3)")
                    time.sleep(2)
                    continue
                
                return None
                
            except Exception as e:
                print(f"Catch Error: {e}")
                retries += 1
                if retries < 3:
                    time.sleep(2)
                    continue
        return None
    def login_check(self):
        response = self.session.get("https://www.crunchyroll.com/", allow_redirects=False)
        try:
            if response.headers["Location"] == "/currently-unavailable-in-your-location":
                return False, "Location blocked"
            else:
                return True, None
        except:
            return True, None
    def get_account_info(self):
        user_info = self.session.get("https://www.crunchyroll.com/accounts/v1/me").json()
        return user_info
    
    def get_info(self, url):
        match = re.search(r'"?https?://www\.crunchyroll\.com/series/([^/"]+)', url)
        self.series_content_id = match.group(1) if match else None
        
        #copyright_info = self.session.get(f"https://static.crunchyroll.com/copyright/{self.series_content_id}.json").json()
        default_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/series/{self.series_content_id}?preferred_audio_language=en-US&locale=en-US").json()
        seasons_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/series/{self.series_content_id}/seasons?force_locale=&preferred_audio_language=en-US&locale=en-US").json()
        
        self.season_content_id = Crunchyroll_utils.find_guid_by_locale(seasons_info["data"][0], self.language)
        
        season_id_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/seasons/{self.season_content_id}/episodes?preferred_audio_language=en-US&locale=en-US").json()
        
        return season_id_info, default_info
        #print("total episode:", season_id_info["total"])
        
    def get_single_info(self, id):
        single_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/objects/{id}?ratings=true&locale=en-US").json()
        
        return single_info

    def download_segment(self, segment_links, config, unixtime, name, service_name="Crunchyroll"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
        with open(os.path.join(config["directorys"]["Temp"], "content", unixtime, name), 'wb') as out_file:
            with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as progress_bar:
                for url in segment_links:
                    retry = 0
                    while retry < 3:
                        try:
                            response = requests.get(url.strip(), timeout=10)
                            response.raise_for_status()
                            out_file.write(response.content)
                            progress_bar.update(1)
                            break
                        except requests.exceptions.RequestException as e:
                            retry += 1
                            time.sleep(2)
                            
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Crunchyroll"):
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
            
    def generate_random_token(self):
        payload = "grant_type=client_id&scope=offline_access&client_id=ty7y4elumwpo9a3fjzx9&client_secret=iwI2U1qBCg3cC96e5ZmXDDd0-ioFk26m"
        headers = {
            "etp-anonymous-id": str(uuid.uuid4()),
            "user-agent": "Crunchyroll/deviceType: ANDROIDTV; appVersion: defaultUserAgent; osVersion: 16; model: AOSP TV on x86; manufacturer: Google; brand: google",
            "accept": "application/json",
            "accept-charset": "UTF-8",
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            "host": "www.crunchyroll.com",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        response2 = self.session.post("https://www.crunchyroll.com/auth/v1/token", data=payload, headers=headers)
        update_token = response2.json()["access_token"]
        self.session.headers.update({"Authorization": "Bearer "+update_token})
        return True, response2.json()
    #def update_token(self):
    #    response1 = self.session.post("https://www.crunchyroll.com/auth/v1/token", data=f"device_id={str(uuid.uuid4())}&device_type=Chrome%20on%20Windows&grant_type=etp_rt_cookie", headers={"Authorization": "Basic bm9haWhkZXZtXzZpeWcwYThsMHE6"})
    #    response2 = self.session.post("https://www.crunchyroll.com/auth/v1/token", data=f"grant_type=client_id", headers={"Authorization": "Basic Y3Jfd2ViOg=="})
    #    update_token = response2.json()["access_token"]
    #    self.session.headers.update({"Authorization": "Bearer "+update_token})
    #    return True