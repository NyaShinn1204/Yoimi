import os
import re
import time
import string
import random
import subprocess
import threading
from tqdm import tqdm
from lxml import etree
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Jff_utils:
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
    
        # Define the namespace (extracted from the MPD file's root element)
        namespace = {'ns': 'urn:mpeg:dash:schema:mpd:2011'}
    
        # Extract all <Representation> elements
        representations = root.findall(".//ns:Representation", namespace)
    
        # Initialize lists for video and audio information
        video_list = []
        audio_list = []
    
        # Extract relevant attributes for each representation
        for elem in representations:
            rep_id = elem.attrib.get('id', '')
            bandwidth = int(elem.attrib.get('bandwidth', 0))
            codecs = elem.attrib.get('codecs', '')
            width = int(elem.attrib.get('width', 0)) if 'width' in elem.attrib else None
            height = int(elem.attrib.get('height', 0)) if 'height' in elem.attrib else None
    
            if rep_id.startswith("p0va0br"):
                video_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "width": width,
                    "height": height,
                    "codecs": codecs
                })
            elif rep_id.startswith("p0aa0br"):
                audio_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "codecs": codecs
                })
    
        # Return the classified lists with details
        return {
            "video_list": video_list,
            "audio_list": audio_list
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
            dict: セグメントリストのリストとビデオの総時間（秒）。セグメントリストが見つからない場合は空の辞書を返す。
        """
        try:
            tree = etree.fromstring(content)
            ns = {'dash': 'urn:mpeg:dash:schema:mpd:2011'}
    
            representation = tree.find(f'.//dash:Representation[@id="{representation_id}"]', ns)
            if representation is None:
                return {}
    
            adaptation_set = representation.find('..')
            segment_template = adaptation_set.find('dash:SegmentTemplate', ns) if adaptation_set is not None else None
            if segment_template is None:
                return {}
    
            segment_timeline = segment_template.find('dash:SegmentTimeline', ns)
            if segment_timeline is None:
                return {}
    
            media_template = segment_template.get('media')
            init_template = segment_template.get('initialization')
    
            media_template = media_template.replace('$RepresentationID$', representation_id)
            init_template = init_template.replace('$RepresentationID$', representation_id)
    
            segment_list = []
            segment_all = []
            segment_all.append(urljoin(url, init_template))
    
            current_time = 0
            total_duration = 0  # 総再生時間（秒）
    
            for segment in segment_timeline.findall('dash:S', ns):
                d_attr = segment.get('d')
                r_attr = segment.get('r')
                if not d_attr:
                    continue
                
                duration = int(d_attr)
                repeat_count = int(r_attr) + 1 if r_attr is not None else 1
    
                for _ in range(repeat_count):
                    segment_file = media_template.replace('$Time$', str(current_time))
                    segment_list.append(urljoin(url, segment_file))
                    segment_all.append(urljoin(url, segment_file))
                    current_time += duration
                    total_duration += int(d_attr)  # 総時間を加算
    
            init_url = urljoin(url, init_template)
    
            return {
                "init": init_url,
                "segments": segment_list,
                "all": segment_all,
                "total_duration": total_duration / 90000  # ミリ秒を秒に変換
            }
    
    
        except etree.ParseError:
            print("XML解析エラー")
            return {}
        except Exception as e:
            print(f"予期せぬエラーが発生しました: {e}")
            return {}

class Jff_license:
    def license_vd_ad(pssh, session, drm_key):
        _WVPROXY = "https://widevine-dash.ezdrm.com/widevine-php/widevine-foreignkey.php?pX=D6F9EE&key={}".format(drm_key) # pXは固定
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
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

class Jff_decrypt:
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Jff-Theator"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Jff_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Jff_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Jff-Theator"):
        mp4decrypt_command = Jff_decrypt.mp4decrypt(keys, config)
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

class Jff_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.common_headers = {
            "host": "www.jff.jpf.go.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
            "content-type": "application/json",
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.7",
            "origin": "https://www.jff.jpf.go.jp",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.jff.jpf.go.jp/mypage/register_account/",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
    def authorize(self, email_or_id, password):
        if email_or_id and password == None:
            status, info, temp_token = self.create_temp_account()
            return status, info, temp_token
        payload = {
          "username": email_or_id,
          "password": password
        }
        headers = self.common_headers.copy()
        sent_login_req = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        if sent_login_req.json()["message"] == "正常終了":
            pass
        else:
            return False, None, None
        
        temp_token = sent_login_req.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json(), temp_token
        
    def create_temp_account(self):
        def random_string(length):
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        def generate_username():
            return str(int(time.time() * 1000))+random_string(6) # not support "_"
        
        def generate_password():
            return str(random.randint(0,9))+random_string(7)+"YO!M!"
        
        username = generate_username()
        password = generate_password()
        
        querystring = { "lang": "ja" }
        
        payload = {
            "nickName": username,
            "email": random_string(10)+"@Yoimi.net",
            "password": password,
            "passwordConfirm": password,
            "country": "jp",
            "newsLetter": "ja",
            "informationCountry1": "",
            "informationCountry2": "",
            "informationCountry3": ""
        }
        
        send_create_req = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts", json=payload, headers=self.common_headers, params=querystring)
        
        temp_key = send_create_req.json()["data"]["temporaryKey"]
        headers = self.common_headers.copy()
        headers.update({
            "referer": "https://www.jff.jpf.go.jp/mypage/definitive_register_account/?key="+temp_key,
        })
        payload = { "key": temp_key }
        apply_email_verify = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        #print(apply_email_verify.json()["message"])
        if apply_email_verify.json()["message"] == "正常終了":
            pass
        else:
            return False, None, None
        
        temp_token = apply_email_verify.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json(), temp_token
    
    def get_content_info(self, url):
        response = self.session.get("https://www.jff.jpf.go.jp/jff-api/contents")
        content_list = response.json().get("data", [])
    
        matched_content = next(
            (single for single in content_list if single.get("detailUrl") and single["detailUrl"] in url),
            None
        )
    
        if matched_content:
            content_code = matched_content.get("contentsCode")
            if content_code:
                single_content_info = self.session.get(f"https://www.jff.jpf.go.jp/jff-api/contents/{content_code}")
                return True, single_content_info.json().get("data")
        
        return False, None
            
    def check_play_ep(self, ep_id):
        drm_info = self.session.get(f"https://www.jff.jpf.go.jp/jff-api/contents/{ep_id}/drm").json()
        if drm_info["data"]["message"] == None:
            if drm_info["data"]["status"] == "outsideArea":
                message = "Region Lock"
                return False, message
            elif drm_info["data"]["status"] == "viewable":
                return True, drm_info
            else:
                return False, drm_info["data"]["message"]
        else:
            return False, drm_info["data"]["message"]
        
    def download_segment(self, segment_links, config, unixtime, service_name="Jff-Theator"):
        downloaded_files = []
        try:
            # Define the base temp directory
            base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
            os.makedirs(base_temp_dir, exist_ok=True)
    
            # Progress bar setup
            progress_lock = threading.Lock()  # Ensure thread-safe progress bar updates
            with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", ascii=True, unit='file') as pbar:
                
                # Thread pool for concurrent downloads
                with ThreadPoolExecutor(max_workers=8) as executor:
                    future_to_url = {}
                    
                    # Submit download tasks
                    for tsf in segment_links:
                        output_temp = os.path.join(base_temp_dir, os.path.basename(tsf.replace("?cfr=4%2F15015", "")))
                        future = executor.submit(self._download_and_save, tsf, output_temp)
                        future_to_url[future] = output_temp
    
                    # Process completed futures
                    for future in as_completed(future_to_url):
                        output_temp = future_to_url[future]
                        try:
                            result = future.result()
                            if result:
                                downloaded_files.append(output_temp)
                        except Exception as e:
                            print(f"Error downloading {output_temp}: {e}")
                        finally:
                            with progress_lock:
                                pbar.update()
    
        except KeyboardInterrupt:
            print('User pressed CTRL+C, cleaning up...')
            return None
    
        return downloaded_files

    def download_segment(self, segment_links, config, unixtime, name, service_name="Jff-Theator"):
        import requests
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
    
    def _download_and_save(self, url, output_path):
        """
        Helper function to download a segment and save it to a file.
        """
        try:
            with open(output_path, 'wb') as outf:
                vid = self.session.get(url).content  # Download the segment
                # vid = self._aes.decrypt(vid.content)  # Uncomment if decryption is needed
                outf.write(vid)  # Write the content to file
            return True
        except Exception as err:
            print(f"Error saving {output_path}: {err}")
            return False
    
    
    def merge_m4s_files(self, input_files, output_file, service_name="Jff-Theator"):
        """
        m4sファイルを結合して1つの動画ファイルにする関数
        
        Args:
            input_files (list): 結合するm4sファイルのリスト
            output_file (str): 出力する結合済みのファイル名
        """
        total_files = len(input_files)
        
        # バイナリモードでファイルを結合
        with open(output_file, "wb") as outfile:
            with tqdm(total=total_files, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                for i, f in enumerate(input_files, start=1):
                    with open(f, "rb") as infile:
                        outfile.write(infile.read())
                    pbar.set_postfix(file=f, refresh=True)
                    pbar.update(1)
        
        # 結合完了メッセージ
        #print(f"結合が完了しました: {output_file}")
        return True
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, duration, title_name_logger, episode_number, additional_info, service_name="Jff-Theator"):
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