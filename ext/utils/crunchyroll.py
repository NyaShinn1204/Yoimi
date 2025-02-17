import re
import os
import uuid
import time
import random
import base64
import threading
import urllib.parse
from tqdm import tqdm
from lxml import etree
from datetime import datetime
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Crunchyroll_utils:
    def random_select_ua() -> str:
        android_version = str(random.randint(13, 15))
        okhttp_version = f"4.{random.randint(10, 12)}.{random.randint(0, 9)}"
        user_agent = f"Crunchyroll/3.74.2 Android/{android_version} okhttp/{okhttp_version}"
        return user_agent
    def find_guid_by_locale(data, locale):
        en_us_guid = None
        
        for version in data["versions"]:
            if version["audio_locale"] == locale:
                return version["guid"]
            if version["audio_locale"] == "en-US":
                en_us_guid = version["guid"]
        
        return en_us_guid
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
                    segment_file = media_template.replace('$Time$', str(current_time)).replace('$Number$', str(len(segment_list)))
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
    def license_vd_ad(pssh, session, token, id):
        _WVPROXY = "https://www.crunchyroll.com/license/v1/license/widevine"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
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
class Crunchyroll_downloader:
    def __init__(self, session):
        self.session = session
        self.language = "ja-JP"
    def authorize(self, email, password):
        retries = 0
        while retries < 3:
            try:
                self.session.headers = {
                    "Authorization": "Basic ZG1yeWZlc2NkYm90dWJldW56NXo6NU45aThPV2cyVmtNcm1oekNfNUNXekRLOG55SXo0QU0=",
                    "Connection": "Keep-Alive",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "ETP-Anonymous-ID": str(uuid.uuid4()),
                    "Host": "www.crunchyroll.com",
                    "User-Agent": Crunchyroll_utils.random_select_ua(),
                    "X-Datadog-Sampling-Priority": "0",
                }
                payload = {
                    "username": email,
                    "password": password,
                    "grant_type": "password",
                    "scope": "offline_access",
                    "device_id": str(uuid.uuid4()),
                    "device_name": "sdk_gphone64_x86_64",
                    "device_type": "Google sdk_gphone64_x86_64"
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
        
        return season_id_info
        #print("total episode:", season_id_info["total"])

    def download_segment(self, segment_links, config, unixtime, service_name="Dmm-TV"):
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
                        output_temp = os.path.join(base_temp_dir, os.path.basename(urllib.parse.urlparse(tsf).path))
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