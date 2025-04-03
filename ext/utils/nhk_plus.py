import re
import os
import jwt
import ast
import uuid
import m3u8
import base64
import random
import struct
import base64
import string
import requests
import subprocess
from tqdm import tqdm
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote, urljoin

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class NHKplus_license:
    def license_vd_ad(pssh, session, drm_token):
        _WVPROXY = "https://drm.npd.plus.nhk.jp/widevine/license"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers={"authorization": "Bearer "+ drm_token})
        response.raise_for_status()
        if response.text == "Possibly compromised client":
            print("THIS WVD IS NOT ALLOWED")
            #return None
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

class NHKplus_utils:
    def parse_private_key():
        # Haha! Crack from Moblie App.
        # NHK+ is suck
        
        encrypted_data = "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\n9LsiyQ==" # Crack from Moblie res/res.xml lol
        
        iv = base64.b64decode('3vh8IpHEcjJYUYhobRBcsQ==')  # IV
        key = base64.b64decode('tK1rb8W9cDAVvf1zKDXVYw==')  # Key
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
        
        header = "-----BEGIN RSA PRIVATE KEY-----\n"
        footer = "\n-----END RSA PRIVATE KEY-----"
        
        return_dec = decrypted.decode('utf-8')
        return_dec = header + return_dec + footer
                
        return return_dec
    
    def extract_nhk_ids(url):
        st_match = re.search(r"https?://plus\.nhk\.jp/watch/st/([^/?]+)", url)
        st_id = st_match.group(1) if st_match else None
        
        # playlist_id の部分を抽出 (UUID形式)
        playlist_match = re.search(r"playlist_id=([a-f0-9\-]{36})", url)
        playlist_id = playlist_match.group(1) if playlist_match else None
        
        return st_id, playlist_id
    
    def extract_nhk_id(url):
        st_match = re.search(r"https?://plus\.nhk\.jp/watch/st/([^/?]+)", url)
        st_id = st_match.group(1) if st_match else None
        
        return st_id
    
class NHKplus_decrypt:
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
            
        mp4decrypt_command.extend(
            [
                "--show-progress",
            ]
        )
        
        for key in keys:
            mp4decrypt_command.extend(
                [
                    "--key",
                    key[0],
                ]
            )
        return mp4decrypt_command
    def decrypt_all_content(keys, video_input_file, video_output_file, audio_input_file, audio_output_file, config, service_name="NHK+"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            NHKplus_decrypt.decrypt_content(keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            NHKplus_decrypt.decrypt_content(keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="NHK+"):
        mp4decrypt_command = NHKplus_decrypt.mp4decrypt(keys, config)
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

class NHKplus_tracks:
    def __init__(self):
        pass
    def find_moov_box(self, mp4_data):
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
    
    def parse_box(self, data, index=0):
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
    
    def remove_duplicates_and_count(self, tracks):
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
    
    def select_tracks(self, tracks):
        # ここでビットレートが一番高いやつを盗んでreturnで殴る
        highest_bitrate_video = max(tracks["video_track"], key=lambda x: x["bitrate"])
    
        # オーディオトラックのnameがmainのやつを引っ張る。 mainっていうのは主音声、subは副音声優先のやつらしい
        main_audio = next((audio for audio in tracks["audio_track"] if audio["name"] == "main"), None)
    
        return {
            "video": highest_bitrate_video,
            "audio": main_audio
        }
    
    
    def parse_m3u8(self, file_content):
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
            "audio_track": self.remove_duplicates_and_count(audio_tracks),  # 重複してるうやつをどか～ん
            "text_track": text_tracks,
        }
    
    def print_tracks(self, tracks):
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
        
        #print(output)
        return output
    def transform_metadata(self, manifests):
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
    
    def get_highest_bitrate_manifest(self, manifests):
        transformed = self.transform_metadata(manifests)
        if not transformed:
            return None
        return max(transformed, key=lambda x: x["bitrateLimit"])
            

class NHKplus_downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        self.common_headers = {
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Sec-GPC": "1",
            "Accept-Language": "ja;q=0.7",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Sec-CH-UA": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": "\"Windows\"",
            "Accept-Encoding": "gzip, deflate, br, zstd",
        }
    def authorize(self, email, password):
        try:
            # Step 1-5: Initial redirects and parameter extraction
            url = "https://pid.nhk.or.jp/account/update/info.do"
            for _ in range(5):  # Combined redirect handling
                response = self.session.get(url, headers=self.common_headers, allow_redirects=False)
                if response.status_code not in (301, 302):
                    break #exit the loop if there is no redirect
                url = response.headers["Location"]
                if "login.auth.nhkid.jp" in url: #special case for login redirect
                    break
                self.logger.debug(f"Redirect: {response.status_code} to {url}", extra={"service_name": "NHK+"}) #print redirect status
            else:
                raise Exception("Too many redirects or no redirect URL found.")
            
            if "login.auth.nhkid.jp" in url: #special case for login redirect
                parsed_url = urlparse(url)
                parameters = parse_qs(parsed_url.query)
                response_parameter = {key: value[0] for key, value in parameters.items()}
            else:
                raise Exception("Did not arrive at login URL")
            
            # Step 6: Initial Login Request
            url = "https://login.auth.nhkid.jp/auth/login"
            payload = {
                "AUTH_TYPE": "AUTH_OP",
                "SITE_ID": "co_site",
                "MESSAGE_AUTH": response_parameter["MESSAGE_AUTH"],
                "AUTHENTICATED": response_parameter["AUTHENTICATED"],
                "snsid": "undefined",
                "Fingerprint": str(uuid.uuid4())
            }
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://login.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
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
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 2: {response.status_code}", extra={"service_name": "NHK+"})

            if response.json()["resultCode"] != "CO-SC0003":
                raise Exception(f"Login failed: {response.json().get('resultMessage', 'Unknown error')}")

            # Step 8-11: Final redirects and data retrieval
            formatted_url = f"{urlparse(response.json()['authenticated']).scheme}://{urlparse(response.json()['authenticated']).netloc}{urlparse(response.json()['authenticated']).path}?{unquote(urlparse(response.json()['authenticated']).query)}"
            url = formatted_url
            for i in range(4):
                response = self.session.get(url, headers=self.common_headers, allow_redirects=False)
                if response.status_code not in (301, 302):
                    break #exit the loop if there is no redirect
                if i == 0:
                    url = "https://agree.auth.nhkid.jp"+response.headers["Location"]
                else:
                    url = response.headers["Location"]
                self.logger.debug(f"Redirect: {response.status_code} to {url}", extra={"service_name": "NHK+"}) #print redirect status
            else:
                raise Exception("Too many redirects or no redirect URL found.")

            find_soup = BeautifulSoup(response.text, "html.parser")
            token = find_soup.find("input", {"name": "t"})["value"]

            url = "https://pid.nhk.or.jp/pid26/repassword.do"
            payload = {"pass": password, "t": token}
            headers = self.common_headers.copy()
            headers.update({
                "Origin": "https://pid.nhk.or.jp",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://pid.nhk.or.jp/account/update/info.do",
            })
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Password reset check: {response.status_code}", extra={"service_name": "NHK+"})


            url = "https://pid.nhk.or.jp/pid23/getPCSummaryListAll3.do"
            response = self.session.get(url, headers=self.common_headers)
            self.logger.debug("GET USER INFO: "+str(response.text), extra={"service_name": "NHK+"})

            response = self.session.get("https://hh.pid.nhk.or.jp/pidh01/portal/getMemInfo.do?callback=USER_INFO")
            data = response.text.replace("true", "True")
            json_part = data[data.find("(") + 1: data.rfind(")")]
            parsed_json = ast.literal_eval(json_part)
            self.logger.debug("GET USER INFO2: "+str(parsed_json), extra={"service_name": "NHK+"})

            return True, parsed_json # Return the user info

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
        
        if additional_info[6] or additional_info[9]:
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