import re
import os
import jwt
import time
import subprocess
from lxml import etree
from tqdm import tqdm
from bs4 import BeautifulSoup
from datetime import datetime

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class mpd_parse:
    @staticmethod
    def extract_video_info(mpd_content, value):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = etree.fromstring(content)
    
        for adaptation_set in root.findall('.//AdaptationSet', namespaces):
            content_type = adaptation_set.get('mimeType', '')
            
            if content_type == 'video/mp4':  # Ensure we're looking at the video AdaptationSet
                for representation in adaptation_set.findall('Representation', namespaces):
                    width = representation.get('width')
                    height = representation.get('height')
                    codecs = representation.get('codecs')
                    resolution = f"{width}x{height} mp4 {codecs}"
                    
                    if resolution == value:  # Matching the resolution
                        base_url_element = representation.find('BaseURL', namespaces)
                        base_url = base_url_element.text if base_url_element is not None else None
                        
                        # Find the pssh for the current AdaptationSet
                        pssh_elements = adaptation_set.findall('ContentProtection', namespaces)
                        pssh_list = []
                        for pssh_element in pssh_elements:
                            pssh = pssh_element.find('cenc:pssh', namespaces)
                            if pssh is not None:
                                pssh_list.append(pssh.text)
                        return {"pssh": pssh_list, "base_url": base_url}
        return None

    @staticmethod
    def extract_audio_info(mpd_content, value):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = etree.fromstring(content)
    
        # Split the value into separate components (audio_sampling_rate, mimeType, and codecs)
        audio_sampling_rate, mime_type, codecs = value.split()
    
        # Find the audio AdaptationSet
        audio_adaptation_set = root.find(".//AdaptationSet[@mimeType='audio/mp4']", namespaces)
    
        if audio_adaptation_set is not None:
            for representation in audio_adaptation_set.findall('Representation', namespaces):
                # Check if the audioSamplingRate and codecs match
                if (representation.get('audioSamplingRate') == audio_sampling_rate and 
                    representation.get('codecs') == codecs):
                    
                    base_url_element = representation.find('BaseURL', namespaces)
                    base_url = base_url_element.text if base_url_element is not None else None
                    
                    # Find the pssh for the current AdaptationSet
                    pssh_elements = audio_adaptation_set.findall('ContentProtection', namespaces)
                    pssh_list = []
                    for pssh_element in pssh_elements:
                        pssh = pssh_element.find('cenc:pssh', namespaces)
                        if pssh is not None:
                            pssh_list.append(pssh.text)
                    return {"pssh": pssh_list, "base_url": base_url}
    
        return None
    
    @staticmethod
    def get_resolutions(mpd_content):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        # 名前空間の定義
        namespace = {'ns': 'urn:mpeg:dash:schema:mpd:2011'}
        
        # MPDテキストを解析
        try:
            root = etree.fromstring(content)
        except etree.ParseError as e:
            print(f"XML Parse Error: {e}")
            return []
        
        # 結果を格納するリスト
        video_representations = []
        bandwidth_list = []
        
        # 映像の AdaptationSet をフィルタリング
        for adaptation_set in root.findall(".//ns:AdaptationSet", namespace):
            mime_type = adaptation_set.get("mimeType")
            if mime_type == "video/mp4":  # 映像のみ
                for representation in adaptation_set.findall("ns:Representation", namespace):
                    # 幅、高さ、コーデックを取得
                    width = representation.get("width")
                    height = representation.get("height")
                    codecs = representation.get("codecs")
                    bandwidth = representation.get("bandwidth")
                    
                    # 映像の情報をリストに追加
                    if width and height and codecs:
                        info = f"{width}x{height} {mime_type.split('/')[-1]} {codecs}"
                        info_b = bandwidth
                        video_representations.append(info)
                        bandwidth_list.append(info_b)
        
        return video_representations, bandwidth_list
    @staticmethod
    def get_duration(mpd_content):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        # MPDテキストを解析
        try:
            root = etree.fromstring(content)
        except etree.ParseError as e:
            print(f"XML Parse Error: {e}")
            return None
        
        # `mediaPresentationDuration` を取得
        duration = root.get("mediaPresentationDuration")
        if not duration:
            print("Duration attribute not found.")
            return None
        
        # ISO 8601 形式の時間を解析
        import re
        pattern = re.compile(r'PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?')
        match = pattern.match(duration)
        if not match:
            print("Invalid duration format.")
            return None
        
        hours = int(match.group(1)) if match.group(1) else 0
        minutes = int(match.group(2)) if match.group(2) else 0
        seconds = float(match.group(3)) if match.group(3) else 0.0
        
        # 総秒数を計算
        total_seconds = hours * 3600 + minutes * 60 + seconds
        return str(int(total_seconds))

class FOD_utils:
    def check_single_episode(url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)

        def contains_repeated_identifier(url, identifier):
            # identifierが2回連続して現れるか確認
            pattern = f"({re.escape(identifier)}).*\\1"
            return bool(re.search(pattern, url))
                
        if contains_repeated_identifier(url, matches_url.group("title_id")):
            #print("True")
            return True
        else:
            #print("False")
            return False
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

class FOD_downloader:
    def __init__(self, session):
        self.session = session
        self.web_headers = {}
    def authorize(self, email, password):
        global user_info_res, login_status
        #_AUTH_MAIN_PAGE = "https://fod.fujitv.co.jp/auth/login/"
        #_AUTH_TEST_1 = "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth"
        _AUTH_USER_STATUS = "https://fod-sp.fujitv.co.jp/apps/api/user/status/?dv_type=tv"
        #_AUTH_SENT_CODE = "https://fod.fujitv.co.jp/renew/auth/mail_auth/?p=1&ac={code}"
        #_AUTH_REDIRECT_URL = "https://fod.fujitv.co.jp/loginredir?r="
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        #default_headers = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "upgrade-insecure-requests": "1",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "none",
        #    "sec-fetch-mode": "navigate",
        #    "sec-fetch-user": "?1",
        #    "sec-fetch-dest": "document",
        #    "accept-encoding": "gzip, deflate, br, zstd"
        #}
        temp_token = self.gen_crack_token()
        
        default_headers = {
            "content-type": "application/json",
            #"tracestate": "2646341@nr=0-2-2646341-637044554-f81d5a7a52304394----1746885957369",
            #"traceparent": "00-23127e81b01f47d1b9a63ca4ece6678e-f81d5a7a52304394-00",
            #"newrelic": "eyJ2IjpbMCwyXSwiZCI6eyJ0eSI6Ik1vYmlsZSIsImFjIjoiMjY0NjM0MSIsImFwIjoiNjM3MDQ0NTU0IiwidHIiOiIyMzEyN2U4MWIwMWY0N2QxYjlhNjNjYTRlY2U2Njc4ZSIsImlkIjoiZjgxZDVhN2E1MjMwNDM5NCIsInRpIjoxNzQ2ODg1OTU3MzY5LCJ0ayI6IjI2NDYzNDEifX0=",
            "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0",
            "x-authorization": "Bearer "+temp_token,
            #"x-newrelic-id": "VgADV1VXCRAGV1ZSAwUCU1A="
        }
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "FOD require email and password", None
            
        payload = {
            "mail_address": email,
            "password": password
        }    
        
        response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        response.raise_for_status()
        
        email_verify_hashkey = response.json()["hash_key"]
        #response = self.session.get("https://fod.fujitv.co.jp/auth/login/", headers=default_headers)
        #response.raise_for_status()
        #soup = BeautifulSoup(response.text, "html.parser")
        #viewstate = soup.find("input", {"name": "__VIEWSTATE"})["value"]
        #viewstategenerator = soup.find("input", {"name": "__VIEWSTATEGENERATOR"})["value"]
        # 
        #payload = {
        #    "__VIEWSTATE": viewstate,
        #    "__VIEWSTATEGENERATOR": viewstategenerator,
        #    "email": email,
        #    "password": password,
        #    "ctl00$ContentMain$hdnServerEnv": "",
        #    "ctl00$ContentMain$hdnFodMail": email,
        #    "ctl00$ContentMain$hdnFodPass": password,
        #    "ctl00$ContentMain$hdnFodLogin": "",
        #    "ctl00$ContentMain$hdnAmazonSignature": "xUOgugvm8yRVgfHrD1pgITydjpHWNJU8622JOK2pVh3h7mIFzuIy7SQHWTHmxjCQOXMZEL6SY1O4JEtjwS2Q+Xc455EZMwnHOJq6aZ+rx4yuEWFEdKxFM8n5j40JA3pqrcfbC/WnySQDEIqKuzPVtAmtC2IvDAPDAEmo+ieNa/ExDkzp7R1v5anxmDsYeU2+UwiAXvRLjax2RPm7vsyOA5FIliOePMIhZcv9p9fmbBsgxBvMWD7KsxX7NpH/uay7XpFiVqzoO2CabtyW0GkyHyuKPM8Zl3qAtjoxakc3dQze1nmSaQdyQtyk9j5XIRBMpRH3q478WuVBr/o3EI/Cqg==",
        #    "ctl00$ContentMain$hdnAmazonPayload": "{\"storeId\":\"amzn1.application-oa2-client.0fa212ac2e9e494197af4fc8b09d096e\",\"webCheckoutDetails\":{\"checkoutReviewReturnUrl\":\"https://fod.fujitv.co.jp/\"},\"chargePermissionType\":\"Recurring\",\"recurringMetadata\":{\"frequency\":{\"unit\":\"Month\",\"value\":1},\"amount\":{\"amount\":0,\"currencyCode\":\"JPY\"}}}",
        #    "ctl00$ContentMain$btnFodId": ""
        #}
        #headers = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "cache-control": "max-age=0",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "origin": "https://fod.fujitv.co.jp",
        #    "content-type": "application/x-www-form-urlencoded",
        #    "upgrade-insecure-requests": "1",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "navigate",
        #    "sec-fetch-user": "?1",
        #    "sec-fetch-dest": "document",
        #    "referer": "https://fod.fujitv.co.jp/auth/login/",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #find_redirecturl = self.session.post(_AUTH_MAIN_PAGE, data=payload, headers=headers, allow_redirects=False)
        #    
        #if find_redirecturl.status_code == 302:
        #    #print("[+] Get Redirect URL: "+find_redirecturl.headers["Location"])
        #    pass
        #else:
        #    return False, "Authentication Failed: Redirect URL Not found", None
        #
        #sent_mailcode = self.session.get(find_redirecturl.headers["Location"], headers=headers)
        #    
        #if sent_mailcode.status_code == 200:
        #    pass
        #else:
        #    return False, "Authentication Failed: Email sent was failed", None
        #
        #get_loginredir = self.session.get(_AUTH_TEST_1, headers=headers)
        #
        #if get_loginredir.status_code == 200:
        #    #print("[+] loginredir headers: ", response.headers)
        #    #print("[+] loginredir!")
        #    #print(get_loginredir.cookies.get("UT"))
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get loginredir", None
        #
        #headers_xauth = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "application/json, text/plain, */*",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "x-authorization": "Bearer "+get_loginredir.cookies.get("UT"),
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "cors",
        #    "sec-fetch-dest": "empty",
        #    "referer": "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #
        #get_user_status_1 = self.session.get(_AUTH_USER_STATUS, headers=headers_xauth)
        #
        #if get_user_status_1.status_code == 200:
        #    #print("[+] user_status_1: "+response.text)
        #    pass
        #else:
        #    #print(response.status_code)
        #    return False, "Authentication Failed: Failed to get user_status_1", None
        #
        mail_auth_code = input("MAIL AUTH CODE : ")
        if mail_auth_code == None:
            return False, "Authentication Failed: Require Mail Auth Code", None
        else:
            pass
        
        payload = {
            "auth_code": str(mail_auth_code),
            "hash_key": email_verify_hashkey
        }
        login_status = self.session.post("https://id.fod.fujitv.co.jp/api/member/CheckAuthCodeApp", headers=default_headers, json=payload)
        login_status.raise_for_status()
        
        fodid_login_token = login_status.json()["fodid_login_token"]
        #self.session.headers.update({"x-authorization": "Bearer "+fodid_login_token})
        
        default_headers["host"] = "fod-sp.fujitv.co.jp"
        
        payload = {
            "fodid_login_token": fodid_login_token
        }
        check_token_status = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_token/", headers=default_headers, json=payload)
        check_token_status.raise_for_status()
        
        uid = check_token_status.json()["uid"]
        
        login_token = self.re_generate_login_token(uid)
        
        
        default_headers["x-authorization"] = "Bearer "+login_token
        self.session.headers.update({"x-authorization": "Bearer "+login_token})
        
        #
        #login_status_1 = self.session.get(_AUTH_SENT_CODE.format(code=mail_auth_code), headers=headers)
        #
        #if login_status_1.status_code == 200:
        #    #print("[+] login_status_1: "+login_status_1.text)
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get login_status_1", None
        #    
        #get_temp_token = self.session.get(_AUTH_REDIRECT_URL, headers=headers)
        #
        #if get_temp_token.status_code == 200:
        #    #print("[+] login headers: ", response.headers)
        #    #print("[+] Get Temp token: ", response.cookies.get("UT"))
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get Temp Token", None
        #
        #headers_xauth = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "application/json, text/plain, */*",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "X-Authorization": "Bearer "+get_temp_token.cookies.get("UT"),
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "cors",
        #    "sec-fetch-dest": "empty",
        #    "referer": "https://fod.fujitv.co.jp/loginredir?r=",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #    
        user_info_res = self.session.get(_AUTH_USER_STATUS, headers=default_headers)
        
        if user_info_res.status_code == 200:
            #print("[+] user_status_2: "+response.text)
            #print("[+] GET REAL TOKEN!!!: ", response.cookies.get("UT"))
            #pass
            #self.session.headers.update({'x-authorization': 'Bearer ' + user_info_res.cookies.get("UT")})
            self.web_headers = {
                "x-authorization": "Bearer "+login_token,
                "host": "fod-sp.fujitv.co.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.12.0",
            }
            #self.web_headers = headers_xauth
            self.web_headers["referer"] = "https://fod.fujitv.co.jp/"
            self.web_headers["origin"] = "https://fod.fujitv.co.jp"
            self.web_headers["host"] = "i.fod.fujitv.co.jp"
            self.web_headers["sec-fetch-site"] = "same-site"
            #self.web_headers["X-Authorization"] = "Bearer " + get_loginredir.cookies.get("CT")
            login_status = True
            return True, user_info_res.json(), user_info_res.cookies.get("uuid")
        else:
            return False, "Authentication Failed: Failed to get user_status_2", None
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
    def re_generate_login_token(self, uid):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx"
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
    def gen_temptoken(self):
        global login_status
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
            "host": "fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.9",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/loginredir?r=",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
        self.session.headers.update({'X-Authorization': 'Bearer ' + jwt_token})
        self.web_headers = headers_xauth
        self.web_headers["referer"] = "https://fod.fujitv.co.jp/"
        self.web_headers["origin"] = "https://fod.fujitv.co.jp"
        self.web_headers["host"] = "i.fod.fujitv.co.jp"
        self.web_headers["sec-fetch-site"] = "same-site"
        self.web_headers["X-Authorization"] = "Bearer " + jwt_token
        login_status = False
        return True, None

    def get_title_parse_single(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/episode/detail/?ep_id={matches_url.group("episode_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
            return_json = metadata_response.json()
            if return_json != None:
                metadata_response_single = return_json
                return True, metadata_response_single, [metadata_response_single["coin"], metadata_response_single["price"]]
            else:
                return False, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
    def get_title_parse_all(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
            return_json = metadata_response.json()
            if return_json["episodes"] != None:
                return True, return_json["episodes"], return_json["detail"]
            else:
                return False, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
    def get_id_type(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''映像タイプを取得するコード'''
        try:   
            #print(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false")
            
            #print(self.web_headers)
            #print("aaa", self.session.headers)
            if matches_url.group("episode_id"):
                metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/episode/detail/?ep_id={matches_url.group("episode_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
                #print(metadata_response.text)
                return_json = metadata_response.json()
                if return_json["genre"] != None:
                    maybe_genre = None
                    
                    if return_json["genre"]["genre_name"].__contains__("アニメ"):
                        maybe_genre = "ノーマルアニメ"
                    elif return_json["genre"]["genre_eng_name"].__contains__("anime"):
                        maybe_genre = "ノーマルアニメ"
                    elif return_json["genre"]["genre_name"].__contains__("映画"):
                        maybe_genre = "劇場"
                    elif return_json["genre"]["genre_eng_name"].__contains__("movie"):
                        maybe_genre = "劇場"
                    else:
                        maybe_genre = "劇場"
                    
                    return True, [return_json["genre"], maybe_genre]
                else:
                    return False, None
            else:
                metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
                #print(metadata_response.text)
                return_json = metadata_response.json()
                if return_json["detail"] != None:
                    maybe_genre = None
                    
                    if return_json["detail"]["attribute"].__contains__("映画"):
                        maybe_genre = "劇場"
                    elif return_json["detail"]["attribute"].__contains__("エピソード"):
                        maybe_genre = "ノーマルアニメ"
                    else:
                        maybe_genre = "ノーマルアニメ"
                    
                    return True, [return_json["detail"]["attribute"], maybe_genre]
                else:
                    return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_mpd_content(self, uuid, url, ut):
        global mpd_content_response
        tries = 3
        
        #device_code = "web"
        device_code = "tv_common/"
        #base_url = "https://fod.fujitv.co.jp/apps/api/1/auth/contents"
        base_url = "https://fod-sp.fujitv.co.jp/apps/api/auth/contents"
        #base_host = "fod.fujitv.co.jp"
        base_host = "fod-sp.fujitv.co.jp"
        
        for attempt in range(tries):
            try:
                if ut == None:
                    response = self.session.get(url)
                    ut = response.cookies.get("CT")
                
                
                unixtime = str(int(time.time() * 1000))
                matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
                self.web_headers["X-Authorization"] = "Bearer "+ut
                self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
                self.web_headers["host"] = base_host
                self.web_headers["sec-fetch-site"] = "same-origin"
                #print(self.web_headers)
                mpd_content_response = self.session.get(f"{base_url}/{device_code}?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
                #print(mpd_content_response.text)
                if mpd_content_response.json():
                    if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
                        self.web_headers["X-Authorization"] = "Bearer "+mpd_content_response.cookies.get("UT")
                        self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
                        self.web_headers["host"] = base_host
                        self.web_headers["sec-fetch-site"] = "same-origin"
                        unixtime = str(int(time.time() * 1000))
                        mpd_content_response = self.session.get(f"{base_url}/{device_code}?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
                        if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
                            pass
                        else:
                            ticket = mpd_content_response.json()["ticket"]
                            mpd_url = mpd_content_response.json()["url"]
                            mpd_content_res = self.session.get(mpd_url)
                            self.session.get(f"https://fod.fujitv.co.jp/api/premium/view_log_pc/?epid={matches_url.group("episode_id")}&_={str(int(time.time() * 1000))}")
                            return True, ticket, mpd_content_res.text
                    else:
                        ticket = mpd_content_response.json()["ticket"]
                        mpd_url = mpd_content_response.json()["url"]
                        mpd_content_res = self.session.get(mpd_url)
                        self.session.get(f"https://fod.fujitv.co.jp/api/premium/view_log_pc/?epid={matches_url.group("episode_id")}&_={str(int(time.time() * 1000))}")
                        return True, ticket, mpd_content_res.text
            except Exception as error:
                print(error)
                #import traceback
                #import sys
                #t, v, tb = sys.exc_info()
                #print(traceback.format_exception(t,v,tb))
                #print(traceback.format_tb(e.__traceback__))
                if attempt == tries -1:
                    return False, None, None
    #def get_mpd_content_free(self, uuid, url, ut):
    #    global mpd_content_response
    #    tries = 3
    #    
    #    #device_code = "web"
    #    device_code = "tv_common/"
    #    #base_url = "https://fod.fujitv.co.jp/apps/api/1/auth/contents"
    #    base_url = "https://fod-sp.fujitv.co.jp/apps/api/auth/contents"
    #    #base_host = "fod.fujitv.co.jp"
    #    base_host = "fod-sp.fujitv.co.jp"
    #    
    #    for attempt in range(tries):
    #        try:
    #            unixtime = str(int(time.time() * 1000))
    #            matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
    #            self.web_headers["X-Authorization"] = "Bearer "+ut
    #            self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
    #            self.web_headers["host"] = base_host
    #            self.web_headers["sec-fetch-site"] = "same-origin"
    #            #print(self.web_headers)
    #            mpd_content_response = self.session.get(f"{base_url}/{device_code}?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
    #            #print(mpd_content_response.text)
    #            if mpd_content_response.json():
    #                prm = matches_url.group("episode_id")+"androidtv_"+datetime.now().strftime("%Y%m%d%H%M%S")+"_fod_"
    #                if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
    #                    self.web_headers["X-Authorization"] = "Bearer "+mpd_content_response.cookies.get("UT")
    #                    self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
    #                    self.web_headers["host"] = base_host
    #                    self.web_headers["sec-fetch-site"] = "same-origin"
    #                    unixtime = str(int(time.time() * 1000))
    #                    mpd_content_response = self.session.get(f"{base_url}/{device_code}?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
    #                    if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
    #                        pass
    #                    else:
    #                        ticket = mpd_content_response.json()["ticket"]
    #                        mpd_url = mpd_content_response.json()["url"]
    #                        mpd_content_res = self.session.get(mpd_url)
    #                        self.session.get(f"https://fod.fujitv.co.jp/api/msd/view_log_free_v2/?epid={matches_url.group("episode_id")}&uid=&dvid=google_google_aosp+tv+on+x86_13&prm={prm}")
    #                        return True, ticket, mpd_content_res.text
    #                else:
    #                    ticket = mpd_content_response.json()["ticket"]
    #                    mpd_url = mpd_content_response.json()["url"]
    #                    mpd_content_res = self.session.get(mpd_url)
    #                    self.session.get(f"https://fod.fujitv.co.jp/api/msd/view_log_free_v2/?epid={matches_url.group("episode_id")}&uid=&dvid=google_google_aosp+tv+on+x86_13&prm={prm}")
    #                    return True, ticket, mpd_content_res.text
    #        except Exception as e:
    #            import traceback
    #            import sys
    #            t, v, tb = sys.exc_info()
    #            print(traceback.format_exception(t,v,tb))
    #            print(traceback.format_tb(e.__traceback__))
    #            if attempt == tries -1:
    #                return False, None
    
    def sent_start_stop_signal(self, bandwidth, video_url, duration):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', video_url)
        uuid = self.session.cookies.get("uuid")
        series_id = matches_url.group("title_id")
        episode_id = matches_url.group("episode_id")
        enq_id = self.session.cookies.get("plus7_guid")
        episode_id_for_web = mpd_content_response.json()["samba"]
        if login_status:
            foduser_id = user_info_res.json().get("member_id")
        else:
            foduser_id = ""
        td_write_key = "257/1dbef148fc11ca71d992972db31166af2b5dba41"
        mpd_video_play_band = bandwidth
        
        # Start Playing
        
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        querystring = {
            "foduser_id": foduser_id,
            "enq_id": enq_id,
            "season_id": series_id,
            "fod_episode_id": episode_id,
            "episode_id": episode_id_for_web,
            "refer": "fodapp",
            "device_category": "pc",
            "session_id": uuid,
            "td_write_key": td_write_key,
            "subpronum": "0",
            "player_status": "play",
            "current_time": "1",
            "buffering": "60",
            "play_band": mpd_video_play_band,
            "internet_speed": "0",
            "play_speed": "1",
            "error_id": "",
            "stream_type": "urn:mpeg:dash:mp4protection:2011",
            "contents_type": "SVOD-TVOD",
            "device_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "device_os_version": "Chrome",
            "device_os_sdk_version": "131.0.0.0"
        }
        
        headers = {
            "host": "tokyo.in.treasuredata.com",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7"
        }
        
        response = self.session.get(url, headers=headers, params=querystring)
        
        #print(response.text)
        #
        # Stop Playing
        
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        querystring = {
            "foduser_id": foduser_id,
            "enq_id": enq_id,
            "season_id": series_id,
            "fod_episode_id": episode_id,
            "episode_id": episode_id_for_web,
            "refer": "fodapp",
            "device_category": "pc",
            "session_id": uuid,
            "td_write_key": td_write_key,
            "subpronum": "0",
            "player_status": "pause",
            "current_time": "3",
            "buffering": "63",
            "play_band": mpd_video_play_band,
            "internet_speed": "0",
            "play_speed": "1",
            "error_id": "",
            "stream_type": "urn:mpeg:dash:mp4protection:2011",
            "contents_type": "SVOD-TVOD",
            "device_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "device_os_version": "Chrome",
            "device_os_sdk_version": "131.0.0.0"
        }
        
        headers = {
            "host": "tokyo.in.treasuredata.com",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7"
        }
        
        response = self.session.get(url, headers=headers, params=querystring)
        
        #print(response.text)
                
        url = "https://measure-api.cms.fod.fujitv.co.jp/apps/api/sameview/measure_viewtime"

        url_2 = mpd_content_response.json()["viewbeaconurl"].replace("@resume_time", "0").replace("@duration", duration).replace("@complete", "0").replace("@play_status", "2").replace("@pausecount", "1")+f"&_={str(int(time.time() * 1000))}"
        
        headers = {
            "host": "measure-api.cms.fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "*/*",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "origin": "https://fod.fujitv.co.jp",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7",
        }
        
        #response = self.session.get(url, headers=headers, params=querystring)
        response = self.session.get(url_2, headers=headers)
        
        #print(response.text)
        pass
    
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