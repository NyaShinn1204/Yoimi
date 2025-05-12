import re
import os
import time
import uuid
import requests
import subprocess

from tqdm import tqdm
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from ext.utils.hulu_jp_util.pymazda.sensordata.sensor_data_builder import SensorDataBuilder

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Hulu_jp_decrypt:
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Hulu_jp"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Hulu_jp_decrypt.decrypt_content_shaka(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Hulu_jp_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Hulu_jp"):
        mp4decrypt_command = Hulu_jp_decrypt.mp4decrypt(keys, config)
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
    def decrypt_content_shaka(keys, input_file, output_file, config, service_name="Hulu_jp"):
        shaka_command = Hulu_jp_decrypt.shaka_packager(keys, config)
        shaka_command.extend([f"input={input_file},stream=video,output={output_file}"])
        #shaka_command.extend([input_file, output_file])
        #f"input={input_file},stream=video,output={output_file}"
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
            with subprocess.Popen(shaka_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:                
                #for line in process.stdout:
                #    print(line)
                process.wait()
                if process.returncode == 0:
                    inner_pbar.n = 100
                    inner_pbar.refresh()
class Hulu_jp_license:
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

class Hulu_jp_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.web_headers = {}
    def authorize(self, email, password):
        #global user_info_res
        global test_temp_token
        _SESSION_CREATE = "https://mapi.prod.hjholdings.tv/api/v1/sessions/create"
        _LOGIN_API = "https://mapi.prod.hjholdings.tv/api/v1/users/auth"
        _USER_INFO_API = "https://mapi.prod.hjholdings.tv/api/v1/users/me"
        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "Hulu jp require email and password", None
            
        default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 9; 22081212C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36",
            "accept-language": "ja",
            "host": "mapi.prod.hjholdings.tv",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
            
        ## generate temp session
        
        payload_query = {
            "app_version": "3.24.0",
            "system_version": "9",
            "device_code": "8",
            "manufacturer": "Sony",
            "is_mobile": "true",
            "os_version": "9",
            "os_build_id": "24",
            "device_manufacturer": "Sony",
            "device_model": "BRAVIA 4K GB",
            "device_name": "BRAVIA_ATV2",
            "user_agent": "",
            "device_higher_category": "android_tv",
            "device_lower_category": "android_tv"
        }
        
        session_response = self.session.get(_SESSION_CREATE, params=payload_query, headers=default_headers).json()
        gaia_token_1 = session_response["gaia_token"]
        session_token_1 = session_response["session_token"]
        
        
        ## send login request    
        payload = {
            "mail_address": email,
            "password": password,
            "app_id": 4,
            "device_code": 7        
        }   
        sensor_data_builder = SensorDataBuilder()
        default_headers.update({
            "x-gaia-authorization": "extra " + gaia_token_1,
            "x-session-token": session_token_1,
            "x-acf-sensor-data": sensor_data_builder.generate_sensor_data(),
            "user-agent": "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV",
        })
        
        login_response = self.session.post(_LOGIN_API, json=payload, headers=default_headers)
        #print(_LOGIN_API)
        #print(login_response.headers)
        #print(login_response.text)
        
        login_response = login_response.json()
        
        default_headers.update({
            "x-user-id": str(login_response["id"])
        })
        
        #return True, login_response
        
        ## get profile list
        payload_query = {
            "with_profiles": "true",
            "app_id": 4,
            "device_code": 7
        }
        
        test_temp_token = "Bearer " + login_response["access_token"]
        
        default_headers.update({
            "authorization": "Bearer " + login_response["access_token"],
            "x-session-token": login_response["session_token"],
            "x-gaia-authorization": "extra " + login_response["gaia_token"]
        })
        
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query, headers=default_headers).json()
        
        profile_list = []
        for single_profile in profile_resposne["profiles"]:
            if single_profile["values"]["has_pin"]:
                pin_status = "Yes"
            else:
                pin_status = "No "
            profile_list.append([single_profile["display_name"], pin_status, single_profile["uuid_in_schema"]])
            
        self.web_headers = default_headers
            
        return True, profile_list
        
        #response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        #response.raise_for_status()
        #
        #email_verify_hashkey = response.json()["hash_key"]
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
    def select_profile(self, uuid, pin=""):
        payload = {
            "pin": pin,
            "profile_id": uuid
        }
        headers = self.web_headers.copy()
        headers["x-user-id"] = None
        headers["authorization"] = None
        headers["x-acf-sensor-data"] = None
        meta_response = self.session.put("https://mapi.prod.hjholdings.tv/api/v1/gaia/auth/profile", json=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                profile_change_response = meta_response.json()
                self.web_headers.update({
                    #"authorization": "Bearer " + profile_change_response["access_token"],
                    "x-session-token": profile_change_response["session_token"],
                })
                return True, profile_change_response
        except:
            return False, "Failed to login profile"
        
    def get_title_info(self, meta_id):
        querystring = {
            "expand_object_flag": "0",
            "app_id": 4,
            "device_code": 7,
            "datasource": "decorator"
        }
        
        meta_response = self.session.get("https://mapi.prod.hjholdings.tv/api/v1/metas/"+str(meta_id), params=querystring)
        try:
            if meta_response.status_code == 200:
                episode_metadata = meta_response.json()
                return True, episode_metadata
        except:
            return False, "Failed to get Meta"
    def find_4k(self, meta_id):
        querystring = {
            "fields": "values",
            "app_id": 4,
            "device_code": 7,
            "datasource": "decorator"
        }
        
        meta_response = self.session.get("https://mapi.prod.hjholdings.tv/api/v1/metas/"+str(meta_id)+"/medias", params=querystring)
        try:
            if meta_response.status_code == 200:
                episode_metadata = meta_response.json()
                def find_4k_videos(data):
                    result = []
                    for media in data.get("medias", []):
                        values = media.get("values", {})
                        if values.get("file_type") == "video/4k":
                            result.append(media)
                    return result
                
                result = find_4k_videos(episode_metadata)
                return result
        except:
            return None
        
    def playback_auth(self, episode_id, uhd=False, media_id=None):
        if uhd:
            payload = {
                "service": "hulu",
                "meta_id": "asset:100011115",
                "media_id": str(media_id),
                "device_code": 7,
                "with_resume_point": False,
                "vuid": str(uuid.uuid4()).replace("-",""),
                "user_id": self.web_headers["x-user-id"],
                "app_id": 4
            }
        else:
            payload = {
                "service": "hulu",
                "meta_id": "asset:"+episode_id,
                "device_code": 7,
                "vuid": str(uuid.uuid4()).replace("-",""),
                "with_resume_point": False,
                "user_id": self.web_headers["x-user-id"],
                "app_id": 4
            }
        meta_response = self.session.post("https://papi.prod.hjholdings.tv/api/v1/playback/auth", json=payload, headers=self.web_headers)
        try:
            if meta_response.status_code == 201:
                episode_metadata = meta_response.json()
                return True, episode_metadata
        except:
            return False, "Failed to auth playback"
    def open_playback_session(self, ovp_video_id, session_id, episode_id):
        payload = {
            "device_code": 7,
            "codecs": "h264", # List: "avc", "hevc", "h264", "h265", "vp9"         NOTICE: avc, hevc is return some title 1600x900. if you want 1080p, just use vp9
            "viewing_url": "https://www.hulu.jp/watch/"+episode_id,
            "app_id": 4
        }
        headers = self.web_headers.copy()
        headers["host"] = "playback.prod.hjholdings.tv"
        headers["x-playback-session-id"] = session_id
        headers["x-acf-sensor-data"] = None
        headers["x-gaia-authorization"] = None
        meta_response = self.session.get("https://playback.prod.hjholdings.tv/session/open/v1/merchants/hulu/medias/"+ovp_video_id, params=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                episode_playdata = meta_response.json()
                return True, episode_playdata
        except:
            return False, "Failed to get episode_playdata"
    
    def close_playback_session(self, session_id):
        headers = self.web_headers.copy()
        headers["host"] = "playback.prod.hjholdings.tv"
        headers["x-playback-session-id"] = session_id
        close_response = self.session.post("https://playback.prod.hjholdings.tv/session/close", headers=headers)
        try:
            if close_response.status_code == 200 and close_response.json()["result"]:
                return True, None
        except:
            return False, close_response.json()
        
    def download_segment(self, segment_links, config, unixtime, name, service_name="Hulu_jp"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
    
        def fetch_and_save(index_url):
            index, url = index_url
            retry = 0
            while retry < 3:
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
            #print("\nダウンロード中断されました。クリーンアップを実行します...")
            for future in futures:
                future.cancel()
            # 未完了ファイルを削除（存在すれば）
            for i in range(len(segment_links)):
                temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
            raise  # 終了ステータスを外に伝えるため再送出

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Hulu_jp"):
        # 出力ディレクトリを作成
        
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