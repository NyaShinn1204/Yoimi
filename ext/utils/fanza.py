import re
import os
import cv2
import json
import time
import hmac
import m3u8
import base64
import hashlib
import requests
import threading
import subprocess

from tqdm import tqdm
from Crypto.Cipher import AES
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Fanza_utils:
    def recaptcha_v3_bypass(anchor_url):
        session = requests.Session()
        session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded"
        })

        match = re.search(r"(api2|enterprise)/anchor\?(.*)", anchor_url)
        mode, param_str = match.groups()
        base_url = f"https://www.google.com/recaptcha/{mode}/"

        params = dict(pair.split("=") for pair in param_str.split("&"))

        response = session.get(base_url + "anchor", params=params)
        token = re.search(r'"recaptcha-token" value="(.*?)"', response.text).group(1)

        post_data = "v={v}&reason=q&c={c}&k={k}&co={co}".format(
            v=params["v"],
            c=token,
            k=params["k"],
            co=params["co"]
        )

        response = session.post(
            base_url + "reload",
            params={"k": params["k"]},
            data=post_data
        )

        return re.search(r'"rresp","(.*?)"', response.text).group(1)

class Fanza_util:
    # Parse logic
    def parse_m3u8(m3u8_url, base_link, license_uid, service_name):
        if service_name == "Fanza_VR":
            headers = {
                "user-agent": "AVProMobileVideo/2.0.5 (Linux;Android 15) ExoPlayerLib/2.8.4",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip"
            }
        else:
            headers = {
                "user-agent": "okhttp/4.12.0",
                "accept-encoding": "gzip",
                "accept": "*/*",
                "connection": "Keep-Alive",
                "x-app-name": "android_2d",
            }
        r = requests.get(m3u8_url, headers=headers)
        x = m3u8.loads(r.text)
        files = x.files[1:]

        key_url = x.keys[0].uri
        if service_name == "Fanza_VR":
            headers = {
                "user-agent": "AVProMobileVideo/2.0.5 (Linux;Android 15) ExoPlayerLib/2.8.4",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip"
            }
        else:
            headers = {
                "user-agent": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
            }
        if "licenseUID" not in key_url:
            key_url = key_url+"&licenseUID="+license_uid+"&smartphone_access=1"
        key = requests.get(key_url, headers=headers).content
        iv = bytes.fromhex("00000000000000000000000000000000")  # バカシステムなのでこれで通ります。:checked:
        parsed_files = []
        for f in files:
            f = base_link + f
            parsed_files.append(f)
        return parsed_files, iv, key
    # Download logic
    def setup_decryptor(iv, key):
        global _aes, return_iv
        return_iv = iv
        _aes = AES.new(key, AES.MODE_CBC, IV=return_iv)
    def download_chunk(files, iv, key, unixtime, config, service_name):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", str(unixtime))
        os.makedirs(base_temp_dir, exist_ok=True)
    
        Fanza_util.setup_decryptor(iv, key)
        stop_flag = threading.Event()
        downloaded_files = []
    
        def fetch_and_decrypt(ts_url):
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    if service_name == "Fanza_VR":
                        headers = {
                            "user-agent": "AVProMobileVideo/2.0.5 (Linux;Android 15) ExoPlayerLib/2.8.4",
                            "accept-encoding": "identity",
                            "connection": "Keep-Alive"
                        }
                    else:
                        headers = {
                            "user-agent": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
                            "accept-encoding": "identity",
                            "connection": "Keep-Alive"
                        }
                    response = requests.get(ts_url.strip(), timeout=10, headers=headers)
                    response.raise_for_status()
                    decrypted_data = _aes.decrypt(response.content)
                    output_path = os.path.join(base_temp_dir, os.path.basename(ts_url))
                    with open(output_path, "wb") as f:
                        f.write(decrypted_data)
                    return output_path
                except Exception:
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
    def mux_video(temp_video_path, output, service_name, config):    
        os.makedirs(os.path.join(config["directorys"]["Downloads"]), exist_ok=True)
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
        
        cap = cv2.VideoCapture(temp_video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_count = cap.get(cv2.CAP_PROP_FRAME_COUNT)
        duration = frame_count / fps
        cap.release()

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

class Fanza_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.service_name = "Fanza"
    def authorize(self, email, password):
        global auth_success, user_id, token
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
        _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
        _CLIENT_ID = "0lvBFN830altTCMZnTYpYPoioUcrhR"
        _CLIENT_SECRET = "WL13ljvW3gJUht8X3u76UwzMxmiFecNT"
        try:
            login_recaptcha_token = Fanza_utils.recaptcha_v3_bypass(
                "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh"
            )

            querystring = {
                "client_id": _CLIENT_ID,
            }

            headers = {
                "host": "accounts.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "smartphone_app": "DMM-APP",
                "smartphone-app": "DMM-APP",
                "x-requested-with": "com.dmm.app.movieplayer",
                "sec-fetch-site": "none",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }

            response = self.session.get(
                _ENDPOINT_RES, params=querystring, headers=headers
            )
            token_match = re.search(r'name="token" value="([^"]*)"/>', response.text)
            token = token_match.group(1) if token_match else None

            _auth = {
                "token": token,
                "login_id": email,
                "password": password,
                "recaptchaToken": login_recaptcha_token,
                "clientId": _CLIENT_ID,
            }

            response = self.session.post(
                "https://accounts.dmm.com/app/service/login/password/authenticate",
                data=_auth,
                headers=headers,
            )

            if response.text.__contains__("認証エラー"):
                return False, "Authentication failed: Account locked"

            querystring = {
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "from_domain": "accounts",
            }
            headers = {
                "host": "www.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "x-requested-with": "com.dmm.app.movieplayer",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "navigate",
                "sec-fetch-dest": "document",
                "referer": "https://accounts.dmm.com/app/service/login/password/authenticate",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }
            redirect_auth_url = self.session.get(
                "https://www.dmm.com/my/-/authorize/",
                allow_redirects=False,
                params=querystring,
                headers=headers,
                cookies={"dmm_app": str(1)},
            ).headers["Location"]

            headers = {
                "authorization": "Basic "
                + base64.b64encode(
                    (_CLIENT_ID + ":" + _CLIENT_SECRET).encode()
                ).decode(),
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; V2338A Build/PQ3B.190801.10101846)",
                "host": "gw.dmmapis.com",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
            }

            _auth = {
                "grant_type": "authorization_code",
                "code": redirect_auth_url.replace(
                    "dmmmovieplayer://android/auth?code=", ""
                ),
                "redirect_uri": "dmmmovieplayer://androidstore/auth/?",
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )
            token_response_json = token_response.json()["header"]

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                refresh_token = token_response.json()["body"]["refresh_token"]
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "Authorization": "Bearer "
                        + token
                    }
                )
                
            _auth = {
                "grant_type": "exchange_token",
                "access_token": token
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "Authorization": "Bearer "
                        + token
                    }
                )
            
            user_info_query = {
                "operationName": "GetServicePlan",
                "variables": {},
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            }
            user_info_res = requests.post(_ENDPOINT_CC, json=user_info_query, headers={"authorization": "Bearer "+token})

            auth_success = True
            user_id = user_info_res.json()["data"]["user"]["id"]
            self.session.headers.update(
                {
                    "x-app-name": "android_2d",
                    "x-app-ver": "v4.1.0",
                    "x-exploit-id": "uid:"+user_id,
                    "host": "video.digapi.dmm.com",
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip",
                    "user-agent": "okhttp/4.12.0",
                }
            )
            
            session_json = {
                "email": hashlib.sha256(email.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": token,
                "refresh_token": refresh_token
            }
            
            return True, user_info_res.json()["data"]["user"], session_json
        except Exception as e:
            return False, e, None
    def check_token(self, token):
        _ENDPOINT_CC = "https://api.tv.dmm.com/graphql"
        res = self.session.post(
            _ENDPOINT_CC,
            json={
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            },
            headers={"Authorization": "Bearer "+token},
        )
        if res.status_code == 200:
            if res.json()["data"] != None:
                user_id = res.json()["data"]["user"]["id"]
                self.session.headers.update({
                    "user-agent": "okhttp/4.12.0",
                    "accept-encoding": "gzip",
                    "accept": "*/*",
                    "connection": "Keep-Alive",
                    "authorization": "Bearer "+token,
                    "x-app-name": "android_2d",
                    "x-app-ver": "v4.1.0",
                    "x-exploit-id": "uid:"+user_id,
                })
                return True, user_id
            else:
                return False, None
        else:
            return False, None
        
    def get_title(self):
        res = self.session.get("https://video.digapi.dmm.com/purchased/list/text?limit=1000&page=1&order=new&hidden_filter=")
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["list_info"]
            else:
                return False, None
        else:
            return False, None
        
    def get_license_uid(self, user_id):
        res = self.session.post("https://gw.dmmapis.com/connect/v1/issueSessionId", json={"user_id": user_id})
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["body"]["unique_id"]
            else:
                return False, None
        else:
            return False, None
        
    def get_license(self, user_id, single, license_uid, secret_key, part_num):
        def get_json(params: dict) -> str:
            return json.dumps(params, separators=(",", ":"), ensure_ascii=False)
        def get_hash(data: str, key: str) -> str:
            return hmac.new(
                key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        def set_post_params(message: str, params: dict, appid: str, secret_key: str) -> dict:
            post_data = {}
            post_data["message"] = message
            post_data["appid"] = appid
            json_data = get_json(params)
            post_data["params"] = json_data
            post_data["authkey"] = get_hash(json_data, secret_key)
            return post_data
        
        params = {
            "exploit_id": "uid:"+ user_id,
            "mylibrary_id": str(single["mylibrary_id"]),
            "product_id": single["product_id"],
            "shop_name": single["shop_name"],
            "device": "iphone",
            "HTTP_SMARTPHONE_APP": "DMM-APP",
            "message": "Digital_Api_Mylibrary.getDetail",
        }
        payload = set_post_params(
            message="Digital_Api_Mylibrary.getDetail",
            params=params,
            appid="android_movieplayer_app",
            secret_key=secret_key,
        )
        
        
        get_select_product_info = self.session.post(
            "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
        ).json()["data"]
        
        
        params = {
            "android_drm": False,
            "bitrate": 0,
            "drm": False,
            "exploit_id": "uid:" + user_id,
            "chrome_cast": False,
            "isTablet": False,
            "licenseUID": license_uid,
            "parent_product_id": get_select_product_info["product_id"],
            "part": part_num,
            "product_id": get_select_product_info["product_id"],
            "secure_url_flag": False,
            "service": "digital",
            "shop": single["shop_name"],
            "smartphone_access": True,
            "transfer_type": "stream",
            "HTTP_USER_AGENT": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
            "device": "iphone",
            "HTTP_SMARTPHONE_APP": "DMM-APP",
            "message": "Digital_Api_Proxy.getURL",
        }
        payload = set_post_params(
            message="Digital_Api_Proxy.getURL",
            params=params,
            appid="android_movieplayer_app",
            secret_key=secret_key,
        )
        
        
        license_response = self.session.post(
            "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
        ).json()
        if license_response["data"]["data"] == None:
            params = {
                "android_drm": False,
                "bitrate": 0,
                "drm": False,
                "exploit_id": "uid:" + user_id,
                "chrome_cast": False,
                "isTablet": False,
                "licenseUID": license_uid,
                "parent_product_id": get_select_product_info["product_id"],
                "part": part_num,
                "product_id": get_select_product_info["content_id"],
                "secure_url_flag": False,
                "service": "digital",
                "shop": single["shop_name"],
                "smartphone_access": True,
                "transfer_type": "stream",
                "HTTP_USER_AGENT": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
                "device": "iphone",
                "HTTP_SMARTPHONE_APP": "DMM-APP",
                "message": "Digital_Api_Proxy.getURL",
            }
            payload = set_post_params(
                message="Digital_Api_Proxy.getURL",
                params=params,
                appid="android_movieplayer_app",
                secret_key=secret_key,
            )
            
            
            license_response = self.session.post(
                "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
            ).json()
        return True, license_response, payload
    
    def get_resolution(self, shop_name, product_id, secret_key):
        def get_json(params: dict) -> str:
            return json.dumps(params, separators=(",", ":"), ensure_ascii=False)
        def get_hash(data: str, key: str) -> str:
            return hmac.new(
                key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        def set_post_params(message: str, params: dict, appid: str, secret_key: str) -> dict:
            post_data = {}
            post_data["message"] = message
            post_data["appid"] = appid
            json_data = get_json(params)
            post_data["params"] = json_data
            post_data["authkey"] = get_hash(json_data, secret_key)
            return post_data
        
        params = {
            "product_id":product_id,
            "service":"digital",
            "shop_name":shop_name,
            "device":"iphone",
            "HTTP_SMARTPHONE_APP":"DMM-APP",
            "message":"Digital_Api_RatePattern.getContentRatePatternListForApp"
        }
        
        payload = set_post_params(
            message="Digital_Api_RatePattern.getContentRatePatternListForApp",
            params=params,
            appid="android_movieplayer_app",
            secret_key=secret_key,
        )
        resolution_response = self.session.post(
            "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
        ).json()
        return True, resolution_response
class Fanza_VR_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.service_name = "Fanza_VR"
    def authorize(self, email, password):
        global auth_success, user_id, token
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
        _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
        _CLIENT_ID = "Ozqufo77TdOALdbSv1OLW3E8I"
        _CLIENT_SECRET = "1WKJioWwERuNG6ThCcMDkNsG8YPiNs6p"
        try:
            login_recaptcha_token = Fanza_utils.recaptcha_v3_bypass(
                "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh"
            )

            querystring = {
                "client_id": _CLIENT_ID,
            }

            headers = {
                "host": "accounts.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "smartphone_app": "DMM-APP",
                "smartphone-app": "DMM-APP",
                "x-requested-with": "com.dmm.app.player.vr",
                "sec-fetch-site": "none",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }

            response = self.session.get(
                _ENDPOINT_RES, params=querystring, headers=headers
            )
            token_match = re.search(r'name="token" value="([^"]*)"/>', response.text)
            token = token_match.group(1) if token_match else None

            _auth = {
                "token": token,
                "login_id": email,
                "password": password,
                "recaptchaToken": login_recaptcha_token,
                "clientId": _CLIENT_ID,
            }

            response = self.session.post(
                "https://accounts.dmm.com/app/service/login/password/authenticate",
                data=_auth,
                headers=headers,
            )

            if response.text.__contains__("認証エラー"):
                return False, "Authentication failed: Account locked"

            querystring = {
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "from_domain": "accounts",
            }
            headers = {
                "host": "www.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "x-requested-with": "com.dmm.app.player.vr",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "navigate",
                "sec-fetch-dest": "document",
                "referer": "https://accounts.dmm.com/app/service/login/password/authenticate",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }
            redirect_auth_url = self.session.get(
                "https://www.dmm.com/my/-/authorize/",
                allow_redirects=False,
                params=querystring,
                headers=headers,
                cookies={"dmm_app": str(1)},
            ).headers["Location"]

            headers = {
                "authorization": "Basic "
                + base64.b64encode(
                    (_CLIENT_ID + ":" + _CLIENT_SECRET).encode()
                ).decode(),
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; V2338A Build/PQ3B.190801.10101846)",
                "host": "gw.dmmapis.com",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
            }

            _auth = {
                "grant_type": "authorization_code",
                "code": redirect_auth_url.replace(
                    "dmmvrplayer://androidstore/auth/?code=", ""
                ),
                "redirect_uri": "dmmvrplayer://androidstore/auth/?",
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )
            token_response_json = token_response.json()["header"]

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                refresh_token = token_response.json()["body"]["refresh_token"]
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "x-authorization": "Bearer "
                        + token
                    }
                )
                
            _auth = {
                "grant_type": "exchange_token",
                "access_token": token
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "x-authorization": "Bearer "
                        + token
                    }
                )
            
            user_info_query = {
                "operationName": "GetServicePlan",
                "variables": {},
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            }
            user_info_res = requests.post(_ENDPOINT_CC, json=user_info_query, headers={"authorization": "Bearer "+token})

            auth_success = True
            user_id = user_info_res.json()["data"]["user"]["id"]
            self.session.headers.update(
                {
                    "x-app-name": "android_vr_store",
                    "x-app-ver": "v2.0.5",
                    "x-exploit-id": "uid:"+user_id,
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip",
                    "user-agent": "okhttp/4.12.0",
                }
            )
            
            session_json = {
                "email": hashlib.sha256(email.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": token,
                "refresh_token": refresh_token
            }
            
            return True, user_info_res.json()["data"]["user"], session_json
        except Exception as e:
            return False, e, None
    def check_token(self, token):
        _ENDPOINT_CC = "https://api.tv.dmm.com/graphql"
        res = self.session.post(
            _ENDPOINT_CC,
            json={
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            },
            headers={"authorization": "Bearer "+token},
        )
        if res.status_code == 200:
            if res.json()["data"] != None:
                user_id = res.json()["data"]["user"]["id"]
                self.session.headers.update({
                    "user-agent": "okhttp/4.12.0",
                    "accept-encoding": "gzip",
                    "accept": "*/*",
                    "connection": "Keep-Alive",
                    "x-authorization": "Bearer "+token,
                    "x-app-name": "android_vr_store",
                    "x-app-ver": "v2.0.5",
                    "x-exploit-id": "uid:"+user_id,
                })
                return True, user_id
            else:
                return False, None
        else:
            return False, None
        
    def get_title(self):
        res = self.session.get("https://vr.digapi.dmm.com/purchase/list/vr?limit=1000&order=new&page=1")
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["content"]["list"]
            else:
                return False, None
        else:
            return False, None
    
    def get_license_uid(self, mylibrary_id, quality_group, part, secret_key):
        params = {
            "x-authorization": self.session.headers["x-authorization"],
            "mylibrary_id": str(mylibrary_id),
            "x-exploit-id": self.session.headers["x-exploit-id"],
            "x-useragent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
            "quality_group": quality_group,
            "part": str(part),
        }
        joined_param = ''.join(f"{params[k]}" for k in ["x-authorization", "mylibrary_id", "x-exploit-id", "x-useragent", "quality_group", "part"])
        auth_code = hmac.new(secret_key.encode(), joined_param.encode(), hashlib.sha256).hexdigest()
        
        querystring = {
            "mylibrary_id": str(mylibrary_id),
            "part": str(part),
            "quality_group": quality_group
        }
        res = self.session.get("https://vr.digapi.dmm.com/playableprovider/stream/vr", params=querystring, headers={
            "x-user-agent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
            "x-api-auth-code": auth_code
        })
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["cookie_info"]["value"], res.json()["content_info"]["redirect"]
            else:
                return False, None, None
        else:
            return False, None, None