"""
SERVICE INFO


name: Fanza
require_account: Yes
enable_refresh: No
support_normal: Yes
support_qr: No
is_drm: Both
cache_session: Yes
use_tlsclient: No
support_url: 
   WIP
   probably all code copy and paste (Exception downloader)
"""

import re
import os
import json
import base64
import hashlib
import requests
import xml.etree.ElementTree as ET
from ext.utils.license_util import license_logic
from ext.utils.pssh_util import return_pssh_json
from ext.utils.zzz_other_util import other_util

class normal:
    __service_config__ = {
        "service_name": "Fanza",
        "require_account": True,
        "enable_refresh": False,
        "support_normal": True,
        "support_qr": False,
        "is_drm": False,
        "cache_session": True,
        "use_tls": False,
    }
    class downloader:
        def __init__(self, session, logger, config):
            self.session = session
            self.logger = logger
            self.config = config
            
            self.default_headers = {
                "user-agent": "UnityPlayer/2020.3.48f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)",
                "accept": "*/*",
                "accept-encoding": "deflate, gzip",
                "cache-control": "no-cache, no-store, must-revalidate",
                "pragma": "no-cache",
                "expires": "0",
            }
            self.session.headers.update(self.default_headers)
    
        def parse_input(self, url_input, id = None):
            global pssh_extract_result
            if os.path.isfile(url_input) and url_input.endswith(".dcv"):
                file_path = os.path.abspath(url_input)
                with open(file_path, "rb") as f:
                    header_text = f.read(1024).decode("utf-8", errors="ignore")
        
                pssh_extract_result = return_pssh_json(file_path)
                single_pssh = pssh_extract_result.get(next(iter(pssh_extract_result)))
                    
                decoded_bytes = base64.b64decode(single_pssh)
                decoded_str = decoded_bytes.decode('utf-8', errors='ignore') 
                self.logger.debug("Decode PSSH: "+decoded_str)
                match = re.search(r'\{.*\}', decoded_str)
                if match:
                    json_str = match.group(0)
                    self.logger.debug("Get Content Json: "+json_str)
                    json_data = json.loads(json_str)
                    content_info = self.find_content_from_id(json_data["fid"])
                else:
                    self.logger.error("Invalid PSSH")
                
                content_name = content_info["title"]
                
                video_info = {
                    "title_name": "",
                    "output_titlename": content_name+"["+os.path.splitext(os.path.basename(file_path))[0]+"]",
                    "content_type": "offline"
                }
                return video_info
        def parse_input_season(self, url_input):
            pass

        def parse_offline_content(self, url_input):
            file_path = os.path.abspath(url_input)

            self.logger.info("Get License UID")
            license_uid = self.get_license_uid()
            self.logger.info(" + "+license_uid)

            self.logger.info("Get Video, Audio PSSH")
            if pssh_extract_result.get("widevine"):
                self.logger.info(" + Widevine: "+ pssh_extract_result["widevine"][:35]+"...")
            if pssh_extract_result.get("playready"):
                self.logger.info(" + Playready: "+ pssh_extract_result["playready"][:35]+"...")
            
            self.logger.info("Decrypting License")

            fake_json = {"pssh_list": pssh_extract_result}
            manifest_info = {
                "widevine": "https://mlic.dmm.com/drm/widevine/license",
                "playready": "https://mlic.dmm.co.jp/drm/playready/rightsmanager.asmx",
                "fairplay": "https://mlic.dmm.com/drm/fairplay/license",
                "clearkey": "https://mlic.dmm.com/drm/clearkey/license"
            }
            temp_headers = {
                "host": "mlic.dmm.com",
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "cross-site",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) DMMPlayerv2/2.5.0 Chrome/134.0.6998.179 Electron/35.1.5 Safari/537.36",
                "authorization": self.session.headers["authorization"],
                "sec-ch-ua": "\"Not:A-Brand\";v=\"24\", \"Chromium\";v=\"134\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Windows\"",
                "priority": "u=1, i",
                "cookie": f"licenseUID={license_uid}"
            }
            decrypt_headers = {
                "widevine": temp_headers, "playready": temp_headers
            }

            license_return = license_logic.decrypt_license(fake_json, manifest_info, decrypt_headers, self.session, self.config, self.logger, debug=False)
            if license_return == None:
                self.logger.error("both license decrypt failed")
                return None, None
            if license_return["type"] == "widevine":
                self.logger.info(f"Decrypt License (Widevine):")
                for license_key in license_return["key"]:
                    if license_key["type"] == "CONTENT":
                        self.logger.info(" + "+license_key['kid_hex']+":"+license_key['key_hex']) 
            elif license_return["type"] == "playready":
                self.logger.info(f"Decrypt License (PlayReady):")
                for license_key in license_return["key"]:
                    self.logger.info(" + "+license_key) 
            
            return file_path, license_return

        def authorize(self, email, password):
            _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
            _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
            _CLIENT_ID = "0lvBFN830altTCMZnTYpYPoioUcrhR"
            _CLIENT_SECRET = "WL13ljvW3gJUht8X3u76UwzMxmiFecNT"
            try:
                login_recaptcha_token = other_util.bypass_recapcha_v3(
                    "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh"
                )
    
                querystring = {
                    "client_id": _CLIENT_ID,
                }
    
                headers = {
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
                    return False, "Authentication failed: Probably account locked. please change password to reset account", False, None
    
                querystring = {
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "from_domain": "accounts",
                }
                headers = {
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
                    return False, f"Authentication failed: {token_response.json()["body"]["reason"]}", False, None
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
                    return False, f"Authentication failed: {token_response.json()["body"]["reason"]}", False, None
                else:
                    token = token_response.json()["body"]["access_token"]
                    self.session.headers.update(
                        {
                            "Authorization": "Bearer "
                            + token
                        }
                    )
                
                status, profile = self.get_userinfo()

                user_id = profile["id"]
                self.session.headers.update(
                    {
                        "x-app-name": "android_2d",
                        "x-app-ver": "v4.1.3",
                        "x-exploit-id": "uid:"+user_id,
                        "connection": "Keep-Alive",
                        "accept-encoding": "gzip",
                        "user-agent": "okhttp/4.12.0",
                    }
                )
                
                session_json = {
                    "method": "LOGIN",
                    "email": hashlib.sha256(email.encode()).hexdigest(),
                    "password": hashlib.sha256(password.encode()).hexdigest(),
                    "access_token": token,
                    "refresh_token": refresh_token,
                    "additional_info": {}
                }
                
                return True, profile, True, session_json
            except Exception as e:
                return False, e, False, None
        def check_token(self, token):
            self.session.headers.update({"Authorization": "Bearer "+ token})
            status, profile = self.get_userinfo()
            return status, profile
        def get_userinfo(self):
            _GRAPQL_API = "https://api.tv.dmm.com/graphql"
            _PAYLOAD = {
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            }
            
            profile_resposne = self.session.post(_GRAPQL_API, json=_PAYLOAD)
            if profile_resposne.status_code == 200 and profile_resposne.json()["data"] != None:
                self.session.headers.update(
                    {
                        "x-app-name": "android_2d",
                        "x-app-ver": "v4.1.3",
                        "x-exploit-id": "uid:"+profile_resposne.json()["data"]["user"]["id"],
                        "connection": "Keep-Alive",
                        "accept-encoding": "gzip",
                        "user-agent": "okhttp/4.12.0",
                    }
                )
                return True, profile_resposne.json()["data"]["user"]
            else:
                return False, None
        def show_userinfo(self, user_data):
            global profile_id
            profile_id = user_data["id"]
            self.logger.info("Logged-in Account")
            self.logger.info(" + id: " + profile_id)
        def judgment_watchtype(self, url):
            if os.path.isfile(url) and ".dvc" in url:
                return "single" ## offline-decrypt
            else:
                return "single"
            
        def find_content_from_id(self, id):
            res = self.session.get("https://video.digapi.dmm.com/purchased/list/text?limit=1000&page=1&order=new&hidden_filter=")
            if res.status_code == 200:
                for single in res.json()["list_info"]:
                    if id in single["product_id"]:
                        return single
                    else:
                        continue
            else:
                return None
            
        def get_license_uid(self):
            payload = {
                "oid": profile_id
            }
            res = self.session.post("https://www.dmm.com/service/digitalapi/digital/-/get_license_uid", data=payload)
            if res.status_code == 200:
                return res.json()["license_uid"]
            else:
                return None
            
class vr:
    __service_config__ = {
        "service_name": "Fanza-VR",
        "require_account": True,
        "enable_refresh": False,
        "support_normal": True,
        "support_qr": False,
        "is_drm": False,
        "cache_session": True,
        "use_tls": False,
    }
    class downloader:
        def __init__(self, session, logger, config):
            self.session = session
            self.logger = logger
            self.config = config
            
            self.default_headers = {
                "user-agent": "UnityPlayer/2020.3.48f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)",
                "accept": "*/*",
                "accept-encoding": "deflate, gzip",
                "cache-control": "no-cache, no-store, must-revalidate",
                "pragma": "no-cache",
                "expires": "0",
            }
            self.session.headers.update(self.default_headers)
    
        def parse_input(self, url_input, id = None):
            if os.path.isfile(url_input) and url_input.endswith(".wsdcf"):
                file_path = os.path.abspath(url_input)
                with open(file_path, "rb") as f:
                    header_text = f.read(1024).decode("utf-8", errors="ignore")
        
                content_name = None
                for line in header_text.splitlines():
                    if line.startswith("Content-Name:"):
                        content_name = line.split(":", 1)[1].strip()
                        break  # 見つけたら即終了
        
                video_info = {
                    "title_name": "",
                    "output_titlename": content_name+"["+os.path.splitext(os.path.basename(file_path))[0]+"]",
                    "content_type": "offline"
                }
                return video_info
        def parse_input_season(self, url_input):
            pass
        
        def parse_offline_content(self, url_input):
            def create_session(token: str, user_id: str) -> requests.Session:
                """
                認証付きセッションを作成し、Cookie を更新して返す
                """
                session = requests.Session()
            
                # 初期ヘッダー
                session.headers.update({
                    "authorization": token,
                    "accept": "application/json",
                    "content-type": "application/json",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; A7S Build/QP1A.190711.020)",
                    "host": "gw.dmmapis.com",
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip"
                })
            
                # セッション発行
                payload = {"user_id": user_id}
                resp = session.post("https://gw.dmmapis.com/connect/v1/issueSessionId", json=payload).json()
            
                # Cookie 更新
                session.cookies.update({
                    "secid": resp["body"]["secure_id"],
                    "dmm_app_uid": resp["body"]["unique_id"]
                })
            
                return session
            
            
            def request_with_headers(session: requests.Session, url: str, headers: dict) -> requests.Response:
                """
                任意のヘッダーを付けて GET リクエストを行う
                """
                return session.get(url, allow_redirects=False, headers=headers)
            
            self.logger.info("Get media info from file")

            file_path = os.path.abspath(url_input)
            with open(file_path, "rb") as f:
                header_text = f.read(1024).decode("utf-8", errors="ignore")

            # Content-Name
            for line in header_text.splitlines():
                if line.startswith("Content-Name:"):
                    content_name = line.split(":", 1)[1].strip()

                if line.startswith("Rights-Issuer:"):
                    match = re.search(r"urn:uuid:([0-9a-fA-F\-]+)", line)
                    if match:
                        rights_issuer_id = match.group(1)

                if "Encryption-Method:" in line:
                    m = re.search(r"Encryption-Method:\s*([A-Za-z0-9]+)(?:;padding=([A-Za-z0-9]+))?", line)
                    if m:
                        method = m.group(1)
                        padding = m.group(2)
            
            self.logger.info(" + Method: "+method)
            self.logger.info(" + Padding: "+padding)

            lines = header_text.split("\n", 7)
            if len(lines) >= 8:
                iv_bytes = lines[7].encode("utf-8", errors="ignore")[:16]
                if len(iv_bytes) == 16:
                    iv = iv_bytes
                    TOKEN = self.session.headers["x-authorization"]
                    USER_ID = profile_id
                    TARGET_URL = f"https://api.webstream.ne.jp/rights/urn:uuid:{rights_issuer_id}"
                    session = create_session(TOKEN, USER_ID)

            # WebStream API を呼び出して8kのlicense keyをraid
            webstream_headers = {
                "host": "api.webstream.ne.jp",
                "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
                              "Chrome/139.0.7258.95 Mobile Safari/537.36 "
                              "AndroidToaster/com.dmm.app.player.vr/2.0.5 "
                              "(app/a45c1b62-1cd9-479c-a8f2-137bf5fb7520; ) "
                              "WebStream DRM ({46bc2e5f-19a2-45b1-9b7e-13bf40633269})",
                "x-requested-with": "com.dmm.app.player.vr",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                          "image/avif,image/webp,image/apng,*/*;q=0.8,"
                          "application/signed-exchange;v=b3;q=0.7",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }
            response = request_with_headers(session, TARGET_URL, webstream_headers)

            # DMMのリダイレクト用アナルバイブヘッダーを挿入
            dmm_headers = {
                "host": "www.dmm.com",
                "user-agent": webstream_headers["user-agent"],
                "x-requested-with": "com.dmm.app.player.vr",
                "accept": webstream_headers["accept"],
                "accept-language": webstream_headers["accept-language"],
            }

            # リダイレクトをやりまくって、ヤリ中毒
            force_exit = False
            for _ in range(4):
                next_url = response.headers.get("Location")
                if not next_url:
                    break

                if "code=D0010001" in next_url:
                    self.logger.error("This content is not buyed. please check account")
                    force_exit = True

                response = request_with_headers(session, next_url, dmm_headers)

            if force_exit:
                return None, None

            root = ET.fromstring(response.text)
            key_value = root.find(".//KeyValue").text.strip()

            self.logger.info("Decrypt License")
            self.logger.info(" + KEY: "+key_value)
            self.logger.info(" + IV: "+base64.b64encode(iv).decode())
            
            decrypt_license = {
                "type": "AES",
                "method": method,
                "key": base64.b64decode(key_value),
                "iv": iv
            }

            return file_path, decrypt_license

        def authorize(self, email, password):
            _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
            _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
            _CLIENT_ID = "Ozqufo77TdOALdbSv1OLW3E8I"
            _CLIENT_SECRET = "1WKJioWwERuNG6ThCcMDkNsG8YPiNs6p"
            try:
                login_recaptcha_token = other_util.bypass_recapcha_v3(
                    "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh"
                )
    
                querystring = {
                    "client_id": _CLIENT_ID,
                }
    
                headers = {
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
                    return False, "Authentication failed: Probably account locked. please change password to reset account", False, None
    
                querystring = {
                    "response_type": "code",
                    "client_id": _CLIENT_ID,
                    "from_domain": "accounts",
                }
                headers = {
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
                    return False, f"Authentication failed: {token_response.json()["body"]["reason"]}", False, None
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
                    return False, f"Authentication failed: {token_response.json()["body"]["reason"]}", False, None
                else:
                    token = token_response.json()["body"]["access_token"]
                    self.session.headers.update(
                        {
                            "x-authorization": "Bearer "+ token,
                            "Authorization": "Bearer "+ token
                        }
                    )
                
                status, profile = self.get_userinfo()

                user_id = profile["id"]
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
                    "method": "LOGIN",
                    "email": hashlib.sha256(email.encode()).hexdigest(),
                    "password": hashlib.sha256(password.encode()).hexdigest(),
                    "access_token": token,
                    "refresh_token": refresh_token,
                    "additional_info": {}
                }
                
                return True, profile, True, session_json
            except Exception as e:
                return False, e, False, None
        def check_token(self, token):
            self.session.headers.update(
                {
                    "x-authorization": "Bearer "+ token,
                    "Authorization": "Bearer "+ token
                }
            )
            status, profile = self.get_userinfo()
            return status, profile
        def get_userinfo(self):
            _GRAPQL_API = "https://api.tv.dmm.com/graphql"
            _PAYLOAD = {
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            }
            
            profile_resposne = self.session.post(_GRAPQL_API, json=_PAYLOAD)
            if profile_resposne.status_code == 200 and profile_resposne.json()["data"] != None:
                self.session.headers.update(
                    {
                        "x-app-name": "android_2d",
                        "x-app-ver": "v4.1.3",
                        "x-exploit-id": "uid:"+profile_resposne.json()["data"]["user"]["id"],
                        "connection": "Keep-Alive",
                        "accept-encoding": "gzip",
                        "user-agent": "okhttp/4.12.0",
                    }
                )
                return True, profile_resposne.json()["data"]["user"]
            else:
                return False, None
        def show_userinfo(self, user_data):
            global profile_id
            profile_id = user_data["id"]
            self.logger.info("Logged-in Account")
            self.logger.info(" + id: " + profile_id)

        def judgment_watchtype(self, url):
            if os.path.isfile(url) and ".wsdcf" in url:
                return "single" ## offline-decrypt
            else:
                return "single"