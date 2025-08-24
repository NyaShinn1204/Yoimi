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
import base64
import hashlib
from ext.utils.zzz_other_util import other_util

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

class normal:
    class downloader:
        def __init__(self, session, logger):
            self.session = session
            self.logger = logger
            
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
            pass
        def parse_input_season(self, url_input):
            pass
        
        def authorize(self, email, password):
            _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
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
                
                user_info_query = {
                    "operationName": "GetServicePlan",
                    "variables": {},
                    "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
                }
                user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query, headers={"authorization": "Bearer "+token})
    
                user_id = user_info_res.json()["data"]["user"]["id"]
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
                
                return True, user_info_res.json()["data"]["user"], True, session_json
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
                return False, None
            else:
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
            
        def show_userinfo(self, user_data):
            profile_id = user_data["id"]
            self.logger.info("Logged-in Account")
            self.logger.info(" + id: " + profile_id)

class vr:
    class downloader:
        def __init__(self, session, logger):
            self.session = session
            self.logger = logger
            
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
            pass
        def parse_input_season(self, url_input):
            pass
        
        def authorize(self, email, password):
            _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
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
                        "dmmvrplayer://android/auth?code=", ""
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
                            "x-authorization": "Bearer "
                            + token
                        }
                    )
                
                user_info_query = {
                    "operationName": "GetServicePlan",
                    "variables": {},
                    "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
                }
                user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query, headers={"authorization": "Bearer "+token})
    
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
                    "method": "LOGIN",
                    "email": hashlib.sha256(email.encode()).hexdigest(),
                    "password": hashlib.sha256(password.encode()).hexdigest(),
                    "access_token": token,
                    "refresh_token": refresh_token,
                    "additional_info": {}
                }
                
                return True, user_info_res.json()["data"]["user"], True, session_json
            except Exception as e:
                return False, e, False, None