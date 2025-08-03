"""
SERVICE INFO


name: H-Next
require_account: Yes
enable_refresh: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://video.hnext.jp/title/xxx
   https://video.hnext.jp/play/xxx/xxx
"""

import uuid
import time

__service_config__ = {
    "service_name": "H-Next",
    "require_account": True,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cahce = True
        
        self.default_headers = {
            "connection": "keep-alive",
            "pragma": "no-cache",
            "cache-control": "no-cache",
            "sec-ch-ua-platform": "\"Android\"",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.169 Mobile Safari/537.36 japanview/1.0.6",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Android WebView\";v=\"138\"",
            "sec-ch-ua-mobile": "?1",
            "baggage": "sentry-environment=prod,sentry-release=v105.0-2-gca2628b65,sentry-public_key=d46f18dd0cfb4b0cb210f8e67c535fe1,sentry-trace_id=7027522fb22847e6a57671c198a8ab7e,sentry-sample_rate=0.0001,sentry-sampled=false",
            "accept": "*/*",
            "x-requested-with": "com.japan_view",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        
        self.session.headers.update(self.default_headers)
        
    def parse_input(self, input):
        pass
    
    def parse_input_season(self, url_input):
        pass
    
    def authorize(self, email_or_id, password):
        _ENDPOINT_LOGIN = "https://tvh.unext.jp/api/1/login"
        
        payload = {
            "login_id": email_or_id,
            "password": password
        }
        
        response = self.session.post(_ENDPOINT_LOGIN, json=payload)
        
        user_response = response.json()
        
        if user_response["common"]["result"]["errorCode"] == "":
            session_json = {
                "method": "LOGIN",
                "email": email_or_id,
                "password": password,
                "access_token": response.cookies["_ut"],
                "refresh_token": None
            }
            return True, user_response["common"]["userInfo"], True, session_json
        elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
            return False, 'Wrong Email or password', False, None
        elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
            return False, 'Require Japan VPN, Proxy', False, None
    def authorize_qr(self):
        _ENDPOINT_CC = "https://cc.unext.jp/"
        _ENDPOINT_LOGIN = "https://tvh.unext.jp/api/1/login"
        
        payload = {
            "operationName": "tvh_loginDelegationCreateSession",
            "query": "mutation tvh_loginDelegationCreateSession($appVersion: String!, $deviceName: String!, $deviceType: String!, $deviceUuid: String!, $location: String!) {\n  loginDelegationCreateSession(\n    appVersion: $appVersion\n    deviceName: $deviceName\n    deviceType: $deviceType\n    deviceUuid: $deviceUuid\n    location: $location\n  ) {\n    code\n    authPageUrlTemplate\n    sessionId\n    __typename\n  }\n}",
            "variables": {
                "appVersion": "",
                "deviceName": "Yoimi",
                "deviceType": "1210",
                "deviceUuid": str(uuid.uuid4()),
                "location": "tokyo"
            }
        }
        
        response = self.session.post(_ENDPOINT_CC, json=payload)
        get_qr_link = response.json()
        
        session_check_data = {
            "operationName": "tvh_loginDelegationPollSession",
            "query": "query tvh_loginDelegationPollSession($code: String!, $sessionId: String!) {\n  loginDelegationPollSession(code: $code, sessionId: $sessionId) {\n    oneTimeToken\n    __typename\n  }\n}",
            "variables": {
              "code": get_qr_link["data"]["loginDelegationCreateSession"]["code"],
              "sessionId": get_qr_link["data"]["loginDelegationCreateSession"]["sessionId"]
            }
        }
        
        print("Login URL:", get_qr_link["data"]["loginDelegationCreateSession"]["authPageUrlTemplate"])
        print("Code:", get_qr_link["data"]["loginDelegationCreateSession"]["code"])
        
        while True:
            send_checkping = self.session.post(f"https://cc.unext.jp/", json=session_check_data)
            if send_checkping.json()["data"]["loginDelegationPollSession"] == None:
                print("Waiting Login...")
                time.sleep(5)
            else:
                print("Login Accept")
                
                one_time_token = send_checkping.json()["data"]["loginDelegationPollSession"]["oneTimeToken"]
                
                payload = {
                    "oneTimeToken": one_time_token,
                }
                
                response = self.session.post(_ENDPOINT_LOGIN, json=payload)
                
                user_response = response.json()
                
                session_json = {
                    "method": "QR_LOGIN",
                    "email": None,
                    "password": None,
                    "access_token": response.cookies["_ut"],
                    "refresh_token": None
                }
                
                return True, user_response["common"]["userInfo"], True, session_json
    def check_token(self, token):
        self.session.cookies.set('_ut', token)
        
        token_check = self.session.get("https://tvh.unext.jp/api/1/adult/mylist/list?page_number=1").json()
        
        if token_check["common"]["result"]["errorCode"] == "GAN9900010":
            return False, None
        else:
            return True, token_check["common"]["userInfo"]
    def get_userinfo(self):
        _USER_INFO_API = "https://tvh.unext.jp/api/1/getuseraccountinfo"
        
        profile_resposne = self.session.get(_USER_INFO_API)
        if profile_resposne.json()["result"]["errorCode"] == "GAN9900010":
            return False, None
        elif profile_resposne.json()["result"]["errorCode"] == "":
            return True, profile_resposne.json()
        else:
            return False, None
        
    def show_userinfo(self, user_data):
        profile_id = user_data["cuid"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + id: " + profile_id)
            