"""
SERVICE INFO


name: WOWOW-Ondemand
require_account: Yes
enable_refresh: No
support_normal: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url:
   WIP
"""

import uuid
import time
import hashlib

__service_config__ = {
    "service_name": "WOWOW-Ondemand",
    "require_account": True,
    "enable_refresh": False,
    "support_normal": False,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        
        self.x_user_id = None
        self.x_session_token = None
        self.wip_access_token = None
        self.wip_refresh_token = None
        
        self.default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.179 Mobile Safari/537.36 jp.ne.wowow.vod.androidtv/3.8.3",
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)
        
    def parse_input(self, url_input):
        pass
    def parse_input_season(self, url_input):
        pass
    def authorize(self, email_or_id, password):
        status, session_token = self.create_device_session()
        _USER_AUTH_API = "https://custom-api.wowow.co.jp/api/v1/wip/users/auth"
        
        payload = {
            "online_id": email_or_id,
            "password": password,
            "client_id": "wod-tv",
            "app_id": 5,
            "device_code": 8,
            "vuid": uuid.uuid4()
        }
        login_response = self.session.post(_USER_AUTH_API, json=payload).json()
        try:
            if login_response["error"]:
                return False, login_response["error"]["message"], False, None
        except:
            pass
        
        user_info = self.get_userinfo()
        
        self.session.headers.update({
            "Authorization": "Bearer "+login_response["access_token"],
            "X-Token-Id": str(login_response["token_id"]),
            "X-Session-Token": session_token
        })
        
        session_json = {
            "method": "LOGIN",
            "email": hashlib.sha256(email_or_id.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": login_response["access_token"],
            "refresh_token": login_response["refresh_token"],
            "additional_info": {
                "x_user_id": str(login_response["id"]),
                "x_session_token": session_token,
                "wip_access_token": login_response["wip_access_token"],
                "wip_refresh_token": login_response["wip_refresh_token"]
            }
        }
        return True, user_info, True, session_json
        
    def authorize_qr(self):
        status, session_token = self.create_device_session()
        _PIN_SESSION_CREATE = "https://session-manager.wowow.co.jp/pin/publish"
        _PIN_SESSION_CHECK = "https://session-manager.wowow.co.jp/pin/check"
        _SESSION_TOKEN_CHECK = "https://session-manager.wowow.co.jp/token/check"
        
        temp_vuid = uuid.uuid4()
        
        payload = {
            "vuid": temp_vuid
        }
        get_login_pin = self.session.post(_PIN_SESSION_CREATE, json=payload)
        if get_login_pin.status_code != 200:
            return False, "Auth Faild: Faild to get QR Login pin", False, None
        else:
            login_pin = get_login_pin.json()
            print("Login URL:", "https://r10.to/hifxfW")
            print("Code:", login_pin["pin_code"])
            
            start_time = time.time()
            
            while True:
                if time.time() - start_time >= login_pin["expires_in"]: # Expire: 5 minitus 
                    print("Code Expired. Please Re-try")
                    break
                payload = {
                    "pin_code": login_pin["pin_code"],
                    "vuid": temp_vuid
                }
                send_checkping = self.session.post(_PIN_SESSION_CHECK, json=payload)         
                if send_checkping.status_code == 200:
                    print("Login Accept")
                    
                    login_status = send_checkping.json()
                    
                    access_token = login_status["access_token"]
                    refresh_token = login_status["refresh_token"]
                    
                    
                    check_response = self.session.post(_SESSION_TOKEN_CHECK, json={}).json()
                    if check_response["result"]:
                        pass
                    else:
                        return False, "Auth Success, But failed to get another cert", False, None
                      
                    status, message = self.get_userinfo()
                    
                    self.session.headers.update({
                        "Authorization": "Bearer "+access_token,
                        "X-Token-Id": str(login_status["token_id"]),
                        "X-Session-Token": session_token
                    })
                    
                    session_json = {
                        "method": "QR_LOGIN",
                        "email": None,
                        "password": None,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "additional_info": {
                            "x_user_id": str(login_status["token_id"]),
                            "x_session_token": session_token,
                            "wip_access_token": check_response["custom_data"]["wip_access_token"],
                            "wip_refresh_token": check_response["custom_data"]["wip_refresh_token"]
                        }
                    }
                    
                    return True, message, True, session_json
                else:
                    print("Waiting Login...")
                    time.sleep(5)
    def create_device_session(self):
        try:
            url = "https://session-manager.wowow.co.jp/sessions/create"
            payload = {
              "app_version": "3.8.3",
              "system_version": "10",
              "device_code": 8,
              "is_mobile": False,
              "os_version": "10",
              "os_build_id": "29",
              "device_manufacturer": "UMIDIGI",
              "device_model": "A7S",
              "device_higher_category": "android_tv",
              "device_lower_category": "android_tv",
              "user_agent": "Mozilla\/5.0 (Linux; Android 10; A7S Build\/QP1A.190711.020; wv) AppleWebKit\/537.36 (KHTML, like Gecko) Version\/4.0 Chrome\/138.0.7204.179 Mobile Safari\/537.36 jp.ne.wowow.vod.androidtv\/3.8.3"
            }
            response = self.session.post(url, json=payload).json()
                        
            return True, response["token"]

        except:
            return False, None
    def check_token(self, token):

        self.session.headers.update({
            "Authorization": "Bearer "+token,
            "X-Token-Id": self.x_user_id,
            "X-User-Id": self.x_user_id,
            "X-Session-Token": self.x_session_token
        })
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        try:
            
            payload = {
                "refresh_token": refresh_token,
                "app_id": 5,
                "device_code": 8
            }
            refresh_response = self.session.post("https://token.prod.hjholdings.tv/token/refresh", json=payload).json()
            
            #refresh_response["token_id"]
            access_token = refresh_response["access_token"]
            refresh_token = refresh_response["refresh_token"]
            session_data["access_token"] = access_token
            session_data["refresh_token"] = refresh_token
            
            self.session.headers.update({
                "authorization": "Bearer "+access_token
            })
            
            return session_data
        except:
            return None
    def get_userinfo(self):
        _USER_INFO_API = "https://mapi.wowow.co.jp/api/v1/users/me"
        
        payload_query = {
            "with_profiles": "true",
            "app_id": 5,
            "device_code": 8
        }
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query)
        if profile_resposne.status_code == 401:
            return False, None
        return True, profile_resposne.json()
    
    def show_userinfo(self, user_data):
        profile_id = user_data["user"]["uuid"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + id: " + profile_id)