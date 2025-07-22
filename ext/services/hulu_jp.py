"""
SERVICE INFO


name: Hulu-jp
require_account: Yes
enable_refresh: Yes
support_qr: No
cache_session: Yes
use_tlsclient: No
support_url: 
   https://www.hulu.jp/xxx
   https://www.hulu.jp/watch/xxx
   https://www.hulu.jp/store/watch/xxx
"""

import re
import hashlib

from ext.utils.pymazda.sensordata.sensor_data_builder import SensorDataBuilder

__user_agent__ = "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV"
__service_config__ = {
    "service_name": "Hulu-jp",
    "require_account": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
    "support_qr": False
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cache = True
        
        self.x_user_id = None
        self.x_session_token = None
        self.x_gaia_authorization = None
        
        self.auth_headers = {
            "user-agent": "jp.happyon.android/3.24.0 (Android 9; 22081212C Build/PQ3B.190801.10101846)",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "accept-language": "ja",
        }

    def authorize(self, email, password):
        self.use_cache = False
        global test_temp_token
        _SESSION_CREATE = "https://mapi.prod.hjholdings.tv/api/v1/sessions/create"
        _LOGIN_API = "https://mapi.prod.hjholdings.tv/api/v1/users/auth"
        _USER_INFO_API = "https://mapi.prod.hjholdings.tv/api/v1/users/me"
        
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
            "app_id": 5,
            "device_code": 8
        }   
        sensor_data_builder = SensorDataBuilder()
        default_headers.update({
            "x-gaia-authorization": "extra " + gaia_token_1,
            "x-session-token": session_token_1,
            "x-acf-sensor-data": sensor_data_builder.generate_sensor_data(),
            "user-agent": "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV",
        })
        
        login_response = self.session.post(_LOGIN_API, json=payload, headers=default_headers)
        login_response = login_response.json()
        
        default_headers.update({
            "x-user-id": str(login_response["id"])
        })
                
        ## get profile list
        payload_query = {
            "with_profiles": "true",
            "app_id": 5,
            "device_code": 8
        }
        
        test_temp_token = "Bearer " + login_response["access_token"]
        
        default_headers.update({
            "authorization": "Bearer " + login_response["access_token"],
            "x-session-token": login_response["session_token"],
            "x-gaia-authorization": "extra " + login_response["gaia_token"]
        })
        
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query, headers=default_headers).json()
        
        self.auth_headers = default_headers.copy()
        
        session_json = {
            "method": "LOGIN",
            "email": hashlib.sha256(email.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": login_response["access_token"],
            "refresh_token": login_response["refresh_token"],
            "additional_info": {
                "x_user_id": str(login_response["id"]),
                "x_session_token": login_response["session_token"],
                "x_gaia_authorization": "extra " + login_response["gaia_token"]
            }
        }
        return True, profile_resposne, True, session_json
    def check_token(self, token):
        self.session.headers.update({
            "authorization": "Bearer " + token,
            "x-user-id": self.x_user_id
        })
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        payload = {
            "refresh_token": refresh_token,
            "app_id": 5,
            "device_code": 8
        }
        refresh_response = self.session.post("https://token.prod.hjholdings.tv/token/refresh", json=payload).json()
        
        #refresh_response["token_id"]
        access_token = refresh_response["access_token"]
        refresh_token = refresh_response["refresh_token"]
        session_json = {
            "method": "normal",
            "email": None,
            "password": None,
            "access_token": access_token,
            "refresh_token": refresh_token
        }
        return session_json
    def get_userinfo(self):
        _USER_INFO_API = "https://mapi.prod.hjholdings.tv/api/v1/users/me"
        
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
        profile_list = []
        for single_profile in user_data["profiles"]:
            if single_profile["values"]["has_pin"]:
                pin_status = "Yes"
            else:
                pin_status = "No "
            profile_list.append([single_profile["display_name"], pin_status, single_profile["uuid_in_schema"]])

        self.logger.info("Get Profile list")
        for idx, one_profile in enumerate(profile_list, 1):
            self.logger.info(f" + {str(idx)}: Has pin: {one_profile[1]} | {one_profile[0]} ")
            
        input_like = input("Please enter the number of the profile you want to use >> ")
        try:
            int(input_like)
        except ValueError:
            print("Invalid Input.")
            exit()
        profile_num = int(input_like) -1
        
        select_profile_uuid = profile_list[profile_num][2]
        if profile_list[profile_num][1] == "Yes":
            pin = input("Profile PIN >> ")
        else:
            pin = ""
                
        status, user_data = self.select_profile(select_profile_uuid, pin=pin)
        
        if status != True:
            self.logger.error(user_data)
        
        self.logger.info("Success change profile")
        self.logger.info(" + Nickname: "+user_data["profile"]["nickname"])
    
    def select_profile(self, uuid, pin=""):
        payload = {
            "pin": pin,
            "profile_id": uuid
        }
        headers = self.auth_headers.copy()
        if self.use_cache:
            headers.update({
                "x-session-token": self.x_session_token,
                "x-gaia-authorization": self.x_gaia_authorization,
            })
        meta_response = self.session.put("https://mapi.prod.hjholdings.tv/api/v1/gaia/auth/profile", json=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                profile_change_response = meta_response.json()
                self.auth_headers.update({
                    "x-session-token": profile_change_response["session_token"],
                })
                return True, profile_change_response
        except:
            return False, "Failed to login profile"
        
    # 単体かシーズンかをチェック
    def judgment_watchtype(self, url):
        match = re.search(r'/watch/(\d+)', url)
        if match:
            return "single"
        else:
            return "season"