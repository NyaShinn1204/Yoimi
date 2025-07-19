"""
SERVICE INFO


name: Hulu-jp
require_account: Yes
enable_refresh: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://www.hulu.jp/xxx
   https://www.hulu.jp/watch/xxx
   https://www.hulu.jp/store/watch/xxx
"""

from ext.utils.pymazda.sensordata.sensor_data_builder import SensorDataBuilder

__user_agent__ = "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV"
__service_config__ = {
    "service_name": "Hulu-jp",
    "require_account": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
    
    def authorize(self, email, password):
        #global user_info_res
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
        
        self.web_headers = default_headers
            
        return True, profile_resposne
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
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query).json()
        return True, profile_resposne
    
    def show_userinfo(self, user_data):
        self.logger.info("Get Profile list")
        for idx, one_profile in enumerate(user_data, 1):
            self.logger.info(f" + {str(idx)}: Has pin: {one_profile[1]} | {one_profile[0]} ")
            
        profile_num = int(input("Please enter the number of the profile you want to use >> ")) -1
        
        select_profile_uuid = user_data[profile_num][2]
        if user_data[profile_num][1] == "Yes":
            pin = input("Profile PIN >> ")
        else:
            pin = ""
        
        status, user_data = self.select_profile(select_profile_uuid, pin=pin)
        
        if status != True:
            self.logger.error(user_data)
        
        self.logger.info("Success change profile")
        self.logger.info(" + Nickname: "+user_data["profile"]["nickname"])
            