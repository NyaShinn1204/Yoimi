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
        pass
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
            