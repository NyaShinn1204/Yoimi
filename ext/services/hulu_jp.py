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
    def __init__(self, session):
        self.session = session
    
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