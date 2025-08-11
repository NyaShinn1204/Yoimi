"""
SERVICE INFO


name: RakutenTV-JP
require_account: No
enable_refresh: No
support_qr: No
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url:
   WIP
"""

import time

__service_config__ = {
    "service_name": "RakutenTV-JP",
    "require_account": False,
    "enable_refresh": False,
    "support_qr": False,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger

        self.default_headers = {
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; A7S Build/QP1A.190711.020) Rakuten TV AndroidTV/2.2.5-edce7eacd6-P (Linux;Android 10) AndroidXMedia3/1.4.1",
            "host": "api.tv.rakuten.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
        }
        self.session.headers.update(self.default_headers)

        self.device_list = {
            "Windows XP": "1",         # DASH        1280x720
            "Windows Vista": "2",      # DASH        1280x720
            "Xbox 360": "3",           # API ERROR
            "Windows 7": "4",          # DASH        1280x720
            "Windows RT": "5",         # API ERROR
            "Windows 8": "6",          # DASH        1280x720
            "Windows Other": "7",      # API ERROR
            "Windows Phone": "8",      # API ERROR
            "iPad": "9",               # HLS         1280x720
            "iPhone,iPod touch": "10", # HLS         960x540
            "Intel Mac": "11",         # HLS & DASH  1280x720
            "Mac Other": "12",         # API ERROR
            "Android mobile": "13",    # DASH        960x540
            "Android tablet": "14",    # DASH        1280x720
            "Android Other": "15",     # API ERROR
            "Chromecast": "16",        # DASH        1920x1080
            "VIERA HLS": "17",         # HLS         SERVER DOWN (Status: 500)
            "VIERA": "18",             # DASH        1920x1080
            "BRAVIA": "19",            # DASH        1920x1080
            "Wii U": "20",             # DASH        1920x1080
            "Xbox One": "21",          # DASH        1920x1080
            "Windows 10": "22",        # DASH        1280x720
            "PS4": "23",               # DASH        1920x1080
            "UNKNOWN DEVICE": "24",    # DASH        1920x1080
            "Android TV": "25",        # DASH        1920x1080
            "Apple TV": "26",          # HLS         1920x1080
            "REGZA": "27",             # DASH        1920x1080
            "Fire TV": "28",           # DASH        1920x1080
        }
        
        self.device_id = self.device_list["Android TV"]
        
    def parse_input(self):
        pass
    def parse_input_season(self):
        pass
    
    def authorize(self, email_or_id, password):
        pass
    def authorize_qr(self):
        client_id = "z6RYVPgpJD6FuD575jby" ## 固定
        auth_basic = "Basic ejZSWVZQZ3BKRDZGdUQ1NzVqYnk6dUphczl5NHFrcmN1RngwRENwV2w2ZnEz" ## 固定
        
        """
        https://r10.to/hifxfW -> https://auth.tv.rakuten.co.jp/oauth/activate_code/
        https://r10.to/hkAGWM -> https://auth.tv.rakuten.co.jp/oauth/activate_code_ftv/
        """
        
        """
        Get QR login pass key
        """
        
        get_login_pass = self.session.get(f"https://auth.tv.rakuten.co.jp/oauth/code.json?response_type=code&client_id={client_id}&nr=1")
        if get_login_pass.status_code != 200:
            return False, "Auth Faild: Fialed to get QR Login pass key", None, None
        else:
            login_key = get_login_pass.json()
            print("Login URL:", "https://r10.to/hifxfW")
            print("Code:", login_key["result"]["code"])
            
            while True:
                querystring = {
                    "grant_type": "authorization_code",
                    "code": login_key["result"]["code"],
                    "polling": "1",
                    "issue_sec_cookie": "0",
                    "device_name": "sdk_google_atv_x86",
                    "device_id": str(self.device_id)
                }
                headers = {
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001) Rakuten TV AndroidTV/2.2.5-edce7eacd6-P (Linux;Android 10) AndroidXMedia3/1.4.1",
                    "authorization": auth_basic,
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip"
                }
                send_checkping = self.session.post(f"https://auth.tv.rakuten.co.jp/oauth/token.json", params=querystring, headers=headers)         
                if send_checkping.status_code == 200:
                    print("Login Accept")
                    
                    login_status = send_checkping.json()
                    
                    access_token = login_status["result"]["access_token"]
                    refresh_token = login_status["result"]["refresh_token"]
                    
                    self.session.headers.update({
                        "Authorization": access_token,
                        "Access-Token": access_token
                    })
                      
                    status, message = self.get_userinfo()
                    
                    session_json = {
                        "method": "QR_LOGIN",
                        "email": None,
                        "password": None,
                        "access_token": access_token,
                        "refresh_token": refresh_token
                    }
                    
                    return True, message, True, session_json
                elif send_checkping.status_code == 403:
                    print("Waiting Login...")
                    time.sleep(5)
    def check_token(self, token):
        pass
    def get_userinfo(self):
        _USER_INFO_API = "https://auth.tv.rakuten.co.jp/app_auth/user_info.json"
        
        profile_resposne = self.session.post(_USER_INFO_API)
        if profile_resposne.json()["status"] == "error":
            return False, None
        elif profile_resposne.json()["status"] == "success":
            return True, profile_resposne.json()["result"]
        else:
            return False, None

    def show_userinfo(self, user_data):
        profile_id = user_data["encrypt_member_id"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + enc_id: " + profile_id)