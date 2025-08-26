"""
SERVICE INFO


name: NHK
require_account: Yes
enable_refresh: No
support_normal: Yes
support_qr: No
is_drm: Both
cache_session: Yes
use_tlsclient: No
support_url: 
   WIP
"""

import uuid
import hashlib

class plus:
    __service_config__ = {
        "service_name": "NHK+",
        "require_account": True,
        "enable_refresh": False,
        "support_normal": True,
        "support_qr": False,
        "is_drm": True,
        "cache_session": True,
        "use_tls": False,
    }
class ondemand:
    __service_config__ = {
        "service_name": "NHK-Ondemand",
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

            self.user_id = None
            
            self.default_headers = {
                "host": "www.nhk-ondemand.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.9.0"
            }
            self.session.headers.update(self.default_headers)
        
        def parse_input(self, url_input):
            pass
        def parse_input_season(self, url_input):
            pass
        def authorize(self, user_id, password):
            tv_device_id = str(uuid.uuid4())

            payload = {
                "tvTerminalId": tv_device_id
            }

            activation_response = self.session.post("https://www.nhk-ondemand.jp/activationcode/generation", data=payload).json()
            
            code = activation_response["activationCode"]


            ## MAIN AUTHORIZATION
            payload = {
                "activationCode": code,
                "password": password,
                "userId": user_id
            }
            self.session.post("https://www.nhk-ondemand.jp/activationcode/authentication", data=payload)

            ## activation
            payload = {
                "tvTerminalId": tv_device_id,
                "activationCode": code
            }
            activation_response_main = self.session.post("https://www.nhk-ondemand.jp/activationcode/verification", data=payload).json()
            client_secret = activation_response_main["clientSecret"]
            user_id = activation_response_main["userId"]
            
            
            payload = {
                "clientSecret": client_secret,
                "userId": user_id
            }
            login_response = self.session.post("https://www.nhk-ondemand.jp/activationcode/login", data=payload).json()

            if login_response["result"] != "OK":
                if login_response["errorCode"] == "E001":
                    return False, "Authencation failed: Wrong ID or Password", False, None
                else:
                    return False, f"Authencation failed: {login_response["errorMessage"]}", False, None
            
            session_json = {
                "method": "LOGIN",
                "email": hashlib.sha256(user_id.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": client_secret,
                "refresh_token": "",
                "additional_info": {
                    "user_id": user_id,
                    "client_secret": client_secret
                }
            }
            
            return True, {"id": user_id}, True, session_json
        
        def check_token(self, token):
            cache_login = "https://www.nhk-ondemand.jp/activationcode/login"
            payload = {
                "clientSecret": token,
                "userId": self.user_id
            }

            response = self.session.post(cache_login, data=payload)

            if response.json()["result"] != "OK":
                return False, None
            else:
                return True, {"id": self.user_id}
        def show_userinfo(self, user_data):
            profile_id = user_data["id"]
            self.logger.info("Logged-in Account")
            self.logger.info(" + id: " + profile_id)

        def judgment_watchtype(self, url):
            if "/program/" in url:
                return "season"
            elif "/goods/" in url:
                return "single"
            else:
                return None