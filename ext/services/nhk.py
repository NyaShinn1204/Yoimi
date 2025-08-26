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

class nhk_plus:
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
class nhk_ondemand:
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
            tv_device_id = uuid.uuid4()

            payload = {
                "tvTerminalId": tv_device_id
            }

            activation_response = self.session.post("https://www.nhk-ondemand.jp/activationcode/generation", json=payload).json()
            
            code = activation_response["activationCode"]


            ## MAIN AUTHORIZATION
            payload = {
                "activationCode": code,
                "password": password,
                "userId": user_id
            }
            self.session.post("https://www.nhk-ondemand.jp/activationcode/authentication", json=payload)

            ## activation
            payload = {
                "tvTerminalId": tv_device_id,
                "activactionCode": code
            }
            activation_response_main = self.session.post("https://www.nhk-ondemand.jp/activationcode/verification", json=payload).json()
            client_secret = activation_response_main["clientSecret"]
            user_id = activation_response_main["userId"]
            
            
            payload = {
                "clientSecret": client_secret,
                "userId": user_id
            }
            login_response = self.session.post("https://www.nhk-ondemand.jp/activationcode/login", json=payload).json()

            if login_response["result"] != "OK":
                return False, "Authencation failed", False, None
            
            session_json = {
                "method": "LOGIN",
                "email": hashlib.sha256(user_id.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": client_secret,
                "refresh_token": "",
                "additional_info": {
                    "client_secret": client_secret
                }
            }
            
            return True, {"userid": user_id}, True, session_json