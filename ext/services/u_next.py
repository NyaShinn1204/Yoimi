import uuid
import time
import hashlib

__service_config__ = {
    "service_name": "U-Next",
    "require_account": True,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "enable_refresh": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cahce = True
        
        self.default_headers = {
            "user-agent": "U-NEXT TV App Android10 5.49.0 A7S",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)
        
    def authorize(self, email_or_id, password):
        _ENDPOINT_LOGIN = "https://napi.unext.jp/1/auth/login"
        
        device_uuid = str(uuid.uuid4())
        
        payload = {
          "common": {
            "userInfo": {
              "userToken": "",
              "service_name": "unext"
            },
            "deviceInfo": {
              "deviceType": "980",
              "appVersion": "1",
              "deviceUuid": device_uuid
            }
          },
          "data": {
            "loginId": email_or_id,
            "password": password
          }
        }
        
        response = self.session.post(_ENDPOINT_LOGIN, json=payload)
        
        user_response = response.json()
        
        if user_response["common"]["result"]["errorCode"] == "":
            
            user_token = user_response["common"]["userInfo"]["userToken"]
            security_token = user_response["common"]["userInfo"]["securityToken"]
            
            ### migrate token
            payload = {
                "client_id": "unextAndroidApp",
                "scope": [
                    "offline",
                    "unext"
                ],
                "portal_user_info": {
                    "securityToken": security_token
                }
            }
            response = self.session.post("https://oauth.unext.jp/oauth2/migration", json=payload)
            
            ### get token
            payload = {
                "client_id": "unextAndroidApp",
                "client_secret": "unextAndroidApp",
                "grant_type": "authorization_code",
                "code": response.json()["auth_code"],
                "redirect_uri": response.json()["redirect_uri"]
            }
            response = self.session.post("https://oauth.unext.jp/oauth2/token", data=payload)
            
            response = response.json()
            
            session_json = {
                "method": "LOGIN",
                "email": hashlib.sha256(email_or_id.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": response["access_token"],
                "refresh_token": response["refresh_token"],
                "additional_info": {
                    "device_uuid": device_uuid,
                    "user_token": user_token
                }
            }
            return True, user_response["common"]["userInfo"], True, session_json
        elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
            return False, 'Wrong Email or password', False, None
        elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
            return False, 'Require Japan VPN, Proxy', False, None
    def authorize_qr(self):
        _ENDPOINT_LOGIN = "https://login-delegation.unext.jp/"
       
        device_uuid = str(uuid.uuid4())
        
        payload = {
            "device": {
                "appVersion": "5.49.0",
                "deviceName": "Yoimi",
                "deviceType": "980",
                "deviceUuid": device_uuid,
                "location": "tokyo"
            }
        }
        
        response = self.session.post(_ENDPOINT_LOGIN+"session", json=payload)
        get_qr_link = response.json()
        
        session_check_data = {
          "code": get_qr_link["code"],
          "sessionId": get_qr_link["dd2388ba"]
        }
        
        print("Login URL:", get_qr_link["authPageUrlTemplate"])
        print("Code:", get_qr_link["code"])
        
        while True:
            send_checkping = self.session.post(_ENDPOINT_LOGIN+"session/poll", json=session_check_data)
            if send_checkping.status_code == 400:
                print("Waiting Login...")
                time.sleep(5)
            elif send_checkping.status_coed == 200:
                print("Login Accept")
                
                ## ToDo: Make Qr Login
                return False, None
                
                 
                #one_time_token = send_checkping.json()["data"]["loginDelegationPollSession"]["oneTimeToken"]
                #
                #payload = {
                #    "oneTimeToken": one_time_token,
                #}
                #
                #response = self.session.post(_ENDPOINT_LOGIN, json=payload)
                #
                #user_response = response.json()
                #
                #session_json = {
                #    "method": "QR_LOGIN",
                #    "email": None,
                #    "password": None,
                #    "access_token": response.cookies["_ut"],
                #    "refresh_token": None,
                #    "additional_info": {}
                #}
                #
                #return True, user_response["common"]["userInfo"], True, session_json
            elif send_checkping.status_code == 403:
                print("Login request is expired")
                return False, None
    def check_token(self, token):
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        try:
            return None
        except:
            return None
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