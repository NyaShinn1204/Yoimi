import re
import time
import hashlib

class FOD_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.login_status = False
    def authorize(self, email, password):        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        status, temp_token = self.get_temp_token()
        
        default_headers = {
            "content-type": "application/json",
            # "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "Hi-YAH!/8.402.1(Google AOSP TV on x86, Android 16 (API 36))",
            "x-ott-agent": "android-tv site/90901 android-app/8.402.1",
            "ott-client-version": "8.402.1",
            "x-ott-language": "en_US",
            "x-authorization": "Bearer "+temp_token["access\token"],
        }
        
        self.session.headers.update(default_headers)
        
        if email == "QR_LOGIN":
            """
            Get QR login url
            """
            # default_headers["host"] = "fod-sp.fujitv.co.jp"
            # self.session.headers.update(default_headers)
            # get_loginurl = self.session.get("https://fod-sp.fujitv.co.jp/apps/api/login/pin/?dv_type=tv")
            # if get_loginurl.status_code != 200:
            #     return False, "Authentication Failed: Failed to get QR login url", None, None, None
            # else:
            #     request_login_json = get_loginurl.json()
            #     print("Login URL:", request_login_json["url"])
            #     print("Code:", request_login_json["code"])
                
            #     while True:
            #         send_checkping = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_pin/", json={"pin": request_login_json["code"]})                        
            #         if send_checkping.status_code == 400:
            #             print("Waiting Login...")
            #             time.sleep(5)
            #         elif send_checkping.status_code == 200:
            #             print("Login Accept")
            #             login_success_json = send_checkping.json()
            #             gen_token = self.gen_login_uid_token(login_success_json["uid"])
            #             self.session.headers.update({"x-authorization": "Bearer "+gen_token})
                        
            #             status, message, login_uuid = self.get_userinfo()
            #             fod_user_id = message.get("member_id")
            #             if message == "1012":
            #                 return False, "Authentication Failed: This account is not subscription", None, None, None
            #             else:
            #                 self.logined_headers = self.session.headers
            #                 self.login_status = [False, True]
                            
            #                 session_json = {
            #                     "method": "QR_LOGIN",
            #                     "email": hashlib.sha256(email.encode()).hexdigest(),
            #                     "password": hashlib.sha256(password.encode()).hexdigest(),
            #                     "access_token": gen_token,
            #                     "refresh_token": None
            #                 }
                            
            #                 return True, message, login_uuid, self.login_status, session_json
        
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "Hi-YAH! require email and password", None, None, None
            
        # payload = {
        #     "mail_address": email,
        #     "password": password
        # }    
        
        # response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        # response.raise_for_status()
        
        # email_verify_hashkey = response.json()["hash_key"]
        # mail_auth_code = input("MAIL AUTH CODE : ")
        # if mail_auth_code == None:
        #     return False, "Authentication Failed: Require Mail Auth Code", None, None, None
        # else:
        #     pass
        
        # payload = {
        #     "auth_code": str(mail_auth_code),
        #     "hash_key": email_verify_hashkey
        # }
        # login_status_check = self.session.post("https://id.fod.fujitv.co.jp/api/member/CheckAuthCodeApp", headers=default_headers, json=payload)
        # login_status_check.raise_for_status()
        
        # fodid_login_token = login_status_check.json()["fodid_login_token"]
        
        # # default_headers["host"] = "fod-sp.fujitv.co.jp"
        # self.session.headers.update(default_headers)
        
        # payload = {
        #     "fodid_login_token": fodid_login_token
        # }
        # check_token_status = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_token/", headers=default_headers, json=payload)
        # check_token_status.raise_for_status()
        
        # uid = check_token_status.json()["uid"]
        
        # login_token = self.gen_login_uid_token(uid)
        
        # self.session.headers.update({"x-authorization": "Bearer "+login_token})
        
        # status, message, login_uuid = self.get_userinfo()
        # fod_user_id = message.get("member_id")
        # if message == "1012":
        #     return False, "Authentication Failed: This account is not subscription", None, None, None
        # else:
        #     self.logined_headers = self.session.headers
        #     self.login_status = [False, True]
        #     session_json = {
        #         "method": "NORMAL",
        #         "email": hashlib.sha256(email.encode()).hexdigest(),
        #         "password": hashlib.sha256(password.encode()).hexdigest(),
        #         "access_token": login_token,
        #         "refresh_token": None
        #     }
        #     return True, message, login_uuid, self.login_status, session_json

    def get_temp_token(self):
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "grant_type": "client_credentials",
          "scope": "read write"
        }
        
        temp_token = self.session.post("https://api.vhx.tv/oauth/token/", json=payload)
        if temp_token.status_code == 200:
            return True, temp_token.json()
        else:
            return False, None
    def gen_login_uid_token(self, uid):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx" # Haha cracked from AndroidTV APK
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "uid": uid,
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jwt_token
    
    def get_userinfo(self):
        global fod_user_id
        url = "https://fod-sp.fujitv.co.jp/apps/api/user/status/"
        
        querystring = { "dv_type": "tv" }
            
        response = self.session.get(url, params=querystring)
        if response.status_code == 200:
            fod_user_id = response.json().get("member_id")
            return True, response.json(), response.cookies.get("uuid")
        elif response.status_code == 401:
            return False, response.json["code"], None