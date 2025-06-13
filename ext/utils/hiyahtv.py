import re
import time
import json
import hashlib

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class HI_YAH_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.login_status = False
    def authorize(self, email, password):        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        status, temp_token = self.get_temp_token()
        
        default_headers = {
            "content-type": "application/json",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "Hi-YAH!/8.402.1(Google AOSP TV on x86, Android 16 (API 36))",
            "x-ott-agent": "android-tv site/90901 android-app/8.402.1",
            "ott-client-version": "8.402.1",
            "x-ott-language": "en_US",
            "authorization": "Bearer "+temp_token["access_token"],
        }
        
        self.session.headers.update(default_headers)
        
        if email == "QR_LOGIN":
            """
            Get QR login url
            """
            # default_headers["host"] = "fod-sp.fujitv.co.jp"
            # self.session.headers.update(default_headers)
            get_loginurl = self.session.post("https://api.vhx.tv/oauth/codes/", json={"client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6","client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd"})
            if get_loginurl.status_code != 201:
                return False, "Authentication Failed: Failed to get QR login url", None, None
            else:
                request_login_json = get_loginurl.json()
                print("Login URL:", "https://www.hiyahtv.com/activate")
                print("Code:", request_login_json["code"])
                
                start_time = time.time()
                
                while True:
                    if time.time() - start_time >= request_login_json["expires_in"]:
                        print("Code Expired. Please Re-try")
                        break
                    send_checkping = self.session.get(f"https://api.vhx.tv/oauth/codes/{request_login_json["code"]}", params={"client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6","client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd"})                        
                    if send_checkping.status_code == 404:
                        print("Waiting Login...")
                        time.sleep(5)
                    elif send_checkping.status_code == 200:
                        print("Login Accept")
                        login_success_json = send_checkping.json()
                        self.session.headers.update({"authorization": "Bearer "+login_success_json["access_token"]})
                      
                        status, message = self.get_userinfo()
                        
                        session_json = {
                            "method": "QR_LOGIN",
                            "email": hashlib.sha256(email.encode()).hexdigest(),
                            "password": hashlib.sha256(password.encode()).hexdigest(),
                            "access_token": login_success_json["access_token"],
                            "refresh_token": login_success_json["refresh_token"]
                        }
                        
                        self.login_status = True
                        
                        return True, message, self.login_status, session_json
        
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "Hi-YAH! require email and password", None, None, None
            
        payload = {
            "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
            "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
            "username": email,
            "grant_type": "password",
            "password": password
        }
        
        response = self.session.post("https://auth.vhx.com/v1/oauth/token", headers=default_headers, json=payload)
        response.raise_for_status()
        
        status, message = self.get_userinfo()
        self.login_status = True
        session_json = {
            "method": "NORMAL",
            "email": hashlib.sha256(email.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": response.json()["acccess_token"],
            "refresh_token": response.json()["refresh_token"]
        }
        return True, message, self.login_status, session_json
    
    def get_temp_token(self):
        self.session.headers.update({"authorization": None})
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
    def check_token(self, token):
        self.session.headers.update({
            "authorization": "Bearer " + token
        })
        status, return_json = self.get_userinfo()
        return status, return_json
    def get_userinfo(self):
        url = "https://api.vhx.com/v2/sites/90901/me"
                    
        response = self.session.get(url)
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, None
    def refresh_token(self, refresh_token, old_session_json):
        status, temp_token = self.get_temp_token()
        self.session.headers.update({"authorization": "Bearer "+ temp_token["access_token"]})
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "grant_type": "refresh_token",
          "refresh_token": refresh_token
        }
        refresh_return = self.session.post("https://api.vhx.tv/oauth/token/", json=payload)
        if refresh_return.status_code == 200:
            self.session.headers.update({"authorization": "Bearer " + refresh_return.json()["access_token"]})
            session_json = {
                "method": "NORMAL",
                "email": old_session_json["email"],
                "password": old_session_json["password"],
                "access_token": refresh_return.json()["access_token"],
                "refresh_token": refresh_return.json()["refresh_token"]
            }
            return True, refresh_return.json(), session_json
        else:
            return False, None, None
        
    def revoke_token(self, token):
        payload = {
          "client_id": "27ef31d7c3817dfdcb9db4d47fbf9ce92144f361c34fe45e5cd80baab2f258b6",      # From Android TV
          "client_secret": "4bc905f4faa17b9e379bbcf0547d7cad710603e316b0a35dc0f3e3568d797bfd",  # From Android TV
          "token": token,
        }
        revoke_status = self.session.post("https://api.vhx.tv/oauth/revoke", json=payload)
        if revoke_status.status_code == 200:
            return True
        else:
            return False
        
    
    def get_contentid_page(self, url):
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")
    
            content_id_name = None
            if "videos" in path_parts:
                videos_index = path_parts.index("videos")
                if videos_index + 1 < len(path_parts):
                    content_id_name = path_parts[videos_index + 1]
            else:
                content_id_name = path_parts[-1]
    
            if not content_id_name:
                return None
    
            full_url = urljoin("https://www.hiyahtv.com/", content_id_name)
            response = self.session.get(full_url)
            response.raise_for_status()

            match = re.search(r'window\.Page\s*=\s*({.*?})\s*(?:</script>|$)', response.text, re.DOTALL)
            if match:
                json_text = match.group(1)
                page_data = json.loads(json_text)
                return page_data
            else:
                return None
            return None
    
        except Exception as e:
            print(e)
            return None
        
    def get_content_info(self, content_id):
        try:
            metadata_response = self.session.get(f"https://api.vhx.com/v2/sites/90901/collections/{content_id}?include_events=1")
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json
            else:
                return False, None
        except Exception:
            return False, None