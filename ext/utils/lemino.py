import re
import os
import time
import json
import hashlib
import requests
import threading
import subprocess

from tqdm import tqdm
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Lemino_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.login_status = False
    def authorize_qr(self):        
        status, temp_token = self.get_temp_token()
        
        default_headers = {
            "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
            "accept-encoding": "gzip",
            "charset": "UTF-8",
            "content-type": "application/json",
            "x-service-token": temp_token
        }
        
        self.session.headers.update(default_headers)
        
        """
        Get QR login pass key
        """
        
        get_loginurl = self.session.post("https://if.lemino.docomo.ne.jp/v1/user/auth/loginkey/create")
        if get_loginurl.status_code != 200:
            return False, "Authentication Failed: Failed to get QR login pass key", None, None
        else:
            request_login_json = get_loginurl.json()
            print("Login URL:", "https://lemino.docomo.ne.jp/tv")
            print("Code:", request_login_json["loginkey"])
            
            start_time = time.time()
            
            while True:
                if time.time() - start_time >= 900: # Expire: 15 minitus 
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
                        "email": None,
                        "password": None,
                        "access_token": login_success_json["access_token"],
                        "refresh_token": login_success_json["refresh_token"]
                    }
                    
                    self.login_status = True
                    
                    return True, message, self.login_status, session_json
                    
    def get_temp_token(self):
        self.session.headers.update({
            "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
            "accept-encoding": "gzip",
            "charset": "UTF-8",
            "content-type": "application/json",
            "x-service-token": None
        })
        
        terminal_type = {
            "android_tv": "1",
            "android": "3"
        }
        
        temp_token = self.session.post("https://if.lemino.docomo.ne.jp/v1/session/init", json={"terminal_type": terminal_type["android_tv"]})
        
        if temp_token.status_code == 200:
            return True, temp_token.headers["x-service-token"]
        else:
            return False, None
    def check_token(self, token):
        self.session.headers.update({
            "x-service-token": token
        })
        status, return_json = self.get_userinfo()
        return status, return_json
    def get_userinfo(self):
        url = "https://if.lemino.docomo.ne.jp/v1/user/loginkey/userinfo/profile"
                    
        response = self.session.post(url, json={"member": True, "profile": True})
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