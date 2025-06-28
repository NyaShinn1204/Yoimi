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
                send_checkping = self.session.get(f"https://if.lemino.docomo.ne.jp/v1/user/loginkey/userinfo/profile", json={"member": True, "profile": True})         
                if send_checkping.status_code == 200:
                    if send_checkping.json()["member"]["account_type"] == None:
                        print("Waiting Login...")
                        time.sleep(5)
                    else:
                        print("Login Accept")
                        login_success_json = send_checkping.json()
                        self.session.headers.update({"authorization": "Bearer "+login_success_json["access_token"]})
                      
                        status, message = self.get_userinfo()
                        
                        session_json = {
                            "method": "QR_LOGIN",
                            "email": None,
                            "password": None,
                            "access_token": login_success_json["access_token"],
                            "refresh_token": None
                        }
                        
                        self.login_status = True
                        
                        return True, message, self.login_status, session_json
    
    def use_temptoken_flug(self):
        status, token = self.get_temp_token()
        self.session.headers.update({
            "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
            "accept-encoding": "gzip",
            "charset": "UTF-8",
            "content-type": "application/json",
            "x-service-token": token
        })
        return True
          
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