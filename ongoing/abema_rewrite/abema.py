import re
import os
import json
import time
import hmac
import uuid
import hashlib
import string
import random
import requests
import subprocess
from base64 import urlsafe_b64encode, urlsafe_b64decode
from tqdm import tqdm
from datetime import datetime
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Abema_utils:
    def gen_temp_token(session):
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        def gen_key_secret(devid):
            SECRETKEY = (b"v+Gjs=25Aw5erR!J8ZuvRrCx*rGswhB&qdHd_SYerEWdU&a?3DzN9B"
                        b"Rbp5KwY4hEmcj5#fykMjJ=AuWz5GSMY-d@H7DMEh3M@9n2G552Us$$"
                        b"k9cD=3TxwWe86!x#Zyhe")
            device_id = devid.encode("utf-8")
            ts_1hour = (int(time.time()) + 60 * 60) // 3600 * 3600
            time_struct = time.gmtime(ts_1hour)
            ts_1hour_str = str(ts_1hour).encode("utf-8")

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(SECRETKEY)
            tmp = h.digest()

            for _ in range(time_struct.tm_mon):
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(urlsafe_b64encode(tmp).rstrip(b"=") + device_id)
            tmp = h.digest()

            for _ in range(time_struct.tm_mday % 5):
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(urlsafe_b64encode(tmp).rstrip(b"=") + ts_1hour_str)
            tmp = h.digest()

            for _ in range(time_struct.tm_hour % 5):  # utc hour
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            finalize = urlsafe_b64encode(tmp).rstrip(b"=").decode("utf-8")
            
            return finalize

        device_id = str(uuid.uuid4())
        json_data = {"deviceId": device_id, "applicationKeySecret": gen_key_secret(device_id)}

        res = session.post(_USERAPI, json=json_data).json()

        try:
            token = res['token']
        except:
            return None

        return [token, device_id]

class Abema_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email_or_id, password):
        if email_or_id and password == None:
            # this area to make temporary token for download
            print()
            return True, None
        
        # ログインのため仮tokenの生成
        self.session.headers.update({'Authorization': 'Bearer ' + Abema_utils.gen_temp_token(self.session)[0]})
        
        _ENDPOINT_MAIL = "https://api.p-c3-e.abema-tv.com/v1/auth/user/email"
        _ENDPOINT_OTP = "https://api.p-c3-e.abema-tv.com/v1/auth/oneTimePassword"
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
        if not re.fullmatch('[0-9]+', email_or_id):
            if not re.fullmatch(mail_regex, email_or_id):
                return False, "Unext require email and password"
            
        if re.search(mail_regex, email_or_id):
            _ENDPOINT_USE = _ENDPOINT_MAIL
            _PAYLOAD_METHOD = "email"
        else:
            _ENDPOINT_USE = _ENDPOINT_OTP
            _PAYLOAD_METHOD = "userId"
            
        auth_payload = {
            _PAYLOAD_METHOD: email_or_id,
            "password": password
        } 
        
        auth_response = self.session.post(_ENDPOINT_USE, json=auth_payload)
        auth_response_json = auth_response.json()
        
        if auth_response.status_code != 200:
            return False, 'Wrong Email or password combination'
        
        userId = auth_response_json["profile"]["userId"]
        self.session.headers.update({'Authorization': 'Bearer ' + auth_response_json["token"]})
        
        user_info_res = self.session.get(_USERAPI+"/"+userId)
        return True, user_info_res.json()
    def check_token(self, token):
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        token_payload = token.split(".")[1]
        token_payload_decoded = str(urlsafe_b64decode(token_payload + "=="), "utf-8")
        payload = json.loads(token_payload_decoded)
        userId = payload["sub"]
        self.session.headers.update({'Authorization': token})
        
        user_info_res = self.session.get(_USERAPI+"/"+userId)
        if user_info_res.status == 200:
            return True, user_info_res.json()
        else:
            return False, "Invalid Token"