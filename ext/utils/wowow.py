import re
import os
import jwt
import ast
import uuid
import m3u8
import random
import base64
import string
import requests
import subprocess
from tqdm import tqdm
from bs4 import BeautifulSoup
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote, urljoin

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class WOD_downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.user_agent = "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 jp.ne.wowow.vod.androidtv/3.7.0"
        self.common_headers = {
            "user-agent": self.user_agent,
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "host": "custom-api.wowow.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
    def authorize(self, email, password):
        try:
            url = "https://custom-api.wowow.co.jp/api/v1/wip/users/auth"
            headers = self.common_headers.copy()
            payload = {
                "online_id": email,
                "password": password,
                "client_id": "wod-tv",
                "app_id": 5,
                "device_code": 8,
                "vuid": uuid.uuid4().hex
            }
            response = self.session.post(url, headers=headers, json=payload, allow_redirects=False).json()
            try:
                if response["error"]:
                    return False, response["error"]["message"]
            except:
                pass
            
            self.user_id = response["id"]
            
            self.session.headers.update({"authorization": response["access_token"]})
            
            return True, response

        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer
    def check_token(self, wat):
        try:
            url = "https://session-manager.wowow.co.jp/token/check"
            headers = self.common_headers.copy()
            headers["host"] = "session-manager.wowow.co.jp"
            headers["x-token-id"] = str(self.user_id)
            headers["x-session-token"] = self.x_session_token
            payload = {
              "wip_access_token": wat
            }
            response = self.session.post(url, json=payload, headers=headers)
            if response.json()["result"]:
                return True, "Valid"
            else:
                return False, "Not Valid"
        except Exception as e:
            return False, e
    def create_video_session(self):
        try:
            url = "https://session-manager.wowow.co.jp/sessions/create"
            headers = self.common_headers.copy()
            headers["host"] = "session-manager.wowow.co.jp"
            payload = {
                "app_version": "3.7.0",
                "system_version": "9",
                "device_code": 6,
                "is_mobile": True,
                "os_version": "9",
                "os_build_id": "28",
                "device_manufacturer": "Redmi",
                "device_model": "23113RKC6C",
                "device_higher_category": "android",
                "device_lower_category": "android",
                "user_agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 jp.ne.wowow.vod.androidtv/3.7.0"
            }
            response = self.session.post(url, headers=headers, json=payload, allow_redirects=False).json()
            
            self.x_session_token = response.json()["token"]
            
            #access_token ="Bearer " + response["wip_access_token"]
            #access_token ="Bearer " + response["access_token"]
            
            return True, response

        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e