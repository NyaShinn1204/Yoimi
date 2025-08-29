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

import re
import os
import uuid
import m3u8
import pickle
import base64
import hashlib
import xmltodict
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

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
        "is_drm": "both",
        "cache_session": True,
        "use_tls": False,
    }
    class downloader:
        def __init__(self, session, logger, config):
            self.session = session
            self.logger = logger
            self.config = config

            self.user_id = None
            self.cookie = None
            
            self.default_headers = {
                "host": "www.nhk-ondemand.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.9.0",
                "no-cookie": "true"
            }
            self.session.headers.update(self.default_headers)
        
        def parse_input(self, url_input, id = None):
            if id == None:
                match = re.search(r'/goods/([^/]+)/', url_input)
                if match:
                    content_id = match.group(1)
            else:
                content_id = id
            status, content_info = self.get_content_infO(content_id)

            episode_count = self.get_episode_count(content_info["siteProgramId"])

            video_info = {
                "raw": content_info,
                "content_type": "drama",
                "episode_count": episode_count,
                "title_name": content_info["siteProgramName"],
                "episode_num": "",
                "episode_name": content_info["subName"],
            }
            
            return video_info
        def parse_input_season(self, url_input):
            match = re.search(r'/program/([^/]+)/', url_input)
            if match:
                program_id = match.group(1)

            # status, content_info = self.get_content_infO(program_id)

            episode_lsit = self.get_episode_list(program_id)

            program_info = self.get_sesaon_info(program_id)

            temp_list = []
            
            for single in episode_lsit:
                self.logger.info(" + "+program_info["Title"]["#text"]+"_"+single["Subtitle"]["#text"])
                temp_json = {}
                temp_json["raw"] = single
                temp_json["episode_name"] = single["Subtitle"]["#text"]
                temp_json["episode_num"] = ""
                temp_json["id_in_schema"] = single["Id"]
                temp_list.append(temp_json)

            video_info = {
                "raw": program_info,
                "episode_list": {
                    "metas": temp_list
                }
            }

            return None, program_info["Title"]["#text"], video_info
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
                
            cookie_text = base64.b64encode(pickle.dumps(self.session.cookies)).decode()
            
            session_json = {
                "method": "LOGIN",
                "email": hashlib.sha256(user_id.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": client_secret,
                "refresh_token": "",
                "additional_info": {
                    "user_id": user_id,
                    "client_secret": client_secret,
                    "cookie": cookie_text
                }
            }
            
            return True, {"id": user_id}, True, session_json
        
        def check_token(self, token):
            #self.session.cookies.update(pickle.loads(base64.b64decode(self.cookie)))

            self.session.cookies.update({"EnvSwitch": "_app"})
            
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
            
        def get_content_infO(self, content_id):
            url = f"https://www.nhk-ondemand.jp/goods/{content_id}/"
            try:
                headers = {
                    "host": "www.nhk-ondemand.jp",
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip",
                    "user-agent": "okhttp/4.9.0",
                }
                info_response = self.session.get(url, headers=headers)
                return True, info_response.json()
            except:
                return False, None
        
        def get_episode_count(self, program_id):
            url = "https://www.nhk-ondemand.jp/xml3/goods/"
            
            payload = {
                "G2": "*",
                "G5": "1,4,5",
                "G8": program_id, # series id
                "G53": "11",
                "G54": "1000" # maybe max count?
            }
            try:
                data = self.session.post(url, data=payload)
                root = xmltodict.parse(data.text)
                return root["PackageList"]["Result"]
            except:
                return 0

        def get_episode_list(self, program_id):
            url = "https://www.nhk-ondemand.jp/xml3/goods/"
            
            payload = {
                "G2": "*",
                "G5": "1,4,5",
                "G8": program_id, # series id
                "G53": "11",
                "G54": "1000" # maybe max count?
            }
            try:
                data = self.session.post(url, data=payload)
                episode_list = xmltodict.parse(data.text)["PackageList"]["Package"]

                return episode_list
            except:
                return 0
            
        def get_sesaon_info(self, program_id):
            url = "https://www.nhk-ondemand.jp/xml2/siteProgram/"

            payload = {
                "P8": program_id,
                "P5": "1,4,5"
            }

            try:
                data = self.session.post(url, data=payload)
                program_info = xmltodict.parse(data.text)
                return program_info["GroupList"]["Group"]
            except:
                return None

        def get_subscribe_id(self):
            cache_login = "https://www.nhk-ondemand.jp/user/availableList/"
            headers = {
                "host": "www.nhk-ondemand.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.9.0"
            }
            self.session.cookies.update({"EnvSwitch": "_app"})
            response = self.session.get(cache_login, headers=headers, allow_redirects=False)

            return response.json()[0]["Id"]

        def open_session_get_dl(self, video_info):
            global playback_json
            cmaf_supported = int(video_info["raw"]["opusList"][0]["cmafSupported"])
            if cmaf_supported == 1:
                playback_url = "https://www.nhk-ondemand.jp/api/play/v1/play/cmaf"
            elif cmaf_supported == 0:
                playback_url = "https://www.nhk-ondemand.jp/api/play/v1/play/hls"
            
            subscribe_id = self.get_subscribe_id()

            payload = {
                "P1": self.session.cookies.get("sessionid"),
                "P2": subscribe_id,
                "P3": video_info["raw"]["opusList"][0]["itemKey"]
            }

            headers = {
                "content-type": "application/x-www-form-urlencoded",
                "host": "www.nhk-ondemand.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.9.0"
            }

            playback_response = self.session.post(playback_url, data=payload, headers=headers).text
            
            playback_json = xmltodict.parse(playback_response)["body"]

            #print(playback_json)
            
            license_list = {"widevine": "https://nod.photron-drm.com/widevine/license", "playready": ""}
            license_header = {
                "authorization": "Bearer "+playback_json["token"],
                "content-type": "application/octet-stream",
                "accept-encoding": "gzip",
                "user-agent": "Dalvik/2.1.0 (Linux; U; Android 16; AOSP TV on x86 Build/BT2A.250323.001.A4)",
                "host": "nod.photron-drm.com",
                "connection": "Keep-Alive"
            }
            license_headers = {"widevine": license_header, "playready": ""}

            return "hls", self.session.get(playback_json["url"]).text, playback_json["url"], license_list, license_headers 
        
        def decrypt_done(self):
            cid = os.path.splitext(os.path.basename(urlparse(playback_json["url"]).path))[0]

            url = "https://www.nhk-ondemand.jp/authap/web/service/SetPlayTime"
            payload = {
                "svid": playback_json["svid"],
                "uuid": playback_json["uid"],
                "cid": cid,
                "playtime": "0000:01"
            }
            self.session.post(url, data=payload)

            url = "https://www.nhk-ondemand.jp/authap/web/service/service_PlayTimeWebService"
            payload = {
                "svid": playback_json["svid"],
                "uuid": playback_json["uid"],
                "cid": cid,
            }
            self.session.post(url, data=payload)
        
        def get_subtitle(self, playback_json):
            params = {
                "sess": playback_json["usid"],
                "tid": playback_json["tid"]
            }
            self.session.get("https://www.nhk-ondemand.jp/hls/service_hlsCaptionService/index.html", params=params)

        def create_segment_links(self, select_track, manifest_link, hls_select_info):
            m3u8_obj = m3u8.loads(hls_select_info)
            segment_urls = [segment.uri for segment in m3u8_obj.segments]
            return None, segment_urls