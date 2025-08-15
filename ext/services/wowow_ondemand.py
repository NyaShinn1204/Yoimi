"""
SERVICE INFO


name: WOWOW-Ondemand
require_account: Yes
enable_refresh: No
support_normal: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url:
   WIP
"""

import re
import uuid
import time
import hashlib

__service_config__ = {
    "service_name": "WOWOW-Ondemand",
    "require_account": True,
    "enable_refresh": False,
    "support_normal": False,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.vuid = None # this value is random
        self.x_user_id = None
        self.x_session_token = None
        self.wip_access_token = None
        self.wip_refresh_token = None
        self.normal_refresh_token = None
        
        self.default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.179 Mobile Safari/537.36 jp.ne.wowow.vod.androidtv/3.8.3",
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)
        
    def parse_input(self, url_input):
        match = re.search(r'/content/(\d+)', url_input)
        if match:
            content_id = match.group(1)
            
        status, content_info = self.get_title_info(content_id)
        
        status, content_list = self.get_content_list(content_info["series_meta"]["meta_id"])
        
        if status == False:
            return "not_availiable_content"
        
        genre_list = []
        for single in content_info["genres"]:
            genre_list.append(single["name"])
        
        video_info = {
            "raw": content_info,
            "content_id": str(content_info["meta_id"]),
            "content_type": genre_list,
            "title_name": content_info["series_meta"]["name"],
            "episode_count": len(content_list),
            "episode_name": content_info["short_name"],
            "episode_num": content_info["episode_number_title"],
        }
        
        return video_info
    def parse_input_season(self, url_input):
        match = re.search(r'/program/(\d+)', url_input)
        if match:
            program_id = match.group(1)
            
        status, real_program = self.get_title_info(program_id)
        real_program_id = real_program["id"]
        
        status, content_list = self.get_content_list(real_program_id)
        
        temp_list = []
        
        content_list = sorted(content_list, key=lambda x: x["episode_id_name"])
        
        for single in content_list:
            temp_json = {}
            temp_json["raw"] = single
            temp_json["episode_name"] = single["short_name"]
            temp_json["episode_num"] = single["episode_number_title"]
            self.logger.info(" - "+single["name"])
            
        video_info = {
            "raw": real_program,
            "episode_list": {
                "metas": temp_list
            }
        }
                
        return None, real_program["name"], video_info
        
    def authorize(self, email_or_id, password):
        status, session_token = self.create_device_session()
        _USER_AUTH_API = "https://custom-api.wowow.co.jp/api/v1/wip/users/auth"
        
        temp_vuid = str(uuid.uuid4()).replace("-", "")
        
        payload = {
            "online_id": email_or_id,
            "password": password,
            "client_id": "wod-tv",
            "app_id": 5,
            "device_code": 8,
            "vuid": temp_vuid
        }
        login_response = self.session.post(_USER_AUTH_API, json=payload).json()
        try:
            if login_response["error"]:
                return False, login_response["error"]["message"], False, None
        except:
            pass
        
        self.session.headers.update({
            "Authorization": "Bearer "+login_response["access_token"],
            "X-Token-Id": str(login_response["token_id"]),
            "X-User-Id": str(login_response["token_id"]),
            "X-Session-Token": session_token
        })
        
        user_info = self.get_userinfo()
        
        session_json = {
            "method": "LOGIN",
            "email": hashlib.sha256(email_or_id.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": login_response["access_token"],
            "refresh_token": login_response["refresh_token"],
            "additional_info": {
                "vuid": temp_vuid,
                "x_user_id": str(login_response["id"]),
                "x_session_token": session_token,
                "wip_access_token": login_response["wip_access_token"],
                "wip_refresh_token": login_response["wip_refresh_token"],
                "normal_refresh_token": login_response["refresh_token"],
            }
        }
        return True, user_info, True, session_json   
    def authorize_qr(self):
        status, session_token = self.create_device_session()
        _PIN_SESSION_CREATE = "https://session-manager.wowow.co.jp/pin/publish"
        _PIN_SESSION_CHECK = "https://session-manager.wowow.co.jp/pin/check"
        _SESSION_TOKEN_CHECK = "https://session-manager.wowow.co.jp/token/check"
        
        temp_vuid = str(uuid.uuid4()).replace("-", "")
        
        payload = {
            "vuid": temp_vuid
        }
        get_login_pin = self.session.post(_PIN_SESSION_CREATE, json=payload)
        if get_login_pin.status_code != 200:
            return False, "Auth Faild: Faild to get QR Login pin", False, None
        else:
            login_pin = get_login_pin.json()
            print("Login URL:", "https://r10.to/hifxfW")
            print("Code:", login_pin["pin_code"])
            
            start_time = time.time()
            
            while True:
                if time.time() - start_time >= login_pin["expires_in"]: # Expire: 5 minitus 
                    print("Code Expired. Please Re-try")
                    break
                payload = {
                    "pin_code": login_pin["pin_code"],
                    "vuid": temp_vuid
                }
                send_checkping = self.session.post(_PIN_SESSION_CHECK, json=payload)         
                if send_checkping.status_code == 200:
                    print("Login Accept")
                    
                    login_status = send_checkping.json()
                    
                    access_token = login_status["access_token"]
                    refresh_token = login_status["refresh_token"]
                    
                    self.session.headers.update({
                        "Authorization": "Bearer "+access_token,
                        "X-Token-Id": str(login_status["token_id"]),
                        "X-User-Id": str(login_status["token_id"]),
                        "X-Session-Token": session_token
                    })
                    
                    check_response = self.session.post(_SESSION_TOKEN_CHECK, json={}).json()
                    if check_response["result"]:
                        pass
                    else:
                        return False, "Auth Success, But failed to get another cert", False, None
                      
                    status, message = self.get_userinfo()
                    
                    session_json = {
                        "method": "QR_LOGIN",
                        "email": None,
                        "password": None,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "additional_info": {
                            "vuid": temp_vuid,
                            "x_user_id": str(login_status["token_id"]),
                            "x_session_token": session_token,
                            "wip_access_token": check_response["custom_data"]["wip_access_token"],
                            "wip_refresh_token": check_response["custom_data"]["wip_refresh_token"],
                            "normal_refresh_token": refresh_token
                        }
                    }
                    
                    return True, message, True, session_json
                else:
                    print("Waiting Login...")
                    time.sleep(5)
    def create_device_session(self):
        try:
            url = "https://session-manager.wowow.co.jp/sessions/create"
            payload = {
              "app_version": "3.8.3",
              "system_version": "10",
              "device_code": 8,
              "is_mobile": False,
              "os_version": "10",
              "os_build_id": "29",
              "device_manufacturer": "UMIDIGI",
              "device_model": "A7S",
              "device_higher_category": "android_tv",
              "device_lower_category": "android_tv",
              "user_agent": "Mozilla\\/5.0 (Linux; Android 10; A7S Build\\/QP1A.190711.020; wv) AppleWebKit\\/537.36 (KHTML, like Gecko) Version\\/4.0 Chrome\\/138.0.7204.179 Mobile Safari\\/537.36 jp.ne.wowow.vod.androidtv\\/3.8.3"
            }
            response = self.session.post(url, json=payload).json()
                        
            return True, response["token"]

        except:
            return False, None
    def check_token(self, token):

        self.session.headers.update({
            "Authorization": "Bearer "+token,
            "X-Token-Id": self.x_user_id,
            "X-User-Id": self.x_user_id,
            "X-Session-Token": self.x_session_token
        })
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        try:
            
            payload = {
                "refresh_token": refresh_token,
                "app_id": 5,
                "device_code": 8,
                "vuid": self.vuid,
                "wip_access_token": self.wip_access_token,
                "wip_refresh_token": self.wip_refresh_token
            }
            refresh_response = self.session.post("https://session-manager.wowow.co.jp/token/refresh", json=payload).json()
            
            session_data["access_token"] = refresh_response["access_token"]
            session_data["refresh_token"] = refresh_response["refresh_token"]
            session_data["additional_info"]["vuid"] = self.vuid
            session_data["additional_info"]["x_user_id"] = str(refresh_response["token_id"]),
            session_data["additional_info"]["wip_access_token"] = refresh_response["wip_access_token"]
            session_data["additional_info"]["wip_refresh_token"] = refresh_response["wip_refresh_token"]
            session_data["additional_info"]["normal_refresh_token"] = refresh_response["refresh_token"]
            
            self.session.headers.update({
                "Authorization": "Bearer "+refresh_response["access_token"],
                "X-Token-Id": self.x_user_id,
                "X-User-Id": self.x_user_id,
                "X-Session-Token": self.x_session_token
            })
            
            return session_data
        except:
            return None
    def get_userinfo(self):
        _USER_INFO_API = "https://mapi.wowow.co.jp/api/v1/users/me"
        
        payload_query = {
            "with_profiles": "true",
            "app_id": 5,
            "device_code": 8
        }
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query)
        if profile_resposne.status_code == 401:
            return False, None
        return True, profile_resposne.json()
    
    def show_userinfo(self, user_data):
        profile_id = user_data["user"]["uuid"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + id: " + profile_id)
        
    # 単体かシーズンかをチェック
    def judgment_watchtype(self, url):
        match = re.search(r'/content/(\d+)', url)
        if match:
            return "single"
        else:
            return "season"
        
    def get_title_info(self, content_id):
        querystring = {
            "expand_object_flag": "0",
            "app_id": "5",
            "device_code": "8",
            "datasource": "decorator",
            "user_status": "2"
        }
        try:
            metadata_response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/ref:{content_id}", params=querystring)
            if metadata_response.status_code == 204:
                metadata_response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/ref:C{content_id}", params=querystring)
                if metadata_response.status_code != 204:
                    return_json = metadata_response.json()
                    return True, return_json
                else:
                    return False, None
            else:
                return_json = metadata_response.json()
                return True, return_json
        except:
            return False, None
    def get_content_list(self, series_id):
        querystring = {
            "expand_object_flag": "0",
            "app_id": "5",
            "device_code": "8",
            "datasource": "decorator",
            "user_status": "2"
        }
        try:
            metadata_response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/{series_id}/children", params=querystring)
            if metadata_response.status_code != 204:
                return_json = metadata_response.json()
                return True, return_json
            else:
                return False, None
        except:
            return False, None
        
    def open_session_get_dl(self, video_info):
        def resolution_to_pixels(resolution_str):
            match = re.match(r"(\d+)x(\d+)", resolution_str)
            if match:
                width, height = map(int, match.groups())
                return width * height
            return 0
        try:
            payload = {}
            payload["meta_id"] = str(video_info["content_id"]) # 152181
            payload["vuid"] = self.vuid
            payload["user_id"] = self.x_user_id
            payload["refresh_token"] = self.normal_refresh_token
            payload["wip_access_token"] = self.wip_access_token
            payload["wip_refresh_token"] = self.wip_refresh_token
            payload["client_id"] = "wod-tv"
            payload["ua"] = "Mozilla\\/5.0 (Linux; Android 10; A7S Build\\/QP1A.190711.020; wv) AppleWebKit\\/537.36 (KHTML, like Gecko) Version\\/4.0 Chrome\\/138.0.7204.179 Mobile Safari\\/537.36 jp.ne.wowow.vod.androidtv\\/3.8.3"
            payload["app_id"] = "5"
            payload["device_code"] = "8"
            payload["device_localized_model"] = "Yoimi V2" #BRAVIA 4K GB
            payload["localized_model"] = "Yoimi V2" #BRAVIA 4K GB
            payload["device_system_name"] = "AndroidTV"
            payload["system_name"] = "AndroidTV"
            payload["device_manufacturer"] = "Sony"
            payload["manufacturer"] = "Sony"
            payload["device_hw_machine"] = ""
            payload["hw_machine"] = ""
            payload["system_version"] = "10"
            payload["device_system_version"] = "10"
            payload["device_mccmnc"] = ""
            payload["mccmnc"] = ""
            payload["device_model"] = "Yoimi V2" #BRAVIA 4K GB
            payload["model"] = "Yoimi V2" #BRAVIA 4K GB
            payload["device_display_name"] = "Yoimi V2" #BRAVIA 4K GB
            payload["display_name"] = "Yoimi V2" #BRAVIA 4K GB
            payload["device_app_version"] = "3.8.3"
            payload["app_version"] = "3.8.3"
            payload["device_app_build_version"] = 243
            payload["app_build_version"] = 243
            playback_auth = self.session.post("https://mapi.wowow.co.jp/api/v1/playback/auth", json=payload).json()
            playback_session_id = playback_auth["playback_session_id"]
            playback_access_token = playback_auth["access_token"]
            ovp_video_id = playback_auth["media"]["ovp_video_id"]
            
            
            headers = self.session.headers.copy()
            headers["authorization"] = playback_access_token
            headers["x-playback-session-id"] = playback_session_id
            
            self.logger.info("Open Video Session")
            
            response = self.session.get(f"https://playback-engine.wowow.co.jp/session/open/v1/projects/wod-prod/medias/{ovp_video_id}?codecs=avc", headers=headers).json()
            
            self.send_stop_signal(playback_access_token, playback_session_id)
            self.logger.info("Close Video Session")
            
            self.logger.info("Get MPD Link")
            
            urls = []
            widevine_url = None
            playready_url = None
            
            sorted_sources = sorted(
                response["sources"],
                key=lambda s: resolution_to_pixels(s.get("resolution", "0x0")),
                reverse=True
            )
            
            self.logger.debug("Source List")
            
            for source in sorted_sources:
                if "manifest.mpd" in source.get("src", ""):
                    self.logger.debug(" + "+source.get("src", ""))
                    urls.append(source["src"])
                    if source.get("key_systems"):
                        widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url")
                        playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url")
                    break
            if urls:
                mpd_link = urls[0].replace("jp/v4", "jp/v6")
                
                self.logger.debug("Select Best quality mpd")
                self.logger.debug(" + "+mpd_link)
                
                self.logger.info(f" + MPD_link: {mpd_link[:15] + '*****'}")
                return "mpd", self.session.get(mpd_link).text, mpd_link, {"widevine": widevine_url, "playready": playready_url}, {}
            else:
                self.logger.warning("No suitable MPD link found")
                return None, None, None, None, None
        except:
            return None, None, None, None, {}
        
    def send_stop_signal(self, access_token, playback_session_id):
        headers = self.session.headers.copy()
        headers["authorization"] = access_token
        headers["x-playback-session-id"] = playback_session_id
        response = self.session.post("https://playback-engine.wowow.co.jp/session/close", headers=headers).json()
        if response["result"]:
            return True
        else:
            return False
        
    # ライセンス処理後の処理
    def decrypt_done(self):
        # 今回は特になし
        pass
    
    # セグメントのリンクを作成
    def create_segment_links(self, get_best_track, manifest_link, video_segment_list, audio_segment_list, seg_timeline):
        video_segment_links = []
        audio_segment_links = []
        video_segment_links.append(get_best_track["video"]["url"])
        audio_segment_links.append(get_best_track["audio"]["url"])
        
        for single_segment in range(video_segment_list):
            temp_link = get_best_track["video"]["url_base"]+get_best_track["video"]["url_segment_base"].replace("$Number$", str(single_segment))
            video_segment_links.append(temp_link)
        for single_segment in range(audio_segment_list):
            temp_link = get_best_track["audio"]["url_base"]+get_best_track["audio"]["url_segment_base"].replace("$Number$", str(single_segment))
            audio_segment_links.append(temp_link)
            
        return audio_segment_links, video_segment_links