"""
SERVICE INFO


name: Hulu-jp
require_account: Yes
enable_refresh: Yes
support_qr: No
cache_session: Yes
use_tlsclient: No
support_url: 
   https://www.hulu.jp/xxx
   https://www.hulu.jp/watch/xxx
   https://www.hulu.jp/store/watch/xxx
"""

import re
import uuid
import hashlib

from ext.utils.pymazda.sensordata.sensor_data_builder import SensorDataBuilder

__service_config__ = {
    "service_name": "Hulu-jp",
    "require_account": True,
    "cache_session": True,
    "enable_refresh": True,
    "use_tls": False,
    "support_qr": False
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cache = True
        
        self.x_user_id = None
        self.x_session_token = None
        self.x_gaia_authorization = None
        
        self.auth_headers = {
            "user-agent": "jp.happyon.android/3.24.0 (Android 9; 22081212C Build/PQ3B.190801.10101846)",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "accept-language": "ja",
        }
        
        self.default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.157 Mobile Safari/537.36",
            "accept-language": "ja",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        
        self.session.headers.update(self.default_headers)

    def parse_input(self, input):
        assets_name = self.get_assets_info(input)
        if assets_name == None:
            self.logger.error("Failed parse Assets info")
            exit(1)
        
        video_id, content_metadata = self.get_info_and_check(assets_name)
        
        return video_id, content_metadata


    def authorize(self, email, password):
        self.use_cache = False
        global test_temp_token
        _SESSION_CREATE = "https://mapi.prod.hjholdings.tv/api/v1/sessions/create"
        _LOGIN_API = "https://mapi.prod.hjholdings.tv/api/v1/users/auth"
        _USER_INFO_API = "https://mapi.prod.hjholdings.tv/api/v1/users/me"
        
        default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 9; 22081212C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36",
            "accept-language": "ja",
            "host": "mapi.prod.hjholdings.tv",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
            
        ## generate temp session
        payload_query = {
            "app_version": "3.24.0",
            "system_version": "9",
            "device_code": "8",
            "manufacturer": "Sony",
            "is_mobile": "true",
            "os_version": "9",
            "os_build_id": "24",
            "device_manufacturer": "Sony",
            "device_model": "BRAVIA 4K GB",
            "device_name": "Yoimi V2", # BRAVIA_ATV2
            "user_agent": "",
            "device_higher_category": "android_tv",
            "device_lower_category": "android_tv"
        }
        
        session_response = self.session.get(_SESSION_CREATE, params=payload_query, headers=default_headers).json()
        gaia_token_1 = session_response["gaia_token"]
        session_token_1 = session_response["session_token"]
        
        
        ## send login request    
        payload = {
            "mail_address": email,
            "password": password,
            "app_id": 5,
            "device_code": 8
        }   
        sensor_data_builder = SensorDataBuilder()
        default_headers.update({
            "x-gaia-authorization": "extra " + gaia_token_1,
            "x-session-token": session_token_1,
            "x-acf-sensor-data": sensor_data_builder.generate_sensor_data(),
            "user-agent": "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV",
        })
        
        login_response = self.session.post(_LOGIN_API, json=payload, headers=default_headers)
        login_response = login_response.json()
        
        default_headers.update({
            "x-user-id": str(login_response["id"])
        })
        
        self.x_user_id = str(login_response["id"])
                
        ## get profile list
        payload_query = {
            "with_profiles": "true",
            "app_id": 5,
            "device_code": 8
        }
        
        test_temp_token = "Bearer " + login_response["access_token"]
        
        default_headers.update({
            "authorization": "Bearer " + login_response["access_token"],
            "x-session-token": login_response["session_token"],
            "x-gaia-authorization": "extra " + login_response["gaia_token"]
        })
        
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query, headers=default_headers).json()
        
        self.auth_headers = default_headers.copy()
        
        session_json = {
            "method": "LOGIN",
            "email": hashlib.sha256(email.encode()).hexdigest(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "access_token": login_response["access_token"],
            "refresh_token": login_response["refresh_token"],
            "additional_info": {
                "x_user_id": str(login_response["id"]),
                "x_session_token": login_response["session_token"],
                "x_gaia_authorization": "extra " + login_response["gaia_token"]
            }
        }
        return True, profile_resposne, True, session_json
    def check_token(self, token):
        self.session.headers.update({
            "authorization": "Bearer " + token,
            "x-user-id": self.x_user_id
        })
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        
        payload = {
            "refresh_token": refresh_token,
            "app_id": 5,
            "device_code": 8
        }
        refresh_response = self.session.post("https://token.prod.hjholdings.tv/token/refresh", json=payload).json()
        
        #refresh_response["token_id"]
        access_token = refresh_response["access_token"]
        refresh_token = refresh_response["refresh_token"]
        session_json = {
            "method": "normal",
            "email": None,
            "password": None,
            "access_token": access_token,
            "refresh_token": refresh_token
        }
        return session_json
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
    
    def show_userinfo(self, user_data):
        profile_list = []
        for single_profile in user_data["profiles"]:
            if single_profile["values"]["has_pin"]:
                pin_status = "Yes"
            else:
                pin_status = "No "
            profile_list.append([single_profile["display_name"], pin_status, single_profile["uuid_in_schema"]])

        self.logger.info("Get Profile list")
        for idx, one_profile in enumerate(profile_list, 1):
            self.logger.info(f" + {str(idx)}: Has pin: {one_profile[1]} | {one_profile[0]} ")
            
        input_like = input("Please enter the number of the profile you want to use >> ")
        try:
            int(input_like)
        except ValueError:
            print("Invalid Input.")
            exit()
        profile_num = int(input_like) -1
        
        select_profile_uuid = profile_list[profile_num][2]
        if profile_list[profile_num][1] == "Yes":
            pin = input("Profile PIN >> ")
        else:
            pin = ""
                
        status, user_data = self.select_profile(select_profile_uuid, pin=pin)
        
        if status != True:
            self.logger.error(user_data)
        
        self.logger.info("Success change profile")
        self.logger.info(" + Nickname: "+user_data["profile"]["nickname"])
    
    def select_profile(self, uuid, pin=""):
        payload = {
            "pin": pin,
            "profile_id": uuid
        }
        headers = self.auth_headers.copy()
        if self.use_cache:
            headers.update({
                "x-session-token": self.x_session_token,
                "x-gaia-authorization": self.x_gaia_authorization,
            })
        meta_response = self.session.put("https://mapi.prod.hjholdings.tv/api/v1/gaia/auth/profile", json=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                profile_change_response = meta_response.json()
                self.auth_headers.update({
                    "x-session-token": profile_change_response["session_token"],
                })
                return True, profile_change_response
        except:
            return False, "Failed to login profile"
        
    # 単体かシーズンかをチェック
    def judgment_watchtype(self, url):
        match = re.search(r'/watch/(\d+)', url)
        if match:
            return "single"
        else:
            return "season"
        
    # エピソードの詳細取得
    # 4kあるかのcheck
    def get_info_and_check(self, asset_name):
        self.logger.info("Creating Video Sesson...")
        status, metadata = self.playback_auth(asset_name)
        
        self.logger.info("Get Title for 1 Episode")
        status, url_metadata = self.get_title_info(metadata["log_params"]["meta_id"])
        self.logger.info("Checking Availiable 4K...")
        
        found4k = self.find_4k(metadata["log_params"]["meta_id"])
        if found4k != []:
            self.logger.info(" + Found 4k, Re-open Session...")
            status, message = self.close_playback_session(metadata["playback_session_id"])
            self.logger.info("Close Video Session")
            ovp_video_id = found4k[0]["ovp_video_id"]
            media_id = found4k[0]["media_id"]
            self.logger.info("Creating Video Sesson 4K...")
            status, metadata = self.playback_auth(asset_name, uhd=True, media_id=media_id)
        else:
            self.logger.info(" - Not Found.")
            ovp_video_id = metadata["media"]["ovp_video_id"]
        
        self.logger.info(" + Session Token: "+metadata["playback_session_id"][:10]+"*****")
        
        if url_metadata["season_id"] == None:
            if url_metadata["season_meta_id"] == None:
                episode_count = 1
            else:
                for single in url_metadata["video_categories"]:
                    if single["ref_id"] == "episode_sub":
                        input_type = "episode_sub"
                    elif single["ref_id"] == "episode_dub":
                        input_type = "episode_dub"
                    else:
                        input_type = "episode"
                    
                episode_count = self.get_total_episode(url_metadata["season_meta_id"], input_type)["total_count"]
            content_type = "movie"
            title_name = url_metadata["series_name"] # ⚠️！要調整！⚠️
            
            if episode_count > 1:
                self.logger.error("Unsupported Type Content.")
                return ovp_video_id, "unexception_type_content"
            else:
                episode_num = None
                episode_name = None
        else:
            input_type = None
            for single in url_metadata["video_categories"]:
                if single["ref_id"] == "episode_sub":
                    input_type = "episode_sub"
                elif single["ref_id"] == "episode_dub":
                    input_type = "episode_dub"
                else:
                    input_type = "episode"
                
            episode_count = self.get_total_episode(url_metadata["season_meta_id"], input_type)["total_count"]
            content_type = "anime"
            title_name = url_metadata["series_name"]
            
            episode_num = url_metadata["episode_number_title"]
            episode_name = url_metadata["header"]
        
        video_info = {
            "raw": metadata,
            "content_type": content_type,
            "episode_count": episode_count,
            "title_name": title_name,
            "episode_num": episode_num,
            "episode_name": episode_name
        }
        
        return ovp_video_id, video_info
    
    # アセッツ名を取得
    def get_assets_info(self, url):
        match = re.search(r'/watch/(\d+)', url)
        
        media_id = match.group(1)
        
        response = self.session.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"})
        
        pattern = rf'["\']?(asset:{media_id})["\']?'
        match = re.search(pattern, response.text)
        if match:
            return match.group(1)
        return None
    # タイトル取得
    def get_title_info(self, meta_id):
        querystring = {
            "expand_object_flag": "0",
            "app_id": 4,
            "device_code": 7,
            "datasource": "decorator"
        }
        
        meta_response = self.session.get("https://mapi.prod.hjholdings.tv/api/v1/metas/"+str(meta_id), params=querystring)
        try:
            if meta_response.status_code == 200:
                episode_metadata = meta_response.json()
                return True, episode_metadata
        except:
            return False, None
    # エピソード数の取得
    def get_total_episode(self, season_id, episode_type):
        querystring = {
            "expand_object_flag": "0",
            "sort": "sort:asc,id_in_schema:asc",
            "order": "asc",
            "app_id": 4,
            "device_code": 7,
            "datasource": "decorator",
            "limit": 999,
            "page": "1",
            "with_total_count": "true",
            "hierarchy_type": episode_type,
            "only_searchable": "true"
        }
        meta_response = self.session.get("https://mapi.prod.hjholdings.tv/api/v1/metas/"+str(season_id)+"/children", params=querystring)
        try:
            if meta_response.status_code == 200:
                meta_res = meta_response.json()
                return meta_res
        except:
            return None
    # 4kのチェック
    def find_4k(self, meta_id):
        querystring = {
            "fields": "values",
            "app_id": 4,
            "device_code": 7,
            "datasource": "decorator"
        }
        
        meta_response = self.session.get("https://mapi.prod.hjholdings.tv/api/v1/metas/"+str(meta_id)+"/medias", params=querystring)
        try:
            if meta_response.status_code == 200:
                episode_metadata = meta_response.json()
                def find_4k_videos(data):
                    result = []
                    for media in data.get("medias", []):
                        values = media.get("values", {})
                        if values.get("file_type") == "video/4k":
                            result.append(media)
                    return result
                
                result = find_4k_videos(episode_metadata)
                return result
        except:
            return None
    #### 映像のSession関係の処理
    def playback_auth(self, assets_name, uhd=False, media_id=None):
        if uhd:
            payload = {
                "service": "hulu",
                "meta_id": assets_name,
                "media_id": str(media_id),
                "device_code": 7,
                "with_resume_point": False,
                "vuid": str(uuid.uuid4()).replace("-",""),
                "user_id": self.x_user_id,
                "app_id": 4
            }
        else:
            payload = {
                "service": "hulu",
                "meta_id": assets_name,
                "device_code": 7,
                "vuid": str(uuid.uuid4()).replace("-",""),
                "with_resume_point": False,
                "user_id": self.x_user_id,
                "app_id": 4
            }
        meta_response = self.session.post("https://papi.prod.hjholdings.tv/api/v1/playback/auth", json=payload, headers=self.auth_headers)
        try:
            if meta_response.status_code == 201:
                episode_metadata = meta_response.json()
                return True, episode_metadata
        except:
            return False, "Failed to auth playback"
    def open_playback_session(self, ovp_video_id, session_id, episode_id):
        payload = {
            "device_code": 7,
            "codecs": "h264", # List: "avc", "hevc", "h264", "h265", "vp9"         NOTICE: avc, hevc is return some title 1600x900. if you want 1080p, just use vp9
            "viewing_url": "https://www.hulu.jp/watch/"+episode_id,
            "app_id": 4
        }
        headers = self.auth_headers.copy()
        headers["host"] = "playback.prod.hjholdings.tv"
        headers["x-playback-session-id"] = session_id
        headers["x-acf-sensor-data"] = None
        headers["x-gaia-authorization"] = None
        meta_response = self.session.get("https://playback.prod.hjholdings.tv/session/open/v1/merchants/hulu/medias/"+ovp_video_id, params=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                episode_playdata = meta_response.json()
                return True, episode_playdata
        except:
            return False, "Failed to get episode_playdata"
    def close_playback_session(self, session_id):
        headers = self.auth_headers.copy()
        headers["host"] = "playback.prod.hjholdings.tv"
        headers["x-playback-session-id"] = session_id
        close_response = self.session.post("https://playback.prod.hjholdings.tv/session/close", headers=headers)
        try:
            if close_response.status_code == 200 and close_response.json()["result"]:
                return True, None
        except:
            return False, close_response.json()