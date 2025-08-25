"""
SERVICE INFO


name: RakutenTV-JP
require_account: No
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
import time
from urllib.parse import urlparse

__service_config__ = {
    "service_name": "RakutenTV-JP",
    "require_account": True,
    "enable_refresh": True,
    "support_normal": False,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger, config):
        self.session = session
        self.logger = logger
        self.config = config

        self.default_headers = {
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001) Rakuten TV AndroidTV/2.2.5-edce7eacd6-P (Linux;Android 10) AndroidXMedia3/1.4.1",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)

        self.device_list = {
            "Windows XP": "1",         # DASH        1280x720
            "Windows Vista": "2",      # DASH        1280x720
            "Xbox 360": "3",           # API ERROR
            "Windows 7": "4",          # DASH        1280x720
            "Windows RT": "5",         # API ERROR
            "Windows 8": "6",          # DASH        1280x720
            "Windows Other": "7",      # API ERROR
            "Windows Phone": "8",      # API ERROR
            "iPad": "9",               # HLS         1280x720
            "iPhone,iPod touch": "10", # HLS         960x540
            "Intel Mac": "11",         # HLS & DASH  1280x720
            "Mac Other": "12",         # API ERROR
            "Android mobile": "13",    # DASH        960x540
            "Android tablet": "14",    # DASH        1280x720
            "Android Other": "15",     # API ERROR
            "Chromecast": "16",        # DASH        1920x1080
            "VIERA HLS": "17",         # HLS         SERVER DOWN (Status: 500)
            "VIERA": "18",             # DASH        1920x1080
            "BRAVIA": "19",            # DASH        1920x1080
            "Wii U": "20",             # DASH        1920x1080
            "Xbox One": "21",          # DASH        1920x1080
            "Windows 10": "22",        # DASH        1280x720
            "PS4": "23",               # DASH        1920x1080
            "UNKNOWN DEVICE": "24",    # DASH        1920x1080
            "Android TV": "25",        # DASH        1920x1080
            "Apple TV": "26",          # HLS         1920x1080
            "REGZA": "27",             # DASH        1920x1080
            "Fire TV": "28",           # DASH        1920x1080
        }
        
        self.device_id = self.device_list["Android TV"]
        
    def parse_input(self, url_input, id = None):
        if id != None:
            url_input = f"https://tv.rakuten.co.jp/content/{id}/"
        match = re.search(r'/content/(\d+)/', url_input)
        if match:
            content_id = match.group(1)
        status, content_info = self.get_id_info(content_id)
        
        season_id = content_info["id"]
        
        status, single_info = self.get_title_info_single(season_id, content_id)
        
        content_type = self.get_genre_jpname(single_info["genre"]["id"])
                
        if single_info["is_play"] == "1":
            is_play = True
        else:
            is_play = False
        
        if is_play == False:
            self.logger.info("This content is not playble.")
            return "not_availiable_content"
        
        video_info = {
            "raw": content_info,
            "raw_single": single_info,
            "content_type": content_type,
            "episode_count": content_info["child_count"],
            "title_name": content_info["name"],
            "episode_num": "",
            "episode_name": single_info["name"],
            "is_play": is_play,
            "support_device_list": content_info["supported_device_list"]
        }
        
        return video_info
        
    def parse_input_season(self, url_input):
        match = re.search(r'/content/(\d+)/', url_input)
        if match:
            season_id = match.group(1)
        
        status, content_info = self.get_id_info(season_id)
        status, all_info = self.get_title_info(season_id)
        
        episode_singles = []
        for single in all_info:
            temp = {}
            temp = single
            temp["id_in_schema"] = single["id"]
            
            if temp["is_play"] == "1":
                self.logger.info(" + "+temp["name_title"])
            else:
                self.logger.info(" - "+temp["name_title"])
            
            episode_singles.append(temp)
        
        video_info = {
            "raw": all_info,
            "episode_list":{
                "metas": episode_singles
            }
        }
        
        return "", content_info["name"], video_info
    
    def authorize(self, email_or_id, password):
        pass
    def authorize_qr(self):
        client_id = "z6RYVPgpJD6FuD575jby" ## 固定
        auth_basic = "Basic ejZSWVZQZ3BKRDZGdUQ1NzVqYnk6dUphczl5NHFrcmN1RngwRENwV2w2ZnEz" ## 固定
        
        """
        https://r10.to/hifxfW -> https://auth.tv.rakuten.co.jp/oauth/activate_code/
        https://r10.to/hkAGWM -> https://auth.tv.rakuten.co.jp/oauth/activate_code_ftv/
        """
        
        """
        Get QR login pass key
        """
        
        get_login_pass = self.session.get(f"https://auth.tv.rakuten.co.jp/oauth/code.json?response_type=code&client_id={client_id}&nr=1")
        if get_login_pass.status_code != 200:
            return False, "Auth Faild: Fialed to get QR Login pass key", None, None
        else:
            login_key = get_login_pass.json()
            print("Login URL:", "https://r10.to/hifxfW")
            print("Code:", login_key["result"]["code"])
            
            self.session.get("https://privacy.rakuten.co.jp/date/jp_utf8.txt")
            
            while True:
                querystring = {
                    "grant_type": "authorization_code",
                    "code": login_key["result"]["code"],
                    "polling": "1",
                    "issue_sec_cookie": "0",
                    "device_name": "Yoimi",
                    "device_id": str(self.device_id)
                }
                headers = {
                    "Authorization": auth_basic,
                }
                send_checkping = self.session.get(f"https://auth.tv.rakuten.co.jp/oauth/token.json", params=querystring, headers=headers)         
                if send_checkping.status_code == 200:
                    print("Login Accept")
                    
                    login_status = send_checkping.json()
                    
                    access_token = login_status["result"]["access_token"]
                    refresh_token = login_status["result"]["refresh_token"]
                    
                    self.session.headers.update({
                        "Authorization": access_token,
                        "Access-Token": access_token
                    })
                      
                    status, message = self.get_userinfo()
                    
                    session_json = {
                        "method": "QR_LOGIN",
                        "email": None,
                        "password": None,
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "additional_info": {}
                    }
                    
                    return True, message, True, session_json
                else:
                    print("Waiting Login...")
                    time.sleep(5)
    def check_token(self, token):
        self.session.headers.update({
            "Authorization": "Bearer "+token,
            "Access-Token": token
        })
        
        check_response = self.session.get(f"https://api.tv.rakuten.co.jp/member/mobile_menu.json?device_id={str(self.device_id)}&point_flag=1")
        if check_response.status_code == 200:
            status, user_info = self.get_userinfo()
            return True, user_info
        elif check_response.status_code == 400:
            return False, None
        else:
            return False, None
    def refresh_token(self, refresh_token, session_data):
        try:
            payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
            refresh_response = self.session.get("https://auth.tv.rakuten.co.jp/oauth/token.json", params=payload, headers={"Authorization": "Basic ejZSWVZQZ3BKRDZGdUQ1NzVqYnk6dUphczl5NHFrcmN1RngwRENwV2w2ZnEz"}).json()
            
            access_token = refresh_response["result"]["access_token"]
            refresh_token = refresh_token
            session_data["access_token"] = access_token
            session_data["refresh_token"] = refresh_token
            
            self.session.headers.update({
                "Authorization": "Bearer "+access_token,
                "Access-Token": access_token
            })
            
            return session_data
        except:
            return None
    def get_userinfo(self):
        _USER_INFO_API = "https://auth.tv.rakuten.co.jp/app_auth/user_info.json"
        
        profile_resposne = self.session.post(_USER_INFO_API)
        if profile_resposne.json()["status"] == "error":
            return False, None
        elif profile_resposne.json()["status"] == "success":
            return True, profile_resposne.json()["result"]
        else:
            return False, None

    def show_userinfo(self, user_data):
        profile_id = user_data["encrypt_member_id"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + enc_id: " + profile_id)
        
    def judgment_watchtype(self, url):
        match = re.search(r'/content/(\d+)/', url)
        if match:
            content_id = match.group(1)
            status, content_info = self.get_id_info(content_id)
            
            if content_info["id"] == content_id:
                return "season"
            else:
                return "single"
            
            
    def get_id_info(self, content_id):
        querystring = {
            "device_id": str(self.device_id),
            "isp_id": "1",
            "rating_type": "18",
            "content_id": content_id,
            "promotion_disp_flag": "1"
        }
        
        try:
            info_response = self.session.get("https://api.tv.rakuten.co.jp/content/detailInfoMulti.json", params=querystring)
            info_response = info_response.json()
            if info_response["status"] == "success":
                return True, info_response["result"]
            else:
                return False, None
        except:
            return False, None
        
    def get_title_info(self, series_id):
        querystring = {
            "device_id": str(self.device_id),
            "isp_id": "1",
            "rating_type": "18",
            "content_id": series_id,
            "offset": "0",
            "count": "24",
            "default_order": "0",
            "parent_flag": "0",
            "pack_id": ""
        }
        try:
            info_response = self.session.get("https://api.tv.rakuten.co.jp/content/child_listmulti.json", params=querystring)
            info_response = info_response.json()
            if info_response["status"] == "success":
                return True, info_response["result"]["content_list"]
            else:
                return False, None
        except:
            return False, None
    def get_title_info_single(self, series_id, content_id):
        querystring = {
            "device_id": str(self.device_id),
            "isp_id": "1",
            "rating_type": "18",
            "content_id": series_id,
            "offset": "0",
            "count": "24",
            "default_order": "0",
            "parent_flag": "0",
            "pack_id": ""
        }
        try:
            info_response = self.session.get("https://api.tv.rakuten.co.jp/content/child_listmulti.json", params=querystring)
            info_response = info_response.json()
            if info_response["status"] == "success":
                for single in info_response["result"]["content_list"]:
                    if single["id"] == content_id:
                        return True, single
                return False, None
            else:
                return False, None
        except:
            return False, None
        
    def get_genre_jpname(self, genre_id):
        querystring = {
            "device_id": str(self.device_id),
            "adult_flg": "0"
        }
        try:
            genre_response = self.session.get("https://api.tv.rakuten.co.jp/web/genre.json", params=querystring)
            genre_response = genre_response.json()
            if genre_response["status"] == "success":
                for single in genre_response["result"]["genre_list"]:
                    if single["id"] == str(genre_id):
                        return single["name"]
            else:
                return None
        except:
            return None
        
    def open_session_get_dl(self, video_info):
        ### if you want check support device, please you self
        # video_info["supported_device_list"]
        
        querystring = {
            "device_id": str(self.device_id),
            "content_id": video_info["raw_single"]["id"],
            "position": "",
            "flagged_aes": "",
            "trailer": "0",
            "auth": "1",
            "log": "1",
            "multi_audio_support": "1"
        }
        
        session_response = self.session.get("https://api.tv.rakuten.co.jp/content/playinfo.json", params=querystring)
        session_response = session_response.json()
        if session_response["status"] == "success":
            pass
        else:
            return None, None, None, None, None
        
        paths = session_response["result"]["paths"][0]
        found_hls = bool(paths.get("path_hls"))
        found_dash = bool(paths.get("path_dash"))
        
        if found_hls and found_dash:
            mpd_link = paths.get("path_dash")
            
            if paths.get("widevine"):
                widevine_url = paths["widevine"]["license_url"]
                wv_license_header = {
                    "authorization": paths["widevine"]["ams_token"],
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
            if paths.get("playready"):
                playready_url = paths["playready"]["license_url"]
                pr_license_header = {
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
                
            mpd_response = self.session.get(mpd_link).text
            return "mpd", mpd_response, mpd_link, {"widevine": widevine_url, "playready": playready_url}, {"widevine": wv_license_header, "playready": pr_license_header}
        elif not found_hls and found_dash:
            mpd_link = paths.get("path_dash")
            
            if paths.get("widevine"):
                widevine_url = paths["widevine"]["license_url"]
                wv_license_header = {
                    "authorization": paths["widevine"]["ams_token"],
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
            if paths.get("playready"):
                playready_url = paths["playready"]["license_url"]
                pr_license_header = {
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
                
            mpd_response = self.session.get(mpd_link).text
            return "mpd", mpd_response, mpd_link, {"widevine": widevine_url, "playready": playready_url}, {"widevine": wv_license_header, "playready": pr_license_header}
        else:
            mpd_link = paths.get("path_hls")
            
            if paths.get("widevine"):
                widevine_url = paths["widevine"]["license_url"]
                wv_license_header = {
                    "authorization": paths["widevine"]["ams_token"],
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
            if paths.get("playready"):
                playready_url = paths["playready"]["license_url"]
                pr_license_header = {
                    "accept-encoding": "gzip",
                    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; sdk_google_atv_x86 Build/QTU1.200805.001)",
                    "connection": "Keep-Alive"
                }
                
            mpd_response = self.session.get(mpd_link).text
            return "mpd", mpd_response, mpd_link, {"widevine": widevine_url, "playready": playready_url}, {"widevine": wv_license_header, "playready": pr_license_header}
    def decrypt_done(self):
        pass
    
    def create_segment_links(self, get_best_track, manifest_link, video_segment_list, audio_segment_list, seg_timeline):
        parsed = urlparse(manifest_link)
        
        path_parts = parsed.path.split("/")
        base_path = "/".join(path_parts[:-1]) + "/"
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"
        
        get_best_track["video"]["url_base"] = base_url
        get_best_track["audio"]["url_base"] = base_url

        def build_segment_links(track):
            """映像または音声の完全なセグメントURLリストを作る"""
            base = get_best_track[track]['url_base']
            if track == "video":
                init_url = get_best_track[track]['url'].replace('$Bandwidth$', get_best_track[track]['id'].replace("video_", ""))
                segment_base = get_best_track[track]['url_segment_base'].replace('$Bandwidth$', get_best_track[track]['id'].replace("video_", ""))
            else:
                init_url = get_best_track[track]['url'].replace('$Bandwidth$', get_best_track[track]['bitrate'])
                segment_base = get_best_track[track]['url_segment_base'].replace('$Bandwidth$', get_best_track[track]['bitrate'])
            links = []
            links.append(base + init_url)
            
            for t in seg_timeline[track]:
                seg_url = segment_base.replace('$Time$', str(t))
                links.append(base + seg_url)
            
            return links
        
        audio_segment_links = build_segment_links('video')
        video_segment_links = build_segment_links('audio')
        
        return audio_segment_links, video_segment_links