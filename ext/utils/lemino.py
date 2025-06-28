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
from collections import defaultdict
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
                send_checkping = self.session.post(f"https://if.lemino.docomo.ne.jp/v1/user/loginkey/userinfo/profile", json={"member": True, "profile": True})         
                if send_checkping.status_code == 200:
                    if send_checkping.json()["member"]["account_type"] == None:
                        print("Waiting Login...")
                        time.sleep(5)
                    else:
                        print("Login Accept")
                        
                        update_token = self.session.post("https://if.lemino.docomo.ne.jp/v1/session/update").headers["x-service-token"]
                        
                        self.session.headers.update({"x-service-token": update_token})
                      
                        status, message = self.get_userinfo()
                        
                        session_json = {
                            "method": "QR_LOGIN",
                            "email": None,
                            "password": None,
                            "access_token": update_token,
                            "refresh_token": None
                        }
                        
                        self.login_status = True
                        
                        return True, message, self.login_status, session_json
    
    def use_temptoken_flag(self):
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
        
    def send_stop_signal(self, play_token, duratation):
        payload = {
            "play_token": play_token,
            "dur": str(duratation),
            "stop_position": "0"
        }
        
        signal_result = requests.post("https://if.lemino.docomo.ne.jp/v1/delivery/watch/stop", json=payload)
        signal_result.raise_for_status()
        
        if signal_result.json()["result"] == "0":
            return True
        else:
            return False
        
    def get_content_info(self, crid):
        url = "https://if.lemino.docomo.ne.jp/v1/meta/contents"
        
        querystring = {
            #"crid": "crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux",
            "crid": crid,
            "filter": "{\"target_age\":[\"G\",\"R-12\",\"R-15\"],\"avail_status\":[\"1\"]}"
        }
        contentinfo_result = self.session.get(url, params=querystring)
        if contentinfo_result.status_code == 200:
            return contentinfo_result.json()
        else:
            raise Exception("FAILED TO GET CONTENT INFO")
    def get_content_list(self, group_id):
        url = "https://if.lemino.docomo.ne.jp/v1/meta/member"
        
        querystring = {
            "parent_filter": json.dumps({
                "crid": [group_id],
                "pit_git_type": ["SERIES"],
                "avail_status": ["1"]
            }),
            "filter": json.dumps({
                "avail_status": ["1"]
            }),
            "child_sort": json.dumps({
                "content_num": "asc"
            })
        }
        serieslist_result = self.session.get(url, params=querystring)
        if serieslist_result.status_code == 200:
            return serieslist_result.json()["parent_list"][0]["title"], len(serieslist_result.json()["parent_list"][0]["child_list"]), serieslist_result.json()["parent_list"][0]
        else:
            raise Exception("FAILED TO GET CONTENT INFO")
    
    def create_titlename_logger(self, id_type, episode_count, title_name, episode_num, episode_name):
        def safe_format(format_string, raw_values):
            keys_in_format = set(re.findall(r"{(\w+)}", format_string))
            values = {k: raw_values.get(k, "") for k in keys_in_format if raw_values.get(k)}
            
            for k in keys_in_format:
                if not raw_values.get(k):
                    format_string = re.sub(rf"_?{{{k}}}", "", format_string)
    
            return format_string.format_map(defaultdict(str, values))
    
        raw_values = {
            "seriesname": title_name,
            "titlename": episode_num,
            "episodename": episode_name
        }
    
        if id_type in ("アニメ", "国内ドラマ", "海外ドラマ"):
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values)
        elif id_type in ("洋画", "邦画"):
            if episode_count == 1:
                title_name_logger = title_name
            else:
                format_string = self.config["format"]["movie"]
                title_name_logger = safe_format(format_string, raw_values)
        else:
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values) 
        return title_name_logger
    
    def analyze_genre(self, search_ids):        
        def _recursive_search_in_genre(current_genre, target_id):
            """
            特定のジャンルオブジェクトの配下（サブジャンル）のみを再帰的に探索する。
            """
            sub_genre_keys = ['sub', 'ttb_top_genre', 'ttb_top_sub_genre']
            for key in sub_genre_keys:
                if key in current_genre and isinstance(current_genre.get(key), list):
                    sub_list = current_genre[key]
                    for sub_genre in sub_list:
                        if sub_genre.get('genre_id') == target_id:
                            return sub_genre
                        
                        found_genre = _recursive_search_in_genre(sub_genre, target_id)
                        if found_genre:
                            return found_genre
            return None
    
        def _find_genre_by_id_with_toplevel_name(genre_data, target_id):
            """
            JSONデータ全体から指定されたgenre_idを持つジャンル情報を検索し、
            そのジャンルが属する最上位のジャンル名も併せて返す。
            """
            vod_genres = genre_data.get('genre_master', {}).get('VOD', [])
            if not vod_genres:
                return None
    
            for top_genre in vod_genres:
                top_genre_name = top_genre.get('genre_name')
    
                if top_genre.get('genre_id') == target_id:
                    return {
                        'genre_info': top_genre,
                        'top_genre_name': top_genre_name
                    }
    
                found_sub_genre = _recursive_search_in_genre(top_genre, target_id)
                if found_sub_genre:
                    return {
                        'genre_info': found_sub_genre,
                        'top_genre_name': top_genre_name
                    }
                    
            return None
            
        genre_list_server = self.session.get("https://conf.lemino.docomo.ne.jp/genre/genre_search.json").json()
        
        found_list = []
        print_list = []
        only_genre_id_list = []
        
        for genre_id in search_ids:
            result = _find_genre_by_id_with_toplevel_name(genre_list_server, genre_id)
    
            if result:
                print_list.append(result["genre_info"]["genre_name"])
                only_genre_id_list.append(result["top_genre_name"])
                found_list.append({
                    'top_genre_name': result['top_genre_name'],
                    'genre_name': result['genre_info']['genre_name'],
                    'genre_id': result['genre_info']['genre_id']
                })
                
        return found_list, print_list, only_genre_id_list
        
    def get_mpd_info(self, cid, lid, crid):
        payload = {
          "play_type": 1,
          "avail_status": "1",
          "terminal_type": 4,
          "content_list": [
            {
              "kind": "main",
              "cid": cid,
              "lid": lid,
              "crid": crid,
              "auto_play": 1,
              "trailer": 0,
              "preview": 0,
              "stop_position": 0
            }
          ]
        }
        play_list_result = self.session.post("https://if.lemino.docomo.ne.jp/v1/user/delivery/watch/ready", json=payload)
        if play_list_result.status_code == 200:
            play_list_json = play_list_result.json()
            play_token = play_list_json["play_token"]
            content_list = play_list_json["play_list"]
            return play_token, content_list
        elif play_list_result.status_code == 400:
            play_list_json = play_list_result.json()
            result_code = play_list_json["result_code"]
            result_message = play_list_json["message"]
            raise Exception("Message: "+result_message+" ERR_CODE: "+result_code)
        else:
            raise Exception("FAILED TO GET CONTENT INFO")