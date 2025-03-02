import re
import uuid
import json
import urllib.parse

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
        self.pathevalutaro_headers = {
            "user-agent": self.user_agent,
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "host": "wod.wowow.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
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
            self.refresh_token = response["refresh_token"]
            self.access_token = response["access_token"]
            self.wip_access_token = response["wip_access_token"]
            self.wip_refresh_token = response["wip_refresh_token"]
            
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
    def create_playback_session(self, meta_id, media_id):
        try:
            payload = {}
            payload["meta_id"] = str(meta_id) # 152181
            payload["media_id"] = str(media_id) # 138916
            payload["device_code"] = str(8)
            payload["vuid"] = uuid.uuid4().hex
            payload["user_id"] = self.user_id
            payload["refresh_token"] = self.refresh_token
            payload["wip_access_token"] = self.wip_access_token
            payload["wip_refresh_token"] = self.wip_refresh_token
            payload["client_id"] = "wod-tv"
            payload["ua"] = "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 jp.ne.wowow.vod.androidtv/3.7.0"
            payload["app_id"] = 5
            payload["device_code"] = 8
            payload["device_localized_model"] = "BRAVIA 4K GB"
            payload["localized_model"] = "BRAVIA 4K GB"
            payload["device_system_name"] = "AndroidTV"
            payload["system_name"] = "AndroidTV"
            payload["device_manufacturer"] = "Sony"
            payload["manufacturer"] = "Sony"
            payload["device_hw_machine"] = ""
            payload["hw_machine"] = ""
            payload["system_version"] = "7.0"
            payload["device_system_version"] = "7.0"
            payload["device_mccmnc"] = ""
            payload["mccmnc"] = ""
            payload["device_model"] = "BRAVIA 4K GB"
            payload["model"] = "BRAVIA 4K GB"
            payload["device_display_name"] = "BRAVIA 4K GB"
            payload["display_name"] = "BRAVIA 4K GB"
            payload["device_app_version"] = "3.7.0"
            payload["app_version"] = "3.7.0"
            payload["device_app_build_version"] = 193
            payload["app_build_version"] = 193
            headers = {
                "x-session-token": self.x_session_token,
                "authorization": "Bearer "+self.access_token,
                "x-user-id": str(self.user_id),
                "content-type": "application/json; charset=UTF-8",
                "host": "mapi.wowow.co.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.9.0"
            }
            response = self.session.post("https://mapi.wowow.co.jp/api/v1/playback/auth", json=payload, headers=headers).json()
            return True, response["playback_session_id"], response["access_token"]
        except Exception as e:
            return False, e, None
    def get_episode_prod_info(self, media_uuid, access_token, playback_session_id):
        headers = {
            'authority': 'playback-engine.wowow.co.jp',
            'sec-ch-ua': '";Not A Brand";v="99", "Chromium";v="94"',
            'authorization': access_token,
            'x-playback-session-id': playback_session_id,
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'wowow-production/102 CFNetwork/1333.0.4 Darwin/21.5.0',
            'x-user-id': str(self.user_id),
            'accept': '*/*',
            'origin': 'https://wod.wowow.co.jp',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://wod.wowow.co.jp/',
            'accept-language': 'zh-CN,zh;q=0.9',
        }
        response = self.session.get(f"https://playback-engine.wowow.co.jp/session/open/v1/projects/wod-prod/medias/{media_uuid}?codecs=avc", headers=headers).json()
        duration = response["duration"]
        sources = response["sources"]
        return duration, sources
    def send_stop_signal(self, access_token, playback_session_id):
        headers = {
            'authority': 'playback-engine.wowow.co.jp',
            'sec-ch-ua': '";Not A Brand";v="99", "Chromium";v="94"',
            'authorization': access_token,
            'x-playback-session-id': playback_session_id,
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'wowow-production/102 CFNetwork/1333.0.4 Darwin/21.5.0',
            'x-user-id': str(self.user_id),
            'accept': '*/*',
            'origin': 'https://wod.wowow.co.jp',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://wod.wowow.co.jp/',
            'accept-language': 'zh-CN,zh;q=0.9',
        }
        response = self.session.post("https://playback-engine.wowow.co.jp/session/close", headers=headers).json()
        if response["result"]:
            return True
        else:
            return False
    def get_all_season_info(self, season_id):
        response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/{season_id}?expand_object_flag=0&user_status=2&app_id=5&device_code=8&datasource=decorator").json()
        for season in response["seasons"]:
            print(season["id"], season["name"])
    def get_season_info(self, only_season_id):
        response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/{only_season_id}?expand_object_flag=0&user_status=2&app_id=5&device_code=8&datasource=decorator").json()
        return response
    def get_season_episode_title(self, season_id):
        payload = {
            "paths": [["meta",season_id,"episodes","episode","f","ena","length"],["meta",season_id,"episodes","episode","f","ena",{"from":0,"to":200},["id","refId","name","schemaId","attributes","genres","middleGenres","shortName","thumbnailUrl","resumePoint","cardInfo","seasonMeta","seriesMeta","publishStartAt","publishEndAt","type","leadSeasonId","titleMetaId","tvodBadge","rental","subscription"]]],
            "method": "get"
        }
        query_params = {
            "paths": json.dumps(payload["paths"], separators=(',', ':')),
            "method": payload["method"]
        }
        query_string = urllib.parse.urlencode(query_params)
        
        response = self.session.get(f"https://wod.wowow.co.jp/pathEvaluator?{query_string}", headers=self.pathevalutaro_headers).json()
        #list_all_ep_id = []
        list_all_ep_title = []
        #for single in response["jsonGraph"]["meta"][str(season_id)]["episodes"]["episode"]["f"]["ena"]:
        #    single = response["jsonGraph"]["meta"][str(season_id)]["episodes"]["episode"]["f"]["ena"][single]
        #    if single == str(season_id):
        #        continue
        #    print(single)
        #    list_all_ep_id.append(single["value"][1])
        for single in response["jsonGraph"]["meta"]:
            if single == str(season_id):
                continue
            #print(single)
            single = response["jsonGraph"]["meta"][single]
            #print(single)
            temp_json = {}
            temp_json["id"] = single["id"]["value"]
            temp_json["short_name"] = single["shortName"]["value"]
            temp_json["thumbnail_json"] = single["thumbnailUrl"]["value"]
            temp_json["genre"] = ", ".join(i["name"] for i in single["genres"]["value"])
            temp_json["refId"] = single["refId"]["value"]
            temp_json["shortest_name"] = single["cardInfo"]["value"]["episodeNumberTitle"]
            temp_json["productionYear"] = single["cardInfo"]["value"]["productionYear"]
            list_all_ep_title.append(temp_json)
        
        list_all_ep_title = sorted(list_all_ep_title, key=lambda x: x["refId"])
        return list_all_ep_title
    def get_season_real_id(self, url):
        # URLからプログラムIDを抽出
        match = re.search(r'program/(\d+)', url)
        if not match:
            raise ValueError("Invalid URL format")
        program_id = int(match.group(1))
        
        # APIエンドポイントとリクエストデータ
        api_url = "https://wod.wowow.co.jp/pathEvaluator"
        data = {
            "paths": [["program", program_id, ["id", "name", "seriesMeta"]]],
            "method": "get"
        }
        # APIリクエスト
        data = {
            "paths": [["program", program_id, ["id", "name", "seriesMeta"]]],
            "method": "get"
        }
        query_params = {
            "paths": json.dumps(data["paths"], separators=(',', ':')),
            "method": data["method"]
        }
        query_string = urllib.parse.urlencode(query_params)
        url = f"{api_url}?{query_string}"
        
        response = self.session.get(url, headers=self.pathevalutaro_headers)
        response.raise_for_status()  # エラーチェック
        
        # 必要なデータを取得
        json_data = response.json()
        return json_data["jsonGraph"]["program"][str(program_id)]["value"][1], json_data["jsonGraph"]["meta"][str(json_data["jsonGraph"]["program"][str(program_id)]["value"][1])]["name"]["value"]
    def get_all_season_id(self, url):
        # URLからプログラムIDを抽出
        match = re.search(r'program/(\d+)', url)
        if not match:
            raise ValueError("Invalid URL format")
        program_id = int(match.group(1))
        
        # APIエンドポイントとリクエストデータ
        api_url = "https://wod.wowow.co.jp/pathEvaluator"
        data = {
            "paths": [["program", program_id, ["id", "name", "seriesMeta"]]],
            "method": "get"
        }
        # APIリクエスト
        data = {
            "paths": [["program", program_id, ["id", "name", "seriesMeta"]]],
            "method": "get"
        }
        query_params = {
            "paths": json.dumps(data["paths"], separators=(',', ':')),
            "method": data["method"]
        }
        query_string = urllib.parse.urlencode(query_params)
        url = f"{api_url}?{query_string}"
        
        response = self.session.get(url, headers=self.pathevalutaro_headers)
        response.raise_for_status()  # エラーチェック
        
        # 必要なデータを取得
        json_data = response.json()
        allseason_metaid = json_data["jsonGraph"]["meta"][str(json_data["jsonGraph"]["program"][str(program_id)]["value"][1])]["seriesMeta"]["value"]["metaId"]
        
        headers = {
            "host": "mapi.wowow.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.9.0"
        }
        response = self.session.get(f"https://mapi.wowow.co.jp/api/v1/metas/{allseason_metaid}/children?schema_id=2&user_status=2&app_id=5&device_code=8&page=1&limit=100&order=asc&datasource=decorator&with_total_count=true&expand_object_flag=true&only_searchable=true", headers=headers)
        response.raise_for_status()  # エラーチェック
        
        return response.json()["total_count"], response.json()["metas"]