import re
import jwt
import time
import dateutil.parser
from datetime import datetime
from collections import defaultdict

class FOD_downloader:
    def __init__(self, session):
        self.session = session
        #self.web_headers = {}
        self.login_status = None
        self.logined_headers = {}
    def authorize(self, email, password):        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        temp_token = self.gen_crack_token()
        
        default_headers = {
            "content-type": "application/json",
            # "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0",
            "x-authorization": "Bearer "+temp_token,
        }
        
        self.session.headers.update(default_headers)
        
        if email == "QR_LOGIN":
            """
            Get QR login url
            """
            # default_headers["host"] = "fod-sp.fujitv.co.jp"
            self.session.headers.update(default_headers)
            get_loginurl = self.session.get("https://fod-sp.fujitv.co.jp/apps/api/login/pin/?dv_type=tv")
            if get_loginurl.status_code != 200:
                return False, "Authentication Failed: Failed to get QR login url", None
            else:
                request_login_json = get_loginurl.json()
                print("Login URL:", request_login_json["url"])
                print("Code:", request_login_json["code"])
                
                while True:
                    send_checkping = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_pin/", json={"pin": request_login_json["code"]})                        
                    if send_checkping.status_code == 400:
                        print("Waiting Login...")
                        time.sleep(5)
                    elif send_checkping.status_code == 200:
                        print("Login Accept")
                        login_success_json = send_checkping.json()
                        gen_token = self.gen_login_uid_token(login_success_json["uid"])
                        self.session.headers.update({"x-authorization": "Bearer "+gen_token})
                        
                        status, message, login_uuid = self.get_userinfo()
                        if message == "1012":
                            return False, "Authentication Failed: This account is not subscription", None
                        else:
                            self.logined_headers = self.session.headers
                            self.login_status = [False, True]
                            return True, message, login_uuid, self.login_status
        
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "FOD require email and password", None, None
            
        payload = {
            "mail_address": email,
            "password": password
        }    
        
        response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        response.raise_for_status()
        
        email_verify_hashkey = response.json()["hash_key"]
        mail_auth_code = input("MAIL AUTH CODE : ")
        if mail_auth_code == None:
            return False, "Authentication Failed: Require Mail Auth Code", None, None
        else:
            pass
        
        payload = {
            "auth_code": str(mail_auth_code),
            "hash_key": email_verify_hashkey
        }
        login_status_check = self.session.post("https://id.fod.fujitv.co.jp/api/member/CheckAuthCodeApp", headers=default_headers, json=payload)
        login_status_check.raise_for_status()
        
        fodid_login_token = login_status_check.json()["fodid_login_token"]
        
        # default_headers["host"] = "fod-sp.fujitv.co.jp"
        self.session.headers.update(default_headers)
        
        payload = {
            "fodid_login_token": fodid_login_token
        }
        check_token_status = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_token/", headers=default_headers, json=payload)
        check_token_status.raise_for_status()
        
        uid = check_token_status.json()["uid"]
        
        login_token = self.re_generate_login_token(uid)
        
        self.session.headers.update({"x-authorization": "Bearer "+login_token})
        
        status, message, login_uuid = self.get_userinfo()
        if message == "1012":
            return False, "Authentication Failed: This account is not subscription", None, None
        else:
            self.logined_headers = self.session.headers
            self.login_status = [False, True]
            return True, message, login_uuid, self.login_status

    def gen_crack_token(self):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx" # Haha cracked from AndroidTV APK
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jwt_token
    
    def gen_login_uid_token(self, uid):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx" # Haha cracked from AndroidTV APK
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "uid": uid,
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        return jwt_token
    
    def get_userinfo(self):
        url = "https://fod-sp.fujitv.co.jp/apps/api/user/status/"
        
        querystring = { "dv_type": "tv" }
            
        response = self.session.get(url, params=querystring)
        if response.status_code == 200:
            return True, response.json(), response.cookies.get("uuid")
        elif response.status_code == 401:
            return False, response.json["code"], None
        
    def gen_temptoken(self):
        secret_key = "II1pq1aFylVZNASr0mea7zXFOhrAPZURZp6Ru3LuqqsUVZ4lyJj2R4kufetQN9mx"
        device_type = "androidTV"
        device_id = "google_google_aosp tv on x86_13"
        
        payload = {
            "iss": "FOD",
            "dv_type": device_type,
            "dv_id": device_id,
        }
        
        jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        headers_xauth = {
            "content-type": "application/json",
           # "host": "id.fod.fujitv.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0",
            "x-authorization": "Bearer "+jwt_token,
        }
        self.session.headers.update({'X-Authorization': 'Bearer ' + jwt_token})
        self.logined_headers = headers_xauth
        self.login_status = [True, True]
        return True, None, self.login_status

    def has_active_courses(self, user_status):
        """
        Check user plan.
        ex):
        1. check courses found
        2. check courses is not expired
        """
        courses = user_status.get("courses", [])
        
        if not courses:
            return False  # Cources not found
    
        now = datetime.now()
    
        for course in courses:
            exp_str = course.get("expiration_date", "")
            if exp_str:
                try:
                    expiration_date = dateutil.parser.parse(exp_str)
                    if expiration_date > now:
                        return True
                except ValueError:
                    continue
            else:
                return True
    
        return False
    
    
    def check_single_episode(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)

        def contains_repeated_identifier(url, identifier):
            pattern = f"({re.escape(identifier)}).*\\1"
            return bool(re.search(pattern, url))
                
        if contains_repeated_identifier(url, matches_url.group("title_id")):
            return True
        else:
            return False
    def get_title_parse_all(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=false&is_kids=false&dv_type=tv", headers=self.web_headers)

            return_json = metadata_response.json()
            if return_json["episodes"] != None:
                return True, return_json["episodes"], return_json["detail"]
            else:
                return False, None, None
        except Exception as e:
            return False, None, None
        
        
    def create_titlename_logger(self, id_type, title_name, episode_num, episode_name):
        def safe_format(format_string, raw_values):
            # フォーマット文字列に使われているキーを抽出
            keys_in_format = set(re.findall(r"{(\w+)}", format_string))
            
            # 存在するキーだけで辞書を作成（不足は除外）
            values = {k: raw_values.get(k, "") for k in keys_in_format if raw_values.get(k)}
            
            # 空文字になるキーがあれば、その "{key}" または "_{key}" を文字列から除去
            for k in keys_in_format:
                if not raw_values.get(k):
                    format_string = re.sub(rf"_?{{{k}}}", "", format_string)
    
            return format_string.format_map(defaultdict(str, values))
    
        # 共通の値（node は引数から取得）
        raw_values = {
            "seriesname": title_name,
            "titlename": episode_num,
            "episodename": episode_name
        }
    
        # ノーマルアニメ・ドラマ
        if id_type in ("ノーマルアニメ", "ノーマルドラマ"):
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values)
    
        # 映画（劇場）
        elif id_type == "映画":
            format_string = self.config["format"]["movie"]
            title_name_logger = safe_format(format_string, raw_values)
            
        return title_name_logger