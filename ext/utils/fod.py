import re
import time
from bs4 import BeautifulSoup
from datetime import datetime
from xml.etree import ElementTree as ET

class mpd_parse:
    @staticmethod
    def get_resolutions(mpd_content):
        # 名前空間の定義
        namespace = {'ns': 'urn:mpeg:dash:schema:mpd:2011'}
        
        # MPDテキストを解析
        try:
            root = ET.fromstring(mpd_content)
        except ET.ParseError as e:
            print(f"XML Parse Error: {e}")
            return []
        
        # 結果を格納するリスト
        video_representations = []
        bandwidth_list = []
        
        # 映像の AdaptationSet をフィルタリング
        for adaptation_set in root.findall(".//ns:AdaptationSet", namespace):
            mime_type = adaptation_set.get("mimeType")
            if mime_type == "video/mp4":  # 映像のみ
                for representation in adaptation_set.findall("ns:Representation", namespace):
                    # 幅、高さ、コーデックを取得
                    width = representation.get("width")
                    height = representation.get("height")
                    codecs = representation.get("codecs")
                    bandwidth = representation.get("bandwidth")
                    
                    # 映像の情報をリストに追加
                    if width and height and codecs:
                        info = f"{width}x{height} {mime_type.split('/')[-1]} {codecs}"
                        info_b = bandwidth
                        video_representations.append(info)
                        bandwidth_list.append(info_b)
        
        return video_representations, bandwidth_list

class FOD_utils:
    def check_single_episode(url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)

        def contains_repeated_identifier(url, identifier):
            # identifierが2回連続して現れるか確認
            pattern = f"({re.escape(identifier)}).*\\1"
            return bool(re.search(pattern, url))
                
        if contains_repeated_identifier(url, matches_url.group("title_id")):
            #print("True")
            return True
        else:
            #print("False")
            return False
class FOD_license:
    def license_vd_ad(all_pssh, custom_data, session):
        _WVPROXY = f"https://cenc.webstream.ne.jp/drmapi/wv/fujitv?custom_data={custom_data}"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(all_pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge))
        response.raise_for_status()
    
        cdm.parse_license(session_id, response.content)
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]
    
        cdm.close(session_id)
        
        keys = {
            "key": keys,
        }
        
        return keys

class FOD_downloader:
    def __init__(self, session):
        self.session = session
        self.web_headers = {}
    def authorize(self, email, password):
        global user_info_res
        _AUTH_MAIN_PAGE = "https://fod.fujitv.co.jp/auth/login/"
        _AUTH_TEST_1 = "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth"
        _AUTH_USER_STATUS = "https://fod.fujitv.co.jp/apps/api/1/user/status"
        _AUTH_SENT_CODE = "https://fod.fujitv.co.jp/renew/auth/mail_auth/?p=1&ac={code}"
        _AUTH_REDIRECT_URL = "https://fod.fujitv.co.jp/loginredir?r="
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        default_headers = {
            "host": "fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.9",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd"
        }
    
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "FOD require email and password", None
        
        response = self.session.get("https://fod.fujitv.co.jp/auth/login/", headers=default_headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        viewstate = soup.find("input", {"name": "__VIEWSTATE"})["value"]
        viewstategenerator = soup.find("input", {"name": "__VIEWSTATEGENERATOR"})["value"]
         
        payload = {
            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategenerator,
            "email": email,
            "password": password,
            "ctl00$ContentMain$hdnServerEnv": "",
            "ctl00$ContentMain$hdnFodMail": email,
            "ctl00$ContentMain$hdnFodPass": password,
            "ctl00$ContentMain$hdnFodLogin": "",
            "ctl00$ContentMain$hdnAmazonSignature": "xUOgugvm8yRVgfHrD1pgITydjpHWNJU8622JOK2pVh3h7mIFzuIy7SQHWTHmxjCQOXMZEL6SY1O4JEtjwS2Q+Xc455EZMwnHOJq6aZ+rx4yuEWFEdKxFM8n5j40JA3pqrcfbC/WnySQDEIqKuzPVtAmtC2IvDAPDAEmo+ieNa/ExDkzp7R1v5anxmDsYeU2+UwiAXvRLjax2RPm7vsyOA5FIliOePMIhZcv9p9fmbBsgxBvMWD7KsxX7NpH/uay7XpFiVqzoO2CabtyW0GkyHyuKPM8Zl3qAtjoxakc3dQze1nmSaQdyQtyk9j5XIRBMpRH3q478WuVBr/o3EI/Cqg==",
            "ctl00$ContentMain$hdnAmazonPayload": "{\"storeId\":\"amzn1.application-oa2-client.0fa212ac2e9e494197af4fc8b09d096e\",\"webCheckoutDetails\":{\"checkoutReviewReturnUrl\":\"https://fod.fujitv.co.jp/\"},\"chargePermissionType\":\"Recurring\",\"recurringMetadata\":{\"frequency\":{\"unit\":\"Month\",\"value\":1},\"amount\":{\"amount\":0,\"currencyCode\":\"JPY\"}}}",
            "ctl00$ContentMain$btnFodId": ""
        }
        headers = {
            "host": "fod.fujitv.co.jp",
            "connection": "keep-alive",
            "cache-control": "max-age=0",
            "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "origin": "https://fod.fujitv.co.jp",
            "content-type": "application/x-www-form-urlencoded",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.9",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "referer": "https://fod.fujitv.co.jp/auth/login/",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
        find_redirecturl = self.session.post(_AUTH_MAIN_PAGE, data=payload, headers=headers, allow_redirects=False)
            
        if find_redirecturl.status_code == 302:
            #print("[+] Get Redirect URL: "+find_redirecturl.headers["Location"])
            pass
        else:
            return False, "Authentication Failed: Redirect URL Not found", None
        
        sent_mailcode = self.session.get(find_redirecturl.headers["Location"], headers=headers)
            
        if sent_mailcode.status_code == 200:
            #print("[+] mail_auth headers: ", sent_mailcode.headers)
            #print("[+] sent mail_auth_code")
            pass
        else:
            return False, "Authentication Failed: Email sent was failed", None
        
        get_loginredir = self.session.get(_AUTH_TEST_1, headers=headers)
        
        if get_loginredir.status_code == 200:
            #print("[+] loginredir headers: ", response.headers)
            #print("[+] loginredir!")
            #print(get_loginredir.cookies.get("UT"))
            pass
        else:
            return False, "Authentication Failed: Failed to get loginredir", None
        
        headers_xauth = {
            "host": "fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "x-authorization": "Bearer "+get_loginredir.cookies.get("UT"),
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.9",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
        
        get_user_status_1 = self.session.get(_AUTH_USER_STATUS, headers=headers_xauth)
        
        if get_user_status_1.status_code == 200:
            #print("[+] user_status_1: "+response.text)
            pass
        else:
            #print(response.status_code)
            return False, "Authentication Failed: Failed to get user_status_1", None
        
        mail_auth_code = input("MAIL AUTH CODE : ")
        if mail_auth_code == None:
            return False, "Authentication Failed: Require Mail Auth Code", None
        else:
            pass
        
        login_status_1 = self.session.get(_AUTH_SENT_CODE.format(code=mail_auth_code), headers=headers)
        
        if login_status_1.status_code == 200:
            #print("[+] login_status_1: "+login_status_1.text)
            pass
        else:
            return False, "Authentication Failed: Failed to get login_status_1", None
            
        get_temp_token = self.session.get(_AUTH_REDIRECT_URL, headers=headers)
        
        if get_temp_token.status_code == 200:
            #print("[+] login headers: ", response.headers)
            #print("[+] Get Temp token: ", response.cookies.get("UT"))
            pass
        else:
            return False, "Authentication Failed: Failed to get Temp Token", None
        
        headers_xauth = {
            "host": "fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "X-Authorization": "Bearer "+get_temp_token.cookies.get("UT"),
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.9",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/loginredir?r=",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
            
        user_info_res = self.session.get(_AUTH_USER_STATUS, headers=headers_xauth)
        
        if user_info_res.status_code == 200:
            #print("[+] user_status_2: "+response.text)
            #print("[+] GET REAL TOKEN!!!: ", response.cookies.get("UT"))
            #pass
            self.session.headers.update({'X-Authorization': 'Bearer ' + user_info_res.cookies.get("UT")})
            self.web_headers = headers_xauth
            self.web_headers["referer"] = "https://fod.fujitv.co.jp/"
            self.web_headers["origin"] = "https://fod.fujitv.co.jp"
            self.web_headers["host"] = "i.fod.fujitv.co.jp"
            self.web_headers["sec-fetch-site"] = "same-site"
            self.web_headers["X-Authorization"] = "Bearer " + get_loginredir.cookies.get("CT")
            return True, user_info_res.json(), user_info_res.cookies.get("uuid")
        else:
            return False, "Authentication Failed: Failed to get user_status_2", None

    def get_title_parse_single(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/episode/detail/?ep_id={matches_url.group("episode_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
            return_json = metadata_response.json()
            if return_json != None:
                metadata_response_single = return_json
                return True, metadata_response_single, [metadata_response_single["coin"], metadata_response_single["price"]]
            else:
                return False, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
    def get_title_parse_all(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''エピソードのタイトルについて取得するコード'''
        try:
            metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/episode/lineup/?ep_id={matches_url.group("episode_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
            return_json = metadata_response.json()
            if return_json["episodes"] != None:
                return True, return_json
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_id_type(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''映像タイプを取得するコード'''
        try:   
            #print(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false")
            
            #print(self.web_headers)
            #print("aaa", self.session.headers)
            if matches_url.group("episode_id"):
                metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/episode/detail/?ep_id={matches_url.group("episode_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
                #print(metadata_response.text)
                return_json = metadata_response.json()
                if return_json["genre"] != None:
                    maybe_genre = None
                    
                    if return_json["genre"]["genre_name"].__contains__("アニメ"):
                        maybe_genre = "ノーマルアニメ"
                    elif return_json["genre"]["genre_eng_name"].__contains__("anime"):
                        maybe_genre = "ノーマルアニメ"
                    elif return_json["genre"]["genre_name"].__contains__("映画"):
                        maybe_genre = "劇場"
                    elif return_json["genre"]["genre_eng_name"].__contains__("movie"):
                        maybe_genre = "劇場"
                    else:
                        maybe_genre = "劇場"
                    
                    return True, [return_json["genre"], maybe_genre]
                else:
                    return False, None
            else:
                metadata_response = self.session.get(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false", headers=self.web_headers)
                #print(metadata_response.text)
                return_json = metadata_response.json()
                if return_json["detail"] != None:
                    maybe_genre = None
                    
                    if return_json["detail"]["attribute"].__contains__("映画"):
                        maybe_genre = "劇場"
                    elif return_json["detail"]["attribute"].__contains__("エピソード"):
                        maybe_genre = "ノーマルアニメ"
                    else:
                        maybe_genre = "ノーマルアニメ"
                    
                    return True, [return_json["detail"]["attribute"], maybe_genre]
                else:
                    return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_mpd_content(self, uuid, url, ut):
        global mpd_content_response
        tries = 3
        for attempt in range(tries):
            try:
                unixtime = str(int(time.time() * 1000))
                matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
                self.web_headers["X-Authorization"] = "Bearer "+ut
                self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
                self.web_headers["host"] = "fod.fujitv.co.jp"
                self.web_headers["sec-fetch-site"] = "same-origin"
                print(self.web_headers)
                mpd_content_response = self.session.get(f"https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
                print(mpd_content_response.text)
                if mpd_content_response.json():
                    if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
                        self.web_headers["X-Authorization"] = "Bearer "+mpd_content_response.cookies.get("UT")
                        self.web_headers["referer"] = f"https://fod.fujitv.co.jp/title/{matches_url.group("title_id")}/{matches_url.group("episode_id")}/"
                        self.web_headers["host"] = "fod.fujitv.co.jp"
                        self.web_headers["sec-fetch-site"] = "same-origin"
                        unixtime = str(int(time.time() * 1000))
                        mpd_content_response = self.session.get(f"https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={matches_url.group("episode_id")}&qa=auto&uuid={uuid}&starttime=0&is_pt=false&dt=&_={unixtime}", headers=self.web_headers)
                        if mpd_content_response.text == '{"code": "2005","relay_code": "0006"}':
                            pass
                        else:
                            ticket = mpd_content_response.json()["ticket"]
                            mpd_url = mpd_content_response.json()["url"]
                            mpd_content_res = self.session.get(mpd_url)
                            self.session.get(f"https://fod.fujitv.co.jp/api/premium/view_log_pc/?epid={matches_url.group("episode_id")}&_={str(int(time.time() * 1000))}")
                            return True, ticket, mpd_content_res.text
                    else:
                        ticket = mpd_content_response.json()["ticket"]
                        mpd_url = mpd_content_response.json()["url"]
                        mpd_content_res = self.session.get(mpd_url)
                        self.session.get(f"https://fod.fujitv.co.jp/api/premium/view_log_pc/?epid={matches_url.group("episode_id")}&_={str(int(time.time() * 1000))}")
                        return True, ticket, mpd_content_res.text
            except Exception as e:
                import traceback
                import sys
                t, v, tb = sys.exc_info()
                print(traceback.format_exception(t,v,tb))
                print(traceback.format_tb(e.__traceback__))
                if attempt == tries -1:
                    return False, None
                
    def sent_start_stop_signal(self, bandwidth, video_url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', video_url)
        uuid = self.session.cookies.get("uuid")
        series_id = matches_url.group("title_id")
        episode_id = matches_url.group("episode_id")
        enq_id = self.session.cookies.get("plus7_guid")
        episode_id_for_web = mpd_content_response.json()["samba"]
        foduser_id = user_info_res.json()["member_id"]
        td_write_key = "257/1dbef148fc11ca71d992972db31166af2b5dba41"
        mpd_video_play_band = bandwidth
        
        # Start Playing
        
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        querystring = {
            "foduser_id": foduser_id,
            "enq_id": enq_id,
            "season_id": series_id,
            "fod_episode_id": episode_id,
            "episode_id": episode_id_for_web,
            "refer": "fodapp",
            "device_category": "pc",
            "session_id": uuid,
            "td_write_key": td_write_key,
            "subpronum": "0",
            "player_status": "play",
            "current_time": "1",
            "buffering": "60",
            "play_band": mpd_video_play_band,
            "internet_speed": "0",
            "play_speed": "1",
            "error_id": "",
            "stream_type": "urn:mpeg:dash:mp4protection:2011",
            "contents_type": "SVOD-TVOD",
            "device_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "device_os_version": "Chrome",
            "device_os_sdk_version": "131.0.0.0"
        }
        
        headers = {
            "host": "tokyo.in.treasuredata.com",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7"
        }
        
        response = self.session.get(url, headers=headers, params=querystring)
        
        print(response.text)
        
        # Stop Playing
        
        url = "https://tokyo.in.treasuredata.com/postback/v3/event/010_fod_dl_tdtracking_video_play/video_play_log/"
        
        querystring = {
            "foduser_id": foduser_id,
            "enq_id": enq_id,
            "season_id": series_id,
            "fod_episode_id": episode_id,
            "episode_id": episode_id_for_web,
            "refer": "fodapp",
            "device_category": "pc",
            "session_id": uuid,
            "td_write_key": td_write_key,
            "subpronum": "0",
            "player_status": "pause",
            "current_time": "3",
            "buffering": "63",
            "play_band": mpd_video_play_band,
            "internet_speed": "0",
            "play_speed": "1",
            "error_id": "",
            "stream_type": "urn:mpeg:dash:mp4protection:2011",
            "contents_type": "SVOD-TVOD",
            "device_ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "device_os_version": "Chrome",
            "device_os_sdk_version": "131.0.0.0"
        }
        
        headers = {
            "host": "tokyo.in.treasuredata.com",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "accept": "*/*",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7"
        }
        
        response = self.session.get(url, headers=headers, params=querystring)
        
        print(response.text)
        
        uiid_temp = mpd_content_response.json()["viewbeaconurl"]   
        view_interval = mpd_content_response.json()["viewbeaconinterval"]
        match = re.search(r"uiid=([^&]+)", uiid_temp)
        if match:
            uiid = match.group(1)
            #print("Extracted uiid:", uiid)
        
        url = "https://measure-api.cms.fod.fujitv.co.jp/apps/api/sameview/measure_viewtime"
        
        querystring = {
            "uiid": uiid,
            "epid": episode_id,
            "ssid": uuid,
            "dvid": "WEB_PC",
            "resume_time": "0",
            "duration": "1411",
            "complete": "0",
            "view_interval": view_interval,
            "view_start_time": datetime.now().strftime("%Y%m%d%H%M"),
            "play_status": "2",
            "isRestriction": "1",
            "pausecount": "1",
            "_": str(int(time.time() * 1000))
        }
        
        headers = {
            "host": "measure-api.cms.fod.fujitv.co.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "accept": "*/*",
            "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "origin": "https://fod.fujitv.co.jp",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://fod.fujitv.co.jp/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7",
            "cookie": "_wasc=UXYFkZEQ682JQnTS.3; _gcl_au=1.1.1823950804.1734766716; _gid=GA1.3.1658627324.1734766716; _td_ssc_id=01JFM2ESAFXT3TWZ145MK21QAD; __lt__cid=d594b2a7-3ca8-4438-a8ec-683e05833088; _fbp=fb.2.1734766716599.65629728370894571; _ugpid=UXYFkwFInfzriv8K.3; _tt_enable_cookie=1; _ttp=wShh55mem74juyKINNP7kaEvxcS.tt.2; fodid_session_id=fgrrocrdejkioj4h95u969mm11; _yjsu_yjad=1734788414.df8ac0d3-83a4-4005-8625-be6681a3661e; FODCID=92115ef7d92a41f57f60ab281c7d0eb31e82437a30bf32945fab3afe82e0718a6b6d9c845cc8b708ba05947159b57ba6; fod_bu=YKjcTxp01PjqTg%2bHRsX5vuZ2zaGBPRm%2fZOPHZHfyuNdHeHh8qDHwSfSa4KL7UitQQ3nlPBd5TCV6nTWbkLqWMaqibe7mmjKTMTXcftUinlw%3d; plus7_ans=202104; plus7_guid=cdc3a9d6-06be-43e1-b8de-d64c77646055; plus7_attr=1_2003-05-01_1320032; plus7_ct=131237; d6hkt=dfbe3196-c220-4d0d-9101-f91a5f181391; ab.storage.deviceId.595c6e71-7cbd-4ec1-86cf-acff84cdaa9d=g%3A3f1e7888-59d8-7fd1-f0a6-352c1f31cb6c%7Ce%3Aundefined%7Cc%3A1734745601727%7Cl%3A1734827516934; ab.storage.userId.595c6e71-7cbd-4ec1-86cf-acff84cdaa9d=g%3A21988097%7Ce%3Aundefined%7Cc%3A1734745642468%7Cl%3A1734827516934; _clck=167i1xr%7C2%7Cfrx%7C0%7C1816; _ga=GA1.3.1196535851.1734766716; _td=ab92c139-04ca-4f13-b2c2-b20dd72f6048; _ga_3FV4ZRCKNN=GS1.1.1734827516.3.1.1734830779.60.0.0; _uetsid=6d41d070bf3d11efb75981b811c7d3ce; _uetvid=6d41eb80bf3d11efa0c2f3481629beff; _clsk=71y4nk%7C1734830780812%7C5%7C1%7Ct.clarity.ms%2Fcollect; ab.storage.sessionId.595c6e71-7cbd-4ec1-86cf-acff84cdaa9d=g%3A2a68f301-eab4-1b2a-b759-8cefffb0b144%7Ce%3A1734832585098%7Cc%3A1734827516933%7Cl%3A1734830785098"
        }
        
        response = self.session.get(url, headers=headers, params=querystring)
        
        print(response.text)
        pass