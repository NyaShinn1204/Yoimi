import re
from bs4 import BeautifulSoup

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
        
    def get_id_type(self, url):
        matches_url = re.match(r'^https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+)?/?$', url)
        '''映像タイプを取得するコード'''
        try:   
            print(f"https://i.fod.fujitv.co.jp/apps/api/lineup/detail/?lu_id={matches_url.group("title_id")}&is_premium=true&dv_type=web&is_kids=false")
            
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
                    if return_json["genre"]["genre_eng_name"].__contains__("anime"):
                        maybe_genre = "ノーマルアニメ"
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
                    if return_json["detail"]["attribute"].__contains__("エピソード"):
                        maybe_genre = "ノーマルアニメ"
                    else:
                        maybe_genre = "ノーマルアニメ"
                    
                    return True, [return_json["detail"]["attribute"], maybe_genre]
                else:
                    return False, None
        except Exception as e:
            print(e)
            return False, None