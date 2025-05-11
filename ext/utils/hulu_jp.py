import re
from ext.utils.hulu_jp_util.pymazda.sensordata.sensor_data_builder import SensorDataBuilder

class Hulu_jp_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.web_headers = {}
    def authorize(self, email, password):
        #global user_info_res
        _SESSION_CREATE = "https://mapi.prod.hjholdings.tv/api/v1/sessions/create"
        _LOGIN_API = "https://mapi-auth.prod.hjholdings.tv/api/v1/users/auth"
        _USER_INFO_API = "https://mapi.prod.hjholdings.tv/api/v1/users/me"
        
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.fullmatch('[0-9]+', email):
            if not re.fullmatch(mail_regex, email):
                return False, "Hulu jp require email and password", None
            
        default_headers = {
            "user-agent": "jp.happyon.android/3.24.0 (Android 9; 22081212C Build/PQ3B.190801.10101846)",
            "accept-language": "ja",
            "host": "mapi.prod.hjholdings.tv",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
            
        ## generate temp session
        
        payload_query = {
            "app_version": "3.24.0",
            "system_version": "9",
            "device_code": "5",
            "manufacturer": "Redmi",
            "is_mobile": "true",
            "os_version": "9",
            "os_build_id": "PQ3B.190801.10101846 release-keys",
            "device_manufacturer": "Redmi",
            "device_model": "22081212C",
            "device_name": "star2qltechn",
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
            "app_id": 3,
            "device_code": 5        
        }   
        sensor_data_builder = SensorDataBuilder()
        default_headers.update({
            "x-gaia-authorization": "extra " + gaia_token_1,
            "x-session-token": session_token_1,
            "x-acf-sensor-data": sensor_data_builder.generate_sensor_data(),
            "user-agent": "jp.happyon.android/3.24.0 (Android 9; 22081212C Build/PQ3B.190801.10101846)",
        })
        
        login_response = self.session.post(_LOGIN_API, json=payload, headers=default_headers).json()
        
        default_headers.update({
            "x-user-id": str(login_response["id"])
        })
        
        #return True, login_response
        
        ## get profile list
        payload_query = {
            "with_profiles": "true",
            "app_id": "3",
            "device_code": "5"
        }
        default_headers.update({
            "authorization": "Bearer " + login_response["access_token"],
            "x-session-token": login_response["session_token"],
            "x-gaia-authorization": "extra " + login_response["gaia_token"]
        })
        
        profile_resposne = self.session.get(_USER_INFO_API, params=payload_query, headers=default_headers).json()
        
        profile_list = []
        for single_profile in profile_resposne["profiles"]:
            if single_profile["values"]["has_pin"]:
                pin_status = "Yes"
            else:
                pin_status = "No "
            profile_list.append([single_profile["display_name"], pin_status, single_profile["uuid_in_schema"]])
            
        self.web_headers = default_headers
            
        return True, profile_list
        
        #response = self.session.post("https://id.fod.fujitv.co.jp/api/member/v2/login_app", headers=default_headers, json=payload)
        #response.raise_for_status()
        #
        #email_verify_hashkey = response.json()["hash_key"]
        #response = self.session.get("https://fod.fujitv.co.jp/auth/login/", headers=default_headers)
        #response.raise_for_status()
        #soup = BeautifulSoup(response.text, "html.parser")
        #viewstate = soup.find("input", {"name": "__VIEWSTATE"})["value"]
        #viewstategenerator = soup.find("input", {"name": "__VIEWSTATEGENERATOR"})["value"]
        # 
        #payload = {
        #    "__VIEWSTATE": viewstate,
        #    "__VIEWSTATEGENERATOR": viewstategenerator,
        #    "email": email,
        #    "password": password,
        #    "ctl00$ContentMain$hdnServerEnv": "",
        #    "ctl00$ContentMain$hdnFodMail": email,
        #    "ctl00$ContentMain$hdnFodPass": password,
        #    "ctl00$ContentMain$hdnFodLogin": "",
        #    "ctl00$ContentMain$hdnAmazonSignature": "xUOgugvm8yRVgfHrD1pgITydjpHWNJU8622JOK2pVh3h7mIFzuIy7SQHWTHmxjCQOXMZEL6SY1O4JEtjwS2Q+Xc455EZMwnHOJq6aZ+rx4yuEWFEdKxFM8n5j40JA3pqrcfbC/WnySQDEIqKuzPVtAmtC2IvDAPDAEmo+ieNa/ExDkzp7R1v5anxmDsYeU2+UwiAXvRLjax2RPm7vsyOA5FIliOePMIhZcv9p9fmbBsgxBvMWD7KsxX7NpH/uay7XpFiVqzoO2CabtyW0GkyHyuKPM8Zl3qAtjoxakc3dQze1nmSaQdyQtyk9j5XIRBMpRH3q478WuVBr/o3EI/Cqg==",
        #    "ctl00$ContentMain$hdnAmazonPayload": "{\"storeId\":\"amzn1.application-oa2-client.0fa212ac2e9e494197af4fc8b09d096e\",\"webCheckoutDetails\":{\"checkoutReviewReturnUrl\":\"https://fod.fujitv.co.jp/\"},\"chargePermissionType\":\"Recurring\",\"recurringMetadata\":{\"frequency\":{\"unit\":\"Month\",\"value\":1},\"amount\":{\"amount\":0,\"currencyCode\":\"JPY\"}}}",
        #    "ctl00$ContentMain$btnFodId": ""
        #}
        #headers = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "cache-control": "max-age=0",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "origin": "https://fod.fujitv.co.jp",
        #    "content-type": "application/x-www-form-urlencoded",
        #    "upgrade-insecure-requests": "1",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "navigate",
        #    "sec-fetch-user": "?1",
        #    "sec-fetch-dest": "document",
        #    "referer": "https://fod.fujitv.co.jp/auth/login/",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #find_redirecturl = self.session.post(_AUTH_MAIN_PAGE, data=payload, headers=headers, allow_redirects=False)
        #    
        #if find_redirecturl.status_code == 302:
        #    #print("[+] Get Redirect URL: "+find_redirecturl.headers["Location"])
        #    pass
        #else:
        #    return False, "Authentication Failed: Redirect URL Not found", None
        #
        #sent_mailcode = self.session.get(find_redirecturl.headers["Location"], headers=headers)
        #    
        #if sent_mailcode.status_code == 200:
        #    pass
        #else:
        #    return False, "Authentication Failed: Email sent was failed", None
        #
        #get_loginredir = self.session.get(_AUTH_TEST_1, headers=headers)
        #
        #if get_loginredir.status_code == 200:
        #    #print("[+] loginredir headers: ", response.headers)
        #    #print("[+] loginredir!")
        #    #print(get_loginredir.cookies.get("UT"))
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get loginredir", None
        #
        #headers_xauth = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "application/json, text/plain, */*",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "x-authorization": "Bearer "+get_loginredir.cookies.get("UT"),
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "cors",
        #    "sec-fetch-dest": "empty",
        #    "referer": "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #
        #get_user_status_1 = self.session.get(_AUTH_USER_STATUS, headers=headers_xauth)
        #
        #if get_user_status_1.status_code == 200:
        #    #print("[+] user_status_1: "+response.text)
        #    pass
        #else:
        #    #print(response.status_code)
        #    return False, "Authentication Failed: Failed to get user_status_1", None
        #
        mail_auth_code = input("MAIL AUTH CODE : ")
        if mail_auth_code == None:
            return False, "Authentication Failed: Require Mail Auth Code", None
        else:
            pass
        
        payload = {
            "auth_code": str(mail_auth_code),
            "hash_key": email_verify_hashkey
        }
        login_status = self.session.post("https://id.fod.fujitv.co.jp/api/member/CheckAuthCodeApp", headers=default_headers, json=payload)
        login_status.raise_for_status()
        
        fodid_login_token = login_status.json()["fodid_login_token"]
        #self.session.headers.update({"x-authorization": "Bearer "+fodid_login_token})
        
        default_headers["host"] = "fod-sp.fujitv.co.jp"
        
        payload = {
            "fodid_login_token": fodid_login_token
        }
        check_token_status = self.session.post("https://fod-sp.fujitv.co.jp/apps/api/login/check_token/", headers=default_headers, json=payload)
        check_token_status.raise_for_status()
        
        uid = check_token_status.json()["uid"]
        
        login_token = self.re_generate_login_token(uid)
        
        
        default_headers["x-authorization"] = "Bearer "+login_token
        self.session.headers.update({"x-authorization": "Bearer "+login_token})
        
        #
        #login_status_1 = self.session.get(_AUTH_SENT_CODE.format(code=mail_auth_code), headers=headers)
        #
        #if login_status_1.status_code == 200:
        #    #print("[+] login_status_1: "+login_status_1.text)
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get login_status_1", None
        #    
        #get_temp_token = self.session.get(_AUTH_REDIRECT_URL, headers=headers)
        #
        #if get_temp_token.status_code == 200:
        #    #print("[+] login headers: ", response.headers)
        #    #print("[+] Get Temp token: ", response.cookies.get("UT"))
        #    pass
        #else:
        #    return False, "Authentication Failed: Failed to get Temp Token", None
        #
        #headers_xauth = {
        #    "host": "fod.fujitv.co.jp",
        #    "connection": "keep-alive",
        #    "sec-ch-ua-platform": "\"Windows\"",
        #    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        #    "accept": "application/json, text/plain, */*",
        #    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        #    "X-Authorization": "Bearer "+get_temp_token.cookies.get("UT"),
        #    "sec-ch-ua-mobile": "?0",
        #    "sec-gpc": "1",
        #    "accept-language": "ja;q=0.9",
        #    "sec-fetch-site": "same-origin",
        #    "sec-fetch-mode": "cors",
        #    "sec-fetch-dest": "empty",
        #    "referer": "https://fod.fujitv.co.jp/loginredir?r=",
        #    "accept-encoding": "gzip, deflate, br, zstd",
        #}
        #    
        user_info_res = self.session.get(_AUTH_USER_STATUS, headers=default_headers)
        
        if user_info_res.status_code == 200:
            #print("[+] user_status_2: "+response.text)
            #print("[+] GET REAL TOKEN!!!: ", response.cookies.get("UT"))
            #pass
            #self.session.headers.update({'x-authorization': 'Bearer ' + user_info_res.cookies.get("UT")})
            self.web_headers = {
                "x-authorization": "Bearer "+login_token,
                "host": "fod-sp.fujitv.co.jp",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.12.0",
            }
            #self.web_headers = headers_xauth
            self.web_headers["referer"] = "https://fod.fujitv.co.jp/"
            self.web_headers["origin"] = "https://fod.fujitv.co.jp"
            self.web_headers["host"] = "i.fod.fujitv.co.jp"
            self.web_headers["sec-fetch-site"] = "same-site"
            #self.web_headers["X-Authorization"] = "Bearer " + get_loginredir.cookies.get("CT")
            login_status = True
            return True, user_info_res.json(), user_info_res.cookies.get("uuid")
        else:
            return False, "Authentication Failed: Failed to get user_status_2", None
    def select_profile(self, uuid):
        payload = {
            "pin": "",
            "profile_id": uuid
        }
        headers = self.web_headers.copy()
        headers["x-user-id"] = None
        headers["authorization"] = None
        headers["x-acf-sensor-data"] = None
        meta_response = self.session.put("https://mapi.prod.hjholdings.tv/api/v1/gaia/auth/profile", json=payload, headers=headers)
        try:
            if meta_response.status_code == 200:
                profile_change_response = meta_response.json()
                self.web_headers.update({
                    "authorization": "Bearer " + profile_change_response["access_token"],
                    "x-session-token": profile_change_response["session_token"],
                    "x-gaia-authorization": "extra " + profile_change_response["gaia_token"]
                })
                return True, meta_response.json()
        except:
            return False, "Failed to login profile"