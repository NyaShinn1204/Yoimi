import re
import json
import hmac
import base64
import hashlib
import requests

class Fanza_utils:
    def recaptcha_v3_bypass(anchor_url):
        session = requests.Session()
        session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded"
        })

        match = re.search(r"(api2|enterprise)/anchor\?(.*)", anchor_url)
        mode, param_str = match.groups()
        base_url = f"https://www.google.com/recaptcha/{mode}/"

        params = dict(pair.split("=") for pair in param_str.split("&"))

        response = session.get(base_url + "anchor", params=params)
        token = re.search(r'"recaptcha-token" value="(.*?)"', response.text).group(1)

        post_data = "v={v}&reason=q&c={c}&k={k}&co={co}".format(
            v=params["v"],
            c=token,
            k=params["k"],
            co=params["co"]
        )

        response = session.post(
            base_url + "reload",
            params={"k": params["k"]},
            data=post_data
        )

        return re.search(r'"rresp","(.*?)"', response.text).group(1)

class Fanza_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email, password):
        global auth_success, user_id, token
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
        _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
        _CLIENT_ID = "0lvBFN830altTCMZnTYpYPoioUcrhR"
        _CLIENT_SECRET = "WL13ljvW3gJUht8X3u76UwzMxmiFecNT"
        try:
            login_recaptcha_token = Fanza_utils.recaptcha_v3_bypass(
                "https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh"
            )

            querystring = {
                "client_id": _CLIENT_ID,
            }

            headers = {
                "host": "accounts.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "smartphone_app": "DMM-APP",
                "smartphone-app": "DMM-APP",
                "x-requested-with": "com.dmm.app.movieplayer",
                "sec-fetch-site": "none",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }

            response = self.session.get(
                _ENDPOINT_RES, params=querystring, headers=headers
            )
            token_match = re.search(r'name="token" value="([^"]*)"/>', response.text)
            token = token_match.group(1) if token_match else None

            _auth = {
                "token": token,
                "login_id": email,
                "password": password,
                "recaptchaToken": login_recaptcha_token,
                "clientId": _CLIENT_ID,
            }

            response = self.session.post(
                "https://accounts.dmm.com/app/service/login/password/authenticate",
                data=_auth,
                headers=headers,
            )

            if response.text.__contains__("認証エラー"):
                return False, "Authentication failed: Account locked"

            querystring = {
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "from_domain": "accounts",
            }
            headers = {
                "host": "www.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": '"Chromium";v="124", "Android WebView";v="124", "Not-A.Brand";v="99"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Android"',
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.6367.82 Safari/537.36 DMMOpenAuth/6.3.2 movieplayer/4.0.4",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "x-requested-with": "com.dmm.app.movieplayer",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "navigate",
                "sec-fetch-dest": "document",
                "referer": "https://accounts.dmm.com/app/service/login/password/authenticate",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
            }
            redirect_auth_url = self.session.get(
                "https://www.dmm.com/my/-/authorize/",
                allow_redirects=False,
                params=querystring,
                headers=headers,
                cookies={"dmm_app": str(1)},
            ).headers["Location"]

            headers = {
                "authorization": "Basic "
                + base64.b64encode(
                    (_CLIENT_ID + ":" + _CLIENT_SECRET).encode()
                ).decode(),
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; V2338A Build/PQ3B.190801.10101846)",
                "host": "gw.dmmapis.com",
                "connection": "Keep-Alive",
                "accept-encoding": "gzip",
            }

            _auth = {
                "grant_type": "authorization_code",
                "code": redirect_auth_url.replace(
                    "dmmvrplayer://androidstore/auth/?code=", ""
                ),
                "redirect_uri": "dmmvrplayer://androidstore/auth/?",
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )
            token_response_json = token_response.json()["header"]

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                refresh_token = token_response.json()["body"]["refresh_token"]
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "Authorization": "Bearer "
                        + token
                    }
                )
                
            _auth = {
                "grant_type": "exchange_token",
                "access_token": token
            }

            token_response = self.session.post(
                _ENDPOINT_TOKEN, json=_auth, headers=headers
            )

            if token_response_json["result_code"] == 0:
                return (
                    False,
                    f"Authentication failed: {token_response.json()["body"]["reason"]}",
                )
            else:
                token = token_response.json()["body"]["access_token"]
                self.session.headers.update(
                    {
                        "Authorization": "Bearer "
                        + token
                    }
                )
            
            user_info_query = {
                "operationName": "GetServicePlan",
                "variables": {},
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            }
            user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)

            auth_success = True
            user_id = user_info_res.json()["data"]["user"]["id"]
            self.session.headers.update(
                {
                    "x-app-name": "android_2d",
                    "x-app-ver": "v4..0",
                    "x-exploit-id": "uid:"+user_id,
                    "host": "video.digapi.dmm.com",
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip",
                    "user-agent": "okhttp/4.12.0",
                }
            )
            
            session_json = {
                "access_token": token,
                "refresh_token": refresh_token
            }
            
            return True, user_info_res.json()["data"]["user"], session_json
        except Exception as e:
            return False, e, None
    def check_token(self, token):
        _ENDPOINT_CC = "https://api.tv.dmm.com/graphql"
        res = self.session.post(
            _ENDPOINT_CC,
            json={
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            },
            headers={"Authorization": "Bearer "+token},
        )
        if res.status_code == 200:
            if res.json()["data"] != None:
                user_id = res.json()["data"]["user"]["id"]
                #self.session.headers.update({"Authorization": "Bearer "+token})
                #self.session.headers.update({"x-exploit-id": "uid:"+user_id})
                self.session.headers.update({
                    "user-agent": "okhttp/4.12.0",
                    "accept-encoding": "gzip",
                    "accept": "*/*",
                    "connection": "Keep-Alive",
                    "authorization": "Bearer "+token,
                    "x-app-name": "android_2d",
                    "x-app-ver": "v4.0.0",
                    "x-exploit-id": "uid:"+user_id,
                    "host": "video.digapi.dmm.com"
                })
                return True
            else:
                return False
        else:
            return False
        
    def get_title(self):
        res = self.session.get("https://video.digapi.dmm.com/purchased/list/text?limit=100&page=1&order=new&hidden_filter=")
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["list_info"]
            else:
                return False, None
        else:
            return False, None
        
    def get_license_uid(self, user_id):
        res = self.session.post("https://gw.dmmapis.com/connect/v1/issueSessionId", json={"user_id": user_id})
        if res.status_code == 200:
            if res.json() != None:
                return True, res.json()["body"]["unique_id"]
            else:
                return False, None
        else:
            return False, None
        
    def get_license(self, user_id, single, license_uid, secret_key):
        def get_json(params: dict) -> str:
            return json.dumps(params, separators=(",", ":"), ensure_ascii=False)
        def get_hash(data: str, key: str) -> str:
            return hmac.new(
                key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        def set_post_params(message: str, params: dict, appid: str, secret_key: str) -> dict:
            post_data = {}
            post_data["message"] = message
            post_data["appid"] = appid
            json_data = get_json(params)
            post_data["params"] = json_data
            post_data["authkey"] = get_hash(json_data, secret_key)
            return post_data
        
        params = {
            "exploit_id": "uid:"+ user_id,
            "mylibrary_id": str(single["mylibrary_id"]),
            "product_id": single["product_id"],
            "shop_name": "videoa",
            "device": "android",
            "HTTP_SMARTPHONE_APP": "DMM-APP",
            "message": "Digital_Api_Mylibrary.getDetail",
        }
        payload = set_post_params(
            message="Digital_Api_Mylibrary.getDetail",
            params=params,
            appid="android_movieplayer_app",
            secret_key=secret_key,
        )
        
        
        get_select_product_info = self.session.post(
            "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
        ).json()["data"]
        
        
        params = {
            "android_drm": False,
            "bitrate": 0,
            "drm": False,
            "exploit_id": "uid:" + user_id,
            "chrome_cast": False,
            "isTablet": False,
            "licenseUID": license_uid,
            "parent_product_id": get_select_product_info["product_id"],
            "product_id": get_select_product_info["content_id"],
            "secure_url_flag": False,
            "service": "digital",
            "shop": "videoa",
            "smartphone_access": True,
            "transfer_type": "stream",
            "HTTP_USER_AGENT": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
            "device": "android",
            "HTTP_SMARTPHONE_APP": "DMM-APP",
            "message": "Digital_Api_Proxy.getURL",
        }
        payload = set_post_params(
            message="Digital_Api_Proxy.getURL",
            params=params,
            appid="android_movieplayer_app",
            secret_key=secret_key,
        )
        
        
        license_response = self.session.post(
            "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
        ).json()
        return True, license_response, payload