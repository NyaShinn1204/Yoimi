import re
import hmac
import json
import base64
import hashlib
import requests
from bs4 import BeautifulSoup


class Fanza_TV_utils:
    def recaptcha_v3_bypass(anchor_url):
        url_base = "https://www.google.com/recaptcha/"
        post_data = "v={}&reason=q&c={}&k={}&co={}"

        session = requests.Session()
        session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})

        matches = re.findall(r"([api2|enterprise]+)\/anchor\?(.*)", anchor_url)[0]
        url_base += matches[0] + "/"
        params = matches[1]

        res = session.get(url_base + "anchor", params=params)
        token = re.findall(r'"recaptcha-token" value="(.*?)"', res.text)[0]

        params = dict(pair.split("=") for pair in params.split("&"))
        post_data = post_data.format(params["v"], token, params["k"], params["co"])

        res = session.post(
            url_base + "reload", params=f'k={params["k"]}', data=post_data
        )

        answer = re.findall(r'"rresp","(.*?)"', res.text)[0]

        return answer


class Dmm_TV_downloader:
    def __init__(self, session):
        self.session = session

    def authorize(self, email, password):
        global auth_success, user_id, token, _AUTHKEY_SECRET
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = "https://accounts.dmm.com/app/service/login/password"
        _ENDPOINT_TOKEN = "https://gw.dmmapis.com/connect/v1/token"
        _CLIENT_ID = "Ozqufo77TdOALdbSv1OLW3E8I"
        _CLIENT_SECRET = "1WKJioWwERuNG6ThCcMDkNsG8YPiNs6p"
        _AUTHKEY_SECRET = "hp2Y944L"
        try:
            login_recaptcha_token = Fanza_TV_utils.recaptcha_v3_bypass(
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
                return False, "Authorization Error"
            # ok

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

            self.session.headers.update(
                {
                    "x-app-name": "android_2d",
                    "x-app-ver": "v4.0.0",
                    "x-exploit-id": "uid:4OOoRg8Nqkdbzm71",
                    "host": "video.digapi.dmm.com",
                    "connection": "Keep-Alive",
                    "accept-encoding": "gzip",
                    "user-agent": "okhttp/4.12.0",
                }
            )

            user_id = user_info_res.json()["data"]["user"]["id"]
            return True, user_info_res.json()["data"]["user"]
        except Exception as e:
            return False, e

    def check_token(self, token):
        global user_id
        _ENDPOINT_CC = "https://api.tv.dmm.com/graphql"
        res = self.session.post(
            _ENDPOINT_CC,
            json={
                "operationName": "GetServicePlan",
                "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }",
            },
            headers={"Authorization": token},
        )
        if res.status_code == 200:
            if res.json()["data"] != None:
                user_id = res.json()["data"]["user"]["id"]
                return True, res.json()["data"]["user"]
            else:
                return False, "Invalid Token"
        else:
            return False, "Invalid Token"

    def get_all_buyed_item(self):
        res = self.session.get(
            "https://video.digapi.dmm.com/purchased/list/all?latest_mylibrary_id=0&limit=50"
        )
        if res.status_code == 200:
            return True, res.json()
        else:
            return False, "Invalid Token"

    def get_info(self, mylibrary_id, content_id, product_id):

        description_req = requests.get(
            f"https://www.dmm.co.jp/digital/videoa/-/detail/=/cid={content_id}/",
            cookies={"age_check_done": "1"},
        )
        if description_req.status_code == 404:
            description = None
        else:
            script_tag = BeautifulSoup(description_req.context, "lxml").find(
                "script", {"type": "application/ld+json"}
            )

            if script_tag:
                try:
                    json_data = json.loads(script_tag.string)
                    description = json_data.get("description", "No description found")
                except json.JSONDecodeError:
                    description = None
            else:
                description = None

        url = "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp"

        payload_json = (
            '{"exploit_id":"uid:'
            + str(user_id)
            + '","mylibrary_id":'
            + str(mylibrary_id)
            + ',"product_id":"'
            + str(product_id)
            + '","shop_name":"videoa","device":"android","HTTP_SMARTPHONE_APP":"DMM-APP","message":"Digital_Api_Mylibrary.getDetail"}'
        )
        print(payload_json)
        payload = {
            "appid": "android_movieplayer_app",
            "authkey": hmac.new(
                _AUTHKEY_SECRET.encode("utf-8"),
                payload_json.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
            "message": "Digital_Api_Mylibrary.getDetail",
            "params": payload_json,
        }
        headers = {
            "user-agent": "DMMPLAY movie_player (93, 4.0.4) API Level:28 PORTALAPP Android",
            "content-type": "application/x-www-form-urlencoded",
            "host": "www.dmm.com",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
        }

        response = self.session.post(url, data=payload, headers=headers)

        if response.json()["event"] == True:
            return True, [response.json()["data"], description]
        else:
            return False, [response.json(), description]


test = Dmm_TV_downloader(requests.Session())

status, message = test.authorize("", "")
print(status, message)

status, message = test.get_all_buyed_item()
print(status, message["content_total"])

for single_ep in message["list"]:
    # print(single_ep)
    status, episode_info = test.get_info(
        single_ep["mylibrary_id"], single_ep["content_id"], single_ep["product_id"]
    )
    # print(status)
    print(episode_info[0]["title"])
    print(episode_info[1])
    # exit(1)
