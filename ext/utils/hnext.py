import uuid
import time
class Hnext_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        
        self.session.headers.update({
            "connection": "keep-alive",
            "pragma": "no-cache",
            "cache-control": "no-cache",
            "baggage": "sentry-environment=prod-react,sentry-release=v105.0-2-gca2628b65,sentry-public_key=d46f18dd0cfb4b0cb210f8e67c535fe1,sentry-trace_id=730f3eadd3e747068f37c996e66e8635,sentry-sample_rate=0.0001,sentry-transaction=%2Flogin%2Fnormal,sentry-sampled=false",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 japanview/1.0.6",
            "content-type": "application/json",
            "accept": "*/*",
            "x-requested-with": "com.japan_view",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate",
            "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        })
    def authorize(self, email_or_id, password):
        _ENDPOINT_LOGIN = "https://tvh.unext.jp/api/1/login"
        
        payload = {
            "login_id": email_or_id,
            "password": password
        }
        
        response = self.session.post(_ENDPOINT_LOGIN, json=payload)
        
        user_response = response.json()
        
        if user_response["common"]["result"]["errorCode"] == "":
            session_json = {
                "method": "LOGIN",
                "email": email_or_id,
                "password": password,
                "access_token": response.cookies["_ut"],
                "refresh_token": None
            }
            return True, user_response["common"]["userInfo"], True, session_json
        elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
            return False, 'Wrong Email or password', False, None
        elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
            return False, 'Require Japan VPN, Proxy', False, None
    def authorize_qr(self):
        _ENDPOINT_CC = "https://cc.unext.jp/"
        _ENDPOINT_LOGIN = "https://tvh.unext.jp/api/1/login"
        
        payload = {
            "operationName": "tvh_loginDelegationCreateSession",
            "query": "mutation tvh_loginDelegationCreateSession($appVersion: String!, $deviceName: String!, $deviceType: String!, $deviceUuid: String!, $location: String!) {\n  loginDelegationCreateSession(\n    appVersion: $appVersion\n    deviceName: $deviceName\n    deviceType: $deviceType\n    deviceUuid: $deviceUuid\n    location: $location\n  ) {\n    code\n    authPageUrlTemplate\n    sessionId\n    __typename\n  }\n}",
            "variables": {
                "appVersion": "",
                "deviceName": "Yoimi",
                "deviceType": "1210",
                "deviceUuid": str(uuid.uuid4()),
                "location": "tokyo"
            }
        }
        
        response = self.session.post(_ENDPOINT_CC, json=payload)
        get_qr_link = response.json()
        
        session_check_data = {
            "operationName": "tvh_loginDelegationPollSession",
            "query": "query tvh_loginDelegationPollSession($code: String!, $sessionId: String!) {\n  loginDelegationPollSession(code: $code, sessionId: $sessionId) {\n    oneTimeToken\n    __typename\n  }\n}",
            "variables": {
              "code": get_qr_link["data"]["loginDelegationCreateSession"]["code"],
              "sessionId": get_qr_link["data"]["loginDelegationCreateSession"]["sessionId"]
            }
        }
        
        print("Login URL:", get_qr_link["data"]["loginDelegationCreateSession"]["authPageUrlTemplate"])
        print("Code:", get_qr_link["data"]["loginDelegationCreateSession"]["code"])
        
        while True:
            send_checkping = self.session.post(f"https://cc.unext.jp/", json=session_check_data)
            if send_checkping.json()["data"]["loginDelegationPollSession"] == None:
                print("Waiting Login...")
                time.sleep(5)
            else:
                print("Login Accept")
                
                one_time_token = send_checkping.json()["data"]["loginDelegationPollSession"]["oneTimeToken"]
                
                payload = {
                    "oneTimeToken": one_time_token,
                }
                
                response = self.session.post(_ENDPOINT_LOGIN, json=payload)
                
                user_response = response.json()
                
                session_json = {
                    "method": "QR_LOGIN",
                    "email": None,
                    "password": None,
                    "access_token": response.cookies["_ut"],
                    "refresh_token": None
                }
                
                return True, user_response["common"]["userInfo"], True, session_json
            
    def check_token(self, token):
        self.session.cookies.set('_ut', token)
        
        token_check = self.session.get("https://tvh.unext.jp/api/1/adult/mylist/list?page_number=1").json()
        
        if token_check["common"]["result"]["errorCode"] == "GAN9900010":
            return False, None
        else:
            return True, token_check["common"]["userInfo"]
        
        
    def get_content_info(self, aid):
        try:
            url = "https://tvh.unext.jp/api/1/adult/titleDetail"
            queryparams = {"title_code": aid}
            
            content_info = self.session.get(url, params=queryparams)
            content_json = content_info.json()["data"]["title"]
            return content_json
        except:
            return None
    def get_mpd_info(self, aed_id):
        querystring = {
            "code": aed_id,
            "keyonly_flg": "0",
            "play_mode": "caption",
            "media_type": "ADULT"
        }
        
        response = self.session.get("https://tvh.unext.jp/api/1/playlisturl", params=querystring).json()
        if response["data"]["result_status"] == 476:
            raise Exception("Require rental/buy")
        if response["data"]["result_status"] == 475:
            raise Exception("Require subscription (H-Next)")
        elif response["data"]["result_status"] == 200:
            play_token = response["data"]["play_token"]
            url_info = response["data"]["url_info"][0]
            return play_token, url_info
        
    def send_stop_signal(self, media_code, play_token):
        signal_result = self.session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/0/?play_token={play_token}&last_viewing_flg=0")
        
        if signal_result.status_code == 200:
            return True
        else:
            return False