import uuid

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
        
        session_json = {
            "method": "LOGIN",
            "email": email_or_id,
            "password": password,
            "access_token": response.cookies["_ut"],
            "refresh_token": None
        }
        
        if user_response["common"]["result"]["errorCode"] == "":
            return True, user_response["common"]["userInfo"], True, session_json
        elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
            return False, 'Require Japan VPN, Proxy', False, None
        elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
            return False, 'Wrong Email or password', False, None
    
    def authorize_qr(self):
        _ENDPOINT_CC = "https://cc.unext.jp/"
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
        
        get_qr_link["data"]["loginDelegationCreateSession"]["authPageUrlTemplate"]
        get_qr_link["data"]["loginDelegationCreateSession"]["code"]
        get_qr_link["data"]["loginDelegationCreateSession"]["sessionId"]