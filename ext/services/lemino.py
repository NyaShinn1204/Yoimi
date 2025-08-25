"""
SERVICE INFO


name: Lemino
require_account: Yes
enable_refresh: No
support_normal: Yes WIP
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://lemino.docomo.ne.jp/contents/xxx
   https://lemino.docomo.ne.jp/search/word/xxx...?crid=xxx
   https://lemino.docomo.ne.jp/contents/xxx (season)
"""

import time
import base64
import string
import secrets
import hashlib
from bs4 import BeautifulSoup

__service_config__ = {
    "service_name": "Lemino",
    "require_account": True,
    "enable_refresh": False,
    "support_normal": False, # WIP, Bruh I cann't check 2fa code.
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger, config):
        self.session = session
        self.logger = logger
        self.config = config
        
        self.default_headers = {
            "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)
    
    def parse_input(self):
        pass
    def parse_input_season(self):
        pass
    
    def authorize(self, email_or_id, password):
        ### define util
        def generate_random_state(length=32):
            """JavaのgenerateRandomState相当: 英数字+ -._~ のランダム文字列"""
            allowed_chars = string.ascii_letters + string.digits + "-._~"
            return ''.join(secrets.choice(allowed_chars) for _ in range(length))
        
        def generate_code_verifier(entropy_bytes=64):
            """JavaのCodeVerifierUtil.generateRandomCodeVerifier相当"""
            if not (32 <= entropy_bytes <= 96):
                raise ValueError("entropy_bytes must be between 32 and 96")
            random_bytes = secrets.token_bytes(entropy_bytes)
            return base64.urlsafe_b64encode(random_bytes).decode('ascii').rstrip('=')
        
        def derive_code_challenge(code_verifier):
            """JavaのderiveCodeVerifierChallenge相当 (SHA-256 → Base64URLエンコード)"""
            sha256_digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
            return base64.urlsafe_b64encode(sha256_digest).decode('ascii').rstrip('=')
        check_url = "https://if.lemino.docomo.ne.jp/check/limit/login"
        login_check = self.session.get(check_url).status_code
        if login_check == 200:
            pass
        else:
            return False, "Login is limited", None, None
        
        client_ids = {
            "https://if.lemino.docomo.ne.jp/check/limit/login": "d00_0372_0001_00",
            "https://stg-if.lemino.docomo.ne.jp/check/limit/login": "d00_0491_0001_00"
        }
        
        client_id = client_ids[check_url]
        
        state = generate_random_state(22)
        nonce = generate_random_state(22)
        code_challenge = derive_code_challenge(generate_code_verifier(64))
        
        querystring = {
            "redirect_uri": "https://rpapl.aif.pub.cilite.docomo.ne.jp/leminoapp",
            "client_id": client_id,
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "scope": "openid accountid_n account_type",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }
        
        get_login_url = self.session.get("https://id.smt.docomo.ne.jp/cgi8/oidc/v2_0/authorize", params=querystring, allow_redirects=False)
        baseauth_url = get_login_url.headers["Location"]
        
        tempsession_id_response = self.session.get(baseauth_url)
        temp_session_id = BeautifulSoup(tempsession_id_response.text, "html.parser").find("input", {"id": "tempSessionId"})["value"]
        
        payload = {
            "operationName":"authenticationIdConfirm",
            "variables":{
                "tempSessionId": temp_session_id,
                "dAccountId": email_or_id
            },
            "query":"mutation authenticationIdConfirm($tempSessionId: String!, $dAccountId: String!) {\n  authenticationIdConfirm(\n    input: {tempSessionId: $tempSessionId, dAccountId: $dAccountId}\n  ) {\n    code\n    errorReason\n    resultData {\n      authList\n      twoStepAuthMethod\n      activationFlg\n      __typename\n    }\n    __typename\n  }\n}"}
        email_check = self.session.post("https://cfg.smt.docomo.ne.jp/aif/pub/flow/v1.0/bff/graphql", json=payload)
        if email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1001":
            if email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "B0001":
               return False, "Wrong Email or ID", None, None
            elif email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00007":
                return False, "User Locked", None, None
            elif email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00008":
                return False, "Force User Locked", None, None
            elif email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00009":
                return False, "Auth User Locked", None, None
        elif email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1000" and email_check.json()["data"]["authenticationIdConfirm"]["resultData"]["twoStepAuthMethod"] != "A4":
            return False, "Require 2fa, and doesn't support! lol!", None, None
        elif email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1000":
            pass
        
        payload = {
            "operationName":"authenticationPwdAuth",
            "variables":{
                "tempSessionId": temp_session_id,
                "dAccountPwd": password
            },
            "query":"mutation authenticationPwdAuth($tempSessionId: String!, $dAccountPwd: String!) {\n  authenticationPwdAuth(\n    input: {tempSessionId: $tempSessionId, dAccountPwd: $dAccountPwd}\n  ) {\n    code\n    errorReason\n    resultData {\n      jwt\n      __typename\n    }\n    __typename\n  }\n}"
        }
        password_check = self.session.post("https://cfg.smt.docomo.ne.jp/aif/pub/flow/v1.0/bff/graphql", json=payload)
        if password_check.json()["data"]["authenticationPwdAuth"]["code"] == "1001":
            if password_check.json()["data"]["authenticationPwdAuth"]["errorReason"] == "A0002":
               return False, "Wrong Password", None, None
            elif password_check.json()["data"]["authenticationPwdAuth"]["errorReason"] == "A0007":
                return False, "User Locked", None, None
            elif password_check.json()["data"]["authenticationPwdAuth"]["errorReason"] == "A0006":
                return False, "Force User Locked", None, None
            elif password_check.json()["data"]["authenticationPwdAuth"]["errorReason"] == "A0005":
                return False, "Auth User Locked", None, None
            elif password_check.json()["data"]["authenticationPwdAuth"]["errorReason"] == "A0004":
                return False, "Temp User Locked", None, None
            
        elif password_check.json()["data"]["authenticationPwdAuth"]["code"] == "1000":
            pass
        
        password_response_return = password_check.json()["data"]["authenticationPwdAuth"]["resultData"]
        if password_response_return == None:
            return False, "Unknown Error", None, None
    def authorize_qr(self):
        status, temp_token = self.get_temp_token()
        
        default_headers = {
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
                            "refresh_token": None,
                            "additional_info": {}
                        }
                        
                        return True, message, True, session_json
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
            "x-service-token": token,
        })
        status, profile = self.get_userinfo()
        return status, profile
    def get_userinfo(self):
        url = "https://if.lemino.docomo.ne.jp/v1/user/userinfo/profile"
                    
        response = self.session.post(url, json={"member": True, "profile": True})
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, None
        
    def show_userinfo(self, user_data):
        profile_id = user_data["profile"]["profile_id"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + id: " + profile_id)
        