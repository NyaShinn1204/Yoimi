"""
SERVICE INFO


name: Lemino
require_account: Yes
enable_refresh: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://lemino.docomo.ne.jp/contents/xxx
   https://lemino.docomo.ne.jp/search/word/xxx...?crid=xxx
   https://lemino.docomo.ne.jp/contents/xxx (season)
"""

import base64
import string
import secrets
import hashlib
from bs4 import BeautifulSoup

__service_config__ = {
    "service_name": "Lemino",
    "require_account": True,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
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
                "tempSessionId":temp_session_id,
                "dAccountId": email_or_id
            },
            "query":"mutation authenticationIdConfirm($tempSessionId: String!, $dAccountId: String!) {\n  authenticationIdConfirm(\n    input: {tempSessionId: $tempSessionId, dAccountId: $dAccountId}\n  ) {\n    code\n    errorReason\n    resultData {\n      authList\n      twoStepAuthMethod\n      activationFlg\n      __typename\n    }\n    __typename\n  }\n}"}
        email_check = self.session.post("https://cfg.smt.docomo.ne.jp/aif/pub/flow/v1.0/bff/graphql", json=payload)
        if email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1001":
            if email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "B0001":
               return False, "Wrong Email or ID", None, None
            if email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00007":
                return False, "User Locked", None, None
            elif email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00008":
                return False, "Force User Locked", None, None
            elif email_check.json()["data"]["authenticationIdConfirm"]["errorReason"] == "00009":
                return False, "Auth User Locked", None, None
        if email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1000" and email_check.json()["data"]["authenticationIdConfirm"]["resultData"]["twoStepAuthMethod"] != "A4":
            return False, "Require 2fa, and doesn't support! lol!", None, None
        if email_check.json()["data"]["authenticationIdConfirm"]["code"] == "1000":
            pass