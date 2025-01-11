import re
import uuid
import json
import hashlib
import platform

class NHKplus_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email_or_id, password):
        #_ENDPOINT_CC = 'https://cc.unext.jp'
        #_ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        #_ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        #_ENDPOINT_OAUTH = 'https://oauth.unext.jp{pse}'
        #_ENDPOINT_TOKEN = 'https://oauth.unext.jp/oauth2/token'
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
        if not re.fullmatch('[0-9]+', email_or_id):
            if not re.fullmatch(mail_regex, email_or_id):
                return False, "NHK+ require email and password"
            
        def generate_fingerprint():
            # システム情報を収集
            system_info = {
                "os": platform.system(),
                "os_version": platform.version(),
                "architecture": platform.architecture(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "uuid": str(uuid.getnode())
            }
    
            # フィンガープリント生成
            system_info_json = json.dumps(system_info, sort_keys=True)
            fingerprint = hashlib.sha256(system_info_json.encode()).hexdigest()
            return fingerprint
        
        payload = {
            "ORG_ID": "undefined",
            "ID": email_or_id,
            "PWD": password,
            "user-agent": self.session.headers["User-Agent"],
            "PIN_CODE": "undefined",
            "Fingerprint": generate_fingerprint(),
            "lowLevelSessionFlg": "undefined"
        }
        
        login_req = self.session.post("https://login.auth.nhkid.jp/auth/login", data=payload)
        print(login_req.text)
    
        ## 初回リクエストとチャレンジID取得
        #response = self.session.get(
        #    _ENDPOINT_CHALLENG_ID.format(
        #        state=Unext_utils.random_name(43),
        #        nonce=Unext_utils.random_name(43)
        #    )
        #)
        #script_tag = BeautifulSoup(response.text, "lxml").find("script", {"id": "__NEXT_DATA__"})
        #json_data = json.loads(script_tag.string)
        #challenge_id = json_data.get("props", {}).get("challengeId")
    #
        ## 認証
        #payload_ = {
        #    "id": email_or_id,
        #    "password": password,
        #    "challenge_id": challenge_id,
        #    "device_code": "920",
        #    "scope": ["offline", "unext"],
        #}
        #auth_response = self.session.post(_ENDPOINT_RES, json=payload_).json()
        #try:
        #    if auth_response["error_hint"] == "GAW0500003":
        #        return False, "Require Japan VPN, Proxy" 
        #    if auth_response["error_hint"] == "GUN8030006":
        #        return False, 'Wrong Email or password combination'
        #except:
        #    pass
        #
        #_ENDPOINT_OAUTH = _ENDPOINT_OAUTH.format(pse=auth_response.get("post_auth_endpoint"))
    #
        #try:
        #    # OAuth 認証コード取得
        #    code_res = self.session.post(_ENDPOINT_OAUTH, allow_redirects=False)
        #    code_res.raise_for_status()
        #    redirect_oauth_url = code_res.headers.get("Location")
        #    res_code = parse_qs(urlparse(redirect_oauth_url).query).get('code', [None])[0]
        #except requests.exceptions.RequestException as e:
        #    return False, f"Authentication failed: {str(e)}"
    #
        ## トークン取得
        #_auth = {
        #    "code": res_code,
        #    "grant_type": "authorization_code",
        #    "client_id": "unextAndroidApp",
        #    "client_secret": "unextAndroidApp",
        #    "code_verifier": None,
        #    "redirect_uri": "jp.unext://page=oauth_callback"
        #}
        #token_response = self.session.post(_ENDPOINT_TOKEN, data=_auth)
        #if token_response.status_code != 200:
        #    return False, 'Wrong Email or password combination'
    #
        #token_data = token_response.json()
        #self.session.headers.update({'Authorization': 'Bearer ' + token_data.get('access_token')})
    #
        ## ユーザー情報取得
        #user_info_query = {
        #    "operationName": "cosmo_userInfo",
        #    "query": """query cosmo_userInfo {
        #        userInfo {
        #            id
        #            multiAccountId
        #            userPlatformId
        #            userPlatformCode
        #            superUser
        #            age
        #            otherFunctionId
        #            points
        #            hasRegisteredEmail
        #            billingCaution {
        #                title
        #                description
        #                suggestion
        #                linkUrl
        #                __typename
        #            }
        #            blockInfo {
        #                isBlocked
        #                score
        #                __typename
        #            }
        #            siteCode
        #            accountTypeCode
        #            linkedAccountIssuer
        #            isAdultPermitted
        #            needsAdultViewingRights
        #            __typename
        #        }
        #    }"""
        #}
        #user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        #return True, user_info_res.json()["data"]["userInfo"]