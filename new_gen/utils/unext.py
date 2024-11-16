import re
import json
import string
import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

class Unext_utils:
    def random_name(length):
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    def check_single_episode(url):
        if url.__contains__("ED"):
            #if re.match(r"^ED\d{8}$", url):
            #    return True
            #else:
            #    return False
            return True
        else:
            return False
    
class Unext_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email, password):
        _ENDPOINT_CC = 'https://cc.unext.jp'
        _ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        _ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        _ENDPOINT_OAUTH = 'https://oauth.unext.jp{pse}'
        _ENDPOINT_TOKEN = 'https://oauth.unext.jp/oauth2/token'
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.search(mail_regex, email):
            response = self.session.get(_ENDPOINT_CHALLENG_ID.format(state=Unext_utils.random_name(43),nonce=Unext_utils.random_name(43)))
                        
            script_tag = BeautifulSoup(response.text, "html.parser").find("script", {"id": "__NEXT_DATA__"})
            json_data = json.loads(script_tag.string)
            challenge_id = json_data.get("props", {}).get("challengeId")
            
            payload_ = {
                "id": email,
                "password": password,
                "challenge_id": challenge_id,
                "device_code": "920",
                "scope": ["offline", "unext"],
            }
            
            _POST_AUTH_ENDPOINT = self.session.post(_ENDPOINT_RES, json=payload_).json().get("post_auth_endpoint")
            _ENDPOINT_OAUTH = _ENDPOINT_OAUTH.format(pse=_POST_AUTH_ENDPOINT)
        else:
            return False, "Unext require email and password"
        
        try:
            code_res = self.session.post(_ENDPOINT_OAUTH, allow_redirects=False)
            if code_res.status_code > 200:
                redirect_oauth_url = code_res.headers.get("Location")
                parsed_url = urlparse(redirect_oauth_url)
                query_params = parse_qs(parsed_url.query)
                res_code = query_params.get('code', [None])[0]
        except requests.exceptions.ConnectionError:
            return False, "Wrong Email or password combination"
        except Exception as e:
            return False, f"An unexpected error occurred: {str(e)}"
        
        _auth = {
            "code": res_code,
            "grant_type": "authorization_code",
            "client_id": "unextAndroidApp",
            "client_secret": "unextAndroidApp",
            "code_verifier": None,
            "redirect_uri": "jp.unext://page=oauth_callback"
        }
        
        res = self.session.post(_ENDPOINT_TOKEN, data=_auth)
        if res.status_code != 200:
            res_j = res.json()
            return False, 'Wrong Email or password combination'

        res_j = res.json()
        self.session.headers.update({'Authorization': 'Bearer ' + res_j.get('access_token')})
                
        res = self.session.post(_ENDPOINT_CC, json={"operationName":"cosmo_userInfo", "query":"query cosmo_userInfo {\n  userInfo {\n    id\n    multiAccountId\n    userPlatformId\n    userPlatformCode\n    superUser\n    age\n    otherFunctionId\n    points\n    hasRegisteredEmail\n    billingCaution {\n      title\n      description\n      suggestion\n      linkUrl\n      __typename\n    }\n    blockInfo {\n      isBlocked\n      score\n      __typename\n    }\n    siteCode\n    accountTypeCode\n    linkedAccountIssuer\n    isAdultPermitted\n    needsAdultViewingRights\n    __typename\n  }\n}\n"})
        return True, res.json()["data"]["userInfo"]
    
    def get_title_parse_single(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitleEpisodes",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0], "page": 1, "pageSize": 100},
            "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        try:
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_titleEpisodes"] != None:
                metadata_response_single = return_json['data']['webfront_title_titleEpisodes']['episodes']
                for episode in metadata_response_single:
                    if episode['id'] == [match[1] for match in matches1 if match[1]][0]:
                        return True, episode
                return False, None
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_title_parse_all(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitleEpisodes",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0], "page": 1, "pageSize": 100},
            "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        try:
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_titleEpisodes"] != None:
                metadata_response_single = return_json['data']['webfront_title_titleEpisodes']['episodes']
                return True, metadata_response_single
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
    
    def get_title_metadata(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''メタデータを取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0]},
            "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n",
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                return True, return_json["data"]["webfront_title_stage"]
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None