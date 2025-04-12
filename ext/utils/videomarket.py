import re

class VideoMarket_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
        self.tv_headers = {
            "accept": "multipart/mixed; deferSpec=20220824, application/json",
            "app-version": "tv.4.1.14",
            "content-type": "application/json",
            "host": "bff.videomarket.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/4.12.0"
        }
        self.hd_headers = {
            "accept": "application/json",
            "vm-device-info": "{\"model\":\"AOSP TV on x86\",\"deviceCode\":\"generic_x86_arm\",\"brand\":\"google\",\"platform\":\"Android TV OS\",\"platformVer\":\"13\",\"sdkVer\":33,\"hdcpVer\":1}",
            "vm-app-info": "{\"ver\":\"tv.4.1.14\"}",
            "vm-codec-info": "{\"isHdr\":false,\"isDdp\":false,\"isAtmos\":false,\"isUhd\":false,\"isHevc\":false}", # false...? trueだとなぜか最初のリクエストが飛ばない。謎
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 13; AOSP TV on x86 Build/TTT5.221206.003)",
            "host": "pf-api.videomarket.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
    def authorize(self, email, password):
        _ENDPOINT_CC = 'https://bff.videomarket.jp/graphql'
        
        status, message, temp_id_token, temp_refresh_token = self.get_temp_token()
        
        payload = {
          "id_token": temp_id_token,
          "password": password,
          "login_id": email
        }
        
        response = self.session.post("https://www.videomarket.jp/login", json=payload)
        
        if response.status_code == 200:
            pass
        elif response.status_code == 401:
            return False, 'Wrong Email or password combination'
        
        auth_response = response.json()
        self.session.headers.update({"Authorization": "Bearer "+auth_response["id_token"]})
        
        user_info_query = {
            "query": "{     user {       isTester       userId       email     }   }"
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["user"]
    def get_temp_token(self):
        _ENDPOINT_CC = 'https://bff.videomarket.jp/graphql'
        _AUTH_DEVICE_URL = "https://auth.videomarket.jp/v1/authorize/device"
        
        payload = {
            "api_key": "43510DE69546794606805E74F797CA84FB8C0938",
            "site_type": 7 # 3 = android, 7 = androidTV
        }    
        headers = {
            "user-agent": "okhttp/4.12.0",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "host": "auth.videomarket.jp"
        }
        
        response = self.session.post(_AUTH_DEVICE_URL, json=payload, headers=headers)
        
        id_token = response.json()["id_token"]
        refrest_token = response.json()["refresh_token"]
        self.session.headers.update({"Authorization": "Bearer "+id_token})
        user_info_query = {
            "query": "{     user {       isTester       userId       email     }   }"
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["user"], id_token, refrest_token
    
    def check_single(self, url):
        pattern = r"https://www\.videomarket\.jp/(player|title)/[A-Z0-9]+/[A-Z0-9]+"
        return bool(re.match(pattern, url))
    
    def get_title_parse_all(self, url):
        match = re.match(r"https://www\.videomarket\.jp/(player|title)/([A-Z0-9]+)", url)
        title_id = match.group(2)
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "Title",
            "variables": {
                "fullTitleId": title_id,
                "limit": 1000
            },
           "query": "query Title($fullTitleId: String!, $limit: Int!) { title(fullTitleId: $fullTitleId, limit: $limit) { titleSummary { __typename ...titleSummary } titleDetail { copyright introduction outline highlight rating subtitleDubType year countries audioType isFavorite isDolbyVision } casts { castId castName roleName additionalInformation } staff { staffName staffRole } series { seriesId seriesName } repPacks { __typename ...repPack } genres { __typename ...genre } contentId } relatedTitleSummaries(fullTitleId: $fullTitleId, limit: $limit) { __typename ...titleSummary } quickPlay(fullTitleId: $fullTitleId) { __typename ...repPack } user { userId } }  fragment titleSummary on TitleSummary { fullTitleId titleName titleImageUrl16x9 courseIds hasFreePack hasEstPack hasDownloadablePack isCouponTarget couponDiscountRate }  fragment story on Story { fullStoryId subtitleDubType encodeVersion isDownloadable isBonusMaterial }  fragment repPack on RepPack { repFullPackId groupType packName fullTitleId titleName storyImageUrl16x9 playTime subtitleDubType outlines courseIds price couponPrice couponDiscountRate discountRate rentalDays viewDays deliveryExpiredAt salesType status { hasBeenPlayed isCourseRegistered isEstPurchased isNowPlaying isPlayable isRented playExpiredAt playableQualityType rentalExpiredAt } packs { canPurchase fullPackId subGroupType fullTitleId qualityConsentType courseIds price couponPrice discountRate couponDiscountRate rentalDays viewDays deliveryExpiredAt salesType stories { __typename ...story } } }  fragment genre on Genre { genreId genreName }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["title"] != None:
                id_type = []
                for single_genre in return_json['data']['title']['genres']:
                    id_type.append(single_genre["genreName"])
                metadata_response_single = return_json['data']['title']['repPacks']
                return True, metadata_response_single, id_type, return_json['data']['title']['titleSummary']
            else:
                return False, None, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
    def get_playing_access_token(self):
        '''Playing Access Tokenを取得するコード'''
        meta_json = {
            "operationName": "PlayingAccessToken",
            "variables": {},
            "query": "query PlayingAccessToken { playingAccessToken }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json, headers=self.tv_headers)
            return_json = metadata_response.json()
            if return_json["data"]["playingAccessToken"] != None:
                return True, return_json['data']['playingAccessToken']
            else:
                return False, None
        except Exception as e:
            print(e)
            return False
        
    def get_playing_token(self, story_id, pack_id, access_token):
        '''Playing Tokenを取得するコード'''
        meta_json = {
            "operationName": "PlayingToken",
            "variables": {
                "fullStoryId": story_id,
                "fullPackId": pack_id,
                "qualityType": 3,
                "token": access_token
            },
            "query": "query PlayingToken($fullStoryId: String!, $fullPackId: String!, $qualityType: Int!, $token: String!) { playingToken(fullStoryId: $fullStoryId, fullPackId: $fullPackId, qualityType: $qualityType, token: $token) }"
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json, headers=self.tv_headers)
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json['data']['playingToken']
            else:
                return False, None
        except Exception as e:
            print(e)
            return False
        
    def get_streaming_info(self, story_id, play_token, user_id):
        '''該当エピソードのメディアデータを取得するコード'''
        meta_json = {
            "userId": user_id,
            "playToken": play_token,
            "fullStoryId": story_id
        }
        try:
            metadata_response = self.session.post("https://bff.videomarket.jp/graphql", json=meta_json, headers=self.hd_headers)
            return_json = metadata_response.json()
            if return_json != None:
                return True, return_json
            else:
                return False, None
        except Exception as e:
            print(e)
            return False