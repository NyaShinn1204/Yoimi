import re
import base64
import requests
from urllib.parse import urlparse, parse_qs

class Dmm_TV_utils:
    def recaptcha_v3_bypass(anchor_url):
        url_base = 'https://www.google.com/recaptcha/'
        post_data = "v={}&reason=q&c={}&k={}&co={}"
        
        session = requests.Session()
        session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        
        matches = re.findall(r'([api2|enterprise]+)\/anchor\?(.*)', anchor_url)[0]
        url_base += matches[0]+'/'
        params = matches[1]
        
        res = session.get(url_base+'anchor', params=params)
        token = re.findall(r'"recaptcha-token" value="(.*?)"', res.text)[0]
        
        params = dict(pair.split('=') for pair in params.split('&'))
        post_data = post_data.format(params["v"], token, params["k"], params["co"])
        
        res = session.post(url_base+'reload', params=f'k={params["k"]}', data=post_data)
        
        answer = re.findall(r'"rresp","(.*?)"', res.text)[0]
        
        return answer
    def parse_url(url):
        # 正規表現で 'season' と 'content' を抽出
        season_match = re.search(r"season=([^&/]+)", url)
        content_match = re.search(r"content=([^&/]+)", url)
    
        # 値を取得、存在しない場合は None
        season = season_match.group(1) if season_match else None
        content = content_match.group(1) if content_match else None
    
        # 'season' の存在でステータスを決定
        status = bool(season)
    
        return status, season, content
    
class Dmm_TV__license:
    def license_vd_ad(video_pssh, audio_pssh, playtoken, session):
        _WVPROXY = "https://mlic.dmm.com/drm/widevine/license"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id_video = cdm.open()
        session_id_audio = cdm.open()
        
        headers = {
            "Origin": "https://tv.dmm.com/",
            "Referer": "https://tv.dmm.com/",
            "Host": "mlic.dmm.com"   
        }
        
        challenge_video = cdm.get_license_challenge(session_id_video, PSSH(video_pssh))
        challenge_audio = cdm.get_license_challenge(session_id_audio, PSSH(audio_pssh))
        response_video = session.post(f"{_WVPROXY}?play_token={playtoken}", data=challenge_video, headers=headers)    
        response_video.raise_for_status()
        response_audio = session.post(f"{_WVPROXY}?play_token={playtoken}", data=challenge_audio, headers=headers)    
        response_audio.raise_for_status()
    
        cdm.parse_license(session_id_video, response_video.content)
        cdm.parse_license(session_id_audio, response_audio.content)
        video_keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id_video)
        ]
        audio_keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id_audio)
        ]
    
        cdm.close(session_id_video)
        cdm.close(session_id_audio)
        
        keys = {
            "video_key": video_keys,
            "audio_key": audio_keys
        }
        
        return keys

class Dmm_TV_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email, password):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = 'https://accounts.dmm.com/app/service/login/password'
        _ENDPOINT_TOKEN = 'https://gw.dmmapis.com/connect/v1/token'
        _CLIENT_ID = 'S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi'
        _CLIENT_SECRET = 'zEq95QPlzmugWhHKayXK2hcGS5z8DYwP'
                
        login_recaptcha_token = Dmm_TV_utils.recaptcha_v3_bypass("https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh")
                
        querystring = {
            "client_id": _CLIENT_ID,
            "parts": ["regist", "snslogin", "darkmode"]
        }
        
        headers = {
            "host": "accounts.dmm.com",
            "connection": "keep-alive",
            "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Android\"",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        
        response = self.session.get(_ENDPOINT_RES, params=querystring, headers=headers)
        token_match = re.search(r'name="token" value="([^"]*)"/>', response.text)
        token = token_match.group(1) if token_match else None

        _auth = {
            "token": token,
            "login_id": email,
            "password": password,
            "use_auto_login": "1",
            "recaptchaToken": login_recaptcha_token,
            "clientId": _CLIENT_ID,
            "parts": ["regist", "snslogin", "darkmode"]
        }

        response = self.session.post("https://accounts.dmm.com/app/service/login/password/authenticate", data=_auth, allow_redirects=False)
        redirect_auth_url = self.session.get(response.text, allow_redirects=False).headers.get("Location")
        
        headers = {
            "authorization": "Basic "+base64.b64encode((_CLIENT_ID + ":" + _CLIENT_SECRET).encode()).decode(),
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; V2338A Build/PQ3B.190801.10101846)",
            "host": "gw.dmmapis.com",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        
        _auth = {
            "grant_type": "authorization_code",
            "code": redirect_auth_url.replace("dmmtv://android/auth/?code=", ""),
            "redirect_uri": "dmmtv://android/auth/"
        }
                
        token_response = self.session.post(_ENDPOINT_TOKEN, json=_auth, headers=headers)
        token_response_json = token_response.json()["header"]
        
        if token_response_json["result_code"] == 0:
            return False, f"Authentication failed: {token_response.json()["body"]["reason"]}"
        else:
            self.session.headers.update({'Authorization': 'Bearer ' + token_response.json()["body"]["access_token"]})

        user_info_query = {
          "operationName": "GetServicePlan",
          "variables": {},
          "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }"
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["user"]
    
    def check_token(self, token):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        res = self.session.post(_ENDPOINT_CC, json={"operationName":"GetServicePlan", "query":"query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }"})
        if res.status_code == 200:
            if res.json()["data"] != None:
                return True, res.json()["data"]["user"]
            else:
                return False, "Invalid Token"
        else:
            return False, "Invalid Token"
        
    def check_free(self, sessionid, contentid=None):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        if contentid != None:
            res = self.session.post(_ENDPOINT_CC, json={"operationName":"FetchStream","variables":{"id":f"{contentid}","protectionCapabilities":[{"systemId":"edef8ba9-79d6-4ace-a3c8-27dcd51d21ed","format":"DASH","audio":[{"codec":"AAC"}],"video":[{"codec":"AV1","bpc":10,"rate":497664000,"yuv444p":True},{"codec":"VP9","bpc":10,"rate":497664000},{"codec":"AVC","bpc":8,"rate":497664000}],"hdcp":"V2_2"}],"audioChannelLayouts":["STEREO"],"device":"BROWSER","http":False},"query":"query FetchStream($id: ID!, $part: Int, $protectionCapabilities: [ProtectionCapability!]!, $audioChannelLayouts: [StreamingAudioChannelLayout!]!, $device: PlayDevice!, $http: Boolean, $temporaryDownload: Boolean) {\n  stream(\n    id: $id\n    part: $part\n    protectionCapabilities: $protectionCapabilities\n    audioChannelLayouts: $audioChannelLayouts\n    device: $device\n    http: $http\n    temporaryDownload: $temporaryDownload\n  ) {\n    contentTypeDetail\n    purchasedProductId\n    qualities {\n      name\n      displayName\n      __typename\n    }\n    textRenditionType\n    languages {\n      lang\n      displayName\n      __typename\n    }\n    videoRenditions {\n      lang\n      qualityName\n      streamingUrls {\n        systemIds\n        videoCodec\n        format\n        bpc\n        streamSize\n        urls\n        hdcp\n        __typename\n      }\n      __typename\n    }\n    audioRenditions {\n      lang\n      audioChannels\n      audioChannelLayout\n      __typename\n    }\n    textRenditions {\n      lang\n      __typename\n    }\n    chapter {\n      op {\n        start\n        end\n        __typename\n      }\n      ed {\n        start\n        end\n        __typename\n      }\n      skippable {\n        start\n        end\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"})
            if res.status_code == 200:
                if res.json()["data"] != None:
                    if res.json()["data"]["stream"]["contentTypeDetail"] == "VOD_FREE":
                        return "true"
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            res = self.session.post(_ENDPOINT_CC, json={"operationName":"FetchVideoEpisodes","variables":{"seasonId":f"{sessionid}","playDevice":"BROWSER","isLoggedIn":False,"type":"MAIN","first":16},"query":"query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n"})
            result_list = []
            if res.status_code == 200:
                if res.json()["data"]["video"]["episodes"]["edges"] != None:
                    for episode in res.json()["data"]["video"]["episodes"]["edges"]:
                        if episode["node"]["freeProduct"] != None:
                            result_list.append("true")
                        else:
                            result_list.append("false")
                            
                    return result_list
                else:
                    return False
            else:
                return False
            
    def get_title_metadata(self, sessionid):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "GetSeason",
            "variables": {
                "id": sessionid,
                "abSplitId": "detail_pv",
                "episodesSize": 20,
                "playDevice": "ANDROID_MOBILE",
                "withAuth": False
            },
            "query": "query GetSeason($id: ID!, $abSplitId: ID!, $episodesSize: Int, $playDevice: PlayDevice!, $withAuth: Boolean!) { abSplit(abSplitId: $abSplitId) @include(if: $withAuth) { abGroup } firstView: video(id: $id) { __typename id seasonType ... on VideoSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag highlight keyVisualImage keyVisualWithoutLogoImage relatedSeasons { __typename ...videoRelatedSeasonFragment } nextDeliveryEpisode { isBeforeDelivered startDeliveryAt } svodEndDeliveryAt continueWatching @include(if: $withAuth) { id content { __typename ...videoContentFragment } } priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoStageSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag keyVisualImage keyVisualWithoutLogoImage priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoSpotLiveSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag spotLiveDescription: description keyVisualImage keyVisualWithoutLogoImage } } tab: video(id: $id) { __typename id ... on VideoSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } episodes: episodes(type: MAIN, first: $episodesSize) { total edges { node { __typename ...mainEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { total edges { node { __typename ...specialEpisodeFragment } } } } ... on VideoStageSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } purchasedStageContents @include(if: $withAuth) { purchasedContentsByPerformanceDate { performanceDate contents { __typename ...purchaseEpisodeFragment } } } allPerformances { __typename ...stagePerformanceFragment } } ... on VideoSpotLiveSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } episodes: episodes(type: MAIN, first: $episodesSize) { edges { node { __typename ...mainEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { edges { node { __typename ...specialEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } } } }  fragment videoRatingFragment on VideoRating { category name }  fragment videoCampaignFragment on VideoCampaign { id name endAt isLimitedPremium }  fragment videoRelatedSeasonFragment on VideoRelatedSeason { id title video { __typename id seasonType ... on VideoSeason { id keyVisualImage keyVisualWithoutLogoImage } } }  fragment VideoPPVExpirationFragment on VideoPPVExpiration { expirationType viewingExpiration viewingStartExpiration startDeliveryAt }  fragment videoPriceSummaryFragment on VideoPriceSummary { campaignId highestPrice lowestPrice discountedHighestPrice discountedLowestPrice isLimitedPremium }  fragment videoViewingExpirationFragment on VideoViewingExpiration { __typename ... on VideoFixedViewingExpiration { expiresAt } ... on VideoLegacyViewingExpiration { expireDay } ... on VideoRentalViewingExpiration { startLimitDay expireDay expireHour } }  fragment videoPPVBundleProductSummaryFragment on VideoPPVProduct { id contentId contentType saleType isPreOrder saleUnitName episodeTitle episodeNumberName viewingExpiration { __typename ...videoViewingExpirationFragment } startDeliveryAt isBeingDelivered }  fragment videoPPVProductPriceFragment on VideoPPVProductPrice { price salePrice isLimitedPremium }  fragment videoPPVProductSummaryFragment on VideoPPVProduct { id contentId contentType contentPriority saleUnitPriority saleUnitName episodeTitle episodeNumberName saleType isPreOrder isPurchased @include(if: $withAuth) isBundleParent bundleProducts { __typename ...videoPPVBundleProductSummaryFragment } price { __typename ...videoPPVProductPriceFragment } viewingExpiration { __typename ...videoViewingExpirationFragment } isOnSale startDeliveryAt isBeingDelivered campaign { __typename ...videoCampaignFragment } hasGoods }  fragment videoFreeProductFragment on VideoFreeProduct { contentId startDeliveryAt endDeliveryAt isBeingDelivered }  fragment videoSVODProductFragment on VideoSVODProduct { contentId startDeliveryAt isBeingDelivered }  fragment videoViewingRightsFragment on VideoViewingRights { isStreamable isDownloadable contentType }  fragment videoPartFragment on VideoPart { contentId number duration resume @include(if: $withAuth) { point isCompleted } }  fragment videoPlayInfoSummaryFragment on VideoPlayInfo { contentId tags highestQuality highestAudioChannelLayout audioRenditions textRenditions isSupportHDR duration parts { __typename ...videoPartFragment } }  fragment videoContentFragment on VideoContent { id seasonId episodeType contentType episodeImage episodeTitle episodeDetail episodeNumber episodeNumberName ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } priceSummary { __typename ...videoPriceSummaryFragment } ppvProducts { __typename ...videoPPVProductSummaryFragment } freeProduct { __typename ...videoFreeProductFragment } svodProduct { __typename ...videoSVODProductFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } playInfo { __typename ...videoPlayInfoSummaryFragment } sampleMovie startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment personFragment on Person { id name }  fragment castFragment on Cast { id castName actorName priority person { __typename ...personFragment } }  fragment staffFragment on Staff { id roleName staffName priority person { __typename ...personFragment } }  fragment videoGenreFragment on VideoGenre { id name }  fragment reviewSummaryFragment on ReviewSummary { reviewerCount reviewCommentCount }  fragment reviewFragment on Review { id reviewerName reviewerId title point hasSpoiler comment date postEvaluationCount helpfulVoteCount isReviewerPurchased }  fragment purchaseEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } audioRenditions textRenditions } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration { __typename ...VideoPPVExpirationFragment } ppvProducts { id contentId isBeingDelivered isPurchased @include(if: $withAuth) startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment mainEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration audioRenditions textRenditions tags parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered isAllowDownload }  fragment pvEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeTitle episodeDetail episodeType contentType playInfo { duration } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } sampleMovie }  fragment specialEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered }  fragment stagePerformanceFragment on VideoStagePerformance { performanceDate contents { id episodeTitle ppvProducts { __typename id ...videoPPVProductSummaryFragment } } }"
        }
        try:
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["firstView"] != None:
                metadata_response_single = return_json["data"]["firstView"]
                return True, metadata_response_single
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None          
    def get_title_parse_all(self, sessionid):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "FetchVideoEpisodes",
            "variables":{"seasonId":f"{sessionid}","playDevice":"BROWSER","isLoggedIn":False,"type":"MAIN","first":16},
            "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
        }
        try:
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if return_json.json()["data"]["video"]["episodes"]["edges"] != None:
                metadata_response_single = return_json["data"]["video"]["episodes"]["edges"]
                return True, metadata_response_single
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_id_type(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''映像タイプを取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0]},
            "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      id\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n"
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                maybe_genre = None
                                
                if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"] == "再生":
                    maybe_genre = "劇場"
                if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("第") or return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("#"):
                    maybe_genre = "ノーマルアニメ"
                else:
                    maybe_genre = "劇場"
                
                return True, [return_json["data"]["webfront_title_stage"]["mainGenreId"], return_json["data"]["webfront_title_stage"]["mainGenreName"], maybe_genre]
            else:
                return False, None
        except Exception as e:
            print("aiueo"+e)
            return False, None