import re
import os
import time
import base64
import requests
import threading
import subprocess
from tqdm import tqdm
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from concurrent.futures import ThreadPoolExecutor, as_completed

import ext.global_func.util.decrypt_subtitle as sub_decrypt

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class DMM_TV_decrypt:
    def mp4decrypt(keys, config):
        if os.name == 'nt':
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
        for key in keys:
            if key["type"] == "CONTENT":
                mp4decrypt_command.extend(
                    [
                        "--show-progress",
                        "--key",
                        "{}:{}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return mp4decrypt_command
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Dmm-TV"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            DMM_TV_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            DMM_TV_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Dmm-TV"):
        mp4decrypt_command = DMM_TV_decrypt.mp4decrypt(keys, config)
        mp4decrypt_command.extend([input_file, output_file])
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
            with subprocess.Popen(mp4decrypt_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:
                for line in process.stdout:
                    match = re.search(r"(ｲ+)", line)  # 進捗解析
                    if match:
                        progress_count = len(match.group(1))
                        inner_pbar.n = progress_count
                        inner_pbar.refresh()
                
                process.wait()
                if process.returncode == 0:
                    inner_pbar.n = 100
                    inner_pbar.refresh()

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
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
    
        season = query.get('season', [None])[0]
        content = query.get('content', [None])[0]
        status = bool(season)
            
        return status, season, content

class Dmm_TV__license:
    def license_vd_ad(pssh, session, config):        
        _WVPROXY = "https://mlic.dmm.com/drm/widevine/license"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        
        headers = {
            "content-type": "application/octet-stream",
            "user-agent": "Android/33 AOSP TV on x86 com.dmm.app.androidtv/2.34.0",
            "host": "mlic.dmm.com",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers=headers)
        response.raise_for_status()
    
        cdm.parse_license(session_id, response.content)
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]
    
        cdm.close(session_id)
                
        keys = {
            "key": keys,
        }
        
        return keys


class Dmm_TV_downloader:
    def __init__(self, session):
        self.session = session
        self.auth_success = False
    def authorize(self, email, password):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        _ENDPOINT_RES = 'https://accounts.dmm.com/app/service/login/password'
        _ENDPOINT_TOKEN = 'https://gw.dmmapis.com/connect/v1/token'
        _CLIENT_ID = 'S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi'
        _CLIENT_SECRET = 'zEq95QPlzmugWhHKayXK2hcGS5z8DYwP'
        try:
            login_recaptcha_token = Dmm_TV_utils.recaptcha_v3_bypass("https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh")
                    
            querystring = {
                "client_id": _CLIENT_ID,
                "parts": ["regist", "snslogin", "darkmode"]
            }
            
            headers = {
                "host": "accounts.dmm.com",
                "connection": "keep-alive",
                "cache-control": "max-age=0",
                "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Android\"",
                "upgrade-insecure-requests": "1",
                "origin": "https://accounts.dmm.com",
                "content-type": "application/x-www-form-urlencoded",
                "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "navigate",
                "sec-fetch-user": "?1",
                "sec-fetch-dest": "document",
                "referer": f"https://accounts.dmm.com/app/service/login/password?client_id={_CLIENT_ID}&parts=regist&parts=snslogin&parts=darkmode",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"
            }
            
            response = self.session.get(_ENDPOINT_RES, params=querystring, headers=headers)
            token_match = re.search(r'name="token" value="([^"]*)"/>', response.text)
            token = token_match.group(1) if token_match else None
    
            _auth = {
                "token": token,
                "login_id": email,
                "password": password,
                "recaptchaToken": login_recaptcha_token,
                "clientId": _CLIENT_ID,
                "parts": ["regist", "snslogin", "darkmode"]
            }
    
            response = self.session.post("https://accounts.dmm.com/app/service/login/password/authenticate", data=_auth, headers=headers)
            querystring = {
                "parts[]": ["regist", "snslogin", "darkmode"],
                "response_type": "code",
                "client_id": _CLIENT_ID,
                "from_domain": "accounts"
            }
            headers = {
                "host": "www.dmm.com",
                "connection": "keep-alive",
                "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": "\"Android\"",
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "sec-fetch-site": "same-site",
                "sec-fetch-mode": "navigate",
                "sec-fetch-dest": "document",
                "referer": "https://accounts.dmm.com/app/service/login/password/authenticate",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"
            }
            redirect_auth_url = self.session.get("https://www.dmm.com/my/-/authorize", allow_redirects=False, params=querystring, headers=headers).headers.get("Location")
            
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
                self.auth_success = False
                return False, f"Authentication failed: {token_response.json()["body"]["reason"]}"
            else:
                self.session.headers.update({'Authorization': 'Bearer ' + token_response.json()["body"]["access_token"]})
    
            user_info_query = {
              "operationName": "GetServicePlan",
              "variables": {},
              "query": "query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }"
            }
            user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
            get_profile_id_query = {
              "operationName": "GetProfileList",
              "variables": {},
              "query": "query GetProfileList { user { id profiles { __typename ...profileFragment } } }  fragment profileIconFragment on ProfileIcon { id url }  fragment profileFragment on Profile { id name profileIcon { __typename ...profileIconFragment } isParent viewableRating canPurchase securityCodeSettings { hasSecurityCode } }"
            }
            get_profile_id_query = self.session.post(_ENDPOINT_CC, json=get_profile_id_query)
            self.session.headers.update({'x-dmm-profile-id': get_profile_id_query.json()["data"]["user"]["profiles"][0]["id"]})
            
            self.auth_success = True
            
            return True, user_info_res.json()["data"]["user"]
        except Exception as e:
            return False, e
    
    def check_token(self, token):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        res = self.session.post(_ENDPOINT_CC, json={"operationName":"GetServicePlan", "query":"query GetServicePlan { user { id planStatus { __typename ...planStatusFragments } } }  fragment paymentStatusFragment on PaymentStatus { isRenewalFailure failureCode message }  fragment planStatusFragments on PlanStatus { provideEndDate nextBillingDate status paymentType paymentStatus(id: DMM_PREMIUM) { __typename ...paymentStatusFragment } isSubscribed planType }"}, headers={"Authorization": token})
        if res.status_code == 200:
            if res.json()["data"] != None:
                return True, res.json()["data"]["user"]
            else:
                return False, "Invalid Token"
        else:
            return False, "Invalid Token"
        
    def check_free(self, url, sessionid, contentid=None):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        if contentid != None:
            payload = {
              "operationName": "GetStream",
              "variables": {
                "contentId": contentid,
                "part": 1,
                "protectionCapabilities": [
                  {
                    "systemId": "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
                    "format": "DASH",
                    "audio": [
                      {
                        "codec": "AAC"
                      }
                    ],
                    "video": [
                      {
                        "codec": "AVC",
                        "tee": False,
                        "bpc": 8,
                        "rate": 503316480,
                        "yuv444p": False
                      },
                      {
                        "codec": "HEVC",
                        "tee": False,
                        "bpc": 8,
                        "rate": 530841600,
                        "yuv444p": False
                      },
                      {
                        "codec": "VP9",
                        "tee": False,
                        "bpc": 8,
                        "rate": 267386880,
                        "yuv444p": False
                      }
                    ],
                    "hdcp": "NONE"
                  }
                ],
                "audioChannelLayouts": [
                  "STEREO"
                ],
                "device": "ANDROID_MOBILE",
                "http": False,
                "temporaryDownload": False
              },
              "query": "query GetStream($contentId: ID!, $part: Int!, $protectionCapabilities: [ProtectionCapability!]!, $audioChannelLayouts: [StreamingAudioChannelLayout!]!, $device: PlayDevice!, $http: Boolean!, $temporaryDownload: Boolean!) { stream(id: $contentId, part: $part, protectionCapabilities: $protectionCapabilities, audioChannelLayouts: $audioChannelLayouts, device: $device, http: $http, temporaryDownload: $temporaryDownload) { qualities { __typename ...qualityFragment } textRenditionType languages { __typename ...languageFragment } videoRenditions { __typename ...videoRenditionFragment } audioRenditions { __typename ...audioRenditionFragment } textRenditions { __typename ...textRenditionFragment } chapter { __typename ...chapterFragment } contentTypeDetail streamCacheExpiration purchasedProductId } }  fragment qualityFragment on Quality { name displayName displayPriority }  fragment languageFragment on Language { lang displayName }  fragment videoRenditionFragment on VideoRendition { lang qualityName streamingUrls { systemIds videoCodec format bpc streamSize urls hdcp } }  fragment audioRenditionFragment on AudioRendition { lang audioChannels audioChannelLayout }  fragment textRenditionFragment on TextRendition { lang }  fragment chapterRangeFragment on ChapterRange { start end }  fragment chapterFragment on Chapter { op { __typename ...chapterRangeFragment } ed { __typename ...chapterRangeFragment } skippable { __typename ...chapterRangeFragment } }"
            }
            res = self.session.post(_ENDPOINT_CC, json=payload)
            if res.status_code == 200:
                if res.json()["data"] != None:
                    if res.json()["data"]["stream"] == None:
                        return ({"status": "false"})
                    temp_json = {}
                    if res.json()["data"]["stream"]["contentTypeDetail"] == "VOD_FREE":
                        temp_json["status"] = "true"
                        
                        ## 開始時刻と終了配信時刻はここだと取得できないので、seasonidからシーズン情報を丸ごととり、一致するcontetnidを見つけそこから取得する、
                        
                        payload = {
                            "operationName": "GetSeason",
                            "variables": {
                                "id": f"{sessionid}",
                                "abSplitId": "detail_pv",
                                "episodesSize": 200,
                                "playDevice": "ANDROID_TV",
                                "withAuth": self.auth_success,
                            },
                            "query": "query GetSeason($id: ID!, $abSplitId: ID!, $episodesSize: Int, $playDevice: PlayDevice!, $withAuth: Boolean!) { abSplit(abSplitId: $abSplitId) @include(if: $withAuth) { abGroup } firstView: video(id: $id) { __typename id seasonType ... on VideoSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag highlight keyVisualImage keyVisualWithoutLogoImage relatedSeasons { __typename ...videoRelatedSeasonFragment } nextDeliveryEpisode { isBeforeDelivered startDeliveryAt } svodEndDeliveryAt continueWatching @include(if: $withAuth) { id content { __typename ...videoContentFragment } } priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoStageSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag keyVisualImage keyVisualWithoutLogoImage priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoSpotLiveSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag spotLiveDescription: description keyVisualImage keyVisualWithoutLogoImage } } tab: video(id: $id) { __typename id ... on VideoSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } episodes: episodes(type: MAIN, first: $episodesSize) { total edges { node { __typename ...mainEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { total edges { node { __typename ...specialEpisodeFragment } } } } ... on VideoStageSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } purchasedStageContents @include(if: $withAuth) { purchasedContentsByPerformanceDate { performanceDate contents { __typename ...purchaseEpisodeFragment } } } allPerformances { __typename ...stagePerformanceFragment } } ... on VideoSpotLiveSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } episodes: episodes(type: MAIN, first: $episodesSize) { edges { node { __typename ...mainEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { edges { node { __typename ...specialEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } } } }  fragment videoRatingFragment on VideoRating { category name }  fragment videoCampaignFragment on VideoCampaign { id name endAt isLimitedPremium }  fragment videoRelatedSeasonFragment on VideoRelatedSeason { id title video { __typename id seasonType ... on VideoSeason { id keyVisualImage keyVisualWithoutLogoImage } } }  fragment VideoPPVExpirationFragment on VideoPPVExpiration { expirationType viewingExpiration viewingStartExpiration startDeliveryAt }  fragment videoPriceSummaryFragment on VideoPriceSummary { campaignId highestPrice lowestPrice discountedHighestPrice discountedLowestPrice isLimitedPremium }  fragment videoViewingExpirationFragment on VideoViewingExpiration { __typename ... on VideoFixedViewingExpiration { expiresAt } ... on VideoLegacyViewingExpiration { expireDay } ... on VideoRentalViewingExpiration { startLimitDay expireDay expireHour } }  fragment videoPPVBundleProductSummaryFragment on VideoPPVProduct { id contentId contentType saleType isPreOrder saleUnitName episodeTitle episodeNumberName viewingExpiration { __typename ...videoViewingExpirationFragment } startDeliveryAt isBeingDelivered }  fragment videoPPVProductPriceFragment on VideoPPVProductPrice { price salePrice isLimitedPremium }  fragment videoPPVProductSummaryFragment on VideoPPVProduct { id contentId contentType contentPriority saleUnitPriority saleUnitName episodeTitle episodeNumberName saleType isPreOrder isPurchased @include(if: $withAuth) isBundleParent bundleProducts { __typename ...videoPPVBundleProductSummaryFragment } price { __typename ...videoPPVProductPriceFragment } viewingExpiration { __typename ...videoViewingExpirationFragment } isOnSale startDeliveryAt isBeingDelivered campaign { __typename ...videoCampaignFragment } hasGoods }  fragment videoFreeProductFragment on VideoFreeProduct { contentId startDeliveryAt endDeliveryAt isBeingDelivered }  fragment videoSVODProductFragment on VideoSVODProduct { contentId startDeliveryAt isBeingDelivered }  fragment videoViewingRightsFragment on VideoViewingRights { isStreamable isDownloadable contentType }  fragment videoPartFragment on VideoPart { contentId number duration resume @include(if: $withAuth) { point isCompleted } }  fragment videoPlayInfoSummaryFragment on VideoPlayInfo { contentId tags highestQuality highestAudioChannelLayout audioRenditions textRenditions isSupportHDR duration parts { __typename ...videoPartFragment } }  fragment videoContentFragment on VideoContent { id seasonId episodeType contentType episodeImage episodeTitle episodeDetail episodeNumber episodeNumberName ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } priceSummary { __typename ...videoPriceSummaryFragment } ppvProducts { __typename ...videoPPVProductSummaryFragment } freeProduct { __typename ...videoFreeProductFragment } svodProduct { __typename ...videoSVODProductFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } playInfo { __typename ...videoPlayInfoSummaryFragment } sampleMovie startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment personFragment on Person { id name }  fragment castFragment on Cast { id castName actorName priority person { __typename ...personFragment } }  fragment staffFragment on Staff { id roleName staffName priority person { __typename ...personFragment } }  fragment videoGenreFragment on VideoGenre { id name }  fragment reviewSummaryFragment on ReviewSummary { reviewerCount reviewCommentCount }  fragment reviewFragment on Review { id reviewerName reviewerId title point hasSpoiler comment date postEvaluationCount helpfulVoteCount isReviewerPurchased }  fragment purchaseEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } audioRenditions textRenditions } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration { __typename ...VideoPPVExpirationFragment } ppvProducts { id contentId isBeingDelivered isPurchased @include(if: $withAuth) startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment mainEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration audioRenditions textRenditions tags parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered isAllowDownload }  fragment pvEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeTitle episodeDetail episodeType contentType playInfo { duration } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } sampleMovie }  fragment specialEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered }  fragment stagePerformanceFragment on VideoStagePerformance { performanceDate contents { id episodeTitle ppvProducts { __typename id ...videoPPVProductSummaryFragment } } }",
                        }
                        res = self.session.post(_ENDPOINT_CC, json=payload)
                        result_list = []
                        if res.status_code == 200:
                            if res.json()["data"]["tab"]["episodes"]["edges"] != None:
                                for episode in res.json()["data"]["tab"]["episodes"]["edges"]:
                                    #if episode["node"]["freeProduct"] != None:
                                    #    temp_json["status"] = "true"
                                    #    temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                                    #    temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                                    #    result_list.append(temp_json)
                                    #else:
                                    #    temp_json["status"] = "false"
                                    #    result_list.append(temp_json)
                                    
                                    if episode["node"]["id"] == contentid:
                                        temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                                        temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                                        result_list.append(temp_json)
                        
                        #temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                        #temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                        return(temp_json)
                    else:
                        temp_json["status"] = "false"
                        return(temp_json)
                else:
                    return ({"status": "false"})
            else:
                return ({"status": "false"})
        elif "shorts" in url:
            payload = {
                "operationName": "FetchVideoEpisodes",
                "variables": {
                    "seasonId":sessionid,
                    "playDevice":"ANDROID_MOBILE",
                    "isLoggedIn":self.auth_success,
                    "first":200,
                    "type":"MAIN"
                },
                "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoEpisodes on VideoContentConnection {\n  edges {\n    node {\n      ...VideoSeasonContent\n      __typename\n    }\n    __typename\n  }\n  pageInfo {\n    endCursor\n    hasNextPage\n    __typename\n  }\n  total\n  allEpisodeNumbers\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n",
            }
            res = self.session.post(_ENDPOINT_CC, json=payload)
            result_list = []
            if res.status_code == 200:
                if res.json()["data"]["video"]["episodes"]["edges"] != None:
                    for episode in res.json()["data"]["video"]["episodes"]["edges"]:
                        temp_json = {}
                        #if episode["node"]["freeProduct"] != None:
                        #    temp_json["status"] = "true"
                        #    temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                        #    temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                        #    result_list.append(temp_json)
                        #else:
                        #    temp_json["status"] = "false"
                        #    result_list.append(temp_json)
                        
                        if episode["node"]["contentType"] == "VOD_2D":
                            temp_json["status"] = "false"
                            result_list.append(temp_json)
                        else:
                            temp_json["status"] = "true"
                            temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                            temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                            result_list.append(temp_json)
                            
                    return result_list
                else:
                    return ({"status": "false"})
            else:
                return ({"status": "false"})
        else:
            #payload = {
            #    "operationName":"FetchVideoEpisodes",
            #    "variables":{
            #        "seasonId":f"{sessionid}",
            #        "playDevice":"BROWSER",
            #        "isLoggedIn":False,
            #        "type":"MAIN",
            #        "first":16
            #    },
            #    "query":"query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n"
            #}
            payload = {
                "operationName": "GetSeason",
                "variables": {
                    "id": f"{sessionid}",
                    "abSplitId": "detail_pv",
                    "episodesSize": 200,
                    "playDevice": "ANDROID_MOBILE",
                    "withAuth": self.auth_success,
                },
                "query": "query GetSeason($id: ID!, $abSplitId: ID!, $episodesSize: Int, $playDevice: PlayDevice!, $withAuth: Boolean!) { abSplit(abSplitId: $abSplitId) @include(if: $withAuth) { abGroup } firstView: video(id: $id) { __typename id seasonType ... on VideoSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag highlight keyVisualImage keyVisualWithoutLogoImage relatedSeasons { __typename ...videoRelatedSeasonFragment } nextDeliveryEpisode { isBeforeDelivered startDeliveryAt } svodEndDeliveryAt continueWatching @include(if: $withAuth) { id content { __typename ...videoContentFragment } } priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoStageSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag keyVisualImage keyVisualWithoutLogoImage priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoSpotLiveSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag spotLiveDescription: description keyVisualImage keyVisualWithoutLogoImage } } tab: video(id: $id) { __typename id ... on VideoSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } episodes: episodes(type: MAIN, first: $episodesSize) { total edges { node { __typename ...mainEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { total edges { node { __typename ...specialEpisodeFragment } } } } ... on VideoStageSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } purchasedStageContents @include(if: $withAuth) { purchasedContentsByPerformanceDate { performanceDate contents { __typename ...purchaseEpisodeFragment } } } allPerformances { __typename ...stagePerformanceFragment } } ... on VideoSpotLiveSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } episodes: episodes(type: MAIN, first: $episodesSize) { edges { node { __typename ...mainEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { edges { node { __typename ...specialEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } } } }  fragment videoRatingFragment on VideoRating { category name }  fragment videoCampaignFragment on VideoCampaign { id name endAt isLimitedPremium }  fragment videoRelatedSeasonFragment on VideoRelatedSeason { id title video { __typename id seasonType ... on VideoSeason { id keyVisualImage keyVisualWithoutLogoImage } } }  fragment VideoPPVExpirationFragment on VideoPPVExpiration { expirationType viewingExpiration viewingStartExpiration startDeliveryAt }  fragment videoPriceSummaryFragment on VideoPriceSummary { campaignId highestPrice lowestPrice discountedHighestPrice discountedLowestPrice isLimitedPremium }  fragment videoViewingExpirationFragment on VideoViewingExpiration { __typename ... on VideoFixedViewingExpiration { expiresAt } ... on VideoLegacyViewingExpiration { expireDay } ... on VideoRentalViewingExpiration { startLimitDay expireDay expireHour } }  fragment videoPPVBundleProductSummaryFragment on VideoPPVProduct { id contentId contentType saleType isPreOrder saleUnitName episodeTitle episodeNumberName viewingExpiration { __typename ...videoViewingExpirationFragment } startDeliveryAt isBeingDelivered }  fragment videoPPVProductPriceFragment on VideoPPVProductPrice { price salePrice isLimitedPremium }  fragment videoPPVProductSummaryFragment on VideoPPVProduct { id contentId contentType contentPriority saleUnitPriority saleUnitName episodeTitle episodeNumberName saleType isPreOrder isPurchased @include(if: $withAuth) isBundleParent bundleProducts { __typename ...videoPPVBundleProductSummaryFragment } price { __typename ...videoPPVProductPriceFragment } viewingExpiration { __typename ...videoViewingExpirationFragment } isOnSale startDeliveryAt isBeingDelivered campaign { __typename ...videoCampaignFragment } hasGoods }  fragment videoFreeProductFragment on VideoFreeProduct { contentId startDeliveryAt endDeliveryAt isBeingDelivered }  fragment videoSVODProductFragment on VideoSVODProduct { contentId startDeliveryAt isBeingDelivered }  fragment videoViewingRightsFragment on VideoViewingRights { isStreamable isDownloadable contentType }  fragment videoPartFragment on VideoPart { contentId number duration resume @include(if: $withAuth) { point isCompleted } }  fragment videoPlayInfoSummaryFragment on VideoPlayInfo { contentId tags highestQuality highestAudioChannelLayout audioRenditions textRenditions isSupportHDR duration parts { __typename ...videoPartFragment } }  fragment videoContentFragment on VideoContent { id seasonId episodeType contentType episodeImage episodeTitle episodeDetail episodeNumber episodeNumberName ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } priceSummary { __typename ...videoPriceSummaryFragment } ppvProducts { __typename ...videoPPVProductSummaryFragment } freeProduct { __typename ...videoFreeProductFragment } svodProduct { __typename ...videoSVODProductFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } playInfo { __typename ...videoPlayInfoSummaryFragment } sampleMovie startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment personFragment on Person { id name }  fragment castFragment on Cast { id castName actorName priority person { __typename ...personFragment } }  fragment staffFragment on Staff { id roleName staffName priority person { __typename ...personFragment } }  fragment videoGenreFragment on VideoGenre { id name }  fragment reviewSummaryFragment on ReviewSummary { reviewerCount reviewCommentCount }  fragment reviewFragment on Review { id reviewerName reviewerId title point hasSpoiler comment date postEvaluationCount helpfulVoteCount isReviewerPurchased }  fragment purchaseEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } audioRenditions textRenditions } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration { __typename ...VideoPPVExpirationFragment } ppvProducts { id contentId isBeingDelivered isPurchased @include(if: $withAuth) startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment mainEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration audioRenditions textRenditions tags parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered isAllowDownload }  fragment pvEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeTitle episodeDetail episodeType contentType playInfo { duration } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } sampleMovie }  fragment specialEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered }  fragment stagePerformanceFragment on VideoStagePerformance { performanceDate contents { id episodeTitle ppvProducts { __typename id ...videoPPVProductSummaryFragment } } }",
            }
            res = self.session.post(_ENDPOINT_CC, json=payload)
            result_list = []
            if res.status_code == 200:
                if res.json()["data"]["tab"]["episodes"]["edges"] != None:
                    for episode in res.json()["data"]["tab"]["episodes"]["edges"]:
                        temp_json = {}
                        #if episode["node"]["freeProduct"] != None:
                        #    temp_json["status"] = "true"
                        #    temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                        #    temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                        #    result_list.append(temp_json)
                        #else:
                        #    temp_json["status"] = "false"
                        #    result_list.append(temp_json)
                        
                        if episode["node"]["contentType"] == "VOD_2D":
                            temp_json["status"] = "false"
                            result_list.append(temp_json)
                        else:
                            temp_json["status"] = "true"
                            temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                            temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                            result_list.append(temp_json)
                            
                    return result_list
                else:
                    return ({"status": "false"})
            else:
                return ({"status": "false"})
            
    def get_title_metadata(self, url, sessionid, legacy=False):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "GetSeason",
            "variables": {
                "id": sessionid,
                "abSplitId": "detail_pv",
                "episodesSize": 200,
                "playDevice": "ANDROID_MOBILE",
                "withAuth": False
            },
            "query": "query GetSeason($id: ID!, $abSplitId: ID!, $episodesSize: Int, $playDevice: PlayDevice!, $withAuth: Boolean!) { abSplit(abSplitId: $abSplitId) @include(if: $withAuth) { abGroup } firstView: video(id: $id) { __typename id seasonType ... on VideoSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag highlight keyVisualImage keyVisualWithoutLogoImage relatedSeasons { __typename ...videoRelatedSeasonFragment } nextDeliveryEpisode { isBeforeDelivered startDeliveryAt } svodEndDeliveryAt continueWatching @include(if: $withAuth) { id content { __typename ...videoContentFragment } } priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoStageSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag keyVisualImage keyVisualWithoutLogoImage priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoSpotLiveSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag spotLiveDescription: description keyVisualImage keyVisualWithoutLogoImage } } tab: video(id: $id) { __typename id ... on VideoSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } episodes: episodes(type: MAIN, first: $episodesSize) { total edges { node { __typename ...mainEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { total edges { node { __typename ...specialEpisodeFragment } } } } ... on VideoStageSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } purchasedStageContents @include(if: $withAuth) { purchasedContentsByPerformanceDate { performanceDate contents { __typename ...purchaseEpisodeFragment } } } allPerformances { __typename ...stagePerformanceFragment } } ... on VideoSpotLiveSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } episodes: episodes(type: MAIN, first: $episodesSize) { edges { node { __typename ...mainEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { edges { node { __typename ...specialEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } } } }  fragment videoRatingFragment on VideoRating { category name }  fragment videoCampaignFragment on VideoCampaign { id name endAt isLimitedPremium }  fragment videoRelatedSeasonFragment on VideoRelatedSeason { id title video { __typename id seasonType ... on VideoSeason { id keyVisualImage keyVisualWithoutLogoImage } } }  fragment VideoPPVExpirationFragment on VideoPPVExpiration { expirationType viewingExpiration viewingStartExpiration startDeliveryAt }  fragment videoPriceSummaryFragment on VideoPriceSummary { campaignId highestPrice lowestPrice discountedHighestPrice discountedLowestPrice isLimitedPremium }  fragment videoViewingExpirationFragment on VideoViewingExpiration { __typename ... on VideoFixedViewingExpiration { expiresAt } ... on VideoLegacyViewingExpiration { expireDay } ... on VideoRentalViewingExpiration { startLimitDay expireDay expireHour } }  fragment videoPPVBundleProductSummaryFragment on VideoPPVProduct { id contentId contentType saleType isPreOrder saleUnitName episodeTitle episodeNumberName viewingExpiration { __typename ...videoViewingExpirationFragment } startDeliveryAt isBeingDelivered }  fragment videoPPVProductPriceFragment on VideoPPVProductPrice { price salePrice isLimitedPremium }  fragment videoPPVProductSummaryFragment on VideoPPVProduct { id contentId contentType contentPriority saleUnitPriority saleUnitName episodeTitle episodeNumberName saleType isPreOrder isPurchased @include(if: $withAuth) isBundleParent bundleProducts { __typename ...videoPPVBundleProductSummaryFragment } price { __typename ...videoPPVProductPriceFragment } viewingExpiration { __typename ...videoViewingExpirationFragment } isOnSale startDeliveryAt isBeingDelivered campaign { __typename ...videoCampaignFragment } hasGoods }  fragment videoFreeProductFragment on VideoFreeProduct { contentId startDeliveryAt endDeliveryAt isBeingDelivered }  fragment videoSVODProductFragment on VideoSVODProduct { contentId startDeliveryAt isBeingDelivered }  fragment videoViewingRightsFragment on VideoViewingRights { isStreamable isDownloadable contentType }  fragment videoPartFragment on VideoPart { contentId number duration resume @include(if: $withAuth) { point isCompleted } }  fragment videoPlayInfoSummaryFragment on VideoPlayInfo { contentId tags highestQuality highestAudioChannelLayout audioRenditions textRenditions isSupportHDR duration parts { __typename ...videoPartFragment } }  fragment videoContentFragment on VideoContent { id seasonId episodeType contentType episodeImage episodeTitle episodeDetail episodeNumber episodeNumberName ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } priceSummary { __typename ...videoPriceSummaryFragment } ppvProducts { __typename ...videoPPVProductSummaryFragment } freeProduct { __typename ...videoFreeProductFragment } svodProduct { __typename ...videoSVODProductFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } playInfo { __typename ...videoPlayInfoSummaryFragment } sampleMovie startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment personFragment on Person { id name }  fragment castFragment on Cast { id castName actorName priority person { __typename ...personFragment } }  fragment staffFragment on Staff { id roleName staffName priority person { __typename ...personFragment } }  fragment videoGenreFragment on VideoGenre { id name }  fragment reviewSummaryFragment on ReviewSummary { reviewerCount reviewCommentCount }  fragment reviewFragment on Review { id reviewerName reviewerId title point hasSpoiler comment date postEvaluationCount helpfulVoteCount isReviewerPurchased }  fragment purchaseEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } audioRenditions textRenditions } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration { __typename ...VideoPPVExpirationFragment } ppvProducts { id contentId isBeingDelivered isPurchased @include(if: $withAuth) startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment mainEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration audioRenditions textRenditions tags parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered isAllowDownload }  fragment pvEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeTitle episodeDetail episodeType contentType playInfo { duration } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } sampleMovie }  fragment specialEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered }  fragment stagePerformanceFragment on VideoStagePerformance { performanceDate contents { id episodeTitle ppvProducts { __typename id ...videoPPVProductSummaryFragment } } }"
        }
        if "shorts" in url:
            legacy = True
        if legacy:
            meta_json = {
                "operationName": "FetchVideo",
                "variables": {
                    "seasonId": sessionid,
                    "device": "ANDROID_MOBILE",
                    "playDevice": "ANDROID_MOBILE",
                    "isLoggedIn": False
                },
                "query": "query FetchVideo($seasonId: ID!, $device: Device!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $purchasedFirst: Int, $purchasedAfter: String) {\n  video(id: $seasonId) {\n    id\n    __typename\n    seasonType\n    seasonName\n    hasBookmark @include(if: $isLoggedIn)\n    titleName\n    highlight(format: HTML)\n    description(format: HTML)\n    notices(format: HTML)\n    packageImage\n    productionYear\n    isNewArrival\n    customTag\n    isPublic\n    isExclusive\n    isBeingDelivered\n    viewingTypes\n    copyright\n    url\n    startPublicAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    rating {\n      category\n      __typename\n    }\n    casts {\n      castName\n      actorName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    staffs {\n      roleName\n      staffName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    categories {\n      id\n      name\n      __typename\n    }\n    genres {\n      id\n      name\n      __typename\n    }\n    relatedItems(device: $device) {\n      videos {\n        seasonId\n        video {\n          id\n          titleName\n          packageImage\n          isNewArrival\n          viewingTypes\n          customTag\n          isExclusive\n          rating {\n            category\n            __typename\n          }\n          ... on VideoSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoLegacySeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoStageSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      books {\n        seriesId\n        title\n        thumbnail\n        url\n        __typename\n      }\n      mono {\n        banner\n        url\n        __typename\n      }\n      scratch {\n        banner\n        url\n        __typename\n      }\n      onlineCrane {\n        banner\n        url\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n    ... on VideoLegacySeason {\n      metaDescription: description(format: PLAIN)\n      packageLargeImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      sampleMovie {\n        url\n        thumbnail\n        __typename\n      }\n      samplePictures {\n        image\n        imageLarge\n        __typename\n      }\n      reviewSummary {\n        averagePoint\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        partNumber\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      content {\n        ...VideoLegacySeasonContent\n        __typename\n      }\n      series {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    ... on VideoStageSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      allPerformances {\n        performanceDate\n        contents {\n          ...VideoStageSeasonContent\n          __typename\n        }\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoStageSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      metaDescription: description(format: PLAIN)\n      titleName\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      __typename\n    }\n    ... on VideoShortSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n  }\n}\n\nfragment BaseContinueWatchingContent on VideoContinueWatching {\n  id\n  resumePoint\n  contentId\n  content {\n    id\n    episodeTitle\n    episodeNumberName\n    episodeNumber\n    episodeImage\n    drmLevel {\n      hasStrictProtection\n      __typename\n    }\n    viewingRights(device: $playDevice) {\n      isStreamable\n      isDownloadable\n      __typename\n    }\n    ppvProducts {\n      id\n      isBeingDelivered\n      isBundleParent\n      isOnSale\n      price {\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      __typename\n    }\n    svodProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    freeProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    priceSummary {\n      campaignId\n      lowestPrice\n      highestPrice\n      discountedLowestPrice\n      isLimitedPremium\n      __typename\n    }\n    ppvExpiration {\n      startDeliveryAt\n      __typename\n    }\n    playInfo {\n      contentId\n      resumePartNumber\n      parts {\n        number\n        duration\n        contentId\n        resume {\n          point\n          isCompleted\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoLegacySeasonContent on VideoContent {\n  id\n  contentType\n  episodeTitle\n  episodeNumberName\n  vrSampleMovie {\n    url\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    textRenditions\n    audioRenditions\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoStageSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  priority\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    isBundleParent\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"
            }
        try:
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if legacy:
                if return_json["data"]["video"] != None:
                    metadata_response_single = return_json["data"]["video"]
                    return True, metadata_response_single
                else:
                    return False, None
            else:
                if return_json["data"]["firstView"] != None:
                    metadata_response_single = return_json["data"]["firstView"]
                    return True, metadata_response_single
                else:
                    return False, None
        except Exception as e:
            print(e)
            return False, None          
    
    def get_title_parse_all(self, url, sessionid):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "FetchVideoEpisodes",
            "variables":{
                "seasonId":f"{sessionid}",
                "playDevice":"BROWSER",
                "isLoggedIn":False,
                "type":"MAIN",
                "first":200
            },
            "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
        }
        if "shorts" in url:
            meta_json["query"] = "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoEpisodes on VideoContentConnection {\n  edges {\n    node {\n      ...VideoSeasonContent\n      __typename\n    }\n    __typename\n  }\n  pageInfo {\n    endCursor\n    hasNextPage\n    __typename\n  }\n  total\n  allEpisodeNumbers\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"
        try:
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["video"]["episodes"]["edges"] != None:
                metadata_response_single = return_json["data"]["video"]["episodes"]["edges"]
                return True, metadata_response_single
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_title_parse_single(self, url, sessionid, content, legacy=False):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        if legacy:
            meta_json = {
                "operationName": "FetchVideo",
                "variables": {
                    "seasonId": content,
                    "device": "BROWSER",
                    "isLoggedIn": self.auth_success,
                    "playDevice": "BROWSER",
                },
                "query": "query FetchVideo($seasonId: ID!, $device: Device!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $purchasedFirst: Int, $purchasedAfter: String) {\n  video(id: $seasonId) {\n    id\n    __typename\n    seasonType\n    seasonName\n    hasBookmark @include(if: $isLoggedIn)\n    titleName\n    highlight(format: HTML)\n    description(format: HTML)\n    notices(format: HTML)\n    packageImage\n    productionYear\n    isNewArrival\n    customTag\n    isPublic\n    isExclusive\n    isBeingDelivered\n    viewingTypes\n    copyright\n    url\n    startPublicAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    rating {\n      category\n      __typename\n    }\n    casts {\n      castName\n      actorName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    staffs {\n      roleName\n      staffName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    categories {\n      id\n      name\n      __typename\n    }\n    genres {\n      id\n      name\n      __typename\n    }\n    relatedItems(device: $device) {\n      videos {\n        seasonId\n        video {\n          id\n          titleName\n          packageImage\n          isNewArrival\n          viewingTypes\n          customTag\n          isExclusive\n          rating {\n            category\n            __typename\n          }\n          ... on VideoSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoLegacySeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoStageSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      books {\n        seriesId\n        title\n        thumbnail\n        url\n        __typename\n      }\n      mono {\n        banner\n        url\n        __typename\n      }\n      scratch {\n        banner\n        url\n        __typename\n      }\n      onlineCrane {\n        banner\n        url\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n    ... on VideoLegacySeason {\n      metaDescription: description(format: PLAIN)\n      packageLargeImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      sampleMovie {\n        url\n        thumbnail\n        __typename\n      }\n      samplePictures {\n        image\n        imageLarge\n        __typename\n      }\n      reviewSummary {\n        averagePoint\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        partNumber\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      content {\n        ...VideoLegacySeasonContent\n        __typename\n      }\n      series {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    ... on VideoStageSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      allPerformances {\n        performanceDate\n        contents {\n          ...VideoStageSeasonContent\n          __typename\n        }\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoStageSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      metaDescription: description(format: PLAIN)\n      titleName\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      __typename\n    }\n    ... on VideoShortSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n  }\n}\n\nfragment BaseContinueWatchingContent on VideoContinueWatching {\n  id\n  resumePoint\n  contentId\n  content {\n    id\n    episodeTitle\n    episodeNumberName\n    episodeNumber\n    episodeImage\n    drmLevel {\n      hasStrictProtection\n      __typename\n    }\n    viewingRights(device: $playDevice) {\n      isStreamable\n      isDownloadable\n      __typename\n    }\n    ppvProducts {\n      id\n      isBeingDelivered\n      isBundleParent\n      isOnSale\n      price {\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      __typename\n    }\n    svodProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    freeProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    priceSummary {\n      campaignId\n      lowestPrice\n      highestPrice\n      discountedLowestPrice\n      isLimitedPremium\n      __typename\n    }\n    ppvExpiration {\n      startDeliveryAt\n      __typename\n    }\n    playInfo {\n      contentId\n      resumePartNumber\n      parts {\n        number\n        duration\n        contentId\n        resume {\n          point\n          isCompleted\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoLegacySeasonContent on VideoContent {\n  id\n  contentType\n  episodeTitle\n  episodeNumberName\n  vrSampleMovie {\n    url\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    textRenditions\n    audioRenditions\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoStageSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  priority\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    isBundleParent\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"
            }
            try:   
                metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
                return_json = metadata_response.json()
                #print(return_json)
                if return_json["data"] != None:
                    return True, return_json["data"]["video"]
                else:
                    return False, None
            except Exception as e:
                print(e)
                return False, None
        else:
            meta_json = {
                "operationName": "FetchVideoEpisodes",
                "variables":{
                    "seasonId":f"{sessionid}",
                    "playDevice":"BROWSER",
                    "isLoggedIn":self.auth_success,
                    "type":"MAIN",
                    "first":200
                },
                "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
            }
            if "shorts" in url:
                meta_json["query"] = "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoShortSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        ...VideoEpisodes\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoEpisodes on VideoContentConnection {\n  edges {\n    node {\n      ...VideoSeasonContent\n      __typename\n    }\n    __typename\n  }\n  pageInfo {\n    endCursor\n    hasNextPage\n    __typename\n  }\n  total\n  allEpisodeNumbers\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"    
            try:
                metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
                return_json = metadata_response.json()
                try:
                    if return_json["data"]["video"]["__typename"] == "VideoStageSeason":
                        meta_json = {
                            "operationName": "FetchVideo",
                            "variables": {
                                "seasonId": f"{sessionid}",
                                "device": "BROWSER",
                                "playDevice": "BROWSER",
                                "isLoggedIn": self.auth_success
                            },
                            "query": "query FetchVideo($seasonId: ID!, $device: Device!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $purchasedFirst: Int, $purchasedAfter: String) {\n  video(id: $seasonId) {\n    id\n    __typename\n    seasonType\n    seasonName\n    hasBookmark @include(if: $isLoggedIn)\n    titleName\n    highlight(format: HTML)\n    description(format: HTML)\n    notices(format: HTML)\n    packageImage\n    productionYear\n    isNewArrival\n    customTag\n    isPublic\n    isExclusive\n    isBeingDelivered\n    viewingTypes\n    copyright\n    url\n    startPublicAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    rating {\n      category\n      __typename\n    }\n    casts {\n      castName\n      actorName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    staffs {\n      roleName\n      staffName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    categories {\n      id\n      name\n      __typename\n    }\n    genres {\n      id\n      name\n      __typename\n    }\n    relatedItems(device: $device) {\n      videos {\n        seasonId\n        video {\n          id\n          titleName\n          packageImage\n          isNewArrival\n          viewingTypes\n          customTag\n          isExclusive\n          rating {\n            category\n            __typename\n          }\n          ... on VideoSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoLegacySeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoStageSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoShortSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      books {\n        seriesId\n        title\n        thumbnail\n        url\n        __typename\n      }\n      mono {\n        banner\n        url\n        __typename\n      }\n      scratch {\n        banner\n        url\n        __typename\n      }\n      onlineCrane {\n        banner\n        url\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n    ... on VideoLegacySeason {\n      metaDescription: description(format: PLAIN)\n      packageLargeImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      sampleMovie {\n        url\n        thumbnail\n        __typename\n      }\n      samplePictures {\n        image\n        imageLarge\n        __typename\n      }\n      reviewSummary {\n        averagePoint\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        partNumber\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      content {\n        ...VideoLegacySeasonContent\n        __typename\n      }\n      series {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    ... on VideoStageSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      allPerformances {\n        performanceDate\n        contents {\n          ...VideoStageSeasonContent\n          __typename\n        }\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoStageSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      metaDescription: description(format: PLAIN)\n      titleName\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      __typename\n    }\n    ... on VideoShortSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n  }\n}\n\nfragment BaseContinueWatchingContent on VideoContinueWatching {\n  id\n  resumePoint\n  contentId\n  content {\n    id\n    episodeTitle\n    episodeNumberName\n    episodeNumber\n    episodeImage\n    drmLevel {\n      hasStrictProtection\n      __typename\n    }\n    viewingRights(device: $playDevice) {\n      isStreamable\n      isDownloadable\n      __typename\n    }\n    ppvProducts {\n      id\n      isBeingDelivered\n      isBundleParent\n      isOnSale\n      price {\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      __typename\n    }\n    svodProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    freeProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    priceSummary {\n      campaignId\n      lowestPrice\n      highestPrice\n      discountedLowestPrice\n      isLimitedPremium\n      __typename\n    }\n    ppvExpiration {\n      startDeliveryAt\n      __typename\n    }\n    playInfo {\n      contentId\n      resumePartNumber\n      parts {\n        number\n        duration\n        contentId\n        resume {\n          point\n          isCompleted\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoLegacySeasonContent on VideoContent {\n  id\n  contentType\n  episodeTitle\n  episodeNumberName\n  vrSampleMovie {\n    url\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    textRenditions\n    audioRenditions\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoStageSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  priority\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    isBundleParent\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"
                        }
                        metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
                        return_json = metadata_response.json()
                        for episode in return_json["data"]["video"]["purchasedContents"]["edges"]:
                            if episode["node"]["id"] == content:
                                return True, episode
                except:
                    pass
                if return_json["data"]["video"]["episodes"]["edges"] != None:
                    metadata_response_single = return_json["data"]["video"]["episodes"]["edges"]
                    found = False
                    for episode in metadata_response_single:
                        if episode['node']['id'] == content:
                            found = True
                            return True, episode
                    if found == False:
                        return False, "not found ??"
                else:
                    return False, "Not found edges"
            except Exception as e:
                return False, e
        
    def get_id_type(self, session_id, legacy=False):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''映像タイプを取得するコード'''
        if legacy:
            meta_json = {
                "operationName": "FetchVideo",
                "variables": {
                    "seasonId": session_id,
                    "device": "BROWSER",
                    "isLoggedIn": False,
                    "playDevice": "BROWSER",
                },
                "query": "query FetchVideo($seasonId: ID!, $device: Device!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $purchasedFirst: Int, $purchasedAfter: String) {\n  video(id: $seasonId) {\n    id\n    __typename\n    seasonType\n    seasonName\n    hasBookmark @include(if: $isLoggedIn)\n    titleName\n    highlight(format: HTML)\n    description(format: HTML)\n    notices(format: HTML)\n    packageImage\n    productionYear\n    isNewArrival\n    customTag\n    isPublic\n    isExclusive\n    isBeingDelivered\n    viewingTypes\n    copyright\n    url\n    startPublicAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    rating {\n      category\n      __typename\n    }\n    casts {\n      castName\n      actorName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    staffs {\n      roleName\n      staffName\n      person {\n        id\n        __typename\n      }\n      __typename\n    }\n    categories {\n      id\n      name\n      __typename\n    }\n    genres {\n      id\n      name\n      __typename\n    }\n    relatedItems(device: $device) {\n      videos {\n        seasonId\n        video {\n          id\n          titleName\n          packageImage\n          isNewArrival\n          viewingTypes\n          customTag\n          isExclusive\n          rating {\n            category\n            __typename\n          }\n          ... on VideoSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoLegacySeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          ... on VideoStageSeason {\n            priceSummary {\n              lowestPrice\n              highestPrice\n              discountedLowestPrice\n              isLimitedPremium\n              __typename\n            }\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      books {\n        seriesId\n        title\n        thumbnail\n        url\n        __typename\n      }\n      mono {\n        banner\n        url\n        __typename\n      }\n      scratch {\n        banner\n        url\n        __typename\n      }\n      onlineCrane {\n        banner\n        url\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n    ... on VideoLegacySeason {\n      metaDescription: description(format: PLAIN)\n      packageLargeImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      sampleMovie {\n        url\n        thumbnail\n        __typename\n      }\n      samplePictures {\n        image\n        imageLarge\n        __typename\n      }\n      reviewSummary {\n        averagePoint\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        partNumber\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      content {\n        ...VideoLegacySeasonContent\n        __typename\n      }\n      series {\n        id\n        name\n        __typename\n      }\n      __typename\n    }\n    ... on VideoStageSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      allPerformances {\n        performanceDate\n        contents {\n          ...VideoStageSeasonContent\n          __typename\n        }\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoStageSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      metaDescription: description(format: PLAIN)\n      titleName\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      __typename\n    }\n    ... on VideoShortSeason {\n      metaDescription: description(format: PLAIN)\n      keyVisualImage\n      keyVisualWithoutLogoImage\n      reviewSummary {\n        averagePoint\n        reviewerCount\n        reviewCommentCount\n        __typename\n      }\n      relatedSeasons {\n        id\n        title\n        __typename\n      }\n      nextDeliveryEpisode {\n        isBeforeDelivered\n        startDeliveryAt\n        __typename\n      }\n      continueWatching @include(if: $isLoggedIn) {\n        ...BaseContinueWatchingContent\n        __typename\n      }\n      priceSummary {\n        lowestPrice\n        highestPrice\n        discountedLowestPrice\n        isLimitedPremium\n        __typename\n      }\n      purchasedContents(first: $purchasedFirst, after: $purchasedAfter) @include(if: $isLoggedIn) {\n        total\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        __typename\n      }\n      svodEndDeliveryAt\n      __typename\n    }\n  }\n}\n\nfragment BaseContinueWatchingContent on VideoContinueWatching {\n  id\n  resumePoint\n  contentId\n  content {\n    id\n    episodeTitle\n    episodeNumberName\n    episodeNumber\n    episodeImage\n    drmLevel {\n      hasStrictProtection\n      __typename\n    }\n    viewingRights(device: $playDevice) {\n      isStreamable\n      isDownloadable\n      __typename\n    }\n    ppvProducts {\n      id\n      isBeingDelivered\n      isBundleParent\n      isOnSale\n      price {\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      __typename\n    }\n    svodProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    freeProduct {\n      contentId\n      isBeingDelivered\n      __typename\n    }\n    priceSummary {\n      campaignId\n      lowestPrice\n      highestPrice\n      discountedLowestPrice\n      isLimitedPremium\n      __typename\n    }\n    ppvExpiration {\n      startDeliveryAt\n      __typename\n    }\n    playInfo {\n      contentId\n      resumePartNumber\n      parts {\n        number\n        duration\n        contentId\n        resume {\n          point\n          isCompleted\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoLegacySeasonContent on VideoContent {\n  id\n  contentType\n  episodeTitle\n  episodeNumberName\n  vrSampleMovie {\n    url\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    textRenditions\n    audioRenditions\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n\nfragment VideoStageSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  priority\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isOnSale\n    isBundleParent\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    tags\n    __typename\n  }\n  __typename\n}\n"
            }
            try:   
                metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
                return_json = metadata_response.json()
                #print(return_json)
                if return_json["data"] != None:
                    return True, ["劇場", return_json["data"]["video"]["rating"]["category"]]
                else:
                    return False, None
            except Exception as e:
                print(e)
                return False, None
        else:
            meta_json = {
                "operationName": "GetSeason",
                "variables": {
                    "id": session_id,
                    "abSplitId": "detail_pv",
                    "episodesSize": 200,
                    "playDevice": "ANDROID_MOBILE",
                    "withAuth": False
                },
                "query": "query GetSeason($id: ID!, $abSplitId: ID!, $episodesSize: Int, $playDevice: PlayDevice!, $withAuth: Boolean!) { abSplit(abSplitId: $abSplitId) @include(if: $withAuth) { abGroup } firstView: video(id: $id) { __typename id seasonType ... on VideoSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag highlight keyVisualImage keyVisualWithoutLogoImage relatedSeasons { __typename ...videoRelatedSeasonFragment } nextDeliveryEpisode { isBeforeDelivered startDeliveryAt } svodEndDeliveryAt continueWatching @include(if: $withAuth) { id content { __typename ...videoContentFragment } } priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoStageSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag keyVisualImage keyVisualWithoutLogoImage priceSummary { __typename ...videoPriceSummaryFragment } } ... on VideoSpotLiveSeason { id seasonType titleId titleName seasonName highlight description(format: PLAIN) isBeingDelivered packageImage isNewArrival isMonopoly: isExclusive viewingTypes url notices copyright productionYear endPublicAt isPublic isOnSale hasBookmark @include(if: $withAuth) rating { __typename ...videoRatingFragment } campaign { __typename ...videoCampaignFragment } customTag spotLiveDescription: description keyVisualImage keyVisualWithoutLogoImage } } tab: video(id: $id) { __typename id ... on VideoSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } episodes: episodes(type: MAIN, first: $episodesSize) { total edges { node { __typename ...mainEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { total edges { node { __typename ...specialEpisodeFragment } } } } ... on VideoStageSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } reviewSummary { __typename ...reviewSummaryFragment } reviews(first: 3) { edges { node { __typename ...reviewFragment } } } purchasedContents(first: $episodesSize) @include(if: $withAuth) { total edges { node { __typename ...purchaseEpisodeFragment } } } purchasedStageContents @include(if: $withAuth) { purchasedContentsByPerformanceDate { performanceDate contents { __typename ...purchaseEpisodeFragment } } } allPerformances { __typename ...stagePerformanceFragment } } ... on VideoSpotLiveSeason { id casts { __typename ...castFragment } staffs { __typename ...staffFragment } genres { __typename ...videoGenreFragment } episodes: episodes(type: MAIN, first: $episodesSize) { edges { node { __typename ...mainEpisodeFragment } } } specials: episodes(type: SPECIAL, first: $episodesSize) { edges { node { __typename ...specialEpisodeFragment } } } pvs: episodes(type: PV) { total edges { node { __typename ...pvEpisodeFragment } } } } } }  fragment videoRatingFragment on VideoRating { category name }  fragment videoCampaignFragment on VideoCampaign { id name endAt isLimitedPremium }  fragment videoRelatedSeasonFragment on VideoRelatedSeason { id title video { __typename id seasonType ... on VideoSeason { id keyVisualImage keyVisualWithoutLogoImage } } }  fragment VideoPPVExpirationFragment on VideoPPVExpiration { expirationType viewingExpiration viewingStartExpiration startDeliveryAt }  fragment videoPriceSummaryFragment on VideoPriceSummary { campaignId highestPrice lowestPrice discountedHighestPrice discountedLowestPrice isLimitedPremium }  fragment videoViewingExpirationFragment on VideoViewingExpiration { __typename ... on VideoFixedViewingExpiration { expiresAt } ... on VideoLegacyViewingExpiration { expireDay } ... on VideoRentalViewingExpiration { startLimitDay expireDay expireHour } }  fragment videoPPVBundleProductSummaryFragment on VideoPPVProduct { id contentId contentType saleType isPreOrder saleUnitName episodeTitle episodeNumberName viewingExpiration { __typename ...videoViewingExpirationFragment } startDeliveryAt isBeingDelivered }  fragment videoPPVProductPriceFragment on VideoPPVProductPrice { price salePrice isLimitedPremium }  fragment videoPPVProductSummaryFragment on VideoPPVProduct { id contentId contentType contentPriority saleUnitPriority saleUnitName episodeTitle episodeNumberName saleType isPreOrder isPurchased @include(if: $withAuth) isBundleParent bundleProducts { __typename ...videoPPVBundleProductSummaryFragment } price { __typename ...videoPPVProductPriceFragment } viewingExpiration { __typename ...videoViewingExpirationFragment } isOnSale startDeliveryAt isBeingDelivered campaign { __typename ...videoCampaignFragment } hasGoods }  fragment videoFreeProductFragment on VideoFreeProduct { contentId startDeliveryAt endDeliveryAt isBeingDelivered }  fragment videoSVODProductFragment on VideoSVODProduct { contentId startDeliveryAt isBeingDelivered }  fragment videoViewingRightsFragment on VideoViewingRights { isStreamable isDownloadable contentType }  fragment videoPartFragment on VideoPart { contentId number duration resume @include(if: $withAuth) { point isCompleted } }  fragment videoPlayInfoSummaryFragment on VideoPlayInfo { contentId tags highestQuality highestAudioChannelLayout audioRenditions textRenditions isSupportHDR duration parts { __typename ...videoPartFragment } }  fragment videoContentFragment on VideoContent { id seasonId episodeType contentType episodeImage episodeTitle episodeDetail episodeNumber episodeNumberName ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } priceSummary { __typename ...videoPriceSummaryFragment } ppvProducts { __typename ...videoPPVProductSummaryFragment } freeProduct { __typename ...videoFreeProductFragment } svodProduct { __typename ...videoSVODProductFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } playInfo { __typename ...videoPlayInfoSummaryFragment } sampleMovie startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment personFragment on Person { id name }  fragment castFragment on Cast { id castName actorName priority person { __typename ...personFragment } }  fragment staffFragment on Staff { id roleName staffName priority person { __typename ...personFragment } }  fragment videoGenreFragment on VideoGenre { id name }  fragment reviewSummaryFragment on ReviewSummary { reviewerCount reviewCommentCount }  fragment reviewFragment on Review { id reviewerName reviewerId title point hasSpoiler comment date postEvaluationCount helpfulVoteCount isReviewerPurchased }  fragment purchaseEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } audioRenditions textRenditions } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration { __typename ...VideoPPVExpirationFragment } ppvProducts { id contentId isBeingDelivered isPurchased @include(if: $withAuth) startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } startLivePerformanceAt endLivePerformanceAt isAllowDownload isBeingDelivered }  fragment mainEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration audioRenditions textRenditions tags parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered isAllowDownload }  fragment pvEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeTitle episodeDetail episodeType contentType playInfo { duration } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } sampleMovie }  fragment specialEpisodeFragment on VideoContent { id seasonId episodeImage episodeNumber episodeNumberName episodeTitle episodeDetail episodeType contentType playInfo { duration parts { __typename ...videoPartFragment } } svodProduct { __typename ...videoSVODProductFragment } freeProduct { __typename ...videoFreeProductFragment } ppvProducts { id isPurchased @include(if: $withAuth) isOnSale isBeingDelivered startDeliveryAt } priceSummary { __typename ...videoPriceSummaryFragment } viewingRights(device: $playDevice) { __typename ...videoViewingRightsFragment } ppvExpiration @include(if: $withAuth) { __typename ...VideoPPVExpirationFragment } isBeingDelivered }  fragment stagePerformanceFragment on VideoStagePerformance { performanceDate contents { id episodeTitle ppvProducts { __typename id ...videoPPVProductSummaryFragment } } }"
            }
            try:   
                metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
                return_json = metadata_response.json()
                #print(return_json)
                if return_json["data"] != None:
                    maybe_genre = None
                    try:
                        if return_json["data"]["firstView"]["seasonType"] == "SHORT":
                            maybe_genre = "ショート"
                        else:
                            if "劇場版" or "劇場" in return_json["data"]["tab"]["episodes"]["edges"]:
                                maybe_genre = "劇場"    
                            if return_json["data"]["tab"]["episodes"]["edges"][0]["node"]["episodeNumberName"].__contains__("第"):
                                maybe_genre = "ノーマルアニメ"
                            else:
                                maybe_genre = "ノーマルアニメ"                        
                            if "劇場版" or "劇場" in return_json["data"]["tab"]["episodes"]["edges"]:
                                maybe_genre = "劇場"    
                            if return_json["data"]["tab"]["episodes"]["edges"][0]["node"]["episodeNumberName"].__contains__("第"):
                                maybe_genre = "ノーマルアニメ"
                            else:
                                maybe_genre = "ノーマルアニメ"
                        #if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"] == "再生":
                        #    maybe_genre = "劇場"
                        #if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("第") or return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("#"):
                        #    maybe_genre = "ノーマルアニメ"
                        #else:
                        #    maybe_genre = "劇場"
                    except:
                        maybe_genre = "劇場"
                    return True, [maybe_genre]
                else:
                    return False, None
            except Exception as e:
                print(e)
                return False, None
        
    def get_mpd_link(self, content_id):
        DRM_ID = {
            "FAIRPLAY": "94ce86fb-07ff-4f43-adb8-93d2fa968ca2",
            "PLAYREADY": "9a04f079-9840-4286-ab92-e65be0885f95",
            "WIDEVINE": "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
        }
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''映像タイプを取得するコード'''
        meta_json = {
            "operationName": "FetchStream",
            "variables":{
                "id":content_id,
                "protectionCapabilities":[
                    {
                        "systemId":DRM_ID["WIDEVINE"],
                        "format":"DASH",
                        "audio":[{"codec":"AAC"}],
                        "video":[{"codec":"AV1","bpc":10,"rate":497664000,"yuv444p":True},{"codec":"VP9","bpc":10,"rate":497664000},{"codec":"AVC","bpc":8,"rate":497664000}], # what this? i don't know
                        "hdcp":"V2_2"}
                    ],
                "audioChannelLayouts":["STEREO"],
                "device":"BROWSER",
                "http":False
            },
            "query": "query FetchStream($id: ID!, $part: Int, $protectionCapabilities: [ProtectionCapability!]!, $audioChannelLayouts: [StreamingAudioChannelLayout!]!, $device: PlayDevice!, $http: Boolean, $temporaryDownload: Boolean) {\n  stream(\n    id: $id\n    part: $part\n    protectionCapabilities: $protectionCapabilities\n    audioChannelLayouts: $audioChannelLayouts\n    device: $device\n    http: $http\n    temporaryDownload: $temporaryDownload\n  ) {\n    contentTypeDetail\n    purchasedProductId\n    qualities {\n      name\n      displayName\n      __typename\n    }\n    textRenditionType\n    languages {\n      lang\n      displayName\n      __typename\n    }\n    videoRenditions {\n      lang\n      qualityName\n      streamingUrls {\n        systemIds\n        videoCodec\n        format\n        bpc\n        streamSize\n        urls\n        hdcp\n        __typename\n      }\n      __typename\n    }\n    audioRenditions {\n      lang\n      audioChannels\n      audioChannelLayout\n      __typename\n    }\n    textRenditions {\n      lang\n      __typename\n    }\n    chapter {\n      op {\n        start\n        end\n        __typename\n      }\n      ed {\n        start\n        end\n        __typename\n      }\n      skippable {\n        start\n        end\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
        }
        try:   
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"] != None:
                content_mpd_list = []
                
                for n_d in return_json["data"]["stream"]["videoRenditions"]:
                    temp_mpd_list = {}
                    temp_mpd_list["quality_name"] = n_d["qualityName"]
                    temp_mpd_list["link_mpd"] = n_d["streamingUrls"][0]["urls"][0]
                    content_mpd_list.append(temp_mpd_list)
                
                return True, content_mpd_list
            else:
                return False, None
        except Exception:
            #print(e)
            #import traceback
            #import sys
            #t, v, tb = sys.exc_info()
            #print(traceback.format_exception(t,v,tb))
            #print(traceback.format_tb(e.__traceback__))
            return False, None
        
    def get_mpd_content(self, url):
        try:
            metadata_response = self.session.get(url, allow_redirects=False)
            #print(metadata_response.headers.Location)
            new_url_cdn = metadata_response.headers.get("Location")
            metadata_response = self.session.get(new_url_cdn, allow_redirects=False)
            return True, metadata_response.text, new_url_cdn
        except Exception as e:
            print(e)
            return False, None, None
        
    def parse_quality(self, links):
        found_status = False
        for link in links:
            if link["quality_name"] == "hd":
                found_status = True
                return link["link_mpd"]
            
        if found_status == False:
            for link in links:
                if link["quality_name"] == "auto":
                    return link["link_mpd"]

    # def download_segment(self, segment_links, config, unixtime, service_name="Dmm-TV"):
    #    downloaded_files = []
    #    try:
    #        # Define the base temp directory
    #        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
    #        os.makedirs(base_temp_dir, exist_ok=True)
    
    #        # Progress bar setup
    #        progress_lock = threading.Lock()  # Ensure thread-safe progress bar updates
    #        with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", ascii=True, unit='file') as pbar:
               
    #            # Thread pool for concurrent downloads
    #            with ThreadPoolExecutor(max_workers=8) as executor:
    #                future_to_url = {}
                   
    #                # Submit download tasks
    #                for tsf in segment_links:
    #                    output_temp = os.path.join(base_temp_dir, os.path.basename(tsf.replace("?cfr=4%2F15015", "")))
    #                    future = executor.submit(self._download_and_save, tsf, output_temp)
    #                    future_to_url[future] = output_temp
    
    #                # Process completed futures
    #                for future in as_completed(future_to_url):
    #                    output_temp = future_to_url[future]
    #                    try:
    #                        result = future.result()
    #                        if result:
    #                            downloaded_files.append(output_temp)
    #                    except Exception as e:
    #                        print(f"Error downloading {output_temp}: {e}")
    #                    finally:
    #                        with progress_lock:
    #                            pbar.update()
    
    #    except KeyboardInterrupt:
    #        print('User pressed CTRL+C, cleaning up...')
    #        return None
    
    #    return downloaded_files
    
    # def _download_and_save(self, url, output_path):
    #    """
    #    Helper function to download a segment and save it to a file.
    #    """
    #    try:
    #        with open(output_path, 'wb') as outf:
    #            vid = self.session.get(url).content  # Download the segment
    #            # vid = self._aes.decrypt(vid.content)  # Uncomment if decryption is needed
    #            outf.write(vid)  # Write the content to file
    #        return True
    #    except Exception as err:
    #        print(f"Error saving {output_path}: {err}")
    #        return False
    
    
    # def merge_m4s_files(self, input_files, output_file, service_name="Dmm-TV"):
    #    """
    #    m4sファイルを結合して1つの動画ファイルにする関数
       
    #    Args:
    #        input_files (list): 結合するm4sファイルのリスト
    #        output_file (str): 出力する結合済みのファイル名
    #    """
    #    total_files = len(input_files)
       
    #    # バイナリモードでファイルを結合
    #    with open(output_file, "wb") as outfile:
    #        with tqdm(total=total_files, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
    #            for i, f in enumerate(input_files, start=1):
    #                with open(f, "rb") as infile:
    #                    outfile.write(infile.read())
    #                pbar.set_postfix(file=f, refresh=True)
    #                pbar.update(1)
                    
    def download_segment(self, segment_links, config, unixtime, name, service_name="Dmm-TV"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
    
        stop_flag = threading.Event()  # ← フラグの作成
    
        def fetch_and_save(index_url):
            index, url = index_url
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    response = self.session.get(url.strip(), timeout=10)
                    response.raise_for_status()
                    temp_path = os.path.join(base_temp_dir, f"{index:05d}.ts")
                    with open(temp_path, 'wb') as f:
                        f.write(response.content)
                    return index
                except requests.exceptions.RequestException:
                    retry += 1
                    time.sleep(2)
            if not stop_flag.is_set():
                raise Exception(f"Failed to download segment {index}: {url}")
    
        futures = []
        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(fetch_and_save, (i, url)) for i, url in enumerate(segment_links)]
                with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"Error: {e}")
                        pbar.update(1)
    
            # 結合処理
            output_path = os.path.join(base_temp_dir, name)
            with open(output_path, 'wb') as out_file:
                for i in range(len(segment_links)):
                    temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                    with open(temp_path, 'rb') as f:
                        out_file.write(f.read())
                    os.remove(temp_path)
    
        except KeyboardInterrupt:
            #print("\nダウンロード中断されました。停止信号を送信します...")
            stop_flag.set()  # ← ここで全スレッドに停止を通知
            for future in futures:
                future.cancel()
            # 未完了ファイルの削除
            for i in range(len(segment_links)):
                temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
            raise  # 終了ステータスを再送出

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Dmm-TV"):
        # 出力ディレクトリを作成
        os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
    
        # ffmpegコマンド
        compile_command = [
            "ffmpeg",
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),
            "-i",
            os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),
            "-c:v",
            "copy",               # 映像はコピー
            "-c:a",
            "aac",                # 音声をAAC形式に変換
            "-b:a",
            "192k",               # 音声ビットレートを設定（192kbpsに調整）
            "-strict",
            "experimental",
            "-y",
            "-progress", "pipe:1",  # 進捗を標準出力に出力
            "-nostats",            # 標準出力を進捗情報のみにする
            output_name,
        ]

        # tqdmを使用した進捗表示
        #duration = 1434.93  # 動画全体の長さ（秒）を設定（例: 23分54.93秒）
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8") as process:
                for line in process.stdout:    
                    # "time=" の進捗情報を解析
                    match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
                    if match:
                        hours = int(match.group(1))
                        minutes = int(match.group(2))
                        seconds = float(match.group(3))
                        current_time = hours * 3600 + minutes * 60 + seconds
    
                        # 進捗率を計算して更新
                        progress = (current_time / duration) * 100
                        pbar.n = int(progress)
                        pbar.refresh()
    
            # プロセスが終了したら進捗率を100%にする
            process.wait()
            if process.returncode == 0:  # 正常終了の場合
                pbar.n = 100
                pbar.refresh()
            pbar.close()
            
    def download_subtitles(self, title_name, title_name_logger, base_link, subtitles, config, logger):
        logger.info(f"Downloading Subtitles  | Total: {str(len(subtitles))} ", extra={"service_name": "Dmm-TV"})
        #print(str(len(subtitles)))
        #for single in subtitles:
        #    print(single)
        #exit(1)
        with tqdm(total=len(subtitles), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"Dmm-TV"}{COLOR_RESET} : ", unit="%") as pbar:
            for i, f in enumerate(subtitles, start=1):
                #with open(f, "rb") as infile:
                #    outfile.write(infile.read())
                #os.remove(f)
                #pbar.set_postfix(file=f, refresh=True)
                raw_subtitle = self.session.get(base_link+f["language"]+".vtt").content
                decode_subtitle = sub_decrypt.parse_binary_content(raw_subtitle)
                
                output_sub_dr = os.path.join(config["directorys"]["Downloads"], title_name, "subtitle")
                if not os.path.exists(output_sub_dr):
                    os.makedirs(output_sub_dr, exist_ok=True)
                
                with open(os.path.join(output_sub_dr, title_name_logger+"_"+f["language"]+".vtt"), "wb") as infile:
                    infile.write(decode_subtitle.encode())
                pbar.update(1)