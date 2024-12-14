import re
import os
import base64
import requests
import subprocess
from tqdm import tqdm
from lxml import etree
from datetime import datetime
from urllib.parse import urljoin

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
    def decrypt_content(keys, input_file, output_file, config, service_name="U-Next"):
        mp4decrypt_command = DMM_TV_decrypt.mp4decrypt(keys, config)
        mp4decrypt_command.extend([input_file, output_file])
        # 「ｲ」の数を最大100として進捗バーを作成
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(mp4decrypt_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
                for line in process.stdout:
                    match = re.search(r"(ｲ+)", line)
                    if match:
                        progress_count = len(match.group(1))
                        pbar.n = progress_count
                        pbar.refresh()
            
            process.wait()
            if process.returncode == 0:  # 正常終了の場合
                pbar.n = 100
                pbar.refresh()
            pbar.close()

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
    def parse_mpd_logic(content):
        try:
            # Ensure the content is in bytes
            if isinstance(content, str):
                content = content.encode('utf-8')
    
            # Parse XML
            root = etree.fromstring(content)
            namespaces = {
                'mpd': 'urn:mpeg:dash:schema:mpd:2011',
                'cenc': 'urn:mpeg:cenc:2013'
            }
    
            # Extract video information
            videos = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    videos.append({
                        'resolution': f"{representation.get('width')}x{representation.get('height')}",
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract audio information
            audios = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    audios.append({
                        'audioSamplingRate': representation.get('audioSamplingRate'),
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract PSSH values
            pssh_list = []
            for content_protection in root.findall('.//mpd:ContentProtection', namespaces):
                pssh_element = content_protection.find('cenc:pssh', namespaces)
                if pssh_element is not None:
                    pssh_list.append(pssh_element.text)
    
            # Build the result
            result = {
                "main_content": content.decode('utf-8'),
                "pssh": pssh_list
            }
    
            return result
    
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid MPD content: {e}")
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred: {e}")
    def parse_mpd_content(mpd_content):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        else:
            content = mpd_content
    
        root = etree.fromstring(content)
    
        # Define the namespace (extracted from the MPD file's root element)
        namespace = {'ns': 'urn:mpeg:dash:schema:mpd:2011'}
    
        # Extract all <Representation> elements
        representations = root.findall(".//ns:Representation", namespace)
    
        # Initialize lists for video and audio information
        video_list = []
        audio_list = []
    
        # Extract relevant attributes for each representation
        for elem in representations:
            rep_id = elem.attrib.get('id', '')
            bandwidth = int(elem.attrib.get('bandwidth', 0))
            codecs = elem.attrib.get('codecs', '')
            width = int(elem.attrib.get('width', 0)) if 'width' in elem.attrib else None
            height = int(elem.attrib.get('height', 0)) if 'height' in elem.attrib else None
    
            if rep_id.startswith("p0va0br"):
                video_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "width": width,
                    "height": height,
                    "codecs": codecs
                })
            elif rep_id.startswith("p0aa0br"):
                audio_list.append({
                    "name": rep_id,
                    "bandwidth": bandwidth,
                    "codecs": codecs
                })
    
        # Return the classified lists with details
        return {
            "video_list": video_list,
            "audio_list": audio_list
        }
    def get_segment_link_list(mpd_content, representation_id, url):
        if isinstance(mpd_content, str):
            content = mpd_content.encode('utf-8')
        else:
            content = mpd_content
        """
        MPDコンテンツから指定されたRepresentation IDに対応するSegmentTemplateのリストを取得する。
    
        Args:
            mpd_content (str): MPDファイルのXMLコンテンツ。
            representation_id (str): 抽出したいRepresentation ID。
            url (str) : mpdファイルのURL
    
        Returns:
            dict: セグメントリストのリスト。セグメントリストが見つからない場合は空の辞書を返す。
        """
        try:
            tree = etree.fromstring(content)
            # 名前空間を設定
            ns = {'dash': 'urn:mpeg:dash:schema:mpd:2011'}
    
            # 指定されたRepresentation IDを持つRepresentation要素を探す
            representation = tree.find(f'.//dash:Representation[@id="{representation_id}"]', ns)
            if representation is None:
              return {}
    
            # 親のAdaptationSet要素を見つける
            adaptation_set = representation.find('..')
    
            # そのAdaptationSetの子要素であるSegmentTemplateを探す
            segment_template = adaptation_set.find('dash:SegmentTemplate', ns)
            if segment_template is None:
              return {}
    
            segment_timeline = segment_template.find('dash:SegmentTimeline', ns)
            if segment_timeline is None:
              return {}
    
            media_template = segment_template.get('media')
            init_template = segment_template.get('initialization')
            
            # テンプレート文字列の $RepresentationID$ を実際のIDに置換
            media_template = media_template.replace('$RepresentationID$', representation_id)
            init_template = init_template.replace('$RepresentationID$', representation_id)
            
            # セグメントリストの構築
            segment_list = []
            segment_all = []
            segment_all.append(urljoin(url, init_template))
            current_time = 0
            for segment in segment_timeline.findall('dash:S', ns):
                d_attr = segment.get('d')
                r_attr = segment.get('r')
                if not d_attr:
                    continue
                duration = int(d_attr)
                
                repeat_count = 1
                if r_attr is not None:
                    repeat_count = int(r_attr) + 1
    
                for _ in range(repeat_count):
                    segment_file = media_template.replace('$Time$', str(current_time))
                    segment_list.append(urljoin(url, segment_file))
                    segment_all.append(urljoin(url, segment_file))
                    current_time += duration
    
    
            init_url = urljoin(url, init_template)
    
    
            return {"init": init_url, "segments": segment_list, "all": segment_all}
    
        except etree.ParseError:
            print("XML解析エラー")
            return {}
        except Exception as e:
            print(f"予期せぬエラーが発生しました: {e}")
            return {}

class Dmm_TV__license:
    def license_vd_ad(pssh, session):
        _WVPROXY = "https://mlic.dmm.com/drm/widevine/license"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge))
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
    def authorize(self, email, password):
        global auth_success
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
            "referer": "https://accounts.dmm.com/app/service/login/password?client_id=S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi&parts=regist&parts=snslogin&parts=darkmode",
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
            auth_success = False
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
        
        auth_success = True
        
        return True, user_info_res.json()["data"]["user"]
    
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
        
    def check_free(self, sessionid, contentid=None):
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
                    temp_json = {}
                    if res.json()["data"]["stream"]["contentTypeDetail"] == "VOD_FREE":
                        temp_json["status"] = "true"
                        temp_json["start_at"] = episode["node"]["freeProduct"]["startDeliveryAt"]
                        temp_json["end_at"] = episode["node"]["freeProduct"]["endDeliveryAt"]
                        return(temp_json)
                    else:
                        temp_json["status"] = "false"
                        return(temp_json)
                else:
                    return False
            else:
                return False
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
                    "withAuth": auth_success,
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
            "variables":{
                "seasonId":f"{sessionid}",
                "playDevice":"BROWSER",
                "isLoggedIn":False,
                "type":"MAIN",
                "first":16
            },
            "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
        }
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
        
    def get_title_parse_single(self, sessionid, content):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "FetchVideoEpisodes",
            "variables":{
                "seasonId":f"{sessionid}",
                "playDevice":"BROWSER",
                "isLoggedIn":False,
                "type":"MAIN",
                "first":16
            },
            "query": "query FetchVideoEpisodes($seasonId: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!, $type: VideoEpisodeType, $first: Int, $last: Int, $after: Int, $before: Int) {\n  video(id: $seasonId) {\n    id\n    __typename\n    ... on VideoSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        allEpisodeNumbers\n        __typename\n      }\n      __typename\n    }\n    ... on VideoSpotLiveSeason {\n      episodes(\n        type: $type\n        first: $first\n        last: $last\n        after: $after\n        before: $before\n      ) {\n        edges {\n          node {\n            ...VideoSeasonContent\n            __typename\n          }\n          __typename\n        }\n        pageInfo {\n          endCursor\n          hasNextPage\n          __typename\n        }\n        total\n        __typename\n      }\n      __typename\n    }\n  }\n}\n\nfragment VideoSeasonContent on VideoContent {\n  id\n  seasonId\n  episodeTitle\n  episodeNumberName\n  episodeNumber\n  episodeImage\n  episodeDetail\n  sampleMovie\n  contentType\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isStreamable\n    isDownloadable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  ppvProducts {\n    id\n    isPurchased @include(if: $isLoggedIn)\n    isBeingDelivered\n    isBundleParent\n    isOnSale\n    price {\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    contentId\n    isBeingDelivered\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    contentId\n    isBeingDelivered\n    __typename\n  }\n  priceSummary {\n    campaignId\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    startDeliveryAt\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    textRenditions\n    audioRenditions\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    resumePartNumber @include(if: $isLoggedIn)\n    parts {\n      number\n      duration\n      contentId\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n",
        }
        try:
            metadata_response = self.session.post(_ENDPOINT_CC, json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["video"]["episodes"]["edges"] != None:
                metadata_response_single = return_json["data"]["video"]["episodes"]["edges"]
                for episode in metadata_response_single:
                    if episode['node']['id'] == content:
                        return True, episode
                    else:
                        return False, None
            else:
                return False, None
        except Exception as e:
            print(e)
            return False, None
        
    def get_id_type(self, session_id):
        _ENDPOINT_CC = 'https://api.tv.dmm.com/graphql'
        '''映像タイプを取得するコード'''
        meta_json = {
            "operationName": "GetSeason",
            "variables": {
                "id": session_id,
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
            #print(return_json)
            if return_json["data"] != None:
                maybe_genre = None
                episode_count = return_json["data"]["tab"]["episodes"]["total"]
                
                if "劇場版" or "劇場" in return_json["data"]["tab"]["episodes"]["edges"]:
                    maybe_genre = "劇場"    
                if return_json["data"]["tab"]["episodes"]["edges"][0]["node"]["episodeNumberName"].__contains__("第"):
                    maybe_genre = "ノーマルアニメ"
                else:
                    maybe_genre = "ノーマル？"
                #if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"] == "再生":
                #    maybe_genre = "劇場"
                #if return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("第") or return_json["data"]["webfront_title_stage"]["currentEpisode"]["playButtonName"].__contains__("#"):
                #    maybe_genre = "ノーマルアニメ"
                #else:
                #    maybe_genre = "劇場"
                
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
            #print(return_json)
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
        except Exception as e:
            print(e)
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
        for link in links:
            if link["quality_name"] == "hd":
                return link["link_mpd"]
            
    def download_segment(self, segment_links, config, unixtime):
        downloaded_files = []
        try:
            # Define the base temp directory
            base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
    
            # Ensure the base temp directory exists
            os.makedirs(base_temp_dir, exist_ok=True)
    
            with tqdm(total=len(segment_links), desc='Downloading', ascii=True, unit='file') as pbar:
                for tsf in segment_links:
                    # Construct the full output file path
                    outputtemp = os.path.join(base_temp_dir, os.path.basename(tsf.replace("?cfr=4%2F15015", "")))
    
                    try:
                        # Open the output file for writing
                        with open(outputtemp, 'wb') as outf:
                            vid = self.session.get(tsf).content  # Download the segment
                            #vid = self._aes.decrypt(vid.content)  # Decrypt the segment
                            outf.write(vid)  # Write the content to file
    
                    except Exception as err:
                        print('Problem occurred\nReason: {}'.format(err))
                        return None  # Exit the function if any error occurs
    
                    # Update the progress bar and append the file to the downloaded list
                    pbar.update()
                    downloaded_files.append(outputtemp)
    
        except KeyboardInterrupt:
            print('User pressed CTRL+C, cleaning up...')
            return None
    
        return downloaded_files

    def merge_m4s_files(self, input_files, output_file):
        """
        m4sファイルを結合して1つの動画ファイルにする関数
    
        Args:
            input_files (list): 結合するm4sファイルのリスト
            output_file (str): 出力する結合済みのファイル名
        """
        # 入力ファイル
       # files = ["init.m4s", "1.m4s", "2.m4s"]
        #output_file = "output.mp4"
        
        # バイナリモードでファイルを結合
        with open(output_file, "wb") as outfile:
            for f in input_files:
                with open(f, "rb") as infile:
                    outfile.write(infile.read())
        
        #print(f"結合が完了しました: {output_file}")
        return True

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="U-Next"):
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
            "copy",
            "-c:a",
            "copy",
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