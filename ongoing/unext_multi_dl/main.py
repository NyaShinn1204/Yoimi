import re
import os
import json
import string
import random
import requests
import subprocess
from tqdm import tqdm
from datetime import datetime
from bs4 import BeautifulSoup
from xml.etree import ElementTree as ET
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import yaml
import shutil
import logging
class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{COLOR_BLUE}{record.service_name}{COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        )
        
        return log_message

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class mpd_parse:
    @staticmethod
    def extract_video_info(mpd_content, value):
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = ET.fromstring(mpd_content)
    
        for adaptation_set in root.findall('.//AdaptationSet', namespaces):
            content_type = adaptation_set.get('contentType', '')
            
            if content_type == 'video':  # Ensure we're looking at the video AdaptationSet
                for representation in adaptation_set.findall('Representation', namespaces):
                    width = representation.get('width')
                    height = representation.get('height')
                    codecs = representation.get('codecs')
                    resolution = f"{width}x{height} mp4 {codecs}"
                    
                    if resolution == value:  # Matching the resolution
                        base_url_element = representation.find('BaseURL', namespaces)
                        base_url = base_url_element.text if base_url_element is not None else None
                        
                        # Find the pssh for the current AdaptationSet
                        pssh_elements = adaptation_set.findall('ContentProtection', namespaces)
                        pssh_list = []
                        for pssh_element in pssh_elements:
                            pssh = pssh_element.find('cenc:pssh', namespaces)
                            if pssh is not None:
                                pssh_list.append(pssh.text)
                        return {"pssh": pssh_list, "base_url": base_url}
        return None

    @staticmethod
    def extract_audio_info(mpd_content, value):
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = ET.fromstring(mpd_content)
    
        # Split the value into separate components (audio_sampling_rate, mimeType, and codecs)
        audio_sampling_rate, mime_type, codecs = value.split()
    
        # Find the audio AdaptationSet
        audio_adaptation_set = root.find(".//AdaptationSet[@contentType='audio']", namespaces)
    
        if audio_adaptation_set is not None:
            for representation in audio_adaptation_set.findall('Representation', namespaces):
                # Check if the audioSamplingRate and codecs match
                if (representation.get('audioSamplingRate') == audio_sampling_rate and 
                    representation.get('codecs') == codecs):
                    
                    base_url_element = representation.find('BaseURL', namespaces)
                    base_url = base_url_element.text if base_url_element is not None else None
                    
                    # Find the pssh for the current AdaptationSet
                    pssh_elements = audio_adaptation_set.findall('ContentProtection', namespaces)
                    pssh_list = []
                    for pssh_element in pssh_elements:
                        pssh = pssh_element.find('cenc:pssh', namespaces)
                        if pssh is not None:
                            pssh_list.append(pssh.text)
                    return {"pssh": pssh_list, "base_url": base_url}
    
        return None
    
    def get_resolutions(mpd_content):
        # 名前空間の定義
        namespace = {'': 'urn:mpeg:dash:schema:mpd:2011'}
        
        # MPDテキストを解析
        root = ET.fromstring(mpd_content)
        
        # 結果を格納するリスト
        video_representations = []
        
        # 映像の AdaptationSet をフィルタリング
        for adaptation_set in root.findall(".//AdaptationSet", namespace):
            if adaptation_set.get("contentType") == "video":  # 映像のみ
                for representation in adaptation_set.findall("Representation", namespace):
                    # 幅、高さ、コーデック、MIMEタイプを取得
                    width = representation.get("width")
                    height = representation.get("height")
                    codecs = representation.get("codecs")
                    mime_type = representation.get("mimeType")
                    
                    # 映像の情報をリストに追加
                    if width and height and mime_type and codecs:
                        info = f"{width}x{height} {mime_type.split('/')[-1]} {codecs}"
                        video_representations.append(info)
        
        return video_representations

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
    def parse_mpd_logic(content):
        from xml.etree import ElementTree as ET
        from lxml import etree    
        
        if isinstance(content, str):
            content = content.encode('utf-8')
        root = etree.fromstring(content)
    
        namespaces = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
        
        videos = []
        for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
            for representation in adaptation_set.findall('mpd:Representation', namespaces):
                resolution = f"{representation.get('width')}x{representation.get('height')}"
                codec = representation.get('codecs')
                mimetype = representation.get('mimeType')
                videos.append({
                    'resolution': resolution,
                    'codec': codec,
                    'mimetype': mimetype
                })
        
        audios = []
        for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
            for representation in adaptation_set.findall('mpd:Representation', namespaces):
                audio_sampling_rate = representation.get('audioSamplingRate')
                codec = representation.get('codecs')
                mimetype = representation.get('mimeType')
                audios.append({
                    'audioSamplingRate': audio_sampling_rate,
                    'codec': codec,
                    'mimetype': mimetype
                })
        
        namespace = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = ET.fromstring(content)
        
        audio_pssh_list = root.findall('.//AdaptationSet[@contentType="audio"]/ContentProtection/cenc:pssh', namespace)
        video_pssh_list = root.findall('.//AdaptationSet[@contentType="video"]/ContentProtection/cenc:pssh', namespace)
        
        audio_pssh = audio_pssh_list[-1] if audio_pssh_list else None
        video_pssh = video_pssh_list[-1] if video_pssh_list else None
        
        result = {
            "main_content": content,
            "video_pssh": video_pssh.text,
            "audio_pssh": audio_pssh.text,
            "video": videos,
            "audio": audios[0] if audios else {}
        }
        
        return result
    
class Unext_license:
    def license_vd_ad(video_pssh, audio_pssh, playtoken, session):
        _WVPROXY = "https://wvproxy.unext.jp/proxy"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id_video = cdm.open()
        session_id_audio = cdm.open()
    
        challenge_video = cdm.get_license_challenge(session_id_video, PSSH(video_pssh))
        challenge_audio = cdm.get_license_challenge(session_id_audio, PSSH(audio_pssh))
        response_video = session.post(f"{_WVPROXY}?play_token={playtoken}", data=challenge_video)    
        if response_video.text == "Possibly compromised client":
            print("THIS WVD IS NOT ALLOWED")
            #return None
        response_video.raise_for_status()
        response_audio = session.post(f"{_WVPROXY}?play_token={playtoken}", data=challenge_audio)    
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
   
class Unext_decrypt:
    def mp4decrypt(keys, config):
        if os.name == 'nt':
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
        
        mp4decrypt_path = os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe" if os.name == 'nt' else "mp4decrypt")
        
        if not os.access(mp4decrypt_path, os.X_OK):
            try:
                os.chmod(mp4decrypt_path, 0o755)
            except Exception as e:
                raise PermissionError(f"Failed to set executable permissions on {mp4decrypt_path}: {e}")
            
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="U-Next"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Unext_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Unext_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="U-Next"):
        mp4decrypt_command = Unext_decrypt.mp4decrypt(keys, config)
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
    
class Unext_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email_or_id, password):
        _ENDPOINT_CC = 'https://cc.unext.jp'
        _ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        _ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        _ENDPOINT_OAUTH = 'https://oauth.unext.jp{pse}'
        _ENDPOINT_TOKEN = 'https://oauth.unext.jp/oauth2/token'
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
        if not re.fullmatch('[0-9]+', email_or_id):
            if not re.fullmatch(mail_regex, email_or_id):
                return False, "Unext require email and password"
    
        # 初回リクエストとチャレンジID取得
        response = self.session.get(
            _ENDPOINT_CHALLENG_ID.format(
                state=Unext_utils.random_name(43),
                nonce=Unext_utils.random_name(43)
            )
        )
        script_tag = BeautifulSoup(response.text, "lxml").find("script", {"id": "__NEXT_DATA__"})
        json_data = json.loads(script_tag.string)
        challenge_id = json_data.get("props", {}).get("challengeId")
    
        # 認証
        payload_ = {
            "id": email_or_id,
            "password": password,
            "challenge_id": challenge_id,
            "device_code": "920",
            "scope": ["offline", "unext"],
        }
        auth_response = self.session.post(_ENDPOINT_RES, json=payload_).json()
        try:
            if auth_response["error_hint"] == "GAW0500003":
                return False, "Require Japan VPN, Proxy" 
            if auth_response["error_hint"] == "GUN8030006":
                return False, 'Wrong Email or password combination'
        except:
            pass
        
        _ENDPOINT_OAUTH = _ENDPOINT_OAUTH.format(pse=auth_response.get("post_auth_endpoint"))
    
        try:
            # OAuth 認証コード取得
            code_res = self.session.post(_ENDPOINT_OAUTH, allow_redirects=False)
            code_res.raise_for_status()
            redirect_oauth_url = code_res.headers.get("Location")
            res_code = parse_qs(urlparse(redirect_oauth_url).query).get('code', [None])[0]
        except requests.exceptions.RequestException as e:
            return False, f"Authentication failed: {str(e)}"
    
        # トークン取得
        _auth = {
            "code": res_code,
            "grant_type": "authorization_code",
            "client_id": "unextAndroidApp",
            "client_secret": "unextAndroidApp",
            "code_verifier": None,
            "redirect_uri": "jp.unext://page=oauth_callback"
        }
        token_response = self.session.post(_ENDPOINT_TOKEN, data=_auth)
        if token_response.status_code != 200:
            return False, 'Wrong Email or password combination'
    
        token_data = token_response.json()
        self.session.headers.update({'Authorization': 'Bearer ' + token_data.get('access_token')})
    
        # ユーザー情報取得
        user_info_query = {
            "operationName": "cosmo_userInfo",
            "query": """query cosmo_userInfo {
                userInfo {
                    id
                    multiAccountId
                    userPlatformId
                    userPlatformCode
                    superUser
                    age
                    otherFunctionId
                    points
                    hasRegisteredEmail
                    billingCaution {
                        title
                        description
                        suggestion
                        linkUrl
                        __typename
                    }
                    blockInfo {
                        isBlocked
                        score
                        __typename
                    }
                    siteCode
                    accountTypeCode
                    linkedAccountIssuer
                    isAdultPermitted
                    needsAdultViewingRights
                    __typename
                }
            }"""
        }
        user_info_res = self.session.post(_ENDPOINT_CC, json=user_info_query)
        return True, user_info_res.json()["data"]["userInfo"]
    def check_token(self, token):
        _ENDPOINT_CC = 'https://cc.unext.jp'
        res = self.session.post(_ENDPOINT_CC, json={"operationName":"cosmo_userInfo", "query":"query cosmo_userInfo {\n  userInfo {\n    id\n    multiAccountId\n    userPlatformId\n    userPlatformCode\n    superUser\n    age\n    otherFunctionId\n    points\n    hasRegisteredEmail\n    billingCaution {\n      title\n      description\n      suggestion\n      linkUrl\n      __typename\n    }\n    blockInfo {\n      isBlocked\n      score\n      __typename\n    }\n    siteCode\n    accountTypeCode\n    linkedAccountIssuer\n    isAdultPermitted\n    needsAdultViewingRights\n    __typename\n  }\n}\n"}, headers={"Authorization": token})
        if res.status_code == 200:
            if res.json()["data"] != None:
                return True, res.json()["data"]["userInfo"]
            else:
                return False, "Invalid Token"
        else:
            return False, "Invalid Token"
    
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
                        return True, episode, episode["minimumPrice"]
                return False, None, None
            else:
                return False, None, None
        except Exception as e:
            print(e)
            return False, None, None
        
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
        
    def get_playtoken(self, episode_id):
        '''メタデータを取得するコード'''
        meta_json = {
            "operationName": "cosmo_getPlaylistUrl",
            "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
            "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_playlistUrl"] != None:
                return True, return_json["data"]["webfront_playlistUrl"]["playToken"], return_json["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"] 
            else:
                return False, None, None
        except Exception as e:
            print(e)
            return False, None, None
            
    def get_mpd_content(self, url_code, playtoken):
        # 18c529a7-04df-41ee-b230-07f95ecd2561 MEZ0000593320
        try:
            metadata_response = self.session.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"})
            if metadata_response.text == "":
                return False, "他の機器で再生中です。同時に複数機器での再生はできません。（462）"
            else:
                return True, metadata_response.text
        except Exception as e:
            #print(e)
            return False, e
        
    def update_progress(self, process, service_name="U-Next"):
        total_size = None
        downloaded_size = 0

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if line.startswith("[#") and "ETA:" in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        downloaded_info = parts[1]
                        downloaded, total = downloaded_info.split('/')

                        # 単位を正規表現で取得
                        downloaded_match = re.search(r"([\d.]+)\s*(MiB|GiB)", downloaded)
                        total_match = re.search(r"([\d.]+)\s*(MiB|GiB)", total)

                        if downloaded_match and total_match:
                            downloaded_value = float(downloaded_match.group(1))
                            downloaded_unit = downloaded_match.group(2)
                            total_value = float(total_match.group(1))
                            total_unit = total_match.group(2)

                            # 単位をMiBに揃える
                            if downloaded_unit == "GiB":
                                downloaded_value *= 1024
                            if total_unit == "GiB":
                                total_value *= 1024

                            if total_size is None:
                                total_size = total_value

                            downloaded_size = downloaded_value

                            percentage = (downloaded_size / total_size) * 100
                            bar = f"{percentage:.0f}%|{'#' * int(percentage // 10)}{'-' * (10 - int(percentage // 10))}|"

                            # GBとMBの判定による表示
                            if total_size >= 1024:  # GBの場合
                                size_info = f" {downloaded_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
                            else:  # MBの場合
                                size_info = f" {downloaded_size:.1f}/{total_size:.1f} MiB"

                            log_message = (
                                f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                                f"{bar}{size_info}"
                            )

                            print(f"\r{log_message}", end="", flush=True)

                    except (IndexError, ValueError, AttributeError) as e:
                        print(f"Error parsing line: {line} - {e}")
                else:
                    print(f"Unexpected format in line: {line}")

        if total_size:
            if total_size >= 1024:  # GBの場合
                final_size_info = f" {total_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
            else:  # MBの場合
                final_size_info = f" {total_size:.1f}/{total_size:.1f} MiB"

            print(
                f"\r{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                f"100%|{'#' * 10}|{final_size_info}",
                flush=True
            )

    def aria2c(self, url, output_file_name, config, unixtime):
        output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)

        if not os.path.exists(output_temp_directory):
            os.makedirs(output_temp_directory, exist_ok=True)
        if os.name == 'nt':
            aria2c = os.path.join(config["directorys"]["Binaries"], "aria2c.exe")
        else:
            aria2c = "aria2c"
        
        if os.name == 'nt':
            if not os.path.isfile(aria2c) or not os.access(aria2c, os.X_OK):
                print(f"aria2c binary not found or not executable: {aria2c}")
            
        aria2c_command = [
            aria2c,
            url,
            "-d",
            os.path.join(config["directorys"]["Temp"], "content", unixtime),
            "-j16",
            "-o", output_file_name,
            "-s16",
            "-x16",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "--allow-overwrite=false",
            "--async-dns=false",
            "--auto-file-renaming=false",
            "--console-log-level=warn",
            "--retry-wait=5",
            "--summary-interval=1",
        ]

        process = subprocess.Popen(
            aria2c_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            encoding='utf-8'
        )

        self.update_progress(process)

        process.wait()

        return os.path.join(config["directorys"]["Temp"], "content", unixtime, output_file_name)
    
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, title_name_logger, service_name="U-Next"):
        if os.name != 'nt':
            os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
        else:
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            os.makedirs(os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name)), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name), sanitize_filename(title_name_logger+".mp4"))
        
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
                    #print(line) 
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
        
    def check_buyed(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''購入済みか確認するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0]},
            "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      id\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n"
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                if return_json["data"]["webfront_title_stage"]["paymentBadgeList"][0]["id"] == "BUY":
                    return True
                else:
                    return False 
            else:
                return False
        except Exception as e:
            return False
        
    def buy_episode(self, title_id, episode_id):
        '''購入またはレンタルするコード'''
        meta_json = {
            "operationName": "cosmo_videoProductList",
            "variables": {
                "titleCode": title_id,
                "episodeCode": episode_id,
                "deviceType": "700"
            },
            "query": "query cosmo_videoProductList($titleCode: ID!, $episodeCode: ID!, $deviceType: String!) {\n  webfront_title_stage(id: $titleCode) {\n    id\n    titleName\n    episode(id: $episodeCode) {\n      episodeName\n      displayNo\n      __typename\n    }\n    __typename\n  }\n  webfront_videoProductList(titleCode: $titleCode, episodeCode: $episodeCode) {\n    ppvProducts {\n      code\n      name\n      saleTypeCode\n      discountRate\n      displayButtonText\n      displayName\n      purchaseDescription\n      displaySaleType\n      displayValidityDurationText\n      discountRate\n      originalPrice\n      price\n      isSale\n      publicEndDate\n      svodAvailableFromText\n      __typename\n    }\n    contractProducts {\n      code\n      name\n      typeCode\n      price\n      displaySaleType\n      displayButtonText\n      ruleTitle\n      ruleNote\n      packDescription {\n        url {\n          browser\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  webfront_pointBack {\n    setting {\n      percentage\n      maxPercentage\n      productList\n      scheduleDate\n      isRestrictedToPoint\n      canIncreasePercentage\n      __typename\n    }\n    point\n    isAnnouncedIos\n    hasVideoSubscription\n    __typename\n  }\n  productsForVideoContent(deviceType: $deviceType, id: $episodeCode) {\n    subscriptions {\n      ... on UnextSubscriptionBundle {\n        name\n        subscriptionType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_videoProductList"] != None:
                if return_json["data"]["webfront_videoProductList"]["ppvProducts"][0]["code"]:
                    #return True
                    meta_json = {
                        "operationName": "cosmo_purchaseVideoProduct",
                        "variables": {
                            "productCode": return_json["data"]["webfront_videoProductList"]["ppvProducts"][0]["code"],
                        },
                        "mutation": "mutation cosmo_purchaseVideoProduct($productCode: ID, $liveTicketCode: ID, $useCooperationPoints: CooperationPointsPolicy) {\n  webfront_purchaseVideoProduct(\n    productCode: $productCode\n    liveTicketCode: $liveTicketCode\n    useCooperationPoints: $useCooperationPoints\n  ) {\n    product {\n      code\n      __typename\n    }\n    __typename\n  }\n}\n"
                    }
                    try:   
                        metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
                        return_json = metadata_response.json()
                        if return_json["data"]["webfront_purchaseVideoProduct"] != None:
                            return True
                        else:
                            return False
                    except Exception as e:
                        return False
                else:
                    return False 
            else:
                return False
        except Exception as e:
            return False
        
    def get_thumbnail_list(self, title_id, episode_id, id_type, config, unixtime):
        output_temp_directory = os.path.join(config["directorys"]["Temp"], "thumbnail", unixtime)
        if not os.path.exists(output_temp_directory):
            os.makedirs(output_temp_directory, exist_ok=True)
        if id_type[2] == "劇場":
            # movie 
            def download_image(url, index):
                tries = 3
                for attempt in range(tries):
                    try:
                        response = requests.get("https://"+url)
                        response.raise_for_status()
                        filename = os.path.join(output_temp_directory, f"{title_id}_key_image_{index + 1}.jpg")
                        with open(filename, 'wb') as file:
                            file.write(response.content)
                        return url, True
                    except requests.RequestException:
                        print(f"[-] Error downloading {url}, attempt {attempt + 1} of {tries}")
                        if attempt == tries - 1:
                            return url, False
            
            meta_json = {
                "operationName":"cosmo_getVideoTitle",
                "variables":{
                    "code":title_id
                },
                "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      id\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n"
            }
            try:   
                metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
                return_json = metadata_response.json()
                if return_json["data"]["webfront_title_stage"] != None:
                    if return_json["data"]["webfront_title_stage"]["thumbnail"]["standard"]:
                        get_url = return_json["data"]["webfront_title_stage"]["thumbnail"]
                    else:
                        return False 
                else:
                    return False
            except Exception as e:
                print(e)
            
            with ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(download_image, get_url[key], index)
                    for index, key in enumerate(get_url.keys())
                    if get_url[key]
                    if get_url[key].__contains__('imgc.nxtv.jp')
                ]
                for future in tqdm(as_completed(futures), total=len(futures), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"U=Next"}{COLOR_RESET} : ", unit="file"):
                    url, success = future.result()
                    if not success:
                        print(f"[-] Failed to download {url}")
        else:
            # episode
            
            ## download key image
            def download_image(url, index):
                tries = 3
                for attempt in range(tries):
                    try:
                        response = requests.get("https://"+url)
                        response.raise_for_status()
                        filename = os.path.join(output_temp_directory, f"{title_id}_key_image{index + 1}.jpg")
                        with open(filename, 'wb') as file:
                            file.write(response.content)
                        return url, True
                    except requests.RequestException:
                        print(f"[-] Error downloading {url}, attempt {attempt + 1} of {tries}")
                        if attempt == tries - 1:
                            return url, False
            
            meta_json = {
                "operationName":"cosmo_getVideoTitle",
                "variables":{
                    "code":title_id
                },
                "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      id\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n"
            }
            try:   
                metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
                return_json = metadata_response.json()
                if return_json["data"]["webfront_title_stage"] != None:
                    if return_json["data"]["webfront_title_stage"]["thumbnail"]["standard"]:
                        get_url = return_json["data"]["webfront_title_stage"]["thumbnail"]
                    else:
                        return False 
                else:
                    return False
            except Exception as e:
                print(e)
            
            with ThreadPoolExecutor() as executor:
                futures = [
                    executor.submit(download_image, get_url[key], index)
                    for index, key in enumerate(get_url.keys())
                    if get_url[key]
                    if get_url[key].__contains__('imgc.nxtv.jp')
                ]
                for future in tqdm(as_completed(futures), total=len(futures), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"U=Next"}{COLOR_RESET} : "):
                    url, success = future.result()
                    if not success:
                        print(f"[-] Failed to download {url}")
                        
            # ダウンロード関数
            def download_image(url, title_id, index, special=None):
                tries = 3
                filename = f"{title_id}_episode_image_special_{index + 1}.jpg" if special else f"{title_id}_episode_image{index + 1}.jpg"
                filename = os.path.join(output_temp_directory, filename)
                for attempt in range(tries):
                    try:
                        response = requests.get("https://" + url)
                        response.raise_for_status()
                        with open(filename, 'wb') as file:
                            file.write(response.content)
                        return url, True
                    except requests.RequestException:
                        if attempt == tries - 1:
                            return url, False
            
            # メイン処理
            meta_json = {
                "operationName": "cosmo_getVideoTitleEpisodes",
                "variables": {
                    "code": title_id,
                    "page": 1,
                    "pageSize": 100
                },
                "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
            }
            
            try:
                metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
                return_json = metadata_response.json()
                if return_json["data"]["webfront_title_titleEpisodes"] is not None:
                    episodes = return_json["data"]["webfront_title_titleEpisodes"]["episodes"]
                    title_id = "SID0104147"  # タイトルIDを指定
            
                    # tqdmを使ってプログレスバーを表示
                    with tqdm(total=len(episodes), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"U=Next"}{COLOR_RESET} : ") as pbar:
                        for index, episode in enumerate(episodes):
                            thumbnails = episode.get("thumbnail", {})
                            for key, url in thumbnails.items():
                                if key == "__typename":
                                    continue
                                special = key != "standard"
                                download_image(url, title_id, index, special=special)
                            pbar.update(1)  # プログレスバーを更新
                else:
                    print("No episodes found.")
            except Exception as e:
                print(f"Error: {e}")
                
                



def set_variable(session, LOG_LEVEL):
    global logger, config, unixtime
    
    unixtime = str(int(time.time()))
    
    logger = logging.getLogger('YoimiLogger')
    if LOG_LEVEL == "DEBUG":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    formatter = CustomFormatter(
        '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def check_proxie(session):
    logger.info("Checking Proxie...", extra={"service_name": "Yoimi"})
    try:
        start = time.time()
        #
        _ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        _ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        
        response = session.get(
            _ENDPOINT_CHALLENG_ID.format(
                state="ma68aiLyo4LhQkOVHGctEN7jH7PGmRIhRVOmzgK8f5y",
                nonce="ArnY3qesx6DVqiMIXYxEnJG2KzHhMe9l4bzZLOaLnZw"
            )
        )
        script_tag = BeautifulSoup(response.text, "lxml").find("script", {"id": "__NEXT_DATA__"})
        json_data = json.loads(script_tag.string)
        challenge_id = json_data.get("props", {}).get("challengeId")
    
        payload_ = {
            "id": "example@example.com",
            "password": "example123",
            "challenge_id": challenge_id,
            "device_code": "920",
            "scope": ["offline", "unext"],
        }
        auth_response = session.post(_ENDPOINT_RES, json=payload_).json()
        #    
        #
        end = time.time()
        time_elapsed = end - start
        time_elapsed = time_elapsed * 1000
        
        try:
            if auth_response["error_hint"] == "GAW0500003":
                logger.error(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
                logger.error(f"However, this proxy is not located in Japan. You will not be able to use it.", extra={"service_name": "Yoimi"})
                exit(1)
        except Exception as e:
            pass
        
        logger.info(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
    except IOError:
        logger.error(f"Connection error of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)
    except:
        logger.error(f"Failed Check Proxies of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        global media_code, playtoken
        #url = "https://video.unext.jp/title/SID0104147"
        #url = "https://video.unext.jp/play/SID0104147/ED00570918"
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema Content for Everyone", extra={"service_name": "Yoimi"})
        if session.proxies != {}:
            check_proxie(session)
        
        unext_downloader = Unext_downloader(session)
        
        if config["authorization"]["use_token"]:
            if config["authorization"]["token"] != "":
                status, message = unext_downloader.check_token(config["authorization"]["token"])
                if status == False:
                    logger.error(message, extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    account_point = str(message["points"])
                    session.headers.update({"Authorization": config["authorization"]["token"]})
                    logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": "U-Next"})
                    logger.info("Loggined Account", extra={"service_name": "U-Next"})
                    logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                    logger.info(" + Point: "+account_point, extra={"service_name": "U-Next"})
            else:
                logger.error("Please input token", extra={"service_name": "U-Next"})
                exit(1)
        else:
            status, message = unext_downloader.authorize(email, password)
            try:
                logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "U-Next"})
            except:
                logger.info("Failed to login", extra={"service_name": "U-Next"})
            if status == False:
                logger.error(message, extra={"service_name": "U-Next"})
                exit(1)
            else:
                account_point = str(message["points"])
                logger.info("Loggined Account", extra={"service_name": "U-Next"})
                logger.info(" + ID: "+message["id"], extra={"service_name": "U-Next"})
                logger.info(" + Point: "+account_point, extra={"service_name": "U-Next"})
            
        status, meta_response = unext_downloader.get_title_metadata(url)
        if status == False:
            logger.error("Failed to Get Series Json", extra={"service_name": "U-Next"})
            exit(1)
        else:
            title_name = meta_response["titleName"]
            
        status = Unext_utils.check_single_episode(url)
        logger.info("Get Video Type for URL", extra={"service_name": "U-Next"})
        status_id, id_type = unext_downloader.get_id_type(url)
        if status_id == False:
            logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
            exit(1)
        logger.info(f" + Video Type: {id_type}", extra={"service_name": "U-Next"})
        if status == False:
            logger.info("Get Title for Season", extra={"service_name": "U-Next"})
            status, messages = unext_downloader.get_title_parse_all(url)
            if status == False:
                logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
                exit(1)
                
            logger.info("Downloading All Episode Thumbnails...", extra={"service_name": "U-Next"})
            
            unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
            
            # Get title for all episode
            for message in messages:
                if id_type[2] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("displayNo", ""),
                        "episodename": message.get("episodeName", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[2] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("displayNo", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("displayNo", ""),
                            "episodename": message.get("episodeName", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
            # ここで各エピソードごとに回してる
            # でもこれだと待ち時間が地獄なので...
            # ここで一括でライセンス取得する
            
            # ここでコメントdl(まとめて)
            for message in messages:
                if additional_info[2]:        
                    sate = {}
                    sate["info"] = {
                        "work_title": title_name,
                        "episode_title": f"{message.get("displayNo", "")} {message.get("episodeName", "")}",
                    #    "duration": 1479,
                        "raw_text": f"{title_name} {message.get("displayNo", "")} {message.get("episodeName", "")}",
                        "series_title": title_name,
                        "episode_text": message.get("displayNo", ""),
                        "episode_number": 1,
                        "subtitle": message.get("episodeName", ""),
                    }
                    
                    def get_niconico_info(stage, data):
                        if stage == 1:
                            querystring = {
                                "q": data,
                                "_sort": "-startTime",
                                "_context": "NCOverlay/3.23.0/Mod For Yoimi",
                                "targets": "title,description",
                                "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
                                "filters[commentCounter][gt]": 0,
                                "filters[genre.keyword][0]": "アニメ",
                                "_offset": 0,
                                "_limit": 20,
                            }
                            
                            result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
                            return result
                        elif stage == 2:
                            result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
                            return result
                        elif stage == 3:
                            payload = {
                                "params":{
                                    "targets": data[1],
                                    "language":"ja-jp"},
                                "threadKey": data[0],
                                "additionals":{}
                            }
                            headers = {
                              "X-Frontend-Id": "6",
                              "X-Frontend-Version": "0",
                              "Content-Type": "application/json"
                            }
                            result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
                            return result
                        
                    logger.info(f"Getting Niconico Comment", extra={"service_name": "U-Next"})
                    return_meta = get_niconico_info(1, sate["info"]["raw_text"])
                    
                    base_content_id = return_meta["data"][0]["contentId"]
                    
                    total_comment = 0
                    total_comment_json = []
                    total_tv = []
                    
                    for index in return_meta["data"]:
                        return_meta = get_niconico_info(2, index["contentId"])
                            
                        filtered_data = [
                            {"id": str(item["id"]), "fork": item["forkLabel"]}
                            for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
                        ]
                        
                        return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
                        for i in return_meta["data"]["globalComments"]:
                            total_comment = total_comment + i["count"]
                        for i in return_meta["data"]["threads"]:
                            for i in i["comments"]:
                                total_comment_json.append(i)
                        if index["tags"].__contains__("dアニメストア"):
                            total_tv.append("dアニメ")
                        else:
                            total_tv.append("公式")
                    
                    def generate_xml(json_data):
                        root = ET.Element("packet", version="20061206")
                        
                        for item in json_data:
                            chat = ET.SubElement(root, "chat")
                            chat.set("no", str(item["no"]))
                            chat.set("vpos", str(item["vposMs"] // 10))
                            timestamp = datetime.fromisoformat(item["postedAt"]).timestamp()
                            chat.set("date", str(int(timestamp)))
                            chat.set("date_usec", "0")
                            chat.set("user_id", item["userId"])
                            
                            if len(item["commands"]) > 1:
                                chat.set("mail", "small shita")
                            else:
                                chat.set("mail", " ".join(item["commands"]))
                            
                            chat.set("premium", "1" if item["isPremium"] else "0")
                            chat.set("anonymity", "0")
                            chat.text = item["body"]
                        
                        return ET.ElementTree(root)
                    
                    def save_xml_to_file(tree, base_filename="output.xml"):
                        directory = os.path.dirname(base_filename)
                        if directory and not os.path.exists(directory):
                            os.makedirs(directory)
                        
                        filename = base_filename
                        counter = 1
                        while os.path.exists(filename):
                            filename = f"{os.path.splitext(base_filename)[0]}_{counter}.xml"
                            counter += 1
                    
                        root = tree.getroot()
                        ET.indent(tree, space="  ", level=0)
                        
                        tree.write(filename, encoding="utf-8", xml_declaration=True)
                        return filename
                    
                    tree = generate_xml(total_comment_json)
                    
                    logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": "U-Next"})
                    logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": "U-Next"})
                    
                    saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
                    
                    logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": "U-Next"})
                    
                    if additional_info[3]:
                        continue
            # ここでライセンス解析(まとめて)
            for message in messages:
                # TODO. ここにいきなコメントを書く
            for message in messages:
                if id_type[2] == "ノーマルアニメ":
                    format_string = config["format"]["anime"]
                    values = {
                        "seriesname": title_name,
                        "titlename": message.get("displayNo", ""),
                        "episodename": message.get("episodeName", "")
                    }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                if id_type[2] == "劇場":
                    format_string = config["format"]["movie"]
                    if message.get("displayNo", "") == "":
                        format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                        values = {
                            "seriesname": title_name,
                        }
                    else:
                        values = {
                            "seriesname": title_name,
                            "titlename": message.get("displayNo", ""),
                            "episodename": message.get("episodeName", "")
                        }
                    try:
                        title_name_logger = format_string.format(**values)
                    except KeyError as e:
                        missing_key = e.args[0]
                        values[missing_key] = ""
                        title_name_logger = format_string.format(**values)
                        
                if message["minimumPrice"] != -1:
                    logger.info(f" ! {title_name_logger} require {message["minimumPrice"]} point", extra={"service_name": "U-Next"})
                    if int(message["minimumPrice"]) > int(account_point):
                        logger.info(f" ! ポイントが足りません", extra={"service_name": "U-Next"})
                        pass
                    else:
                        is_buyed = unext_downloader.check_buyed(url)
                        if is_buyed == True:
                            logger.info(f" ! {title_name_logger} have already been purchased.", extra={"service_name": "U-Next"})
                        else:
                            check_downlaod = input(COLOR_GREEN+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+COLOR_RESET+" "+f"[{COLOR_GRAY}INFO{COLOR_RESET}]"+" "+f"{COLOR_BLUE}U-Next{COLOR_RESET}"+" : "+f" ! Do you want to buy {title_name_logger}?"+" | "+"y/n"+" ")
                            logger.info(f"Coming soon", extra={"service_name": "U-Next"})
                            return
                    
                status, playtoken, media_code = unext_downloader.get_playtoken(message["id"])
                if status == False:
                    logger.error("Failed to Get Episode Playtoken", extra={"service_name": "U-Next"})
                    exit(1)
                else:
                    logger.info(f"Get License for 1 Episode", extra={"service_name": "U-Next"})
                    status, mpd_content = unext_downloader.get_mpd_content(media_code, playtoken)
                    if status == False:
                        logger.error("Failed to Get Episode MPD_Content", extra={"service_name": "U-Next"})
                        logger.error(f"Reason: {mpd_content}", extra={"service_name": "U-Next"})
                        session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                        session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
                        exit(1)
                    mpd_lic = Unext_utils.parse_mpd_logic(mpd_content)
        
                    logger.info(f" + Video PSSH: {mpd_lic["video_pssh"]}", extra={"service_name": "U-Next"})
                    logger.info(f" + Audio PSSH: {mpd_lic["audio_pssh"]}", extra={"service_name": "U-Next"})
                    
                    license_key = Unext_license.license_vd_ad(mpd_lic["video_pssh"], mpd_lic["audio_pssh"], playtoken, session)
                    
                    logger.info(f"Decrypt License for 1 Episode", extra={"service_name": "U-Next"})
                    
                    logger.info(f" + Decrypt Video License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["video_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                    logger.info(f" + Decrypt Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["audio_key"] if key['type'] == 'CONTENT']}", extra={"service_name": "U-Next"})
                                        
                    logger.info("Checking resolution...", extra={"service_name": "U-Next"})
                    resolution_s = mpd_parse.get_resolutions(mpd_content)
                    logger.info("Found resolution", extra={"service_name": "U-Next"})
                    for resolution_one in resolution_s:
                        logger.info(" + "+resolution_one, extra={"service_name": "U-Next"})
                    
                    logger.info("Video, Audio Content Link", extra={"service_name": "U-Next"})
                    video_url = mpd_parse.extract_video_info(mpd_content, resolution_s[-1])["base_url"]
                    audio_url = mpd_parse.extract_audio_info(mpd_content, "48000 audio/mp4 mp4a.40.2")["base_url"]
                    logger.info(" + Video_URL: "+video_url, extra={"service_name": "U-Next"})
                    logger.info(" + Audio_URL: "+audio_url, extra={"service_name": "U-Next"})
                    
                    def sanitize_filename(filename):
                        filename = filename.replace(":", "：").replace("?", "？")
                        return re.sub(r'[<>"/\\|*]', "_", filename)
                    
                    if additional_info[1]:
                        random_string = str(int(time.time() * 1000))
                        title_name_logger_video = random_string+"_video_encrypted.mp4"
                        title_name_logger_audio = random_string+"_audio_encrypted.mp4"
                    else:
                        title_name_logger_video = sanitize_filename(title_name_logger+"_video_encrypted.mp4")
                        title_name_logger_audio = sanitize_filename(title_name_logger+"_audio_encrypted.mp4")
                    
                    logger.info("Downloading Encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                    
                    video_downloaded = unext_downloader.aria2c(video_url, title_name_logger_video, config, unixtime)
                    audio_downloaded = unext_downloader.aria2c(audio_url, title_name_logger_audio, config, unixtime)                    

                    logger.info("Decrypting encrypted Video, Audio Files...", extra={"service_name": "U-Next"})
                    
                    Unext_decrypt.decrypt_all_content(license_key["video_key"], video_downloaded, video_downloaded.replace("_encrypted", ""), license_key["audio_key"], audio_downloaded, audio_downloaded.replace("_encrypted", ""), config)
                    
                    logger.info("Muxing Episode...", extra={"service_name": "U-Next"})
                    
                    result = unext_downloader.mux_episode(title_name_logger_video.replace("_encrypted",""), title_name_logger_audio.replace("_encrypted",""), os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, sanitize_filename(title_name), int(message["duration"]), title_name_logger)
                        
                    dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                    
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        for filename in os.listdir(dir_path):
                            file_path = os.path.join(dir_path, filename)
                            try:
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                                elif os.path.isdir(file_path):
                                    shutil.rmtree(file_path)
                            except Exception as e:
                                print(f"削除エラー: {e}")
                    else:
                        print(f"指定されたディレクトリは存在しません: {dir_path}")
                    
                    logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "U-Next"})
                                           
                    
                    session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
                    session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")
            logger.info("Finished download Series: {}".format(title_name), extra={"service_name": "U-Next"})
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(v)
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))
        session.get(f"https://beacon.unext.jp/beacon/interruption/{media_code}/1/?play_token={playtoken}")
        session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/1/?play_token={playtoken}&last_viewing_flg=0")