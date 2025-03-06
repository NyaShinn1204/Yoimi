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
from mutagen.mp4 import MP4, MP4Cover
from xml.etree import ElementTree as ET
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

def config_load(config, service_name="unext"):
    global load_command
    path1 = os.path.join(config["directorys"]["Service_util"])
    test1 = open(os.path.join(path1.replace("{servicename}", service_name), "command_list.json"), "r")
    load_command = json.load(test1)
    
def find_entry_by_name(json_data, target_name):
    for entry in json_data.get("operations", []):
        if entry.get("name") == target_name:
            entry["body"] = entry["body"].replace("\\n", "\n")
            return entry
    return None

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
    def __init__(self, session, config):
        self.session = session
        self.config = config
        config_load(self.config)
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
        operation_name = "cosmo_getPlaylistUrl"
        return_commandlist = find_entry_by_name(load_command, operation_name)
        meta_json = {
            "operationName": "cosmo_getPlaylistUrl",
            "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
            "query": return_commandlist["body"]
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_playlistUrl"] != None:
                #print(return_json["data"]["webfront_playlistUrl"]["urlInfo"][0])
                #print("moviePartsPositionList" in return_json["data"]["webfront_playlistUrl"]["urlInfo"][0])
                #print("found")
                if ("moviePartsPositionList" in return_json["data"]["webfront_playlistUrl"]["urlInfo"][0]):
                    movieparts = return_json["data"]["webfront_playlistUrl"]["urlInfo"][0]["moviePartsPositionList"]
                else:
                    movieparts = None
                return True, return_json["data"]["webfront_playlistUrl"]["playToken"], return_json["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"], [movieparts]
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
    
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, title_name_logger, episode_number, additional_info, service_name="U-Next"):
        if os.name != 'nt':
            os.makedirs(os.path.join(config["directorys"]["Downloads"], title_name), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
        else:
            def sanitize_filename(filename):
                filename = filename.replace(":", "：").replace("?", "？")
                return re.sub(r'[<>"/\\|*]', "_", filename)
            os.makedirs(os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name)), exist_ok=True)
            output_name = os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name), sanitize_filename(title_name_logger+".mp4"))
        
        base_command = [
            "ffmpeg",
            "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, video_name),  # 動画
            "-i", os.path.join(config["directorys"]["Temp"], "content", unixtime, audio_name),  # 音声
            "-map", "0:v:0",  # 動画ストリームを選択
            "-map", "1:a:0",  # 音声ストリームを選択
            "-c:v", "copy",  # 映像の再エンコードなし
            "-c:a", "copy",  # 音声の再エンコードなし
            "-strict", "experimental",
            "-y",
            "-progress", "pipe:1",  # 進捗を標準出力に出力
            "-nostats",  # 標準出力を進捗情報のみにする
        ]
        
        # メタデータを追加する場合
        if additional_info[6] or additional_info[8]:
            metadata_path = os.path.join(config["directorys"]["Temp"], "content", unixtime, "metadata", f"{episode_number}_metadata.txt")
            base_command.extend(["-i", metadata_path, "-map_metadata", "2"])
        
        ## サムネイルを追加する場合
        #if additional_info[4] or additional_info[5]:
        #    thumbnail_path = os.path.join(config["directorys"]["Temp"], "thumbnail", unixtime, f"thumbnail_{episode_number}.jpg")
        #    base_command.extend(["-i", thumbnail_path, "-map", "2:v:0", "-disposition:v:1", "attached_pic"])  # サムネイルを埋め込み
        
        compile_command = base_command + [output_name]
        
        #print(compile_command)

        #print(" ".join(compile_command))
        # tqdmを使用した進捗表示
        #duration = 1434.93  # 動画全体の長さ（秒）を設定（例: 23分54.93秒）
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
            with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace") as process:
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
    def apply_thumbnail(self, episode_number, title_name, title_name_logger, unixtime, config):
        try:
            if os.name != 'nt':
                mp4_file = os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4")
            else:
                def sanitize_filename(filename):
                    filename = filename.replace(":", "：").replace("?", "？")
                    return re.sub(r'[<>"/\\|*]', "_", filename)
                mp4_file = os.path.join(config["directorys"]["Downloads"], sanitize_filename(title_name), sanitize_filename(title_name_logger+".mp4"))
            thumbnail_file = os.path.join(config["directorys"]["Temp"], "thumbnail", unixtime, f"thumbnail_{episode_number}.jpg")
            
            # MP4ファイルを読み込む
            video = MP4(mp4_file)
            
            # サムネイル画像をバイナリデータとして読み込む
            with open(thumbnail_file, "rb") as f:
                cover = MP4Cover(f.read(), imageformat=MP4Cover.FORMAT_JPEG)
            
            # メタデータとしてサムネイルを追加
            video["covr"] = [cover]
            
            # 変更を保存
            video.save()
            return True
        except:
            return False
    def get_id_type(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''映像タイプを取得するコード'''
        operation_name = "cosmo_getVideoTitle"
        return_commandlist = find_entry_by_name(load_command, operation_name)
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0]},
            "query": return_commandlist["body"]
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                maybe_genre = None
                                
                if return_json["data"]["webfront_title_stage"]["keyEpisodes"]["current"]["playButtonName"] == "再生":
                    maybe_genre = "劇場"
                if return_json["data"]["webfront_title_stage"]["keyEpisodes"]["current"]["playButtonName"].__contains__("第") or return_json["data"]["webfront_title_stage"]["keyEpisodes"]["current"]["playButtonName"].__contains__("#") or return_json["data"]["webfront_title_stage"]["keyEpisodes"]["current"]["playButtonName"].__contains__("を再生"):
                    maybe_genre = "ノーマルアニメ"
                else:
                    maybe_genre = "劇場"
                
                return True, [return_json["data"]["webfront_title_stage"]["mainGenreId"], return_json["data"]["webfront_title_stage"]["mainGenreName"], maybe_genre, return_json["data"]["webfront_title_stage"]["productionYear"], return_json["data"]["webfront_title_stage"]["copyright"]]
            else:
                return False, None
        except Exception as e:
            print("aiueo"+e)
            return False, None
        
    def check_buyed(self, url):
        matches1 = re.findall(r"(SID\d+)|(ED\d+)", url)
        '''購入済みか確認するコード'''
        operation_name = "cosmo_getVideoTitle"
        return_commandlist = find_entry_by_name(load_command, operation_name)
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": [match[0] for match in matches1 if match[0]][0]},
            "query": return_commandlist["body"]
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
        operation_name = "cosmo_videoProductList"
        return_commandlist = find_entry_by_name(load_command, operation_name)
        meta_json = {
            "operationName": "cosmo_videoProductList",
            "variables": {
                "titleCode": title_id,
                "episodeCode": episode_id,
                "deviceType": "700"
            },
            "query": return_commandlist["body"]
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_videoProductList"] != None:
                if return_json["data"]["webfront_videoProductList"]["ppvProducts"][0]["code"]:
                    operation_name = "cosmo_videoProductList"
                    return_commandlist = find_entry_by_name(load_command, operation_name)
                    meta_json = {
                        "operationName": "cosmo_purchaseVideoProduct",
                        "variables": {
                            "productCode": return_json["data"]["webfront_videoProductList"]["ppvProducts"][0]["code"],
                        },
                        "mutation": return_commandlist["body"]
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
        operation_name = "cosmo_getVideoTitle"
        return_commandlist = find_entry_by_name(load_command, operation_name)
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
                "query": return_commandlist["body"]
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
                "query": return_commandlist["body"]
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
                filename = f"{title_id}_episode_image_special_{index}.jpg" if special else f"thumbnail_{index}.jpg"
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
            operation_name = "cosmo_getVideoTitleEpisodes"
            return_commandlist = find_entry_by_name(load_command, operation_name)
            meta_json = {
                "operationName": "cosmo_getVideoTitleEpisodes",
                "variables": {
                    "code": title_id,
                    "page": 1,
                    "pageSize": 100
                },
                "query": return_commandlist["body"]
            }
            
            try:
                metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
                return_json = metadata_response.json()
                if return_json["data"]["webfront_title_titleEpisodes"] is not None:
                    episodes = return_json["data"]["webfront_title_titleEpisodes"]["episodes"]
            
                    # tqdmを使ってプログレスバーを表示
                    with tqdm(total=len(episodes), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"U=Next"}{COLOR_RESET} : ") as pbar:
                        for index, episode in enumerate(episodes):
                            thumbnails = episode.get("thumbnail", {})
                            for key, url in thumbnails.items():
                                if key == "__typename":
                                    continue
                                special = key != "standard"
                                download_image(url, title_id, episode.get("displayNo", {}), special=special)
                            pbar.update(1)  # プログレスバーを更新
                else:
                    print("No episodes found.")
            except Exception as e:
                print(f"Error: {e}")
                
    def create_ffmetadata(self, productionYear, meta_info, unixtime, chapter, episode_number, episode_duration, comment, copyright, additional_info):
        # meta_info = [id_type, series_name, title_name, episodename]
        format_string = self.config["format"]["metadata_title"]
        values = {
            "seriesname": meta_info[1],
            "titlename": meta_info[2],
            "episodename": meta_info[3]
        }
        try:
            title = format_string.format(**values)
        except KeyError as e:
            missing_key = e.args[0]
            values[missing_key] = ""
            title = format_string.format(**values)
        #logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
        if additional_info[8]:
            chapter_text = ""
            if chapter == [[]]:
                pass
            else:
                #print(chapter)
            
                # チャプター情報を取得
                chapters = chapter[0]
            
                # OPENING の前の謎空間
                if chapters[0]["fromSeconds"] > 0:
                    chapter_text += f"\n[CHAPTER]\nTIMEBASE=1/1000\nSTART=0\nEND={chapters[0]['fromSeconds']*1000}\ntitle=\n"
            
                for i in range(len(chapters)):
                    current_chapter = chapters[i]
                    
                    # 現在のチャプターを追加
                    chapter_text += f"\n[CHAPTER]\nTIMEBASE=1/1000\nSTART={current_chapter['fromSeconds']*1000}\nEND={current_chapter['endSeconds']*1000}\ntitle={current_chapter['type']}\n"
            
                    # OPENING と ENDING の間の MAIN チャプター
                    if i < len(chapters) - 1:
                        next_chapter = chapters[i + 1]
                        if current_chapter["endSeconds"] < next_chapter["fromSeconds"]:
                            chapter_text += f"\n[CHAPTER]\nTIMEBASE=1/1000\nSTART={current_chapter['endSeconds']*1000}\nEND={next_chapter['fromSeconds']*1000}\ntitle=\n"
            
                # ENDING の後の謎空間
                last_chapter = chapters[-1]
                if last_chapter["endSeconds"] < episode_duration:
                    chapter_text += f"\n[CHAPTER]\nTIMEBASE=1/1000\nSTART={last_chapter['endSeconds']*1000}\nEND={episode_duration*1000}\ntitle=\n"
        
        # メタデータファイルの作成
        additional_meta = f"comment={comment}\ncopyright={copyright}\n"
        original_metadata = f";FFMETADATA1\ndate={productionYear}\ntitle={title}\n"+additional_meta+"\n"
        if additional_info[8]:
            original_metadata = original_metadata + chapter_text
        filename = episode_number + "_metadata.txt"
        directory = os.path.join(self.config["directorys"]["Temp"], "content", unixtime, "metadata")
        file_path = os.path.join(directory, filename)
        os.makedirs(directory, exist_ok=True)
        
        with open(file_path, "w", encoding="utf-8") as meta_file:
            meta_file.write(original_metadata)