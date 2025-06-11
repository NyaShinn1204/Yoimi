import json
import logging
import os
import re
import string
import tempfile
import subprocess
import random
import requests
from binascii import unhexlify
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

from xml.etree import ElementTree as ET

import m3u8
from Crypto.Cipher import AES
from tqdm import tqdm

# 破損原因
# playtokenを取得後にファイルをダウンロードしてる
# 以上
# :middle_finger:

def is_channel(url):
    url = re.findall('(slot)', url)
    if url:
        return True
    return False

yuu_log = logging.getLogger('yuu.unext')

class UNextDownloader:
    def __init__(self, url, session):
        self.key = None
        self.iv = None

        self.url = url
        self.session = session

        self.merge = True

        if os.name == "nt":
            self.yuu_folder = os.path.join(os.getenv('LOCALAPPDATA'), 'yuu_data')
            sffx = '\\'
        else:
            self.yuu_folder = os.path.join(os.getenv('HOME'), '.yuu_data')
            sffx = '/'
        if not os.path.isdir(self.yuu_folder):
            os.mkdir(self.yuu_folder)

        self.temporary_folder = tempfile.mkdtemp(dir=self.yuu_folder)
        self.temporary_folder = self.temporary_folder + sffx

        self._aes = None

    def setup_decryptor(self):
        self.iv = unhexlify(self.iv)
        self._aes = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        
    
    def mp4decrypt(self, keys):
        if os.name == "nt":
            mp4decrypt_command = [os.path.join("binaries", "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join("binaries", "mp4decrypt")]
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
    
    
    def decrypt_content(self, keys, input_file, output_file):
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"{input_file} not found.")
        
        mp4decrypt_command = self.mp4decrypt(keys)
        mp4decrypt_command.extend([input_file, output_file])
        
        # 「ｲ」の数を最大100として進捗バーを作成
        with tqdm(total=100, desc="Decrypting Content", unit="%") as pbar:
            with subprocess.Popen(mp4decrypt_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
                for line in process.stdout:
                    match = re.search(r"(ｲ+)", line)
                    if match:
                        progress_count = len(match.group(1))
                        pbar.n = progress_count
                        pbar.refresh()
            
            process.wait()
            pbar.close()
        
    def mux_episode(self, video_name, audio_name, output_name):
        compile_command = [
            "ffmpeg",
            "-i",
            os.path.join(self.temporary_folder, video_name),
            "-i",
            os.path.join(self.temporary_folder, audio_name),
            "-c:v",
            "copy",
            "-c:a",
            "copy",
            "-strict",
            "experimental",
            output_name,
        ]
        subprocess.run(compile_command)
            
    def download_episode(self, video_url, audio_url, _out_, episode_license):
        try:
            # 動画のダウンロード処理
            vid_response = self.session.get(video_url, stream=True)
            vid_response.raise_for_status()
            vid_size = int(vid_response.headers.get('content-length', 0))
            
            outputtemp = self.temporary_folder + os.path.basename(_out_.replace(".mp4", "_encrypt_video.mp4").replace(" ", "_"))
            
            with open(outputtemp, 'wb') as outf, tqdm(total=vid_size, desc='Downloading Video', ascii=True, unit='B', unit_scale=True) as pbar:
                for chunk in vid_response.iter_content(chunk_size=1024):
                    if chunk:
                        outf.write(chunk)
                        pbar.update(len(chunk))
            
            self.decrypt_content(episode_license["video_key"], outputtemp, outputtemp.replace("_encrypt_video.mp4", "_decrypt_video.mp4"))
            
            # 音声のダウンロード処理
            aud_response = self.session.get(audio_url, stream=True)
            aud_response.raise_for_status()
            aud_size = int(aud_response.headers.get('content-length', 0))
            
            outputtemp = self.temporary_folder + os.path.basename(_out_.replace(".mp4", "_encrypt_audio.mp4").replace(" ", "_"))
            
            with open(outputtemp, 'wb') as outf, tqdm(total=aud_size, desc='Downloading Audio', ascii=True, unit='B', unit_scale=True) as pbar:
                for chunk in aud_response.iter_content(chunk_size=1024):
                    if chunk:
                        outf.write(chunk)
                        pbar.update(len(chunk))
            
            self.decrypt_content(episode_license["audio_key"], outputtemp, outputtemp.replace("_encrypt_audio.mp4", "_decrypt_audio.mp4"))
            
        except KeyboardInterrupt:
            yuu_log.warn('User pressed CTRL+C, cleaning up...')
            return None
        except Exception as err:
            yuu_log.error(f'Problem occurred\nreason: {err}')
            return None
        
    def download_chunk(self, files, key, iv):
        if iv.startswith('0x'):
            self.iv = iv[2:]
        else:
            self.iv = iv
        self.key = key
        self.downloaded_files = []
        self.setup_decryptor() # Initialize a new decryptor
        try:
            with tqdm(total=len(files), desc='Downloading', ascii=True, unit='file') as pbar:
                for tsf in files:
                    outputtemp = self.temporary_folder + os.path.basename(tsf)
                    if outputtemp.find('?tver') != -1:
                        outputtemp = outputtemp[:outputtemp.find('?tver')]
                    with open(outputtemp, 'wb') as outf:
                        try:
                            vid = self.session.get(tsf)
                            vid = self._aes.decrypt(vid.content)
                            outf.write(vid)
                        except Exception as err:
                            yuu_log.error('Problem occured\nreason: {}'.format(err))
                            return None
                    pbar.update()
                    self.downloaded_files.append(outputtemp)
        except KeyboardInterrupt:
            yuu_log.warn('User pressed CTRL+C, cleaning up...')
            return None
        return self.downloaded_files


class UNext:
    
    class mpd_parse:
        @staticmethod
        def extract_video_info(mpd_content, value, resolution_data):
            namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
            root = ET.fromstring(mpd_content)
        
            for adaptation_set in root.findall('.//AdaptationSet', namespaces):
                content_type = adaptation_set.get('contentType', '')
                
                if content_type == 'video':
                    for representation in adaptation_set.findall('Representation', namespaces):
                        width = representation.get('width')
                        height = representation.get('height')
                        resolution = f"{width}x{height} mp4"
                        
                        if resolution == resolution_data[value][0]:
                            base_url_element = representation.find('BaseURL', namespaces)
                            base_url = base_url_element.text if base_url_element is not None else None
                            return {"base_url": base_url}
            return None
    
        @staticmethod
        def extract_audio_info(mpd_content, bandwidth_calculation_audio):
            namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
            root = ET.fromstring(mpd_content)
        
            audio_bandwidth = bandwidth_calculation_audio
        
            audio_adaptation_set = root.find(".//AdaptationSet[@contentType='audio']", namespaces)
        
            if audio_adaptation_set is not None:
                for representation in audio_adaptation_set.findall('Representation', namespaces):
                    if (representation.get('bandwidth') == audio_bandwidth):
                        
                        base_url_element = representation.find('BaseURL', namespaces)
                        base_url = base_url_element.text if base_url_element is not None else None
                        return {"base_url": base_url}
        
            return None
    
    def __init__(self, url, session):
        self.session = session
        self.type = 'U-Next'
        self.yuu_logger = logging.getLogger('yuu.unext.UNext')

        self.url = url
        self.m3u8_url = None
        self.episode_license = None
        self.play_token = None
        self.mpd_file = None
        self.resolution = None
        self.resolution_o = None
        self.device_id = None
        self.is_m3u8 = False
        self.est_filesize = None # In MiB

        #self.resolution_data = {
        #    "1080p": ["4000kb/s", "AAC 192kb/s 2ch"],
        #    "720p": ["2000kb/s", "AAC 160kb/s 2ch"],
        #    "480p": ["900kb/s", "AAC 128kb/s 2ch"],
        #    "360p": ["550kb/s", "AAC 128kb/s 2ch"],
        #    "240p": ["240kb/s", "AAC 64kb/s 1ch"],
        #    "180p": ["120kb/s", "AAC 64kb/s 1ch"]
        #}
        

        self.resolution_data = {
            "1080p": ["1920x1080 mp4"],
            "720p": ["1280x720 mp4"],
            "396p": ["704x396 mp4"],
        }

        self.bitrate_calculation = {
            "1080p": 5175,
            "720p": 2373,
            "480p": 1367,
            "360p": 878,
            "240p": 292,
            "180p": 179
        }
        self.bandwidth_calculation = {
            "1080p": 4017744,
            "720p": 2442656,
            "396p": 1431904
        }
        self.bandwidth_calculation_audio = "125448"
        #self.height_calculation = {
        #    "1080p": 1920*1080,
        #    "720p": 1280*720,
        #    "396p": 704*396,
        #}

        self.authorization_required = True
        self.authorized = False # Ignore for now

        self.resumable = True

        self._STRTABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        self._HKEY = b"3AF0298C219469522A313570E8583005A642E73EDD58E3EA2FB7339D3DF1597E"

        self._KEYPARAMS = {
            "osName": "android",
            "osVersion": "6.0.1",
            "osLand": "ja_JP",
            "osTimezone": "Asia/Tokyo",
            "appId": "tv.abema",
            "appVersion": "3.27.1"
        }

        self._MEDIATOKEN_API = "https://api.abema.io/v1/media/token"
        self._LICENSE_API = "https://license.abema.io/abematv-hls"
        self._USERAPI = "https://api.abema.io/v1/users"
        self._PROGRAMAPI = 'https://api.abema.io/v1/video/programs/'
        self._CHANNELAPI = 'https://api.abema.io/v1/media/slots/'
        self._SERIESAPI = "https://api.abema.io/v1/video/series/"
        self._WVPROXY = "https://wvproxy.unext.jp/proxy"
        
        self._COMMANDCENTER_API = "https://cc.unext.jp"

        # Use Chrome UA
        self.session.headers.update({"User-Agent": "U-NEXT Phone App Android7.1.2 5.29.0 SM-G955N"})


    def convert_kanji_to_int(string):
        """
        Return "漢数字" to "算用数字"
        """
        result = string.translate(str.maketrans("零〇一壱二弐三参四五六七八九拾", "00112233456789十", ""))
        convert_table = {"十": "0", "百": "00", "千": "000"}
        unit_list = "|".join(convert_table.keys())
        while re.search(unit_list, result):
            for unit in convert_table.keys():
                zeros = convert_table[unit]
                for numbers in re.findall(rf"(\d+){unit}(\d+)", result):
                    result = result.replace(numbers[0] + unit + numbers[1], numbers[0] + zeros[len(numbers[1]):len(zeros)] + numbers[1])
                for number in re.findall(rf"(\d+){unit}", result):
                    result = result.replace(number + unit, number + zeros)
                for number in re.findall(rf"{unit}(\d+)", result):
                    result = result.replace(unit + number, "1" + zeros[len(number):len(zeros)] + number)
                result = result.replace(unit, "1" + zeros)
        return result

    def __repr__(self):
        return '<yuu.AbemaTV: URL={}, Resolution={}, Device ID={}, m3u8 URL={}>'.format(self.url, self.resolution, self.device_id, self.m3u8_url)

    def get_downloader(self):
        """
        Return a :class: of the Downloader
        """
        return UNextDownloader(self.url, self.session)

    def resume_prepare(self):
        """
        Add support for resuming files, this function will prepare everything to start resuming download.
        """
        return None

    def random_name(self, length):
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def authorize(self, username, password):
        _ENDPOINT_CHALLENG_ID = 'https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback'
        _ENDPOINT_RES = 'https://oauth.unext.jp/oauth2/login'
        _ENDPOINT_OAUTH = 'https://oauth.unext.jp{pse}'
        _ENDPOINT_TOKEN = 'https://oauth.unext.jp/oauth2/token'
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.search(mail_regex, username):
            response = self.session.get(_ENDPOINT_CHALLENG_ID.format(state=self.random_name(43),nonce=self.random_name(43)))
                        
            script_tag = BeautifulSoup(response.text, "html.parser").find("script", {"id": "__NEXT_DATA__"})
            json_data = json.loads(script_tag.string)
            challenge_id = json_data.get("props", {}).get("challengeId")
            
            payload_ = {
                "id": username,
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
            self.yuu_logger.debug('U-Next Response: {}'.format("Failed login"))
            return False, 'Wrong Email or password combination'

        res_j = res.json()
        self.yuu_logger.debug('Authentication Token: {}'.format(res_j.get('access_token')))
        self.session.headers.update({'Authorization': 'Bearer ' + res_j.get('access_token')})
                
        self.authorized = True
        return True, 'Authorized'

    def parse(self, resolution=None, check_only=False):
        """
        Function to parse abema url
        """

        res_list = [
            '396p', '720p', '1080p', 'best', 'worst'
        ]

        if resolution not in res_list:
            if not check_only:
                return None, 'Unknown resolution: {}. (Check it with `-R`)'.format(resolution)

        if resolution == 'best':
            resolution = '1080p'
            self.resolution_o = 'best'
        if resolution == 'worst':
            resolution = '396p'
        
        # https://video.unext.jp/play/SID0104158/ED00547149?ps=2
        # https://video.unext.jp/title/SID0104147
        # https://video.unext.jp/freeword?query=%E3%82%8D%E3%82%B7%E3%83%87%E3%83%AC&td=SID0104147

        series = re.search(r"(title|freeword).*(?:td=|/)(SID\d+)", self.url)
        
        if series:   # Go to series
            title_id = series.group(2)
            episode_list = self.get_video_all_episodes(title_id)
            #video_id = series.group(2)
            #self.yuu_logger.info('Series url format detected, fetching all links...')
            #self.yuu_logger.debug('Requesting data to Abema API.')
            #req = self.session.get(self._SERIESAPI + video_id)
            #if req.status_code != 200:
            #    self.yuu_logger.log(40, 'Abema Response: ' + req.text)
            #    return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            #self.yuu_logger.debug('Data requested')
            #self.yuu_logger.debug('Parsing json results...')
#
            m3u8_url_list = []
            output_list = []
#
            #jsdata = req.json()
            #to_be_requested = "{api}{vid}/programs?seriesVersion={sv}&seasonId={si}&offset=0&order={od}&limit=100"
#
            #season_data = jsdata['seasons']
            #if not season_data:
            #    season_data = [{'id': ''}] # Assume film or some shit
            #version = jsdata['version']
            #prog_order = jsdata['programOrder']
            for episode_meta in episode_list:
                playtoken, url_code, episode_url = self.get_playlist_url(episode_meta["id"])
                
                jsdata = self.get_video_episode_meta(episode_meta["id"])
                sedata = self.get_video_episodes(title_id)
                
                self.yuu_logger.debug('Data requested')
                self.yuu_logger.debug('Parsing json API')
                self.mpd_file = self.get_mpd_content(episode_url, playtoken)
                mpd_lic = self.parse_mpd_logic(self.mpd_file)
                            
                            
                self.episode_license = self.get_episode_license(mpd_lic["video_pssh"],  mpd_lic["audio_pssh"], playtoken)
                output_name = sedata["episodeName"] + "_" + jsdata["subTitle"]
                self.est_filesize = self.calculate_video_size(self.bandwidth_calculation[resolution], 2997)
                self.yuu_logger.debug('Episode Link: {}'.format(episode_url))
                self.yuu_logger.debug('Video title: {}'.format(sedata["episodeName"]))
                self.yuu_logger.debug('Episode number: {}'.format(jsdata["subTitle"]))
                self.yuu_logger.debug('Video License: {}'.format(self.episode_license["video_key"]))
                self.yuu_logger.debug('Audio License: {}'.format(self.episode_license["audio_key"]))
                
                self.session.get(f"https://beacon.unext.jp/beacon/interruption/{url_code}/1/?play_token={playtoken}")
                self.session.get(f"https://beacon.unext.jp/beacon/stop/{url_code}/1/?play_token={playtoken}&last_viewing_flg=0")
                
                m3u8_url_list.append(episode_url)
                output_list.append(output_name)
                    
            self.resolution = resolution
            self.m3u8_url = m3u8_url_list
            self.play_token = playtoken

            if not output_list:
                err_msg = "All video are for premium only, please provide login details."
            else:
                err_msg = "Success"

            return output_list, err_msg

        if '.m3u8' in self.url[-5:]:
            reg = re.compile(r'(program|slot)\/[\w+-]+')
            self.url = re.search(reg, m3u8)[0]
            self.is_m3u8 = True

        ep_link = self.url[self.url.rfind('/')+1:]

        self.yuu_logger.debug('Requesting data to Abema API')  # Go to episode
        
        
        if is_channel(self.url):
            self.yuu_logger.info(40, "haha unext is not found is_channel")
        else:
            match = re.search(r'SID(\d+)/ED(\d+)', self.url)
            
            if match:
                se_id = "SID"+match.group(1)
                ep_id = "ED"+match.group(2)
            
            episode_id = ep_id
            
            playtoken, url_code, episode_url = self.get_playlist_url(episode_id)
            
            jsdata = self.get_video_episode_meta(episode_id)
            sedata = self.get_video_episodes(se_id)
            
            self.yuu_logger.debug('Data requested')
            self.yuu_logger.debug('Parsing json API')
            self.mpd_file = self.get_mpd_content(episode_url, playtoken)
            mpd_lic = self.parse_mpd_logic(self.mpd_file)
            
            self.episode_license = self.get_episode_license(mpd_lic["video_pssh"],  mpd_lic["audio_pssh"], playtoken)
            
            output_name = sedata["episodeName"] + "_" + jsdata["subTitle"]
                        
            self.est_filesize = self.calculate_video_size(self.bandwidth_calculation[resolution], 2997)
            
            self.yuu_logger.debug('Episode Link: {}'.format(episode_url))
            self.yuu_logger.debug('Video title: {}'.format(sedata["episodeName"]))
            self.yuu_logger.debug('Episode number: {}'.format(jsdata["subTitle"]))
            self.yuu_logger.debug('Video License: {}'.format(self.episode_license["video_key"]))
            self.yuu_logger.debug('Audio License: {}'.format(self.episode_license["audio_key"]))

        self.resolution = resolution
        self.m3u8_url = episode_url
        self.play_token = playtoken
        
        self.session.get(f"https://beacon.unext.jp/beacon/interruption/{url_code}/1/?play_token={playtoken}")
        self.session.get(f"https://beacon.unext.jp/beacon/stop/{url_code}/1/?play_token={playtoken}&last_viewing_flg=0")
        
        return output_name, 'Success'

    def get_video_episodes(self, title_name):
        meta_json = {
            "operationName": "cosmo_getVideoTitleEpisodes",
            "variables": {"code": title_name},
            "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        response = self.session.post(self._COMMANDCENTER_API, json=meta_json)
        return (
            response.json()["data"]["webfront_title_titleEpisodes"]["episodes"][0]
        )
        
    def get_video_all_episodes(self, title_name):
        meta_json = {
            "operationName": "cosmo_getVideoTitleEpisodes",
            "variables": {"code": title_name},
            "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        response = self.session.post(self._COMMANDCENTER_API, json=meta_json)
        return (
            response.json()["data"]["webfront_title_titleEpisodes"]["episodes"]
        )

    def get_playlist_url(self, episode_id):
        meta_json = {
            "operationName": "cosmo_getPlaylistUrl",
            "variables": {
                "code": episode_id,
                "playMode": "dub",
                "bitrateLow": 1500,
                "bitrateHigh": None,
                "validationOnly": False,
            },
            "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        response = self.session.post(self._COMMANDCENTER_API, json=meta_json)
        return (
            response.json()["data"]["webfront_playlistUrl"]["playToken"],
            response.json()["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"],
            response.json()["data"]["webfront_playlistUrl"]["urlInfo"][0]["movieProfile"][0]["playlistUrl"]
        ) 
        
    def get_mpd_content(self, episode_url, playtoken):
        response = self.session.get(f"{episode_url}&play_token={playtoken}")
        return response.text

    def get_video_episode_meta(self, episode_id):
        meta_json = {
            "operationName": "cosmo_getPlaylistUrl",
            "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
            "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        response = self.session.post(self._COMMANDCENTER_API, json=meta_json)
        return response.json()["data"]["webfront_playlistUrl"]

    def parse_mpd_logic(self, content):
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

    def get_episode_license(self, video_pssh, audio_pssh, playtoken):
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
        response_video = self.session.post(f"{self._WVPROXY}?play_token={playtoken}", data=challenge_video)    
        response_video.raise_for_status()
        response_audio = self.session.post(f"{self._WVPROXY}?play_token={playtoken}", data=challenge_audio)    
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

    def calculate_video_size(self, bandwidth_bps, duration_sec):
        size_bytes = (bandwidth_bps * duration_sec) / 8
        size_megabytes = size_bytes / (1024 * 1024)
        return str(int(size_megabytes))


    def resolutions(self, m3u8_uri):
        self.yuu_logger.debug('Requesting data to API')

        m3u8_ = m3u8_uri[:m3u8_uri.rfind('/')]
        base_url = m3u8_[:m3u8_.rfind('/')] + '/'
        m3u8_1080 = m3u8_[:m3u8_.rfind('/')] + '/1080/playlist.m3u8'
        m3u8_720 = m3u8_[:m3u8_.rfind('/')] + '/720/playlist.m3u8'
        m3u8_480 = m3u8_[:m3u8_.rfind('/')] + '/480/playlist.m3u8'
        m3u8_360 = m3u8_[:m3u8_.rfind('/')] + '/360/playlist.m3u8'
        m3u8_240 = m3u8_[:m3u8_.rfind('/')] + '/240/playlist.m3u8'
        m3u8_180 = m3u8_[:m3u8_.rfind('/')] + '/180/playlist.m3u8'

        rr_all = self.session.get(base_url + 'playlist.m3u8')

        if 'timeshift forbidden' in rr_all.text:
            return None, 'This video can\'t be downloaded for now.'

        r_all = m3u8.loads(rr_all.text)

        play_res = []
        for r_p in r_all.playlists:
            temp = []
            temp.append(r_p.stream_info.resolution)
            temp.append(base_url + r_p.uri)
            play_res.append(temp)

        resgex = re.compile(r'(\d*)(?:\/\w+.ts)')

        ava_reso = []
        for resdata in play_res:
            reswh, m3u8_uri = resdata
            resw, resh = reswh
            self.yuu_logger.debug('Validating {}p resolution'.format(resh))
            rres = m3u8.loads(self.session.get(m3u8_uri).text)

            m3f = rres.files[1:]
            if not m3f:
                return None, 'This video can\'t be downloaded for now.'
            self.yuu_logger.debug('Sample link: ' + m3f[5])

            if 'tsda' in rres.files[5]:
                # Assume DRMed
                return None, 'This video has a different DRM method and cannot be decrypted by yuu for now'

            if str(resh) in re.findall(resgex, m3f[5]):
                ava_reso.append(
                    [
                        '{h}p'.format(h=resh),
                        '{w}x{h}'.format(w=resw, h=resh)
                    ]
                )

        if ava_reso:
            reso = [r[0] for r in ava_reso]
            self.yuu_logger.debug('Resolution list: {}'.format(', '.join(reso)))

        return ava_reso, 'Success'

    def check_output(self, output=None, output_name=None):
        if output:
            fn_, ext_ = os.path.splitext(output)
            if ext_ != 'mp4':
                output = fn_ + '.mp4'
        else:
            output = '{}.mp4'.format(output_name)

        return output
