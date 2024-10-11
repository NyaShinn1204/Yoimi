import hashlib
import hmac
import json
import logging
import os
import re
import struct
import string
import tempfile
import time
import uuid
import random
import requests
from base64 import urlsafe_b64encode
from binascii import unhexlify
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

import m3u8
from Crypto.Cipher import AES
from tqdm import tqdm

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
    def __init__(self, url, session):
        self.session = session
        self.type = 'U-Next'
        self.yuu_logger = logging.getLogger('yuu.unext.UNext')

        self.url = url
        self.m3u8_url = None
        self.resolution = None
        self.resolution_o = None
        self.device_id = None
        self.is_m3u8 = False
        self.est_filesize = None # In MiB

        self.resolution_data = {
            "1080p": ["4000kb/s", "AAC 192kb/s 2ch"],
            "720p": ["2000kb/s", "AAC 160kb/s 2ch"],
            "480p": ["900kb/s", "AAC 128kb/s 2ch"],
            "360p": ["550kb/s", "AAC 128kb/s 2ch"],
            "240p": ["240kb/s", "AAC 64kb/s 1ch"],
            "180p": ["120kb/s", "AAC 64kb/s 1ch"]
        }

        self.bitrate_calculation = {
            "1080p": 5175,
            "720p": 2373,
            "480p": 1367,
            "360p": 878,
            "240p": 292,
            "180p": 179
        }

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
        #if not self.device_id:
        #    self.yuu_logger.info('{}: Fetching temporary token'.format(self.type))
        #    res, reas = self.get_token() # Abema needs authorization header before authenticating
        #    if not res:
        #        return res, reas
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
            '180p', '240p', '360p', '480p', '720p', '1080p', 'best', 'worst'
        ]

        if resolution not in res_list:
            if not check_only:
                return None, 'Unknown resolution: {}. (Check it with `-R`)'.format(resolution)

        if resolution == 'best':
            resolution = '1080p'
            self.resolution_o = 'best'
        if resolution == 'worst':
            resolution = '180p'
        
        # https://video.unext.jp/play/SID0104158/ED00547149?ps=2
        # https://video.unext.jp/title/SID0104147
        # https://video.unext.jp/freeword?query=%E3%82%8D%E3%82%B7%E3%83%87%E3%83%AC&td=SID0104147

        series = re.search(r"(title|freeword).*(?:td=|/)(SID\d+)", self.url)
        
        if series:   # Go to series
            video_id = series.group(2)
            self.yuu_logger.info('Series url format detected, fetching all links...')
            self.yuu_logger.debug('Requesting data to Abema API.')
            req = self.session.get(self._SERIESAPI + video_id)
            if req.status_code != 200:
                self.yuu_logger.log(40, 'Abema Response: ' + req.text)
                return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            self.yuu_logger.debug('Data requested')
            self.yuu_logger.debug('Parsing json results...')

            m3u8_url_list = []
            output_list = []

            jsdata = req.json()
            to_be_requested = "{api}{vid}/programs?seriesVersion={sv}&seasonId={si}&offset=0&order={od}&limit=100"

            season_data = jsdata['seasons']
            if not season_data:
                season_data = [{'id': ''}] # Assume film or some shit
            version = jsdata['version']
            prog_order = jsdata['programOrder']
            for ns, season in enumerate(season_data, 1):
                self.yuu_logger.info('Processing season ' + str(ns))
                self.yuu_logger.debug('Requesting data to Abema API.')
                req_season = self.session.get(to_be_requested.format(api=self._SERIESAPI, vid=video_id, sv=version, si=season['id'], od=prog_order))
                if req_season.status_code != 200:
                    self.yuu_logger.log(40, 'Abema Response: ' + req_season.text)
                    return None, 'Error occured when communicating with Abema (Response: {})'.format(req_season.status_code)
                self.yuu_logger.debug('Data requested')
                self.yuu_logger.debug('Parsing json results...')

                season_jsdata = req_season.json()
                self.yuu_logger.debug('Processing total of {ep} episode for season {se}'.format(ep=len(season_jsdata['programs']), se=ns))

                for nep, episode in enumerate(season_jsdata['programs'], 1):
                    free_episode = False
                    if 'label' in episode:
                        if 'free' in episode['label']:
                            free_episode = True
                    elif 'freeEndAt' in episode:
                        free_episode = True

                    if 'episode' in episode:
                        try:
                            episode_name = episode['episode']['title']
                            if not episode_name:
                                episode_name = episode_name['title']['number']
                        except KeyError:
                            episode_name = episode_name['title']['number']
                    else:
                        episode_name = nep

                    if not free_episode and not self.authorized:
                        self.yuu_logger.warn('Skipping episode {} (Not authorized and premium video)'.format(episode_name))
                        continue

                    self.yuu_logger.info('Processing episode {}'.format(episode_name))

                    req_ep = self.session.get(self._PROGRAMAPI + episode['id'])
                    if req_ep.status_code != 200:
                        self.yuu_logger.log(40, 'Abema Response: ' + req_ep.text)
                        return None, 'Error occured when communicating with Abema (Response: {})'.format(req_ep.status_code)
                    self.yuu_logger.debug('Data requested')
                    self.yuu_logger.debug('Parsing json API')

                    ep_json = req_ep.json()
                    title = ep_json['series']['title']
                    epnumber = episode["episode"]["title"]
                    epnum = episode["episode"]["number"]
                    epnumber_tmp = AbemaTV.convert_kanji_to_int(epnumber)
                    if re.match(r'第\d+話\s*(.+)', epnumber_tmp):
                        eptle = re.match(r'第\d+話\s*(.+)', epnumber_tmp).group(1)
                    elif re.search(r'#\d+', epnumber_tmp):
                        eptle = re.match(r'#\d+\s*(.+)', epnumber_tmp).group(1)
                    else:
                        before_space = epnumber_tmp.split(" ")[0]
                        after_space = " ".join(epnumber_tmp.split(" ")[1:])
                        if any(char.isdigit() for char in before_space):
                            eptle = after_space
                        else:
                            eptle = None
                    hls = ep_json['playback']['hls']
                    output_name = title + "_" + epnumber

                    m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])

                    self.yuu_logger.debug('M3U8 Link: {}'.format(m3u8_url))
                    self.yuu_logger.debug('Video title: {}'.format(title))

                    m3u8_url_list.append(m3u8_url)
                    output_list.append(output_name)

            self.resolution = resolution
            self.m3u8_url = m3u8_url_list

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
            #req = self.session.get(self._CHANNELAPI + ep_link)
            #if req.status_code != 200:
            #    self.yuu_logger.log(40, 'Abema Response: ' + req.text)
            #    return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            #self.yuu_logger.debug('Data requested')
            #self.yuu_logger.debug('Parsing json API')
            #
            #jsdata = req.json()
            #output_name = jsdata['slot']['title']
            #if 'playback' in jsdata['slot']:
            #    hls = jsdata['slot']['playback']['hls']
            #else:
            #    hls = jsdata['slot']['chasePlayback']['hls']  # Compat
            #
            #m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
            #if self.is_m3u8:
            #    m3u8_url = self.url
            #
            #self.yuu_logger.debug('M3U8 Link: {}'.format(m3u8_url))
            #self.yuu_logger.debug('Title: {}'.format(output_name))
        else:
            #print(ep_link)
            #title_parse = re.search(r'SID(\d+)/ED(\d+)', ep_link)
            #
            #series_id = title_parse.group(1)

            match = re.search(r'SID(\d+)/ED(\d+)', self.url)
            
            if match:
                se_id = "SID"+match.group(1)
                ep_id = "ED"+match.group(2)
                #print(f"SID: {se_id}, ED: {ep_id}")
            #else:
            #    print("SID or ED not found.")
            
            #episode_id = re.sub(r'\?.*', '', ep_link)
            episode_id = ep_id
            
            playtoken, url_code = self.get_playlist_url(episode_id)
            
            print(playtoken, url_code)
            
            mpd_content = self.get_mpd_content(url_code, playtoken)
            if mpd_content == "":
                return None, 'Error Video is playing (Response: 500)'
            parse_json = self.parse_mpd(mpd_content, playtoken, url_code)
            #print(parse_json)
            
            
            #print(episode_id)
            
            jsdata = self.get_video_episode_meta(episode_id)
            sedata = self.get_video_episodes(se_id)
            print(sedata)
            
            #if ep_link.__contains__("?ps"):
            #    ep_link = ep_link.replace("?ps=2", "")
            #print(ep_link)
            
            
            #status, meta_response, error = get_title_metadata(cleaned_id)
            #if status == True:
            #    abema_get_series_id_extract_episode = re.match(r"(\d+-\d+_s\d+)", abema_get_series_id).group(1)
            #    found_json = next((item for item in meta_response["seasons"] if item['id'] == abema_get_series_id_extract_episode), None)
            #    if found_json is not None:
            
#            req = self.session.get(self._PROGRAMAPI + ep_link)
#            if req.status_code != 200:
#                self.yuu_logger.log(40, 'Abema Response: ' + req.text)
#                return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            self.yuu_logger.debug('Data requested')
            self.yuu_logger.debug('Parsing json API')
#            jsdata = req.json()
#            if jsdata['mediaStatus']:
#                if 'drm' in jsdata['mediaStatus']:
#                    if jsdata['mediaStatus']['drm']:
#                        return None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
#            title = jsdata['series']['title']
#            epnumber = jsdata['episode']['title']
#            if "ライブ" in epnumber.lower() or "live" in epnumber.lower():
#                self.yuu_logger.debug('Live Content: True')
#            else:
#                self.yuu_logger.debug('Live Content: False')
#            epnum = jsdata['episode']['number']
#            epnumber_tmp = AbemaTV.convert_kanji_to_int(epnumber)
#            if re.match(r'第\d+話\s*(.+)', epnumber_tmp):
#                eptle = re.match(r'第\d+話\s*(.+)', epnumber_tmp).group(1)
#            elif re.search(r'#\d+', epnumber_tmp):
#                eptle = re.match(r'#\d+\s*(.+)', epnumber_tmp).group(1)
#            else:
#                before_space = epnumber_tmp.split(" ")[0]
#                after_space = " ".join(epnumber_tmp.split(" ")[1:])
#                if any(char.isdigit() for char in before_space):
#                    eptle = after_space
#                else:
#                    eptle = None
#            hls = jsdata['playback']['hls']
            output_name = sedata["episodeName"] + "_" + jsdata["subTitle"]

            #m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
            #if self.is_m3u8:
            #    m3u8_url = self.url

            #self.yuu_logger.debug('M3U8 Link: {}'.format(m3u8_url))
            self.yuu_logger.debug('Video title: {}'.format(sedata["episodeName"]))
            self.yuu_logger.debug('Episode number: {}'.format(jsdata["subTitle"]))
            #self.yuu_logger.debug('Episode num: {}'.format(epnum))
            #self.yuu_logger.debug('Episode title: {}'.format(eptle))

        self.resolution = resolution
        self.m3u8_url = m3u8_url
        
        self.session.get(f"https://beacon.unext.jp/beacon/stop/{url_code}/1/?play_token={playtoken}&last_viewing_flg=0")

        return output_name, 'Success'


    def parse_m3u8(self, m3u8_url):
        self.yuu_logger.debug('Requesting m3u8')
        r = self.session.get(m3u8_url)
        self.yuu_logger.debug('Data requested')

        if 'timeshift forbidden' in r.text:
            return None, None, None, 'This video can\'t be downloaded for now.'

        if r.status_code == 403:
            return None, None, None, 'This video is geo-locked for Japan only.'

        self.yuu_logger.debug('Parsing m3u8')

        x = m3u8.loads(r.text)
        files = x.files[1:]
        if not files[0]:
            files = files[1:]
        try:
            if 'tsda' in files[5]:
                # Assume DRMed
                return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
        except Exception:
            try:
                if 'tsda' in files[-1]:
                    # Assume DRMed
                    return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
            except Exception:
                if 'tsda' in files[0]:
                    # Assume DRMed
                    return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
        resgex = re.findall(r'(\d*)(?:\/\w+.ts)', files[0])[0]
        keys_data = x.keys[0]
        iv = x.keys[0].iv
        ticket = x.keys[0].uri[18:]

        parsed_files = []
        for f in files:
            if f.startswith('/tsvpg') or f.startswith('/tspg'):
                f = 'https://ds-vod-abematv.akamaized.net' + f
            parsed_files.append(f)

        if self.resolution[:-1] != resgex:
            if not self.resolution_o:
                self.yuu_logger.warn('Changing resolution, from {} to {}p'.format(self.resolution, resgex))
            self.resolution = resgex + 'p'
        self.yuu_logger.debug('Total files: {}'.format(len(files)))
        self.yuu_logger.debug('IV: {}'.format(iv))
        self.yuu_logger.debug('Ticket key: {}'.format(ticket))

        n = 0.0
        for seg in x.segments:
            n += seg.duration

        self.est_filesize = round((round(n) * self.bitrate_calculation[self.resolution]) / 1024 / 6, 2)

        return parsed_files, iv[2:], ticket, 'Success'

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
        print(response.json()["data"])
        return (
            response.json()["data"]["webfront_playlistUrl"]["playToken"],
            response.json()["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"],
        ) 
        
    def get_mpd_content(self, url_code, playtoken):
        # 18c529a7-04df-41ee-b230-07f95ecd2561 MEZ0000593320
        response = self.session.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"})
        
        #print(response.status_code)
        return response.text

    def get_video_episode_meta(self, episode_id):
        meta_json = {
            "operationName": "cosmo_getPlaylistUrl",
            "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
            "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
        }
        response = self.session.post(self._COMMANDCENTER_API, json=meta_json)
        return response.json()["data"]["webfront_playlistUrl"]

    def parse_mpd(self, content, playtoken, url_code):
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
            "playtoken": playtoken,
            "video_pssh": video_pssh.text,
            "audio_pssh": audio_pssh.text,
            "url_code": url_code,
            "video": videos,
            "audio": audios[0] if audios else {}
        }
        
        return result

    def get_video_key(self, ticket):
        self.yuu_logger.debug('Sending parameter to API')
        restoken = self.session.get(self._MEDIATOKEN_API, params=self._KEYPARAMS).json()
        mediatoken = restoken['token']
        self.yuu_logger.debug('Media token: {}'.format(mediatoken))

        self.yuu_logger.debug('Sending ticket and media token to License API')
        rgl = self.session.post(self._LICENSE_API, params={"t": mediatoken}, json={"kv": "a", "lt": ticket})
        if rgl.status_code == 403:
            return None, 'Access to this video are not allowed\nProbably a premium video or geo-locked.'

        gl = rgl.json()

        cid = gl['cid']
        k = gl['k']

        self.yuu_logger.debug('CID: {}'.format(cid))
        self.yuu_logger.debug('K: {}'.format(k))

        self.yuu_logger.debug('Summing up data with STRTABLE')
        res = sum([self._STRTABLE.find(k[i]) * (58 ** (len(k) - 1 - i)) for i in range(len(k))])

        self.yuu_logger.debug('Result: {}'.format(res))
        self.yuu_logger.debug('Intepreting data')

        encvk = struct.pack('>QQ', res >> 64, res & 0xffffffffffffffff)

        self.yuu_logger.debug('Encoded video key: {}'.format(encvk))
        self.yuu_logger.debug('Hashing data')

        h = hmac.new(unhexlify(self._HKEY), (cid + self.device_id).encode("utf-8"), digestmod=hashlib.sha256)
        enckey = h.digest()

        self.yuu_logger.debug('Second Encoded video key: {}'.format(enckey))
        self.yuu_logger.debug('Decrypting result')

        aes = AES.new(enckey, AES.MODE_ECB)
        vkey = aes.decrypt(encvk)

        self.yuu_logger.debug('Decrypted, Result: {}'.format(vkey))

        return vkey, 'Success getting video key'


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
            if ext_ != 'ts':
                output = fn_ + '.ts'
        else:
            output = '{}.ts'.format(output_name)

        return output
