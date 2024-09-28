import hashlib
import hmac
import json
import logging
import os
import re
import struct
import tempfile
import time
import uuid
from base64 import urlsafe_b64encode
from binascii import unhexlify

import m3u8
from Crypto.Cipher import AES
from tqdm import tqdm

def is_channel(url):
    url = re.findall('(slot)', url)
    if url:
        return True
    return False

yuu_log = logging.getLogger('yuu.abematv')

class AbemaTVDownloader:
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


class AbemaTV:
    def __init__(self, url, session):
        self.session = session
        self.type = 'AbemaTV'
        self.yuu_logger = logging.getLogger('yuu.abematv.AbemaTV')

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

        self.authorization_required = False
        self.authorized = False # Ignore for now
        #self.authorize = True # Ignore for now

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

        # Use Chrome UA
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'})


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
        return AbemaTVDownloader(self.url, self.session)

    def resume_prepare(self):
        """
        Add support for resuming files, this function will prepare everything to start resuming download.
        """
        return None

    def authorize(self, username, password):
        if not self.device_id:
            self.yuu_logger.info('{}: Fetching temporary token'.format(self.type))
            res, reas = self.get_token() # Abema needs authorization header before authenticating
            if not res:
                return res, reas
        _ENDPOINT_MAIL = 'https://api.abema.io/v1/auth/user/email'
        _ENDPOINT_OTP = 'https://api.abema.io/v1/auth/oneTimePassword'
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.search(mail_regex, username):
            _ENDPOINT_USE = _ENDPOINT_MAIL
            _USERNAME_METHOD = 'email'
        else:
            _ENDPOINT_USE = _ENDPOINT_OTP
            _USERNAME_METHOD = 'userId'
        auth_ = {
            _USERNAME_METHOD: username,
            "password": password
        }

        res = self.session.post(_ENDPOINT_USE, json=auth_)
        if res.status_code > 299:
            res_j = res.json()
            self.yuu_logger.debug('Abema Response: {}'.format(res_j['message']))
            return False, 'Wrong {} and password combination'.format(_USERNAME_METHOD)

        res_j = res.json()
        self.yuu_logger.debug('Authentication Token: {}'.format(res_j['token']))
        self.session.headers.update({'Authorization': 'bearer ' + res_j['token']})

        self.authorized = True
        return True, 'Authorized'


    def get_token(self):
        def key_secret(devid):
            SECRETKEY = (b"v+Gjs=25Aw5erR!J8ZuvRrCx*rGswhB&qdHd_SYerEWdU&a?3DzN9B"
                        b"Rbp5KwY4hEmcj5#fykMjJ=AuWz5GSMY-d@H7DMEh3M@9n2G552Us$$"
                        b"k9cD=3TxwWe86!x#Zyhe")
            deviceid = devid.encode("utf-8")
            ts_1hour = (int(time.time()) + 60 * 60) // 3600 * 3600
            time_struct = time.gmtime(ts_1hour)
            ts_1hour_str = str(ts_1hour).encode("utf-8")

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(SECRETKEY)
            tmp = h.digest()

            for _ in range(time_struct.tm_mon):
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(urlsafe_b64encode(tmp).rstrip(b"=") + deviceid)
            tmp = h.digest()

            for _ in range(time_struct.tm_mday % 5):
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(urlsafe_b64encode(tmp).rstrip(b"=") + ts_1hour_str)
            tmp = h.digest()

            for _ in range(time_struct.tm_hour % 5):  # utc hour
                h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
                h.update(tmp)
                tmp = h.digest()

            finalize = urlsafe_b64encode(tmp).rstrip(b"=").decode("utf-8")

            self.yuu_logger.debug('Secret Key: {}'.format(finalize))

            return finalize

        if self.authorized: # Ignore this if already login
            return True, 'Success'

        deviceid = str(uuid.uuid4())
        self.yuu_logger.debug('Generated Device UUID: {}'.format(deviceid))
        json_data = {"deviceId": deviceid, "applicationKeySecret": key_secret(deviceid)}
        self.yuu_logger.debug('Generated applicationKeySecret: {}'.format(json_data['applicationKeySecret']))

        self.yuu_logger.debug('Sending json data')
        res = self.session.post(self._USERAPI, json=json_data).json()

        try:
            self.yuu_logger.debug('Data sent, getting token')
            token = res['token']
            self.yuu_logger.debug('User token: {}'.format(token))
        except:
            return None, 'Failed to get user token.'

        self.device_id = deviceid
        self.session.headers.update({'Authorization': 'bearer ' + token})

        return 'Success', 'Success'


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

        # https://abema.tv/video/title/26-55 (series/playlists)
        # https://api.abema.io/v1/video/series/26-55
        # https://api.abema.io/v1/video/series/26-55/programs?seriesVersion=1577436473958778090&seasonId=26-55_s1&offset=0&order=seq&limit=40

        series = re.search(r"(?P<series>title)/(?P<video_id>.*[^-_])", self.url)

        if series:
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
            to_be_requested = "{api}{vid}/programs?seriesVersion={sv}&seasonId={si}&offset=0&order={od}"

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

        self.yuu_logger.debug('Requesting data to Abema API')
        if is_channel(self.url):
            req = self.session.get(self._CHANNELAPI + ep_link)
            if req.status_code != 200:
                self.yuu_logger.log(40, 'Abema Response: ' + req.text)
                return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            self.yuu_logger.debug('Data requested')
            self.yuu_logger.debug('Parsing json API')

            jsdata = req.json()
            output_name = jsdata['slot']['title']
            if 'playback' in jsdata['slot']:
                hls = jsdata['slot']['playback']['hls']
            else:
                hls = jsdata['slot']['chasePlayback']['hls']  # Compat

            m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
            if self.is_m3u8:
                m3u8_url = self.url

            self.yuu_logger.debug('M3U8 Link: {}'.format(m3u8_url))
            self.yuu_logger.debug('Title: {}'.format(output_name))
        else:
            req = self.session.get(self._PROGRAMAPI + ep_link)
            if req.status_code != 200:
                self.yuu_logger.log(40, 'Abema Response: ' + req.text)
                return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code)
            self.yuu_logger.debug('Data requested')
            self.yuu_logger.debug('Parsing json API')
            jsdata = req.json()
            if jsdata['mediaStatus']:
                if 'drm' in jsdata['mediaStatus']:
                    if jsdata['mediaStatus']['drm']:
                        return None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
            title = jsdata['series']['title']
            epnumber = jsdata['episode']['title']
            if "ライブ" in epnumber.lower() or "live" in epnumber.lower():
                self.yuu_logger.debug('Live Content: True')
            else:
                self.yuu_logger.debug('Live Content: False')
            epnum = jsdata['episode']['number']
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
            hls = jsdata['playback']['hls']
            output_name = title + "_" + epnumber

            m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
            if self.is_m3u8:
                m3u8_url = self.url

            self.yuu_logger.debug('M3U8 Link: {}'.format(m3u8_url))
            self.yuu_logger.debug('Video title: {}'.format(title))
            self.yuu_logger.debug('Episode number: {}'.format(epnumber))
            self.yuu_logger.debug('Episode num: {}'.format(epnum))
            self.yuu_logger.debug('Episode title: {}'.format(eptle))

        self.resolution = resolution
        self.m3u8_url = m3u8_url

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
