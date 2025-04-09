# Gyao was already service end.
# Maybe delete this servoce file for v1.3.0


import json
import logging
import os
import re
import tempfile

import m3u8
from tqdm import tqdm

yuu_log = logging.getLogger('yuu.gyao')

class GYAODownloader:
    def __init__(self, url, session):
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


    def download_chunk(self, files, key, iv):
        self.downloaded_files = []
        try:
            with tqdm(total=len(files), desc='Downloading', ascii=True, unit='file') as pbar:
                for tsf in files:
                    outputtemp = self.temporary_folder + os.path.basename(tsf)
                    with open(outputtemp, 'wb') as outf:
                        try:
                            vid = self.session.get(tsf)
                            outf.write(vid.content)
                        except Exception as err:
                            yuu_log.error('Problem occured\nreason: {}'.format(err))
                            return None
                    pbar.update()
                    self.downloaded_files.append(outputtemp)
        except KeyboardInterrupt:
            yuu_log.warn('User pressed CTRL+C, cleaning up...')
            return None
        return self.downloaded_files


class GYAO:
    def __init__(self, url, session):
        self.session = session
        self.type = 'GYAO'
        self.yuu_logger = logging.getLogger('yuu.gyao.GYAO')

        self.url = url
        self.m3u8_url = None
        self.resolution = None
        self.policy_key = None
        self.account = None
        self.m3u8_url_list = None
        self.is_m3u8 = False
        self.est_filesize = None # In MiB

        self.resolution_data = {
            "1080p-0": ["~5000kb/s", "AAC 64kb/s 2ch"],
            "720p-0": ["2000kb/s", "AAC 64kb/s 2ch"],
            "480p-0": ["900kb/s", "AAC 64kb/s 2ch"],
            "360p-0": ["550kb/s", "AAC 64kb/s 2ch"],
            "240p-0": ["~200kb/s", "AAC 64kb/s 1ch"],
            "1080p-1": ["~5000kb/s", "AAC 128kb/s 2ch"],
            "720p-1": ["~2000kb/s", "AAC 128kb/s 2ch"],
            "480p-1": ["~900kb/s", "AAC 128kb/s 2ch"],
            "360p-1": ["~550kb/s", "AAC 128kb/s 2ch"],
            "240p-1": ["~200kb/s", "AAC 128kb/s 2ch"],
        }

        self.authorization_required = False
        self.authorized = False # Ignore for now

        self.resumable = True

        # Use Chrome UA
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'})


    def __repr__(self):
        return '<yuu.GYAO: URL={}, Resolution={}, m3u8 URL={}>'.format(self.url, self.resolution, self.m3u8_url)

    def get_downloader(self):
        """
        Return a :class: of the Downloader
        """
        return GYAODownloader(self.url, self.session)

    def authorize(self, username, password):
        """
        Bypassed since I need an account to test login
        """
        return True, None

    def get_token(self):
        headers = {'X-User-Agent': 'Unknown Pc GYAO!/2.0.0 Web'}
        query = '?fields=title%2Cid%2CvideoId'
        v_id = re.findall(r'(?isx)http(?:|s)://gyao.yahoo.co.jp/(?:player|title[\w])/(?P<p1>[\w]*.*)', self.url)
        if not v_id:
            return None, 'Video URL are not valid'

        self.yuu_logger.debug('Fetching data account...')
        r_vid = self.session.get('https://gyao.yahoo.co.jp/dam/v1/videos/' + v_id[0].replace('/', ':').rstrip(':') + query, headers=headers)
        r_cov = self.session.get("http://players.brightcove.net/4235717419001/default_default/index.html?videoId=" + r_vid.json()['videoId'])
        data_account = re.findall(r'<video-js\s+[^>]*\bdata-account\s*=.([\d]*).*>', r_cov.text, re.IGNORECASE | re.DOTALL | re.VERBOSE)

        r_pk = self.session.get("http://players.brightcove.net/{}/default_default/index.html".format(data_account[0]))

        pkey = re.findall(r'policyKey\s*:\s*(["\'])(?P<pk>.+?)\1', r_pk.text)[0][1]

        self.yuu_logger.debug('Account: {}'.format(data_account[0]))
        self.yuu_logger.debug('Policy key: {}'.format(pkey))

        self.account = data_account[0]
        self.policy_key = pkey

        return 'SUCCESS', 'SUCCESS'


    def parse(self, resolution=None, check_only=False):
        """
        Function to parse gyao url
        """
        self.yuu_logger.debug('Requesting data to GYAO/Brightcove API')

        res_list = [
            '240p-0', '360p-0', '480p-0', '720p-0', '1080p-0',
            '240p-1', '360p-1', '480p-1', '720p-1', '1080p-1',
            'best', 'worst'
        ]

        if resolution not in res_list:
            if not check_only:
                return None, 'Unknown resolution: {}. (Check it with `-R`)'.format(resolution)

        if resolution == 'best':
            _resolution = '1080p-0'
        elif resolution == 'worst':
            _resolution = '240p-1'
        else:
            _resolution = resolution

        v_id = re.findall(r'(?isx)http(?:|s)://gyao.yahoo.co.jp/(?:player|p|title[\w])/(?P<p1>[\w]*.*)', self.url)
        if not v_id:
            return None, 'Video URL are not valid'
        self.yuu_logger.debug('Video ID: {}'.format(v_id[0]))

        headers = {'X-User-Agent': 'Unknown Pc GYAO!/2.0.0 Web'}
        r_vid = self.session.get('https://gyao.yahoo.co.jp/dam/v1/videos/' + v_id[0].replace('/', ':').rstrip(':') + '?fields=title%2Cid%2CvideoId%2CshortTitle', headers=headers).json()
        title = r_vid['title']
        ep_title = r_vid['shortTitle']

        output_name = title.replace(ep_title, '').replace('\u3000', ' ') + ' - ' + ep_title

        headers_pk = {
            'Accept': 'application/json;pk=' + self.policy_key,
        }

        error_bc = {
            'CLIENT_GEO': 'This video is geo-locked for Japan only.'
        }

        self.yuu_logger.debug('Requesting HLS and video info')
        req_bc = self.session.get('https://edge.api.brightcove.com/playback/v1/accounts/{}/videos/{}'.format(self.account, r_vid['videoId']), headers=headers_pk)
        self.yuu_logger.debug('Data requested')
        if req_bc.status_code == 403:
            error_reason = req_bc[0]['error_subcode']
            return None, error_bc[error_reason]

        self.yuu_logger.debug('Parsing json API')

        jsdata = req_bc.json()
        hls_list = jsdata['sources'][2]['src'] # Use EXT-V4 http version as the base
        hls_list2 = jsdata['sources'][0]['src'] # Use EXT-V3 http version as the one that will be sent over

        self.yuu_logger.debug('M3U8 Link: {}'.format(hls_list))
        self.yuu_logger.debug('Title: {}'.format(output_name))

        self.m3u8_url_list = hls_list

        self.yuu_logger.debug('Requesting m3u8 list')
        r = self.session.get(hls_list)
        r2 = self.session.get(hls_list2)
        self.yuu_logger.debug('m3u8 requested')

        if r.status_code == 403:
            return None, 'This video is geo-locked for Japan only.'

        self.yuu_logger.debug('Parsing m3u8')

        r_all = m3u8.loads(r.text)
        r2_all = m3u8.loads(r2.text)

        band_list_v4 = []
        for v4d in r_all.playlists:
            s_info = v4d.stream_info
            audio_inf = s_info.audio.strip('audio')
            if _resolution[-2:] == audio_inf:
                band_list_v4.append((s_info.bandwidth, str(s_info.resolution[1]) + audio_inf))

        for v3d in r2_all.playlists:
            bw = v3d.stream_info.bandwidth
            for v4d in band_list_v4:
                bwv4, resv4 = v4d
                if bw == bwv4:
                    self.m3u8_url = v3d.uri
                    self.resolution = resv4
                    self.est_filesize = round(bw / 1024 / 5, 2)
                    break

        if not self.m3u8_url:
            if resolution == 'worst':
                need_band = sorted(band_list_v4)[0]
            elif resolution == 'best':
                need_band = sorted(band_list_v4, reverse=True)[0]
            else:
                return None, 'Resolution {} are not exist in this video.'.format(self.resolution)
            for v3 in r2_all.playlists:
                bw = v3.stream_info.bandwidth
                if bw == need_band:
                    self.m3u8_url = v3.uri
                    self.resolution = _resolution
                    self.est_filesize = round(bw / 1024 / 5, 2)
                    break

        return output_name, None


    def parse_m3u8(self, m3u8_url):
        self.yuu_logger.debug('Requesting m3u8')
        r = self.session.get(m3u8_url)
        self.yuu_logger.debug('m3u8 requested')
        if r.status_code == 403:
            return None, None, 'This video is geo-locked for Japan only.'

        self.yuu_logger.debug('Parsing m3u8')

        x = m3u8.loads(r.text)
        files = x.files

        self.yuu_logger.debug('Total files: {}'.format(len(files)))

        return files, None, None, 'Success'


    def resolutions(self):
        self.yuu_logger.debug('Requesting data to API')

        r_all = m3u8.loads(self.session.get(self.m3u8_url_list).text)

        ava_reso = []
        for r_p in r_all.playlists:
            temp_ = []
            res = r_p.stream_info.resolution
            aud_d = r_p.stream_info.audio.strip('audio')
            r_c = '{h}p{a}'.format(h=res[1], a=aud_d)
            res_name = '{w}x{h}'.format(w=res[0], h=res[1])

            temp_.append(r_c)
            temp_.append(res_name)

            ava_reso.append(temp_)

        if ava_reso:
            reso = [r[0] for r in ava_reso]
            self.yuu_logger.debug('Resolution list: {}'.format(', '.join(reso)))

        return ava_reso


    def get_video_key(self, ticket):
        """
        Return True since there's not key decryption in GYAO
        """
        return True, None


    def check_output(self, output=None, output_name=None):
        if output:
            fn_, ext_ = os.path.splitext(output)
            if ext_ != 'ts':
                output = fn_ + '.ts'
        else:
            output = '{x} ({m} {r}).ts'.format(x=output_name, m=self.type, r=self.resolution[:-2])

        return output
