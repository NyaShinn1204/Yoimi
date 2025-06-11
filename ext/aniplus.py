import logging
import re
import os
from tqdm import tqdm

yuu_log = logging.getLogger('yuu.aniplus')

class AniplusDownloader:
    def __init__(self, url, session):
        self.url = url
        self.session = session

        self.merge = False

        self.session.headers.update(
            {
                "Range": "bytes=0-",
                "Sec-Fetch-Mode": "no-cors",
                "Accept-Encoding": "identity;q=1, *;q=0"
            }
        ) # Update once again just to make sure


    def download_chunk(self, files, output):
        output_ext = output[output.rfind('.'):]
        if output[:-4] != '.mp4':
            output = output[:len(output_ext) * -1] + '.mp4'
        try:
            with self.session.get(files, stream=True) as r:
                resp_head = r.headers
                length = int(resp_head['Content-Length'])
                current_chunk = 524288 # 512 KB
                with tqdm(total=length, desc='Downloading', ascii=True, unit='file') as pbar:
                    with open(output, 'wb') as outf:
                        for chunk in r.iter_content(chunk_size=524288):
                            if chunk:
                                outf.write(chunk)
                                pbar.update(len(chunk))
                                current_chunk += len(chunk)
        except KeyboardInterrupt:
            yuu_log.warn('User pressed CTRL+C.')


class Aniplus:
    def __init__(self, url, session):
        self.session = session
        self.type = 'Aniplus'
        self.yuu_logger = logging.getLogger('yuu.aniplus.Aniplus')

        self.url = url
        self.webpage_data = None
        self.resolution = None
        self.est_filesize = None # In MiB
        self.files_uri = None
        self.m3u8_url = False # placeholder

        self.resolution_data = {
            "720p": ["~1000kb/s 25fps", "AAC 160kb/s 1ch"]
        }

        self.authorization_required = True
        self.authorized = False

        self.resumable = False

        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'})

    def __repr__(self):
        return '<yuu.Aniplus: URL={}, Resolution={}, Authorized={}>'.format(self.url, self.resolution, self.authorized)

    def get_downloader(self):
        """
        Return a :class: of the Downloader
        """
        return AniplusDownloader(self.url, self.session)


    def authorize(self, username, password):
        _AUTH_URL = 'https://www.aniplus-asia.com/login/'
        creds = {
            'ihcaction': 'login',
            'log': username,
            'pwd': password
        }

        self.yuu_logger.debug('Logging in with username `{}` and password `{}`'.format(creds['log'], '*' * len(creds['pwd'])))
        r = self.session.post(_AUTH_URL, data=creds)
        if r.status_code != 200:
            return False, 'Error {}: Probably wrong username/password combination'.format(r.status_code)

        # Cookie are set automatically in requests after post (Via Set-Cookie in response headers)
        self.authorized = True
        return True, 'Authorized'


    def resolutions(self, placeholder_uri=None):
        """
        Return a resolutions list data
        Since Aniplus only have one resolution available, I just return hardcoded list
        """
        return ['720p', '1280x720']


    def parse(self, resolution=None, check_only=False):
        """
        Parse Aniplus data
        """
        self.yuu_logger.debug('Requesting data to Aniplus')

        res_list = ['720p', 'best', 'worst']
        if resolution not in res_list:
            if not check_only:
                return None, 'Unknown resolution: {}. (Check it with `-R`)'.format(resolution)

        if resolution in ['best', 'worst']:
            resolution = '720p'

        req = self.session.get(self.url)
        self.yuu_logger.debug('Data requested')
        self.yuu_logger.debug('Parsing webpage result')

        test_region = re.findall(r"error\-region", req.text)
        if test_region:
            None, 'Video are geo-locked. Refer to: https://www.aniplus-asia.com/error-region/'

        outputname = re.findall(r"<title>([\w\s]*).*>", req.text)[0].strip()

        self.webpage_data = req.text
        self.resolution = resolution
        self.session.headers.update({'Referer': self.url})
        self.yuu_logger.debug('Output: {}'.format(outputname))

        return outputname, 'Success'


    def get_video_key(self, ticket):
        """
        Return True since there's no key decryption in Aniplus
        But use this to fetch the estimated size
        """
        self.session.headers.update(
            {
                "Range": "bytes=0-",
                "Sec-Fetch-Mode": "no-cors",
                "Accept-Encoding": "identity;q=1, *;q=0"
            }
        )

        with self.session.get(self.files_uri, stream=True) as r:
            resp_head = r.headers
            length = int(resp_head['Content-Length'])
            self.est_filesize = round(length / 1024 / 1024, 2)
        return True, None


    def get_token(self):
        """
        Return empty data
        """
        return True, None


    def parse_m3u8(self, m3u8_url):
        video_src = re.findall(r"<source type=\"video/mp4\"\s+[^>]*\bsrc\s*=.([\w:/.]*).*>", self.webpage_data, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if not video_src:
            return None, None, 'Failed to fetch video url'
        self.files_uri = video_src[0]
        self.yuu_logger.debug('Video URL: {}'.format(self.files_uri))
        return video_src[0], None, None, 'Success'


    def check_output(self, output=None, output_name=None):
        if output:
            fn_, ext_ = os.path.splitext(output)
            if ext_ != 'mp4':
                output = fn_ + '.mp4'
        else:
            output = '{x} ({m} {r}).mp4'.format(x=output_name, m=self.type, r=self.resolution)

        return output
