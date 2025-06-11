import requests
import re
import os
import time
import subprocess
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

class Download:
    def __init__(self, querystring):
        self.querystring = querystring
        self.session = requests.Session()
        self.cookies = { ## THIS COOKIE IS EXPIRED LOL
            "g_smt_spsp2": "0bf6zYQNKXACkGwihyONrv32E81B94408695B073A0EA30881E3920EB970CA00D66BA5339F5CBA20E2CF2D87",
            "op_skip": "0",
            "sbscrb_stat": "4",
            "sc_flg": "0",
            "apple_purchase": "0",
            "google_purchase": "0",
            "_egl-uuid": "5e42a472-258c-4713-a50a-f96a0fb3a525",
            "mute_setting": "0",
            "g_smt_omitnumkey": "RhptIeZBgcfbh6v7m2VEf4",
            "docomo_purchase": "1",
            "standard_bitrate_cd": "5",
            "dma_user": "32679aced8b3fc94f8952793ade8ea6f297",
            "certificate_session_id": "2024092120024576v0jjPt4jc7WBH5SM",
            "view_count_achieve": "1",
            "sub_device": "03",
            "repeat_play": "0",
            "_gcl_au": "1.1.912002657.1726915922",
            "AWSALBCORS": "ZEFX9Jqx5UWM9u06NMblUxT0QlgpFg+KkvMPd1v4giqw/zx6J6iWHB15rouba8ViSmBehEcF8E9j++F9qr8Drl+H6ofbHLWsbe5NXC+JSSGvm7lmbTXbU9nJ22sx",
            "PC030011_window_width": "854",
            "adxppthrd": "acf50788-0c30-4e14-aeaa-0e9f085a4f72",
            "AWSALB": "ZEFX9Jqx5UWM9u06NMblUxT0QlgpFg+KkvMPd1v4giqw/zx6J6iWHB15rouba8ViSmBehEcF8E9j++F9qr8Drl+H6ofbHLWsbe5NXC+JSSGvm7lmbTXbU9nJ22sx",
            "browser_id": "20240612203351hXelInI2y1vSlB5Qm4",
            "cf_app_flag": "0",
            "class_id": "2",
            "continuous_play": "1",
            "dma_user2": "32679aced8b3fc94f8952793ade8ea6f297",
            "g_smt_chkck": "docomo",
            "g_smt_ssk_langinfo": "ja",
            "JSESSIONID": "269E7A1EF0B36FFB04F1677AE444118B",
            "last_play_bitrate_cd": "5",
            "login_flag": "1",
            "member_status": "1",
            "navi_device": "61",
            "PC030011_window_height": "485",
            "play_speed": "1",
            "spsp": "0bf6zYQNKXACkGwihyONrv32E81B94408695B073A0EA30881E3920EB970CA00D66BA5339F5CBA20E2CF2D87",
            "time_format": "0",
            "user_id": "7cdfc3253800eaf0515ea6442e70d2f3cd951e1d107d3e5fa8cfecaf11f404ff",
            "uu_id": "20240921195155ebypnt5YoUPRtFaCaD",
            "volume_setting": "0.5"
        }
        self.folders = {
            "binaries": os.path.join(os.getcwd(), "binaries"),
            "output": os.path.join(os.getcwd(), "output"),
            "temp": os.path.join(os.getcwd(), "temp"),
        }

    def downloader(self):
        header = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        }
        ab = requests.get("https://animestore.docomo.ne.jp/animestore/rest/WS010105", params=self.querystring, cookies=self.cookies, headers=header)
        get_temp_json = ab.json()
        
        if get_temp_json.get("data", None):
            print("haha. cookie is invalid.")
        work_title = get_temp_json["data"]["workTitle"]
        onetimekey = get_temp_json["data"]["oneTimeKey"]
        get_mpd_content = requests.get(get_temp_json["data"]["contentUrls"]["highest"]).text

        modified_url = re.sub(r'/\d{10}\.mpd$', '', get_temp_json["data"]["contentUrls"]["highest"])
        result = self.parse_mpd(get_mpd_content)

        auth_token = self.get_license(result['default_kids'][0], onetimekey)
        license_keys = self.license_requests(auth_token, PSSH(result['max_video']['pssh']))

        video_filename = f"{work_title}_{get_temp_json['data']['partDispNumber']}_{get_temp_json['data']['partTitle']}_video_encrypted.mp4"
        audio_filename = f"{work_title}_{get_temp_json['data']['partDispNumber']}_{get_temp_json['data']['partTitle']}_audio_encrypted.mp4"

        video_download = self.aria2c(modified_url + "/" + result['max_video']['url'], video_filename.replace(":", ""))
        audio_download = self.aria2c(modified_url + "/" + result['max_audio']['url'], audio_filename.replace(":", ""))

        self.decrypt(license_keys, video_download, video_download.replace("_encrypted", ""))
        self.decrypt(license_keys, audio_download, audio_download.replace("_encrypted", ""))

        self.compile_mp4(video_download.replace("_encrypted", ""), audio_download.replace("_encrypted", ""), f"{work_title}_{get_temp_json['data']['partDispNumber']}_{get_temp_json['data']['partTitle']}.mp4", work_title)
        
    def series_downloader(self, workid):
        querystring = { "workId": workid }

        headers = {
            "host": "animestore.docomo.ne.jp",
            "connection": "keep-alive",
            "sec-ch-ua": "\"Brave\";v=\"129\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"129\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.5",
            "sec-fetch-site": "none",
            "sec-fetch-mode": "navigate",
            "sec-fetch-user": "?1",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd"
        }
        
        html_content = self.session.get("https://animestore.docomo.ne.jp/animestore/ci_pc", params=querystring, cookies=self.cookies, headers=headers).text
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # <li class="optionText">の部分のテキストを取得
        option_text = soup.find('li', class_='optionText').get_text()
        print("Option Text:", option_text)
        
        # swiper-slide内のそれぞれのnumberとline2内のspanのテキストを取得
        slides = soup.find_all('div', class_='swiper-slide')
        for slide in slides:
            number = slide.find('span', class_='number').get_text()
            line2 = slide.find('h3', class_='line2').span.get_text()
            print(f"Number: {number}, Line2: {line2}")
    def parse_mpd(self, mpd_content):
        # XMLをパース
        root = ET.fromstring(mpd_content)
    
        # Namespaces定義
        namespaces = {
            'default': 'urn:mpeg:dash:schema:mpd:2011',
            'cenc': 'urn:mpeg:cenc:2013',
            'mspr': 'urn:microsoft:playready'
        }
    
        # ContentProtectionタグからdefault_KIDを取得
        default_kids = []
        # PSSHのリスト
        pssh_list = []
    
        # rootからContentProtectionタグを探索（名前空間に注意）
        for content_protection in root.findall(".//default:ContentProtection", namespaces):
            if '{urn:mpeg:cenc:2013}default_KID' in content_protection.attrib:
                default_kids.append(content_protection.attrib['{urn:mpeg:cenc:2013}default_KID'])
    
            # PSSHの取得
            pssh_element = content_protection.find("cenc:pssh", namespaces)
            if pssh_element is not None:
                pssh_list.append(pssh_element.text)
    
        # 最大ビットレートのビデオとオーディオを取得
        max_video_url = None
        max_video_pssh = None
        max_video_bandwidth = 0
    
        max_audio_url = None
        max_audio_pssh = None
        max_audio_bandwidth = 0
    
        # ビデオとオーディオのRepresentationを探す
        for adaptation_set in root.findall(".//default:AdaptationSet", namespaces):
            mime_type = adaptation_set.attrib.get('mimeType', '')
    
            for representation in adaptation_set.findall("default:Representation", namespaces):
                bandwidth = int(representation.attrib['bandwidth'])
                base_url = representation.find("default:BaseURL", namespaces).text
    
                # PSSHの取得（PSSHはContentProtection内にある場合もあるので）
                if pssh_list:
                    # 最初のPSSHを使用（必要に応じて変更可能）
                    max_video_pssh = pssh_list[0] if "video" in mime_type else max_video_pssh
                    max_audio_pssh = pssh_list[0] if "audio" in mime_type else max_audio_pssh
    
                if "video" in mime_type:
                    if bandwidth > max_video_bandwidth:
                        max_video_bandwidth = bandwidth
                        max_video_url = base_url
    
                elif "audio" in mime_type:
                    if bandwidth > max_audio_bandwidth:
                        max_audio_bandwidth = bandwidth
                        max_audio_url = base_url
    
        return {
            'default_kids': default_kids,  # すべてのdefault_KIDをリストで返す
            'max_video': {
                'url': max_video_url,
                'pssh': max_video_pssh
            },
            'max_audio': {
                'url': max_audio_url,
                'pssh': max_audio_pssh
            }
        }
    def get_license(self, keyid, onetimekey):
        headers = {
            "Origin": "https://animestore.docomo.ne.jp",
            "Referer": "https://animestore.docomo.ne.jp/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        }
        url = f"https://wv.animestore.docomo.ne.jp/RequestLicense/Tokens/?&keyId={keyid}&oneTimeKey={onetimekey}"
        status = requests.get(url, headers=headers)
        return status.json()["tokenInfo"]

    def license_requests(self, auth_token, pssh):
        headers = {
            "Origin": "https://animestore.docomo.ne.jp",
            "Referer": "https://animestore.docomo.ne.jp/",
            "Acquirelicenseassertion": auth_token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        }
        device = Device.load("./private/google_sdk_gphone64_x86_64_17.0.0_9691cff8_28926_l3.wvd")
        cdm = Cdm.from_device(device)
        session_id = cdm.open()

        challenge = cdm.get_license_challenge(session_id, pssh)
        response = requests.post("https://danime.drmkeyserver.com/widevine_license", data=challenge, headers=headers)
        response.raise_for_status()

        cdm.parse_license(session_id, response.content)
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]

        cdm.close(session_id)
        return keys 

    def aria2c(self, url, output_file_name):
        aria2c = os.path.join(self.folders["binaries"], "aria2c.exe")
        aria2c_command = [
            aria2c,
            url,
            "-d", self.folders["temp"],
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
            "--summary-interval=0",
        ]
        subprocess.run(aria2c_command)
        return os.path.join(self.folders["temp"], output_file_name)

    def compile_mp4(self, video_file, audio_file, output_file, work_title):    
        output_directory = os.path.join(self.folders["output"], work_title)
        
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    
        compile_command = [
            os.path.join(self.folders["binaries"], "ffmpeg.exe"),
            "-i",
            video_file,
            "-i",
            audio_file,
            "-c:v",
            "copy",
            "-c:a",
            "copy",
            "-strict",
            "experimental",
            os.path.join(output_directory, output_file),
        ]
        subprocess.run(compile_command)
    

    def mp4decrypt(self, keys):
        mp4decrypt_command = [os.path.join(self.folders["binaries"], "mp4decrypt.exe")]
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

    def decrypt(self, keys, input_file, output_file):
        mp4decrypt_command = Download.mp4decrypt(self, keys)
        mp4decrypt_command.extend([input_file, output_file])
        subprocess.run(mp4decrypt_command)
        
    def get(self, name):
        self.now_unixtime = str(int(time.time() * 1000))
        response = self.session.get(f"https://animestore.docomo.ne.jp/animestore/rest/WS000105?length=20&mainKeyVisualSize=2&searchKey={name}&vodTypeList=svod_tvod&_={self.now_unixtime}", cookies=self.cookies)
        #print(response.json())
        hit = []
        print(f"検索ヒット数: {response.json()["data"]["maxCount"]}")
        print("ヒットした作品一覧:")
        for i in response.json()["data"]["workList"]:
            print(i["workInfo"]["workTitle"])
            temp_json = {"workTitle": i["workInfo"]["workTitle"], "workId": i["workId"]}
            hit.append(temp_json)
        
        return hit

if __name__ == "__main__":
    querystring = {
        "viewType": 5,
        "partId": 27146002,
        "defaultPlay": 5
    }
    downloader = Download(querystring)
    downloader.downloader()
    #querystring = {}
    #downloader = Download(querystring)
    #hit = downloader.get("状態異常")
    #downloader.series_downloader(hit[0]["workId"])