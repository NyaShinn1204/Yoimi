import re
import os
import json
import time
import hmac
import uuid
import struct
import base64
import hashlib
import subprocess
from tqdm import tqdm
from lxml import etree
from Crypto.Cipher import AES
from datetime import datetime
from binascii import unhexlify
from urllib.parse import urljoin
import xml.etree.ElementTree as ET
from base64 import urlsafe_b64encode, urlsafe_b64decode

import ext.utils.abema_util.decrypt_key as dash_decrypt
import ext.global_func.util.decrypt_subtitle as sub_decrypt

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Abema_utils:
    def gen_temp_token(session):
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        def gen_key_secret(devid):
            SECRETKEY = (b"v+Gjs=25Aw5erR!J8ZuvRrCx*rGswhB&qdHd_SYerEWdU&a?3DzN9B"
                        b"Rbp5KwY4hEmcj5#fykMjJ=AuWz5GSMY-d@H7DMEh3M@9n2G552Us$$"
                        b"k9cD=3TxwWe86!x#Zyhe")
            device_id = devid.encode("utf-8")
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
            h.update(urlsafe_b64encode(tmp).rstrip(b"=") + device_id)
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
            
            return finalize

        device_id = str(uuid.uuid4())
        json_data = {"deviceId": device_id, "applicationKeySecret": gen_key_secret(device_id)}

        res = session.post(_USERAPI, json=json_data).json()

        try:
            token = res['token']
        except:
            return None

        return [token, device_id]
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
            list: セグメントリスト。各セグメントテンプレートの初期化URLとセグメントURLリストを含む。
        """
        try:
            tree = etree.fromstring(content)
            # 名前空間を設定
            ns = {'dash': 'urn:mpeg:dash:schema:mpd:2011'}
    
            # SegmentTemplateを探す（最初はvideo、次はaudio）
            segment_templates = tree.findall('.//dash:SegmentTemplate', ns)
            if not segment_templates:
                print("not found")
                return []
            
            result = []
    
            # 最初のSegmentTemplateはvideoとして処理
            video_segment_template = segment_templates[0]
            video_result = Abema_utils.process_segment_template(video_segment_template, ns, representation_id, url, "video")
            result.append(video_result)
            
            # 二番目のSegmentTemplateはaudioとして処理
            if len(segment_templates) > 1:
                audio_segment_template = segment_templates[1]
                audio_result = Abema_utils.process_segment_template(audio_segment_template, ns, representation_id, url, "audio")
                result.append(audio_result)
    
            return result
    
        except etree.ParseError:
            print("XML解析エラー")
            return []
        except Exception as e:
            print(f"予期せぬエラーが発生しました: {e}")
            return []
    
    def process_segment_template(segment_template, ns, representation_id, url, segment_type):
        """
        セグメントテンプレートを処理して、セグメントリストを生成するヘルパー関数。
    
        Args:
            segment_template (Element): SegmentTemplate要素。
            ns (dict): 名前空間の辞書。
            representation_id (str): Representation ID。
            url (str): mpdファイルのURL。
            segment_type (str): セグメントの種類（'video' または 'audio'）。
    
        Returns:
            dict: セグメント情報を含む辞書。
        """
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
                segment_file = media_template.replace('$Number$', str(len(segment_list)))
                segment_list.append(urljoin(url, segment_file))
                segment_all.append(urljoin(url, segment_file))
                current_time += duration
    
        init_url = urljoin(url, init_template)
    
        return {
            "type": segment_type,
            "init": init_url,
            "segments": segment_list,
            "all": segment_all
        }
class Abema_decrypt:
    def mp4decrypt(key, config):
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
            
        mp4decrypt_command.extend(
            [
                "--show-progress",
                "--key",
                key,
            ]
        )
        return mp4decrypt_command
    def decrypt_content(keys, input_file, output_file, config, service_name="Abema"):
        mp4decrypt_command = Abema_decrypt.mp4decrypt(keys, config)
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

# ここからコンテンツ保護解除
class hls:
    def get_video_key(session=None, device_id=None, ticket=None, response=None, logger=None, user_id=None):
        _MEDIATOKEN_API = "https://api.p-c3-e.abema-tv.com/v1/media/token"
        _LICENSE_API = "https://license.abema.io/abematv-hls"
        
        _STRTABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        _HKEY = b"3AF0298C219469522A313570E8583005A642E73EDD58E3EA2FB7339D3DF1597E"
        
        _KEYPARAMS = {
            "osName": "pc",
            "osVersion": "1.0.0",
            "osLand": "ja",
            "osTimezone": "Asia/Tokyo",
            "appVersion": "v25.130.0"
        }
        restoken = session.get(_MEDIATOKEN_API, params=_KEYPARAMS).json()
        mediatoken = restoken['token']
        rgl = session.post(_LICENSE_API, params={"t": mediatoken}, json={"kv": "a", "lt": ticket})
        if rgl.status_code == 403:
            return None, 'Access to this video are not allowed\nProbably a premium video or geo-locked.'

        gl = rgl.json()

        cid = gl['cid']
        k = gl['k']
        res = sum([_STRTABLE.find(k[i]) * (58 ** (len(k) - 1 - i)) for i in range(len(k))])

        encvk = struct.pack('>QQ', res >> 64, res & 0xffffffffffffffff)

        h = hmac.new(unhexlify(_HKEY), (cid + device_id).encode("utf-8"), digestmod=hashlib.sha256)
        enckey = h.digest()

        aes = AES.new(enckey, AES.MODE_ECB)
        vkey = aes.decrypt(encvk)

        return vkey, "Success"

class dash:
    def get_default_KID(mpd_content):
        root = ET.fromstring(mpd_content)
    
        namespaces = {
            '': 'urn:mpeg:dash:schema:mpd:2011',
            'cenc': 'urn:mpeg:cenc:2013'
        }
    
        for elem in root.iterfind('.//{urn:mpeg:dash:schema:mpd:2011}Period//{urn:mpeg:dash:schema:mpd:2011}AdaptationSet//{urn:mpeg:dash:schema:mpd:2011}ContentProtection', namespaces):
            default_KID = elem.get('{urn:mpeg:cenc:2013}default_KID')
            if default_KID:
                return default_KID
        return None
    def get_video_key(session=None, device_id=None, ticket=None, response=None, logger=None, user_id=None):
        _KEYPARAMS = {
            "osName": "pc",
            "osVersion": "1.0.0",
            "osLand": "ja",
            "osTimezone": "Asia/Tokyo",
            "appVersion": "v25.130.0"
        }
        restoken = session.get("https://api.p-c3-e.abema-tv.com/v1/media/token", params=_KEYPARAMS).json()
        mediatoken = restoken['token']                    
        
        dash_mpd = session.get(response['playback']['dash'], params={"t": mediatoken, "enc": "clear", "dt": "pc_unknown", "ccf": 0, "dtid": "jdwHcemp6THr", "ut": 1}).text
        sex_kid = dash.get_default_KID(dash_mpd)
        
        logger.debug("Get default_kid: {}".format(sex_kid), extra={"service_name": "Abema"})
        
        kid = base64.b64encode(bytes.fromhex(sex_kid.replace("-", "").upper())).decode('utf-8').replace("==", "").replace("+", "-").replace("/", "_")
        
        logger.debug("Gen KID: {}".format(kid), extra={"service_name": "Abema"})
        
        rgl = session.post("https://license.p-c3-e.abema-tv.com/abematv-dash", params={"t": mediatoken, "cid": response["id"], "ct": "program"}, json={"kids":[kid],"type":"temporary"})
        if rgl.status_code == 403:
            return None, 'Access to this video are not allowed\nProbably a premium video or geo-locked.'

        gl = rgl.json()["keys"][0]

        kid = gl['kid']
        k = gl['k']
        kty = gl['kty']
        
        logger.debug("GET KID: {}".format(kid), extra={"service_name": "Abema"})
        logger.debug("GET K: {}".format(k), extra={"service_name": "Abema"})
        logger.debug("GET KTY: {}".format(kty), extra={"service_name": "Abema"})
        
        k_value = k
        hash = k_value.split(".")[-1]
        k_slice = k_value.split(".")[0]
        y_slice = k_value.split(".")[1]
        
        decrypt_json = dash_decrypt.decrypt_key(rgl.json(), k_slice, y_slice, hash, kid, user_id)
        
        #decrypt = pm.require("./abema_util/decrypt")
        #
        #print("K_SLICE", k_slice)
        #print("y_slice", y_slice)
        #
        #print(kid, user_id, y_slice)
        #
        #x = decrypt.get_x(k_slice)
        #y = decrypt.get_y(kid, user_id, y_slice)
        #logger.debug("GET X (Uint8Array): {}".format(x), extra={"service_name": "Abema"})
        #logger.debug("GET Y (Uint8Array): {}".format(y), extra={"service_name": "Abema"})
        #
        #t = hash
        #e = [int(z) for z in y]
        #n = [int(z) for z in x]
        #decrypt_json = decrypt.decrypt_key(rgl.json(), t, e, n)
        temp_d = decrypt_json['keys'][0]['k']
        temp_f = decrypt_json['keys'][0]['kid']
        
        temp_d = temp_d.replace('_', '/').replace('-', '+')
        temp_f = temp_f.replace('_', '/').replace('-', '+')
        
        while len(temp_d) % 4 != 0:
            temp_d += '='
        while len(temp_f) % 4 != 0:
            temp_f += '='
        
        raw1 = base64.b64decode(temp_d)
        raw2 = base64.b64decode(temp_f)
        
        result_key = ''.join(format(c, '02x') for c in raw1)
        result_kid = ''.join(format(c, '02x') for c in raw2)
        
        logger.debug("Decrypt Key!", extra={"service_name": "Abema"})
        logger.debug(f"{result_kid}:{result_key}", extra={"service_name": "Abema"})
        # Kをdecryptする方法?
        # Step1. AES-CBC, HMAC-SHA256, Blowfish-ECB, RC4, Base58 encoding (Bitcoin variant)を用いてkからclearkeyを生成する
        # Step2. mp4decryptを使ってコンテンツ保護を解除
        
        # Source: https://forum.videohelp.com/threads/414857-Help-me-to-download-this-video-from-abema
        
        return [f"{result_kid}:{result_key}", dash_mpd], "Success"
#ここまで

class Abema_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email_or_id, password):
        if email_or_id and password == None:
            # this area to make temporary token for download
            print()
            return True, None
        
        # ログインのため仮tokenの生成
        temp_token = Abema_utils.gen_temp_token(self.session)
        self.session.headers.update({'Authorization': 'Bearer ' + temp_token[0]})
        
        _ENDPOINT_MAIL = "https://api.p-c3-e.abema-tv.com/v1/auth/user/email"
        _ENDPOINT_OTP = "https://api.p-c3-e.abema-tv.com/v1/auth/oneTimePassword"
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        mail_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
        if not re.fullmatch('[0-9]+', email_or_id):
            if not re.fullmatch(mail_regex, email_or_id):
                return False, "Unext require email and password"
            
        if re.search(mail_regex, email_or_id):
            _ENDPOINT_USE = _ENDPOINT_MAIL
            _PAYLOAD_METHOD = "email"
        else:
            _ENDPOINT_USE = _ENDPOINT_OTP
            _PAYLOAD_METHOD = "userId"
            
        auth_payload = {
            _PAYLOAD_METHOD: email_or_id,
            "password": password
        } 
        
        auth_response = self.session.post(_ENDPOINT_USE, json=auth_payload)
        auth_response_json = auth_response.json()
        
        if auth_response.status_code != 200:
            return False, 'Wrong Email or password combination'
        
        userId = auth_response_json["profile"]["userId"]
        self.session.headers.update({'Authorization': 'Bearer ' + auth_response_json["token"]})
        
        user_info_res = self.session.get(_USERAPI+"/"+userId)
        return True, user_info_res.json(), temp_token[1]
    def check_token(self, token):
        _USERAPI = "https://api.p-c3-e.abema-tv.com/v1/users"
        token_payload = token.split(".")[1]
        token_payload_decoded = str(urlsafe_b64decode(token_payload + "=="), "utf-8")
        payload = json.loads(token_payload_decoded)
        userId = payload["sub"]
        self.session.headers.update({'Authorization': token})
        
        user_info_res = self.session.get(_USERAPI+"/"+userId)
        if user_info_res.status_code == 200:
            return True, user_info_res.json()
        else:
            return False, "Invalid Token"
        
    def setup_decryptor(self, key, iv):
        iv = unhexlify(iv)
        _aes = AES.new(key, AES.MODE_CBC, IV=iv)
        return iv, _aes

    def download_chunk(self, files, key, iv, decrypt_type, output_temp_directory, service_name="Abema"):
        if decrypt_type == "hls":
            if iv.startswith('0x'):
                iv = iv[2:]
            else:
                iv = iv
                iv, _aes = self.setup_decryptor(key, iv)
        downloaded_files = []
        try:
            with tqdm(total=len(files), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit='file') as pbar:
                for tsf in files:
                    outputtemp = os.path.join(output_temp_directory, os.path.basename(tsf))
                    if not os.path.exists(output_temp_directory):
                        os.makedirs(output_temp_directory, exist_ok=True)
                    if outputtemp.find('?tver') != -1:
                        outputtemp = outputtemp[:outputtemp.find('?tver')]
                    with open(outputtemp, 'wb') as outf:
                        try:
                            vid = self.session.get(tsf)
                            if decrypt_type == "hls":
                                vid = _aes.decrypt(vid.content)
                            else:
                                vid = vid.content
                            outf.write(vid)
                        except Exception as err:
                            print(err)
                            return None
                    pbar.update()
                    downloaded_files.append(outputtemp)
        except KeyboardInterrupt:
            return None
        return downloaded_files
    def merge_video(self, path, output, output_directory, service_name="Abema"):
        """
        m4sファイルを結合して1つの動画ファイルにする関数
        
        Args:
            input_files (list): 結合するm4sファイルのリスト
            output_file (str): 出力する結合済みのファイル名
        """
        total_files = len(path)
        
        if not os.path.exists(output_directory):
            os.makedirs(output_directory, exist_ok=True)
        
        # バイナリモードでファイルを結合
        with open(output, "wb") as outfile:
            with tqdm(total=total_files, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                for i, f in enumerate(path, start=1):
                    with open(f, "rb") as infile:
                        outfile.write(infile.read())
                    os.remove(f)
                    pbar.set_postfix(file=f, refresh=True)
                    pbar.update(1)
            
    def download_niconico_comment(self, logger, additional_info, title_name, episode_title, episode_number, config, title_name_logger, service_type="Abema"):
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
        def convert_int_to_kanji(num: int) -> str:
            """
            Return "算用数字" to "漢数字"
            """
            kanji_units = ['', '十', '百', '千']
            kanji_large_units = ['', '万', '億', '兆', '京']
            kanji_digits = '零一二三四五六七八九'
            
            if num == 0:
                return kanji_digits[0]
            
            result = ''
            str_num = str(num)
            length = len(str_num)
            
            for i, digit in enumerate(str_num):
                if digit != '0':
                    result += kanji_digits[int(digit)] + kanji_units[(length - i - 1) % 4]
                if (length - i - 1) % 4 == 0:
                    result += kanji_large_units[(length - i - 1) // 4]
            
            result = result.replace('一十', '十')  # 「一十」は「十」に置き換え、バグ対策
            return result
        if additional_info[2]:        
            sate = {}
            episode_text = re.sub(r'^第\d+話\s*', '', episode_title)
            sate["info"] = {
                "work_title": title_name,
                "episode_title": episode_title,
                "raw_text": f"{title_name} {episode_title}",
                "series_title": title_name,
                "episode_text": episode_title.replace(episode_text, ""),
                "episode_number": episode_number,
                "subtitle": episode_text,
            }
                        
            def get_niconico_info(stage, data):
                if stage == 1:
                    querystring = {
                        "q": data,
                        "_sort": "-startTime",
                        "_context": "NCOverlay/3.24.0/Mod For Yoimi",
                        "targets": "title,description",
                        "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
                        "filters[commentCounter][gt]": 0,
                        "filters[genre.keyword][0]": "アニメ",
                        "_offset": 0,
                        "_limit": 20,
                    }
                    
                    result = self.session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
                    return result
                elif stage == 2:
                    result = self.session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
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
                    result = self.session.post("https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
                    return result
                
            logger.info("Getting Niconico Comment", extra={"service_name": service_type})
            return_meta = get_niconico_info(1, f'{sate["info"]["work_title"]} {sate["info"]["episode_number"]}話 OR {convert_int_to_kanji(sate["info"]["episode_number"])}話 OR エピソード{sate["info"]["episode_number"]} OR episode{sate["info"]["episode_number"]} OR ep{sate["info"]["episode_number"]} OR #{sate["info"]["episode_number"]} OR 第{sate["info"]["episode_number"]}話 OR "{sate["info"]["subtitle"]}"')
            
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
                    
                    #if len(item["commands"]) > 1:
                    #    chat.set("mail", "small shita")
                    #else:
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
            
                ET.indent(tree, space="  ", level=0)
                
                tree.write(filename, encoding="utf-8", xml_declaration=True)
                return filename
            
            tree = generate_xml(total_comment_json)
            
            logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": service_type})
            logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": service_type})
            
            saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
            
            logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": service_type})
            
            if additional_info[3]:
                return
        
    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Abema"):
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
            
    # hehe sub function
    def download_subtitles(self, title_name, title_name_logger, subtitles, config, logger):
        logger.info(f"Downloading Subtitles  | Total: {str(len(subtitles))} ", extra={"service_name": "Abema"})
        #print(str(len(subtitles)))
        #for single in subtitles:
        #    print(single)
        #exit(1)
        with tqdm(total=len(subtitles), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{"Abema"}{COLOR_RESET} : ", unit="%") as pbar:
            for i, f in enumerate(subtitles, start=1):
                #with open(f, "rb") as infile:
                #    outfile.write(infile.read())
                #os.remove(f)
                #pbar.set_postfix(file=f, refresh=True)
                raw_subtitle = self.session.get(f["URI"]).content
                decode_subtitle = sub_decrypt.parse_binary_content(raw_subtitle)
                
                output_sub_dr = os.path.join(config["directorys"]["Downloads"], title_name, "subtitle")
                if not os.path.exists(output_sub_dr):
                    os.makedirs(output_sub_dr, exist_ok=True)
                
                with open(os.path.join(output_sub_dr, title_name_logger+"_"+f["LANGUAGE"]+".vtt"), "wb") as infile:
                    infile.write(decode_subtitle.encode())
                pbar.update(1)