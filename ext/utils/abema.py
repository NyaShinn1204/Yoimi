import re
import os
import json
import time
import hmac
import uuid
import hashlib
import subprocess
from tqdm import tqdm
from lxml import etree
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime
from urllib.parse import urljoin

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