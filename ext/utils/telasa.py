import os
import re
import uuid
import time
import requests
import subprocess
import boto3
import boto3.session
from tqdm import tqdm
from pycognito import AWSSRP
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

import ext.utils.telasa_util.aws_function as aws_function

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Telasa_decrypt:
    def mp4decrypt(keys, config):
        if os.name == 'nt':
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else:
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
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
    def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, config, service_name="Telasa"):
        with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            Telasa_decrypt.decrypt_content(video_keys, video_input_file, video_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 1つ目の進捗を更新
    
            Telasa_decrypt.decrypt_content(audio_keys, audio_input_file, audio_output_file, config, service_name=service_name)
            outer_pbar.update(1)  # 2つ目の進捗を更新
    
    def decrypt_content(keys, input_file, output_file, config, service_name="Telasa"):
        mp4decrypt_command = Telasa_decrypt.mp4decrypt(keys, config)
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

class Telasa_license:
    def license_vd_ad(pssh, session, playback_token, config):
        _WVPROXY = "https://license.kddi-video.com/"
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers={"x-custom-data": f"token_type=playback&token_value={playback_token}&widevine_security_level=L3"})
        response.raise_for_status()
    
        cdm.parse_license(session_id, response.content)
        keys = [
            {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
            for key in cdm.get_keys(session_id)
        ]
    
        cdm.close(session_id)
                
        keys = {
            "key": keys,
        }
        
        return keys

class Telasa_downloader:
    def __init__(self, session):
        self.session = session
        self.session.headers.update({"X-Device-Id": str(uuid.uuid4())})
    def authorize(self, email_or_id, password):
        x_device_id = str(uuid.uuid4())
        self.session.headers.update({
            "x-device-id": x_device_id,
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)" # Emulator UA
        })
        
        email_check = self.session.get("https://api-videopass-login.kddi-video.com/v1/account/openid/email-mapping?email={email}".format(email=email_or_id)).json()
        if email_check["status"]["type"] != "OK":
            return False, "Email check failed", email_check["status"]["message"]
        else:
            pass
        
        username = email_check["data"]
        
        region = 'ap-northeast-1'
        userpool = "ap-northeast-1_PsTlZi7OG"
        clientid = "7u36u43euliqbfljf035tq5jjc"
        
        amz_session = boto3.Session()
        cognito = amz_session.client('cognito-idp', region_name=region)
        aws_srp = AWSSRP(
            username=username,
            password=password,
            pool_id=userpool,
            client_id=clientid,
            client=cognito
        )
        auth_params = aws_srp.get_auth_params()
        try:
            response = cognito.initiate_auth(
                ClientId=clientid,
                AuthFlow='USER_SRP_AUTH',
                AuthParameters=auth_params
            )
        except ClientError as e:
            return False, "Failed to auth", e
        challenge_response = aws_srp.process_challenge(response["ChallengeParameters"], auth_params)
        response = cognito.respond_to_auth_challenge(
            ClientId=clientid,
            ChallengeName='PASSWORD_VERIFIER',
            ChallengeResponses=challenge_response
        )
        auth_result = response['AuthenticationResult']
        
        access_token = auth_result['AccessToken']
        id_token = auth_result['IdToken']
        refresh_token = auth_result['RefreshToken']
        access_token_expiry = datetime.now() + timedelta(seconds=auth_result['ExpiresIn'])
        #print(access_token, id_token, refresh_token, access_token_expiry)
        
        #user_info = self.session.post("https://cognito-idp.ap-northeast-1.amazonaws.com/", headers={"X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser", "X-Amz-User-Agent": "aws-amplify/5.0.4 auth framework/2", "Content-Type": "application/x-amz-json-1.1"}, json={"AccessToken": access_token}).json()
        #print(user_info)
        
        #new_token = aws_util.refresh_access_token(refresh_token, clientid)
        
        self.session.headers.update({"Authorization": "Bearer "+access_token})
        url = "https://api-videopass.kddi-video.com/v1/users/me"
        
        headers = {
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "x-device-id": x_device_id,
            "accept-encoding": "compress, gzip",
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        
        response = self.session.get(url, headers=headers).json()

        return True, None, response["data"]
    def check_token(self, token):
        url = "https://api-videopass.kddi-video.com/v1/users/me"
        
        headers = {
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "x-device-id": str(uuid.uuid4()),
            "accept-encoding": "compress, gzip",
            "authorization": "Bearer "+token,
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        
        response = self.session.get(url, headers=headers).json()
        
        if response["type"] != "OK":
            return False, None
        else:
            return True, response["data"]
    def refresh_token(self, refresh_token):
        clientid = "7u36u43euliqbfljf035tq5jjc"
        
        aws_util = aws_function.aws_fun()
        self.session.headers.update({"Authorization": "Bearer "+aws_util.refresh_access_token(refresh_token, clientid)})
        return True
    def get_id_type(self, url):
        genre_list = []
        more_info = []
        match = re.search(r'/videos/(\d+)', url)
        if match:
            video_id = match.group(1)
            payload = {"video_ids":[video_id]}
            get_video_info = self.session.post("https://api-videopass-anon.kddi-video.com/v3/batch/query", json=payload, headers={"x-device-id": str(uuid.uuid4())}).json()
            genre_tag = get_video_info["data"]["items"][0]["data"]["genres"]
            more_info.append(get_video_info["data"]["items"][0]["data"]["year_of_production"])
            more_info.append(get_video_info["data"]["items"][0]["data"]["copyright"])
            button_data = get_video_info["data"]["items"][0]["video_button_status"]["button_licenses"]
            if "freemium" in str(button_data):
                for i in button_data:
                    if i["license"] == "freemium":
                        episode_type = "FREE"
            else:
                episode_type = "PREMIUM"
            more_info.append(episode_type)
            #print(genre_tag)
            for si in genre_tag:
                if si["id"] == 280:
                    genre_list.append("劇場")
                else:
                    for i in si["parent_genre"]:
                        if i["id"] == 256:
                            genre_list.append("ノーマルアニメ")
            #if 280 in genre_tag:
            #    genre_list.append("劇場")
            #elif 256 in genre_tag:
            #    genre_list.append("ノーマルアニメ")
            return True, genre_list, more_info
        return False, None, None
    def get_title_parse_single(self, url):
        match = re.search(r'/videos/(\d+)', url)
        if match:
            video_id = match.group(1)
            payload = {"video_ids":[video_id]}
            get_video_info = self.session.post("https://api-videopass-anon.kddi-video.com/v3/batch/query", json=payload, headers={"x-device-id": str(uuid.uuid4())}).json()
            return True, get_video_info["data"]["items"][0]
        return False, None
    def get_playback_token(self, id):
        payload = {"query":"{ playbackToken( item_id: "+str(id)+", item_type: Mezzanine ) { token expires_at license_id } }"}
        playback_token = self.session.post("https://playback.kddi-video.com/graphql", json=payload).json()["data"]["playbackToken"]["token"]
        return playback_token
    def get_streaming_link(self, id, playback_token):
        payload = {"query":"{ manifests( item_id: \""+str(id)+"\", item_type: Mezzanine, playback_token: \""+playback_token+"\" ) { protocol items { name url } } subtitles( id: \""+str(id)+"\", playback_token: \""+playback_token+"\" ) { language url } mezzanine( id: \""+str(id)+"\" ) { id title time { last_played duration endStart }, recommend { previous { id title images { url } } next { id title images { url } } }, video { id } } thumbnailSeekings( id: \""+str(id)+"\", playback_token: \""+playback_token+"\" ) { quality url } }"}
        streaming_list = self.session.post("https://playback.kddi-video.com/graphql", json=payload).json()
        return streaming_list
    
    def get_series_info(self, series_id):
        url = "https://api-videopass.kddi-video.com/v3/series/"+series_id
        
        headers = {
            "accept-encoding": "compress, gzip",
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        
        response = self.session.get(url, headers=headers).json()["data"]
        return response

    def get_episodes_info(self, episode_ids):
        url = "https://api-videopass.kddi-video.com/v3/batch/query"
        
        headers = {
            "accept-encoding": "compress, gzip",
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        payload = {
            "video_ids": episode_ids
        }
        
        response = self.session.post(url, headers=headers, json=payload).json()['data']['items']
        
        episode_list = []
        for i in response:
            episode_list.append([
                i["data"]["subtitle"],
                i["data"]["duration"],
                i["data"]["title_id"]
            ])
        
        return episode_list

    def download_segment(self, segment_links, config, unixtime, name, service_name="Telasa"):
        base_temp_dir = os.path.join(config["directorys"]["Temp"], "content", unixtime)
        os.makedirs(base_temp_dir, exist_ok=True)
        with open(os.path.join(config["directorys"]["Temp"], "content", unixtime, name), 'wb') as out_file:
            with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as progress_bar:
                for url in segment_links:
                    retry = 0
                    while retry < 3:
                        try:
                            response = self.session.get(url.strip(), timeout=10)
                            response.raise_for_status()
                            out_file.write(response.content)
                            progress_bar.update(1)
                            break
                        except requests.exceptions.RequestException as e:
                            retry += 1
                            time.sleep(2)

    def mux_episode(self, video_name, audio_name, output_name, config, unixtime, title_name, duration, service_name="Telasa"):
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