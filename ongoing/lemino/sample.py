import re
import os
import time
import requests
import subprocess
from urllib.parse import urlparse
from tqdm import tqdm
from datetime import datetime
COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

session = requests.Session()
session.headers.update({
    "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
    "accept-encoding": "gzip",
    "charset": "UTF-8",
    "content-type": "application/json",
})

terminal_type = {
    "android_tv": "1",
    "android": "3"
}

service_token = session.post("https://if.lemino.docomo.ne.jp/v1/session/init", json={"terminal_type": terminal_type["android_tv"]}).headers["X-Service-Token"]

session.headers.update({"X-Service-Token": service_token})

def login_qr():
    get_loginkey = session.post("https://if.lemino.docomo.ne.jp/v1/user/auth/loginkey/create")
    get_loginkey.raise_for_status()
    
    if get_loginkey.json()["result"] == "0":
        pass
    else:
        return
    
    login_key = get_loginkey.json()["loginkey"]
    
def login_email():
    # Android, AndroidTV SSL Traffic is patched. fuck you docomo
    # Unsupported :(
    return None

def check_login():
    while True:
        payload = {
            "member": True,
            "profile": True
        }
        login_result = session.post("https://if.lemino.docomo.ne.jp/v1/user/loginkey/userinfo/profile", json=payload)
        login_result.raise_for_status()
        
        if login_result.json()["member"]["account_type"] != None:
            return True, login_result.json()
        else:
            time.sleep(5)
            continue
        
def get_user_info():
    url = "https://if.lemino.docomo.ne.jp/v1/user/userinfo/profile"
    
    payload = {
        "member": True,
        "profile": True
    }
    user_info_result = session.post(url, json=payload)
    user_info_result.raise_for_status()
    
    return user_info_result.json()
def get_subscription_info():
    url = "https://if.lemino.docomo.ne.jp/v1/user/userinfo/subscribelist"
    
    payload = {
        "prconsistent_read_flagofile": False
    }
    subscription_result = session.post(url, json=payload)
    subscription_result.raise_for_status()
    
    return subscription_result.json()
def get_dmarket_info():
    url = "https://if.lemino.docomo.ne.jp/limited/v1/user/userinfo/dmarket"
    
    dmarket_info_result = session.post(url)
    dmarket_info_result.raise_for_status()
    
    return dmarket_info_result.json()
# content get
def get_content_info(crid):
    url = "https://if.lemino.docomo.ne.jp/v1/meta/contents"
    
    querystring = {
        #"crid": "crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux",
        "crid": crid,
        "filter": "{\"target_age\":[\"G\",\"R-12\",\"R-15\"],\"avail_status\":[\"1\"]}"
    }
    contentinfo_result = session.get(url, params=querystring)
    contentinfo_result.raise_for_status()
    
    return contentinfo_result.json()

def get_mpd_info(cid, lid, crid):
    payload = {
      "play_type": 1,
      "avail_status": "1",
      "terminal_type": 4,
      "content_list": [
        {
          "kind": "main",
          "cid": cid,
          "lid": lid,
          "crid": crid,
          "auto_play": 1,
          "trailer": 0,
          "preview": 0,
          "stop_position": 0
        }
      ]
    }
    play_list_result = session.post("https://if.lemino.docomo.ne.jp/v1/user/delivery/watch/ready", json=payload)
    play_list_result.raise_for_status()
    
    play_list_json = play_list_result.json()
    
    play_token = play_list_json["play_token"]
    content_list = play_list_json["play_list"]
    return play_token, content_list


def widevine_license(custom_data, pssh):
    url = "https://drm.lemino.docomo.ne.jp/widevine_license"
    headers = {
        "acquirelicenseassertion": custom_data,
        "user-agent": "inidrmagent/2.0 (Android 10; jp.ne.docomo.lemino.androidtv)",
        "content-type": "application/octet-stream",
        "host": "drm.lemino.docomo.ne.jp",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    }
    # Widevine License Logic HERE
    from pywidevine.cdm import Cdm
    from pywidevine.device import Device
    from pywidevine.pssh import PSSH
    device = Device.load(
        "../../cdms/wv/public.wvd"
    )
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
    response = session.post(url, data=bytes(challenge), headers=headers)
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

def send_stop_signal(play_token, duratation):
    payload = {
        "play_token": play_token,
        "dur": str(duratation),
        "stop_position": "0"
    }
    
    signal_result = requests.post("https://if.lemino.docomo.ne.jp/v1/delivery/watch/stop", json=payload)
    signal_result.raise_for_status()
    
    if signal_result.json()["result"] == "0":
        return True
    else:
        return False

def update_session():
    url = "https://if.lemino.docomo.ne.jp/v1/session/update"
    
    update_session = session.post(url)
    update_session.raise_for_status()
    
    session.headers.update({"X-Service-Token": update_session.headers["X-Service-Token"]})
    
    return True


# DO NOT PUBLIC THIS SECION
# THIS INFO IS AUTH KEY
service_token = "DO NOT PUBLISH THIS"
session.headers.update({"X-Service-Token": service_token})
user_response = get_user_info()
print("Got User Info!")
print(" + Member Status: ", user_response["member"]["member_status"])

print("Getting Content Info")
print(" + Using `ちょこさく【25/6/9配信】#238`")
print(" + CRID:", "crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux")
print("Posting...")
content_info = get_content_info("crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux")

duration_sec = content_info["meta_list"][0]["duration_sec"]
cid = content_info["meta_list"][0]["cid_obj"][0]["cid"]
lid = content_info["meta_list"][0]["license_list"][0]["license_id"]

print(" + Duration:", str(duration_sec))
print(" + LID:", lid)
play_token, content_list = get_mpd_info(cid=cid, lid=lid, crid="crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux")
print("Got Playtoken, Content List!")
print(" + Play Token:", play_token)
mpd_link = content_list[0]["play_url"]
print(" + MPD URL:", mpd_link)

print("Parsing MPD...")
import parser as parser
Tracks = parser.global_parser()
mpd_text = session.get(mpd_link).text
transformed_data = Tracks.mpd_parser(mpd_text, real_bitrate=True)
        
print(f" + Video, Audio PSSH: {transformed_data["pssh_list"]["widevine"]}")
license_key = widevine_license(content_list[0]["custom_data"], transformed_data["pssh_list"]["widevine"])
print("Decrypt License for 1 Episode")
print(f" + Decrypt Video, Audio License: {[f"{key['kid_hex']}:{key['key_hex']}" for key in license_key["key"] if key['type'] == 'CONTENT']}")

print("Send Stop Signal")
send_stop_signal(play_token, duration_sec)

print("Got Tracks")
track_data = Tracks.print_tracks(transformed_data, real_bitrate=True)
print(track_data)
get_best_track = Tracks.select_best_tracks(transformed_data)

print("Selected Best Track:")
print(f" + Video: [{get_best_track["video"]["codec"]}] [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps")
print(f" + Audio: [{get_best_track["audio"]["codec"]}] | {get_best_track["audio"]["bitrate"]} kbps")      
              
duration = Tracks.calculate_video_duration(transformed_data["info"]["mediaPresentationDuration"])
print(" + Episode Duration: "+str(int(duration)))                    

print("Video, Audio Content Segment Link")
video_segment_list = Tracks.calculate_segments(duration, int(get_best_track["video"]["seg_duration"]), int(get_best_track["video"]["seg_timescale"]))
print(" + Video Segments: "+str(int(video_segment_list)))                 
audio_segment_list = Tracks.calculate_segments(duration, int(get_best_track["audio"]["seg_duration"]), int(get_best_track["audio"]["seg_timescale"]))
print(" + Audio Segments: "+str(int(audio_segment_list)))

parsed = urlparse(mpd_link)
base_path = parsed.path.rsplit('/', 1)[0] + '/'
base_url = f"{parsed.scheme}://{parsed.netloc}{base_path}"

video_segments = Tracks.get_segment_link_list(mpd_text, get_best_track["video"]["id"], base_url)
video_segment_links = [item.replace("$Bandwidth$", get_best_track["video"]["bitrate"]) for item in video_segments["all"]]
audio_segments = Tracks.get_segment_link_list(mpd_text, get_best_track["audio"]["id"], base_url)
audio_segment_links = [item.replace("$Bandwidth$", get_best_track["audio"]["bitrate"]) for item in audio_segments["all"]]


def download_segment(segment_links, unixtime, name, service_name="TEMP"):
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed
    base_temp_dir = os.path.join("content", unixtime)
    os.makedirs(base_temp_dir, exist_ok=True)

    stop_flag = threading.Event()  # ← フラグの作成

    def fetch_and_save(index_url):
        index, url = index_url
        retry = 0
        while retry < 3 and not stop_flag.is_set():
            try:
                response = requests.get(url.strip(), timeout=10)
                response.raise_for_status()
                temp_path = os.path.join(base_temp_dir, f"{index:05d}.ts")
                with open(temp_path, 'wb') as f:
                    f.write(response.content)
                return index
            except requests.exceptions.RequestException:
                retry += 1
                time.sleep(2)
        if not stop_flag.is_set():
            raise Exception(f"Failed to download segment {index}: {url}")

    futures = []
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(fetch_and_save, (i, url)) for i, url in enumerate(segment_links)]
            with tqdm(total=len(segment_links), desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Error: {e}")
                    pbar.update(1)

        # 結合処理
        output_path = os.path.join(base_temp_dir, name)
        with open(output_path, 'wb') as out_file:
            for i in range(len(segment_links)):
                temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
                with open(temp_path, 'rb') as f:
                    out_file.write(f.read())
                os.remove(temp_path)

    except KeyboardInterrupt:
        #print("\nダウンロード中断されました。停止信号を送信します...")
        stop_flag.set()  # ← ここで全スレッドに停止を通知
        for future in futures:
            future.cancel()
        # 未完了ファイルの削除
        for i in range(len(segment_links)):
            temp_path = os.path.join(base_temp_dir, f"{i:05d}.ts")
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
        raise  # 終了ステータスを再送出

def decrypt_all_content(video_keys, video_input_file, video_output_file, audio_keys, audio_input_file, audio_output_file, service_name="TEMP"):
    with tqdm(total=2, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
        decrypt_content_shaka(video_keys, video_input_file, video_output_file, stream_type="video", service_name=service_name)
        outer_pbar.update(1)  # 1つ目の進捗を更新

        decrypt_content_shaka(audio_keys, audio_input_file, audio_output_file, stream_type="audio", service_name=service_name)
        outer_pbar.update(1)  # 2つ目の進捗を更新
def shaka_packager(keys):
    if os.name == 'nt':
        shaka_decrypt_command = [os.path.join("../../binaries/3.4.2_packager-win-x64.exe")]
    else:
        shaka_decrypt_command = [os.path.join("../../binaries/3.4.2_packager-linux-arm64")]
    for key in keys:
        if key["type"] == "CONTENT":
            shaka_decrypt_command.extend(
                [
                    "--enable_raw_key_decryption",
                    "--keys",
                    "key_id={}:key={}".format(key["kid_hex"], key["key_hex"]),
                ]
            )
    return shaka_decrypt_command
def decrypt_content_shaka(keys, input_file, output_file, stream_type, service_name="TEMP"):
    shaka_command = shaka_packager(keys)
    shaka_command.extend([f"input={input_file},stream={stream_type},output={output_file}"])
    #shaka_command.extend([input_file, output_file])
    #f"input={input_file},stream=video,output={output_file}"
    
    with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
        with subprocess.Popen(shaka_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:                
            #for line in process.stdout:
            #    print(line)
            process.wait()
            if process.returncode == 0:
                inner_pbar.n = 100
                inner_pbar.refresh()
def mux_episode(video_name, audio_name, output_name, unixtime, duration, service_name="TEMP"):
    compile_command = [
        "ffmpeg",
        "-i",
        os.path.join("content", unixtime, video_name),
        "-i",
        os.path.join("content", unixtime, audio_name),
        "-c:v",
        "copy",               # 映像はコピー
        "-c:a",
        "copy",                # 音声をコピー
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
                #print(line)
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

unixtime = str(int(time.time()))

os.makedirs(os.path.join("content", unixtime), exist_ok=True)

download_segment(video_segment_links, unixtime, "download_encrypt_video.mp4")
download_segment(audio_segment_links, unixtime, "download_encrypt_audio.mp4")

print("Decrypting encrypted Video, Audio Segments...")

decrypt_all_content(license_key["key"], os.path.join("content", unixtime, "download_encrypt_video.mp4"), os.path.join("content", unixtime, "download_decrypt_video.mp4"), license_key["key"], os.path.join("content", unixtime, "download_encrypt_audio.mp4"), os.path.join("content", unixtime, "download_decrypt_audio.mp4"))

print("Muxing Episode...")

output_path = os.path.join(content_info["meta_list"][0]["title"].replace("/","／")+".mp4")

result = mux_episode("download_decrypt_video.mp4", "download_decrypt_audio.mp4", output_path, unixtime, int(duration))

print("Success Download!")