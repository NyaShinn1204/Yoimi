import os
import re
import m3u8
import shutil
import threading

from util.abema.utils.main import *

episode_done = threading.Event()

def check_output(output=None, output_name=None):
    if output:
        fn_, ext_ = os.path.splitext(output)
        if ext_ != 'ts':
            output = fn_ + '.ts'
    else:
        output = '{}.ts'.format(output_name)
    return output

def parse_m3u8(m3u8_url):
    import data.setting as setting
    print('Requesting m3u8')
    r = setting.abema_session.get(m3u8_url)
    print('Data requested')
    if 'timeshift forbidden' in r.text:
        return None, None, None, 'This video can\'t be downloaded for now.'
    if r.status_code == 403:
        return None, None, None, 'This video is geo-locked for Japan only.'
    print('Parsing m3u8')
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
    #if self.resolution[:-1] != resgex:
    #    if not self.resolution_o:
    #        self.yuu_logger.warn('Changing resolution, from {} to {}p'.format(self.resolution, resgex))
    #    self.resolution = resgex + 'p'
    print('Total files: {}'.format(len(files)))
    print('IV: {}'.format(iv))
    print('Ticket key: {}'.format(ticket))
    return parsed_files, iv[2:], ticket, 'Success'

def get_video_key(ticket):
    import data.setting as setting
    
    import hmac
    import struct
    import hashlib
    from Crypto.Cipher import AES
    from binascii import unhexlify
    
    _KEYPARAMS = {
        "osName": "android",
        "osVersion": "6.0.1",
        "osLand": "ja_JP",
        "osTimezone": "Asia/Tokyo",
        "appId": "tv.abema",
        "appVersion": "3.27.1"
    }
    
    _MEDIATOKEN_API = "https://api.abema.io/v1/media/token"
    _LICENSE_API = "https://license.abema.io/abematv-hls"
    _STRTABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    _HKEY = b"3AF0298C219469522A313570E8583005A642E73EDD58E3EA2FB7339D3DF1597E"
    
    print('Sending parameter to API')
    restoken = setting.abema_session.get(_MEDIATOKEN_API, params=_KEYPARAMS).json()
    print(restoken)
    mediatoken = restoken['token']
    print('Media token: {}'.format(mediatoken))
    print('Sending ticket and media token to License API')
    rgl = setting.abema_session.post(_LICENSE_API, params={"t": mediatoken}, json={"kv": "a", "lt": ticket})
    if rgl.status_code == 403:
        return None, 'Access to this video are not allowed\nProbably a premium video or geo-locked.'
    gl = rgl.json()
    cid = gl['cid']
    k = gl['k']
    print('CID: {}'.format(cid))
    print('K: {}'.format(k))
    print('Summing up data with STRTABLE')
    res = sum([_STRTABLE.find(k[i]) * (58 ** (len(k) - 1 - i)) for i in range(len(k))])
    print('Result: {}'.format(res))
    print('Intepreting data')
    encvk = struct.pack('>QQ', res >> 64, res & 0xffffffffffffffff)
    print('Encoded video key: {}'.format(encvk))
    print('Hashing data')
    h = hmac.new(unhexlify(_HKEY), (cid + setting.abema_auth["email"]["deviceid"]).encode("utf-8"), digestmod=hashlib.sha256)
    enckey = h.digest()
    print('Second Encoded video key: {}'.format(enckey))
    print('Decrypting result')
    aes = AES.new(enckey, AES.MODE_ECB)
    vkey = aes.decrypt(encvk)
    print('Decrypted, Result: {}'.format(vkey))
    return vkey, 'Success getting video key'

def setup_decryptor(iv_temp):
    global _aes, iv
    from Crypto.Cipher import AES
    from binascii import unhexlify
    iv = unhexlify(iv_temp)
    _aes = AES.new(key_tmp, AES.MODE_CBC, IV=iv)

import os
import time
import threading
import subprocess
from tqdm import tqdm

def update_progress(total_var, speed_var, downloaded_var, remaining_time_var, tqdm_obj):
    """
    プログレスバーの情報を取得して、tkinter の変数を更新する関数。
    `tqdm_obj` から進行状況、スピード、ETA などを取得して反映。
    """
    while not tqdm_obj.n >= tqdm_obj.total:
        downloaded_var.set(str(tqdm_obj.n)+" Fragments")  # ダウンロード済みのファイル数を設定
        total_var.set(str(tqdm_obj.total)+" Fragments")  # 総ファイル数を設定

        # Speed の取得 (Noneの場合は0を設定)
        speed = tqdm_obj.format_dict.get('rate', 0) or 0  # None の場合は 0 を設定
        speed_var.set(f"{speed:.2f} Fragments/s")

        # ETA の取得 (Noneの場合は0を設定)
        eta = tqdm_obj.format_dict.get('remaining', 0) or 0  # None の場合は 0 を設定
        remaining_time_var.set(f"{int(eta)}s")

        time.sleep(1)  # 更新頻度を調整

    downloaded_var.set(total_var.get())  # ダウンロード終了時、ダウンロード済みファイル数を総ファイル数に設定
    remaining_time_var.set("0s")
    speed_var.set("0")


def download_chunk(files, key, iv):
    """
    ファイルのリストを順にダウンロードし、復号化して指定のディレクトリに保存する。
    """
    import data.setting as setting
    
    setting.downloader_downloader.set("Python Native")

    if iv.startswith('0x'):
        iv_temp = iv[2:]
    else:
        iv_temp = iv
    global key_tmp
    key_tmp = key
        
    downloaded_files = []
    setup_decryptor(iv_temp)  # 復号化用の設定を初期化

    output_temp_directory = os.path.join(setting.folders["temp"], "content", setting.unixtime)

    if not os.path.exists(output_temp_directory):
        os.makedirs(output_temp_directory, exist_ok=True)

    try:
        # `tqdm` プログレスバーを設定し、`pbar` オブジェクトを `update_progress` 関数に渡す
        with tqdm(total=len(files), desc='Downloading', ascii=True, unit='file') as pbar:
            # `update_progress` 関数を別スレッドで開始し、`tqdm` の状態を UI に反映
            threading.Thread(target=update_progress, args=(setting.downloader_total, setting.downloader_speed, setting.downloader_downloaded, setting.downloader_elapsed, pbar), daemon=True).start()
            
            for tsf in files:
                output_temp_file = os.path.join(output_temp_directory, os.path.basename(tsf))
                if '?tver' in output_temp_file:
                    output_temp_file = output_temp_file.split('?tver')[0]

                with open(output_temp_file, 'wb') as outf:
                    try:
                        # ファイルをダウンロードし、復号化して書き込む
                        vid = setting.abema_session.get(tsf)
                        vid = _aes.decrypt(vid.content)
                        outf.write(vid)
                    except Exception as err:
                        print(f'Problem occurred\nReason: {err}')
                        return None
                
                pbar.update()  # tqdm のカウントを更新
                downloaded_files.append(output_temp_file)

    except KeyboardInterrupt:
        print('User pressed CTRL+C, cleaning up...')
        return None
    
    # 最後にファイルのパスを返す
    return downloaded_files


def log_errors(process):
    """
    外部プロセスのエラーログをリアルタイムに取得し、出力する関数。
    """
    for error in iter(process.stderr.readline, ''):
        print(f"Error: {error.strip()}")


def log_errors(process):
    for error in iter(process.stderr.readline, ''):
        print(f"Error: {error.strip()}")


def delete_folder_contents(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.unlink(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)

def merge_video(path, output):
    import data.setting as setting
    """
    Merge every video chunk to a single file output
    """
    from tqdm import tqdm
    with open(os.path.join(os.path.join(setting.folders["temp"], "content", output)), 'wb') as out:
        with tqdm(total=len(path), desc="Merging", ascii=True, unit="file") as pbar:
            for i in path:
                out.write(open(i, 'rb').read())
                os.remove(i)
                pbar.update()

def mux_video(old_file, muxfile, title_name):
    import data.setting as setting
    import subprocess
    """
    Mux .ts or .mp4 or anything to a .mkv

    It will try to use ffmpeg first, if it's not in the PATH, then it will try to use mkvmerge
    If it's doesn't exist too, it just gonna skip.
    """
    # MkvMerge/FFMPEG check
    use_ffmpeg = False
    use_mkvmerge = False
    
    check_ffmpeg = subprocess.run(['ffmpeg', '-version'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check_mkvmerge = subprocess.run(['mkvmerge', '-V'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    if check_mkvmerge.returncode == 0:
        use_mkvmerge = True
    if check_ffmpeg.returncode == 0:
        use_ffmpeg = True
    else:
        return "Error"
    
    output_directory = os.path.join(setting.folders["output"], parse_titlename(title_name))
    
    if not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)
    
    fn_, _ = os.path.splitext(old_file)
    
    #print(os.path.join(setting.folders["temp"], "content", _out_))
    print(muxfile)
    print(old_file)
    #
    #print(os.path.join(output_directory, f"{fn_}.{muxfile.replace(" ","_")}"))
    
    if use_mkvmerge:
        subprocess.run(['mkvmerge', '-o', '{f}.{e}'.format(f=fn_, e=muxfile), os.path.join(setting.folders["temp"], "content", old_file)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if use_ffmpeg:
        subprocess.run([
            'ffmpeg', 
            '-i', os.path.join(setting.folders["temp"], "content", old_file), 
            '-c', 'copy', 
            os.path.join(output_directory, f"{fn_}.{muxfile.replace(" ","_")}")
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return '{f}.{e}'.format(f=fn_,e=muxfile)

def download_episode(video_resolution, audio_resolution, m3u8_url, index, outputs, title_name, abema_get_series_id):
    threading.Thread(target=download_episode_main, args=(video_resolution, audio_resolution, m3u8_url, index, outputs, title_name)).start()

def download_episode_main(video_resolution, audio_resolution, m3u8_url, index, outputs, title_name):
    global output_temp_direcotry
    import data.setting as setting

    print("index: " + str(index))
    
    if video_resolution == "best":
        video_meta = setting.abema_video_meta[-1]
        last_video_quality = video_meta[-1]
        video_resolution = last_video_quality
    if audio_resolution == "best":
        audio_meta = setting.abema_audio_meta[-1]
        last_audio_quality = audio_meta[-1]
        audio_resolution = last_audio_quality

    print(video_resolution, audio_resolution, m3u8_url)
    
    if isinstance(outputs, str):
        outputs = [outputs]
    
    bitrate_calculation = {
        "1080p": 5175,
        "720p": 2373,
        "480p": 1367,
        "360p": 878,
        "240p": 292,
        "180p": 179
    }
    
    r = setting.abema_session.get(m3u8_url)
    
    x = m3u8.loads(r.text)
    
    n = 0.0
    for seg in x.segments:
        n += seg.duration
    est_filesize = round((round(n) * bitrate_calculation[video_resolution[0]]) / 1024 / 6, 2)
    
    print("Parsing m3u8 and fetching video key fro files")
    files, iv, ticket, reason = parse_m3u8(m3u8_url)
    
    key, reason = get_video_key(ticket)
    if not key:
        print('{}'.format(reason))
    
    muxfile = "mp4"
    illegalchar = ['/', '<', '>', ':', '"', '\\', '|', '?', '*']
    #for pos, _out_ in enumerate(outputs):
    _out_ = outputs[index]
    _out_ = check_output("", _out_)
    for char in illegalchar:
        _out_ = _out_.replace(char, '_')
        
    print('Output: {}'.format(_out_))
    print('Resolution: {}'.format(video_resolution[0]))
    print('Estimated file size: {} MiB'.format(est_filesize))
    print('Mux file extension: {}'.format(muxfile))

    output_temp_direcotry = os.path.join(setting.folders["temp"], "content", setting.unixtime)
    
    if not os.path.exists(output_temp_direcotry):
        os.makedirs(output_temp_direcotry, exist_ok=True)
    
    setting.downloader_status.set("Episode Downloading")
    
    dl_list = download_chunk(files, key, iv)
    if not dl_list:
        delete_folder_contents(output_temp_direcotry)
    
    setting.downloader_status.set("Episode Download Complete")
        
    print('Finished downloading')
    print('Merging video')
    setting.downloader_status.set("Episode Marging")
    merge_video(dl_list, _out_)
    setting.downloader_status.set("Episode Marge Complete")
    delete_folder_contents(output_temp_direcotry)
    #_out_ = os.path.join(setting.folders["temp"], "content", _out_)
    if os.path.isfile(os.path.join(setting.folders["temp"], "content", _out_)):
        setting.downloader_status.set("Episode Muxing")
        print('Muxing video')
        result = mux_video(_out_, muxfile, title_name)
        if not result:
            print('There\'s no available muxers that can be used, skipping...')
            mux = False # Automatically set to False so it doesn't spam the user
        elif result and os.path.isfile(result):
            os.remove(os.path.join(setting.folders["temp"], "content", _out_))
            _out_ = result
        setting.downloader_status.set("Episode Mux Complete")
    print('Finished downloading: {}'.format(_out_))
    episode_done.set()
    #shutil.rmtree(output_temp_direcotry)
    
def download_series(video_resolution, audio_resolution, m3u8_url, outputs, title_name):
    threading.Thread(target=download_series_main, args=(video_resolution, audio_resolution, m3u8_url, outputs, title_name)).start()

def download_series_main(video_resolution, audio_resolution, m3u8_url, outputs, title_name):
    m3u8_url_to_download = m3u8_url
    i = 0
    for m3u8_url_for in m3u8_url_to_download:       
        download_episode_main(video_resolution, audio_resolution, m3u8_url_for, i, outputs, title_name)
        episode_done.wait()
        episode_done.clear()
        
        i = i + 1
    
    print("[+] 多分ダウンロード完了")