import re
import os
import sys
import yaml
import time
import hmac
import m3u8
import base64
import struct
import shutil
import logging
import hashlib
import datetime
import traceback
from tqdm import tqdm
import pythonmonkey as pm
from Crypto.Cipher import AES
from datetime import datetime
from binascii import unhexlify
import xml.etree.ElementTree as ET

from ext.utils import abema
#from abema import abema

__service_name__ = "Abema"

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{COLOR_BLUE}{record.service_name}{COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        )
        
        return log_message

def set_variable(session, LOG_LEVEL):
    global logger, config, unixtime
    
    unixtime = str(int(time.time()))
    
    logger = logging.getLogger('YoimiLogger')
    if LOG_LEVEL == "DEBUG":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    formatter = CustomFormatter(
        '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def check_proxie(session):
    logger.info("Checking Proxie...", extra={"service_name": "Yoimi"})
    try:
        start = time.time()
        _ENDPOINT_CHECK_IP = 'https://api.p-c3-e.abema-tv.com/v1/ip/check'
        
        auth_response = session.get(_ENDPOINT_CHECK_IP, params={"device": "android"})

        from ext.utils.abema_util.region_check_pb2 import RegionInfo
        from google.protobuf.json_format import MessageToJson
        
        proto_message = RegionInfo()
        proto_message.ParseFromString(auth_response.content)
        
        auth_json = MessageToJson(proto_message)
        
        end = time.time()
        time_elapsed = end - start
        time_elapsed = time_elapsed * 1000
        
        try:
            if auth_json["location"] != "JP":
                logger.error(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
                logger.error(f"However, this proxy is not located in Japan. You will not be able to use it.", extra={"service_name": "Yoimi"})
                exit(1)
        except Exception as e:
            pass
        
        logger.info(f"{session.proxies} - Working {round(time_elapsed)}ms", extra={"service_name": "Yoimi"})
    except IOError:
        logger.error(f"Connection error of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)
    except:
        logger.error(f"Failed Check Proxies of {session.proxies}", extra={"service_name": "Yoimi"})
        exit(1)

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #url = https://abema.tv/video/title/26-215
        #url = "https://abema.tv/video/title/26-215"
        #url = https://abema.tv/channels/abema-anime/slots/9aLq5QwL6DpLBR
        #url = https://abema.tv/video/episode/25-262_s1_p13
        #url = https://abema.app/XXX
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt Content for Everyone", extra={"service_name": "Yoimi"})
        if session.proxies != {}:
            check_proxie(session)
        
        abema_downloader = abema.Abema_downloader(session)
        
        if email and password != None:
            if config["authorization"]["use_token"]:
                if config["authorization"]["token"] != "":
                    status, message = abema_downloader.check_token(config["authorization"]["token"])
                    if status == False:
                        logger.error(message, extra={"service_name": "Abema"})
                        exit(1)
                    else:
                        session.headers.update({"Authorization": config["authorization"]["token"]})
                        logger.debug("Get Token: "+config["authorization"]["token"], extra={"service_name": "Abema"})
                        logger.info("Loggined Account", extra={"service_name": "Abema"})
                        logger.info(" + ID: "+message["profile"]["userId"], extra={"service_name": "Abema"})
                        for plan_num, i in enumerate(message["subscriptions"]):
                            logger.info(f" + Plan {f"{plan_num+1}".zfill(2)}: "+i["planName"], extra={"service_name": "Abema"})
                else:
                    logger.error("Please input token", extra={"service_name": "Abema"})
                    exit(1)
            else:
                status, message, device_id = abema_downloader.authorize(email, password)
                try:
                    logger.debug("Get Token: "+session.headers["Authorization"], extra={"service_name": "Abema"})
                except:
                    logger.info("Failed to login", extra={"service_name": "Abema"})
                if status == False:
                    logger.error(message, extra={"service_name": "Abema"})
                    exit(1)
                else:
                    logger.info("Loggined Account", extra={"service_name": "Abema"})
                    logger.info(" + ID: "+message["profile"]["userId"], extra={"service_name": "Abema"})
                    for plan_num, i in enumerate(message["subscriptions"]):
                        logger.info(f" + Plan {f"{plan_num+1}".zfill(2)}: "+i["planName"], extra={"service_name": "Abema"})
            user_id = message["profile"]["userId"]
            if "プレミアム" in message["subscriptions"]:
                you_premium = True
            elif message["subscriptions"] == []:
                you_premium = False
            else:
                you_premium = False
                 
        else:
            temp_token = abema.Abema_utils.gen_temp_token(session)
            session.headers.update({'Authorization': 'Bearer ' + temp_token[0]})
            device_id = temp_token[1]
            status, message = abema_downloader.check_token('Bearer ' + temp_token[0])
            if status == False:
                logger.error(message, extra={"service_name": "Abema"})
                exit(1)
            user_id = message["profile"]["userId"]
            you_premium = False
                    
        if url.__contains__("abema.app"):
            temp_url = session.get(url, allow_redirects=False)
            url = temp_url.headers["Location"]
            
        matches = re.findall(r'(\d{1,3}-\d{1,3}(?:_[\w-]+)?)', url)
        if matches:
            abema_get_series_id = max((match for match in matches if '_' in match), default=None)
            if abema_get_series_id is None:
                abema_get_series_id = max(matches, key=len)
        else:
            exit("except error unknown error lol moment")
        print(abema_get_series_id)
        print(re.match(r"^(\d+-\d+)", abema_get_series_id).group(1))
        response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/contentlist/series/{re.match(r"^(\d+-\d+)", abema_get_series_id).group(1)}?includes=liveEvent%2Cslot").json()
        id_type = response["genre"]["name"]
        title_name = response["title"]
        
        if abema_get_series_id.__contains__("_p"):
            logger.info("Get Title for 1 Episode", extra={"service_name": "Abema"})
            print("episode download")
            response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/video/programs/{abema_get_series_id}?division=0&include=tvod").json()
            if id_type == "アニメ":
                format_string = config["format"]["anime"].replace("_{episodename}", "")
                values = {
                    "seriesname": title_name,
                    "titlename": response["episode"].get("title", ""),
                }
                try:
                    title_name_logger = format_string.format(**values)
                except KeyError as e:
                    missing_key = e.args[0]
                    values[missing_key] = ""
                    title_name_logger = format_string.format(**values)
            if id_type == "劇場":
                # どうやってこれ判定するねん
                print("")
                
            
                
            if 'label' in response:
                if 'free' in response['label']:
                    content_type = True
                else:
                    content_type = False
            elif 'freeEndAt' in response:
                content_type = True
            else:
                content_type = False
                
            if content_type == True:
                free_end_at = response['freeEndAt']
                tdt = datetime.fromtimestamp(free_end_at)
                d_week = {'Sun':'日','Mon':'月','Tue':'火','Wed':'水','Thu':'木','Fri':'金','Sat':'土'}
                free_end_at = tdt.strftime('%Y年%m月%d日({}) %H時%M分%S秒').format(d_week[tdt.strftime('%a')])
                
                content_type = "FREE   "
                content_status_lol = f" | END FREE {free_end_at}"
            else:
                content_type = "PREMIUM"
                content_status_lol = ""
            logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": "Abema"})
            if you_premium == False:
                if content_type == "PREMIUM":
                    return
            
            hls = response['playback']['hls']
            duration = response['info']['duration']
            
            m3u8_content = session.get(hls).text
            
            resolution_list = []
            resolution_data = {
                "1080p": ["4000kb/s", "AAC 192kb/s 2ch"],
                "720p": ["2000kb/s", "AAC 160kb/s 2ch"],
                "480p": ["900kb/s", "AAC 128kb/s 2ch"],
                "360p": ["550kb/s", "AAC 128kb/s 2ch"],
                "240p": ["240kb/s", "AAC 64kb/s 1ch"],
                "180p": ["120kb/s", "AAC 64kb/s 1ch"]
            }
            bitrate_calculation = {
                "1080p": 5175,
                "720p": 2373,
                "480p": 1367,
                "360p": 878,
                "240p": 292,
                "180p": 179
            }
            
            resolution_list = []
            base_link = hls.replace("playlist.m3u8", "")
            r_all = m3u8.loads(m3u8_content)
    
            play_res = []
            for r_p in r_all.playlists:
                temp = []
                temp.append(r_p.stream_info.resolution)
                temp.append(base_link + r_p.uri)
                play_res.append(temp)
            resgex = re.compile(r'(\d*)(?:\/\w+.ts)')
    
            resolution_list = []
            for resdata in play_res:
                reswh, m3u8_uri = resdata
                resw, resh = reswh
                rres = m3u8.loads(session.get(m3u8_uri).text)
    
                m3f = rres.files[1:]
                if not m3f:
                    return None, 'This video can\'t be downloaded for now.'
    
                if 'tsda' in rres.files[5]:
                    return None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
    
                if str(resh) in re.findall(resgex, m3f[5]):
                    resolution_list.append(
                        [
                            '{w}x{h}'.format(w=resw, h=resh),
                            '{h}p'.format(h=resh),
                            '{h}'.format(h=resh)
                        ]
                    )
            logger.info('Available resolution:', extra={"service_name": "Abema"})
            print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
            for res in resolution_list:
                r_c = res[1]
                wxh = res[0]
                vidq, audq = resolution_data[r_c]
                print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))

            m3u8_url = base_link+resolution_list[-1][2]+"/playlist.m3u8"

            logger.debug('Title: {}'.format(title_name_logger), extra={"service_name": "Abema"})
            logger.debug('Total Resolution: {}'.format(resolution_list), extra={"service_name": "Abema"})
            logger.debug('M3U8 Link: {}'.format(m3u8_url), extra={"service_name": "Abema"})
            
            def parse_m3u8(m3u8_url):
                r = session.get(m3u8_url)
        
                if 'timeshift forbidden' in r.text:
                    return None, None, None, 'This video can\'t be downloaded for now.'
        
                if r.status_code == 403:
                    return None, None, None, 'This video is geo-locked for Japan only.'
                
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
                iv = x.keys[0].iv
                ticket = x.keys[0].uri[18:]
        
                parsed_files = []
                for f in files:
                    if f.startswith('/tsvpg') or f.startswith('/tspg'):
                        f = 'https://ds-vod-abematv.akamaized.net' + f
                    parsed_files.append(f)
        
                logger.debug('Total files: {}'.format(len(files)), extra={"service_name": "Abema"})
                logger.debug('IV: {}'.format(iv), extra={"service_name": "Abema"})
                logger.debug('Ticket key: {}'.format(ticket), extra={"service_name": "Abema"})
        
                n = 0.0
                for seg in x.segments:
                    n += seg.duration
        
                est_filesize = round((round(n) * bitrate_calculation[resolution_list[-1][1]]) / 1024 / 6, 2)
        
                return parsed_files, iv[2:], ticket, est_filesize, 'Success'
            
            files, iv, ticket, filesize, reason = parse_m3u8(m3u8_url)
            
            if filesize > 1000:
                filesize = round(filesize / 1000, 1)
                filesize = str(filesize)+" GiB"
            else:
                filesize = str(filesize)+" MiB"
            
            logger.info('Output: {}'.format(title_name_logger+".mp4"), extra={"service_name": "Abema"})
            logger.info('Resolution: {}'.format(resolution_list[-1][1]), extra={"service_name": "Abema"})
            logger.info('Estimated file size: {}'.format(filesize), extra={"service_name": "Abema"})
            
            output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)
            
            decrypt_type = "hls" # or dash
            
            if decrypt_type == "hls":
                def get_video_key(ticket):
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
            if decrypt_type == "dash":
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
                def get_video_key(null):
                    global dash_mpd
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
                    sex_kid = get_default_KID(dash_mpd)
                    
                    logger.debug("Get default_kid: {}".format(sex_kid), extra={"service_name": "Abema"})
                    
                    kid = base64.b64encode(bytes.fromhex(sex_kid.replace("-", "").upper())).decode('utf-8').replace("==", "").replace("+", "-")
                    
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
                    
                    decrypt = pm.require("./utils/abema_util/decrypt")
                    
                    x = decrypt.get_x(k_slice)
                    y = decrypt.get_y(kid, user_id, y_slice)
                    logger.debug("GET X (Uint8Array): {}".format(x), extra={"service_name": "Abema"})
                    logger.debug("GET Y (Uint8Array): {}".format(y), extra={"service_name": "Abema"})
                    
                    t = hash
                    e = [int(z) for z in y]
                    n = [int(z) for z in x]
                    decrypt_json = decrypt.decrypt_key(rgl.json(), t, e, n)

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
                    
                    return f"{result_kid}:{result_key}", "Success"
            def setup_decryptor(key, iv):
                iv = unhexlify(iv)
                _aes = AES.new(key, AES.MODE_CBC, IV=iv)
                return iv, _aes
        
            def download_chunk(files, key, iv):
                if decrypt_type == "hls":
                    if iv.startswith('0x'):
                        iv = iv[2:]
                    else:
                        iv = iv
                        iv, _aes = setup_decryptor(key, iv)
                downloaded_files = []
                try:
                    with tqdm(total=len(files), desc='Downloading', ascii=True, unit='file') as pbar:
                        for tsf in files:
                            outputtemp = os.path.join(output_temp_directory, os.path.basename(tsf))
                            if not os.path.exists(output_temp_directory):
                                os.makedirs(output_temp_directory, exist_ok=True)
                            if outputtemp.find('?tver') != -1:
                                outputtemp = outputtemp[:outputtemp.find('?tver')]
                            with open(outputtemp, 'wb') as outf:
                                try:
                                    vid = session.get(tsf)
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
            def merge_video(path, output, service_name="Abema"):
                """
                m4sファイルを結合して1つの動画ファイルにする関数
                
                Args:
                    input_files (list): 結合するm4sファイルのリスト
                    output_file (str): 出力する結合済みのファイル名
                """
                total_files = len(path)
                
                # バイナリモードでファイルを結合
                with open(output, "wb") as outfile:
                    with tqdm(total=total_files, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="file") as pbar:
                        for i, f in enumerate(path, start=1):
                            with open(f, "rb") as infile:
                                outfile.write(infile.read())
                            os.remove(f)
                            pbar.set_postfix(file=f, refresh=True)
                            pbar.update(1)
            
            try:
                key, reason = get_video_key(ticket)
                if not key:
                    logger.error('{}'.format(reason), extra={"service_name": "Abema"})
                if decrypt_type == "dash":
                    # 720p.1 = video
                    # 720p 2 = audio
                    segment_list = abema.Abema_utils.get_segment_link_list(dash_mpd, f"{resolution_list[-1][1]}.1", "https://ds-vod-abematv.akamaized.net/")
                    files = segment_list[0]["all"]
                    downloaded_files = download_chunk(files, key, iv)
                    temp_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_video_encrypted.mp4")
                    merge_video(downloaded_files, temp_output)
                    abema.Abema_decrypt.decrypt_content(key, temp_output, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_video.mp4"), config)
                    files = [s.replace('p.1', 'p.2') for s in segment_list[1]["all"]]
                    downloaded_files = download_chunk(files, key, iv)
                    temp_output = os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_audio_encrypted.mp4")
                    merge_video(downloaded_files, temp_output)
                    abema.Abema_decrypt.decrypt_content(key, temp_output, os.path.join(config["directorys"]["Temp"], "content", unixtime, "download_audio.mp4"), config)
                    
                    result = abema_downloader.mux_episode("download_video.mp4", "download_audio.mp4", os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"), config, unixtime, title_name, int(duration))
                    dir_path = os.path.join(config["directorys"]["Temp"], "content", unixtime)
                    
                    if os.path.exists(dir_path) and os.path.isdir(dir_path):
                        for filename in os.listdir(dir_path):
                            file_path = os.path.join(dir_path, filename)
                            try:
                                if os.path.isfile(file_path):
                                    os.remove(file_path)
                                elif os.path.isdir(file_path):
                                    shutil.rmtree(file_path)
                            except Exception as e:
                                print(f"削除エラー: {e}")
                    else:
                        print(f"指定されたディレクトリは存在しません: {dir_path}")
                    logger.info('Finished download: {}'.format(title_name_logger), extra={"service_name": "Abema"})
                    
                if decrypt_type == "hls":
                    downloaded_files = download_chunk(files, key, iv)
                    merge_video(downloaded_files, os.path.join(config["directorys"]["Downloads"], title_name, title_name_logger+".mp4"))
            except Exception as e:
                logger.error("Traceback has occurred", extra={"service_name": __service_name__})
                type_, value, _ = sys.exc_info()
                print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
                print("\n----ERROR LOG----")
                print("ENative:\n"+traceback.format_exc())
                print("EType:\n"+str(type_))
                print("EValue:\n"+str(value))
                print("Service: "+__service_name__)
                print("Version: "+additional_info[0])
                print("----END ERROR LOG----")
            
        else:
            logger.info(f"Get Title for Season", extra={"service_name": "Abema"})
            print("series download")
            content_id = re.match(r"^(\d+-\d+)", abema_get_series_id).group(1)
            if abema_get_series_id.__contains__("_s"):
                query_string = {
                    "seasonId": abema_get_series_id,
                    "limit": 100,
                    "offset": 0,
                    "orderType": "asc",
                    "include": "liveEvent,slot"
                }
                response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/contentlist/episodeGroups/{content_id}_eg0/contents", params=query_string).json()
                for message in response["episodeGroupContents"]:
                    if id_type == "アニメ":
                        format_string = config["format"]["anime"].replace("_{episodename}", "")
                        values = {
                            "seriesname": title_name,
                            "titlename": message["episode"].get("title", ""),
                        }
                        try:
                            title_name_logger = format_string.format(**values)
                        except KeyError as e:
                            missing_key = e.args[0]
                            values[missing_key] = ""
                            title_name_logger = format_string.format(**values)
                    if id_type == "劇場":
                       # どうやってこれ判定するねん
                       print("")
                                              
                    if 'label' in message:
                        if 'free' in message['label']:
                            content_type = True
                    elif 'freeEndAt' in message:
                        content_type = True
                    elif message["video"]["terms"][0]["onDemandType"] == 3:
                        content_type = True
                    else:
                        content_type = False
                        
                    if content_type == True:
                        if message["video"]["terms"][0]["onDemandType"] == 3:
                            free_end_at = message["video"]["terms"][0]["endAt"]
                        else:
                            free_end_at = message['freeEndAt']
                        tdt = datetime.fromtimestamp(free_end_at)
                        d_week = {'Sun':'日','Mon':'月','Tue':'火','Wed':'水','Thu':'木','Fri':'金','Sat':'土'}
                        free_end_at = tdt.strftime('%Y年%m月%d日({}) %H時%M分%S秒').format(d_week[tdt.strftime('%a')])
                        
                        content_type = "FREE   "
                        content_status_lol = f" | END FREE {free_end_at}"
                    else:
                        content_type = "PREMIUM"
                        content_status_lol = ""
                    logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": "Abema"})
            else:
                response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/video/series/{content_id}", params={"includeSlot": "true"}).json()
                
                season_response = response["seasons"]
                
                for season_num, i in enumerate(season_response):
                    logger.info(f"Processing season {str(season_num+1)} | {i["name"]}", extra={"service_name": "Abema"})
                    for i2 in i["episodeGroups"]:
                        #print(i2["id"])
                        query_string = {
                            "seasonId": i["id"],
                            "limit": 100,
                            "offset": 0,
                            "orderType": "asc",
                            "include": "liveEvent,slot"
                        }
                        response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/contentlist/episodeGroups/{i2["id"]}/contents", params=query_string).json()
                        
                        episode_group_ontents = response["episodeGroupContents"]
                        
                        if len(season_response) == 1:
                            if len(episode_group_ontents) == 1:
                                seriesname = title_name
                            else:
                                seriesname = title_name + "_" + i2["name"]
                        else:
                            seriesname = i["name"]
                            
                        for message in episode_group_ontents:
                            if id_type == "アニメ":
                                format_string = config["format"]["anime"].replace("_{episodename}", "")
                                values = {
                                    "seriesname": seriesname,
                                    "titlename": message["episode"].get("title", ""),
                                }
                                try:
                                    title_name_logger = format_string.format(**values)
                                except KeyError as e:
                                    missing_key = e.args[0]
                                    values[missing_key] = ""
                                    title_name_logger = format_string.format(**values)
                            if id_type == "劇場":
                                # どうやってこれ判定するねん
                                print("")
                            if 'label' in message:
                                if 'free' in message['label']:
                                    content_type = True
                            elif 'freeEndAt' in message:
                                content_type = True
                            elif message["video"]["terms"][0]["onDemandType"] == 3:
                                content_type = True
                            else:
                                content_type = False
                                
                            if content_type == True:
                                if message["video"]["terms"][0]["onDemandType"] == 3:
                                    free_end_at = message["video"]["terms"][0]["endAt"]
                                else:
                                    free_end_at = message['freeEndAt']
                                tdt = datetime.fromtimestamp(free_end_at)
                                d_week = {'Sun':'日','Mon':'月','Tue':'火','Wed':'水','Thu':'木','Fri':'金','Sat':'土'}
                                free_end_at = tdt.strftime('%Y年%m月%d日({}) %H時%M分%S秒').format(d_week[tdt.strftime('%a')])
                                
                                content_type = "FREE   "
                                content_status_lol = f" | END FREE {free_end_at}"
                            else:
                                content_type = "PREMIUM"
                                content_status_lol = ""
                            logger.info(f" + {content_type} | {title_name_logger} {content_status_lol}", extra={"service_name": "Abema"})
    except Exception:
        logger.error("Traceback has occurred", extra={"service_name": __service_name__})
        #print(traceback.format_exc())
        #print("\n")
        type_, value, _ = sys.exc_info()
        #print(type_)
        #print(value)
        print("If the process stops due to something unexpected, please post the following log to \nhttps://github.com/NyaShinn1204/Yoimi/issues.")
        print("\n----ERROR LOG----")
        print("ENative:\n"+traceback.format_exc())
        print("EType:\n"+str(type_))
        print("EValue:\n"+str(value))
        print("Service: "+__service_name__)
        print("Version: "+additional_info[0])
        print("----END ERROR LOG----")