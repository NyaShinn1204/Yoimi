import re
import os
import sys
import yaml
import time
import m3u8
import logging
import datetime
import traceback
from tqdm import tqdm
from Crypto.Cipher import AES
from datetime import datetime
from binascii import unhexlify
import xml.etree.ElementTree as ET

#from ext.utils import unext
#from abema import abema
import abema

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

        from region_check_pb2 import RegionInfo
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
            
            hls = response['playback']['hls']
            
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
            resolutions = re.findall(r"RESOLUTION=(\d+)x(\d+)", m3u8_content)
            
            resolution_list = []
            
            for resolution in resolutions:
                width, height = map(int, resolution)
                
                temp_list = []
                
                temp_list.append(f"{width}x{height}")
                temp_list.append(f"{height}p")
                    
                resolution_list.append(temp_list)

            logger.info('Available resolution:', extra={"service_name": "Abema"})
            #logger.log(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16), extra={"service_name": "Abema"})
            print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
            for res in resolution_list:
                r_c = res[1]
                wxh = res[0]
                vidq, audq = resolution_data[r_c]
                #logger.log(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16), extra={"service_name": "Abema"})
                print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))

            m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[-1])

            logger.debug('Title: {}'.format(title_name_logger), extra={"service_name": "Abema"})
            logger.debug('Total Resolution: {}'.format(resolution_list), extra={"service_name": "Abema"})
            logger.debug('M3U8 Link: {}'.format(m3u8_url), extra={"service_name": "Abema"})
            
            def parse_m3u8(m3u8_url):
                #self.yuu_logger.debug('Requesting m3u8')
                r = session.get(m3u8_url)
                #self.yuu_logger.debug('Data requested')
        
                if 'timeshift forbidden' in r.text:
                    return None, None, None, 'This video can\'t be downloaded for now.'
        
                if r.status_code == 403:
                    return None, None, None, 'This video is geo-locked for Japan only.'
        
                #self.yuu_logger.debug('Parsing m3u8')
        
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
                #    #if not self.resolution_o:
                #    #    self.yuu_logger.warn('Changing resolution, from {} to {}p'.format(self.resolution, resgex))
                #    self.resolution = resgex + 'p'
                logger.debug('Total files: {}'.format(len(files)), extra={"service_name": "Abema"})
                logger.debug('IV: {}'.format(iv), extra={"service_name": "Abema"})
                logger.debug('Ticket key: {}'.format(ticket), extra={"service_name": "Abema"})
        
                n = 0.0
                for seg in x.segments:
                    n += seg.duration
        
                est_filesize = round((round(n) * bitrate_calculation[resolution[-1]+"p"]) / 1024 / 6, 2)
        
                return parsed_files, iv[2:], ticket, est_filesize, 'Success'
            
            files, iv, ticket, filesize, reason = parse_m3u8(m3u8_url)
            #print(files, iv, ticket, filesize, reason)
            
            if filesize > 1000:
                filesize = round(filesize / 1000, 1)
                filesize = str(filesize)+" GiB"
            else:
                filesize = str(filesize)+" MiB"
            
            logger.info('Output: {}'.format(title_name_logger+".mp4"), extra={"service_name": "Abema"})
            logger.info('Resolution: {}'.format(resolution[-1]+"p"), extra={"service_name": "Abema"})
            logger.info('Estimated file size: {}'.format(filesize), extra={"service_name": "Abema"})
            
            output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)
            
            def get_default_KID(mpd_content):
                root = ET.fromstring(mpd_content)
            
                namespaces = {
                    '': 'urn:mpeg:dash:schema:mpd:2011',  # デフォルト名前空間
                    'cenc': 'urn:mpeg:cenc:2013'  # CENC名前空間
                }
            
                # 'ContentProtection'タグ内で'cenc:default_KID'を検索
                for elem in root.iterfind('.//{urn:mpeg:dash:schema:mpd:2011}Period//{urn:mpeg:dash:schema:mpd:2011}AdaptationSet//{urn:mpeg:dash:schema:mpd:2011}ContentProtection', namespaces):
                    # 名前空間付きの属性名でdefault_KIDを取得
                    default_KID = elem.get('{urn:mpeg:cenc:2013}default_KID')
                    if default_KID:
                        return default_KID
                return None
            def get_video_key(ticket):
                #self.yuu_logger.debug('Sending parameter to API')
                _KEYPARAMS = {
                    "osName": "pc",
                    "osVersion": "1.0.0",
                    "osLand": "ja",
                    "osTimezone": "Asia/Tokyo",
                    "appVersion": "v25.130.0"
                }
                restoken = session.get("https://api.p-c3-e.abema-tv.com/v1/media/token", params=_KEYPARAMS).json()
                mediatoken = restoken['token']
                #self.yuu_logger.debug('Media token: {}'.format(mediatoken))
                
                
                mpd = session.get(response['playback']['dash'], params={"t": mediatoken, "enc": "clear", "dt": "pc_unknown", "ccf": 0, "dtid": "jdwHcemp6THr", "ut": 1}).text
                import base64
                sex_kid = get_default_KID(mpd)
                
                print(sex_kid.replace("-", "").upper())
                
                kid = base64.b64encode(bytes.fromhex(sex_kid.replace("-", "").upper())).decode('utf-8').replace("==", "").replace("+", "-")
                
                print(kid)
        
                #self.yuu_logger.debug('Sending ticket and media token to License API')
                print(response["id"])
                rgl = session.post("https://license.p-c3-e.abema-tv.com/abematv-dash", params={"t": mediatoken, "cid": response["id"], "ct": "program"}, json={"kids":[kid],"type":"temporary"})
                if rgl.status_code == 403:
                    return None, 'Access to this video are not allowed\nProbably a premium video or geo-locked.'
        
                gl = rgl.json()["keys"][0]
        
                cid = gl['kid']
                k = gl['k']
        
                #self.yuu_logger.debug('CID: {}'.format(cid))
                #self.yuu_logger.debug('K: {}'.format(k))
        
                #self.yuu_logger.debug('Summing up data with STRTABLE')
                res = sum(["123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".find(k[i]) * (58 ** (len(k) - 1 - i)) for i in range(len(k))])
        
                #self.yuu_logger.debug('Result: {}'.format(res))
                #self.yuu_logger.debug('Intepreting data')
        
                import struct
                import hmac
                import hashlib
                encvk = struct.pack('>QQ', res >> 64, res & 0xffffffffffffffff)
        
                #self.yuu_logger.debug('Encoded video key: {}'.format(encvk))
                #self.yuu_logger.debug('Hashing data')
        
                h = hmac.new(unhexlify("3AF0298C219469522A313570E8583005A642E73EDD58E3EA2FB7339D3DF1597E"), (cid + device_id).encode("utf-8"), digestmod=hashlib.sha256)
                enckey = h.digest()
        
                #self.yuu_logger.debug('Second Encoded video key: {}'.format(enckey))
                #self.yuu_logger.debug('Decrypting result')
        
                aes = AES.new(enckey, AES.MODE_ECB)
                vkey = aes.decrypt(encvk)
        
                #self.yuu_logger.debug('Decrypted, Result: {}'.format(vkey))
        
                return vkey, 'Success getting video key'
            def setup_decryptor(key):
                iv = unhexlify(iv)
                _aes = AES.new(key, AES.MODE_CBC, IV=iv)
                return iv, _aes
        
            def download_chunk(files, key, iv):
                if iv.startswith('0x'):
                    iv = iv[2:]
                else:
                    iv = iv
                downloaded_files = []
               #iv, _aes = setup_decryptor(key) # Initialize a new decryptor
                try:
                    with tqdm(total=len(files), desc='Downloading', ascii=True, unit='file') as pbar:
                        for tsf in files:
                            outputtemp = os.path.join(output_temp_directory, os.path.basename(tsf))
                            if not os.path.exists(output_temp_directory):
                                os.makedirs(output_temp_directory, exist_ok=True)
                            if outputtemp.find('?tver') != -1:
                                outputtemp = outputtemp[:outputtemp.find('?tver')]
                            print(outputtemp)
                            with open(outputtemp, 'wb') as outf:
                                try:
                                    vid = session.get(tsf)
                                   # vid = _aes.decrypt(vid.content)
                                    outf.write(vid.content)
                                except Exception as err:
                                    print(err)
                                    #yuu_log.error('Problem occured\nreason: {}'.format(err))
                                    return None
                            pbar.update()
                            downloaded_files.append(outputtemp)
                except KeyboardInterrupt:
                    #yuu_log.warn('User pressed CTRL+C, cleaning up...')
                    return None
                return downloaded_files
            def merge_video(path, output):
                with open(output, 'wb') as out:
                    with tqdm(total=len(path), desc="Merging", ascii=True, unit="file") as pbar:
                        for i in path:
                            out.write(open(i, 'rb').read())
                            os.remove(i)
                            pbar.update()
            
            try:
                key, reason = get_video_key(ticket)
                if not key:
                    logger.error('{}'.format(reason), extra={"service_name": "Abema"})
                    #continue
            except:
                print("lol")
            key = ""
            downloaded_files = download_chunk(files, key, iv)
            merge_video(downloaded_files, os.path.join(config["directorys"]["Temp"], "content", unixtime, "fuck_abema.mp4"))
            
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
                    
                
                #if len(response["seasons"]) != 1:
                #    for season_num, i in enumerate(response["seasons"]):
                #        logger.info(f"Processing season {str(season_num+1)} | {i["name"]}", extra={"service_name": "Abema"})
                #        query_string = {
                #            "seasonId": i["id"],
                #            "limit": 100,
                #            "offset": 0,
                #            "orderType": "asc",
                #            "include": "liveEvent,slot"
                #        }
                #        response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/contentlist/episodeGroups/{content_id}_eg0/contents", params=query_string).json()
                #        for message in response["episodeGroupContents"]:
                #            if id_type == "アニメ":
                #                format_string = config["format"]["anime"].replace("_{episodename}", "")
                #                values = {
                #                    "seriesname": i["name"],
                #                    "titlename": message["episode"].get("title", ""),
                #                }
                #                try:
                #                    title_name_logger = format_string.format(**values)
                #                except KeyError as e:
                #                    missing_key = e.args[0]
                #                    values[missing_key] = ""
                #                    title_name_logger = format_string.format(**values)
                #            if id_type == "劇場":
                #                format_string = config["format"]["movie"]
                #                if message.get("displayNo", "") == "":
                #                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                #                    values = {
                #                        "seriesname": title_name,
                #                    }
                #                else:
                #                    values = {
                #                        "seriesname": i["name"],
                #                        "titlename": message["episode"].get("displayNo", ""),
                #                        #"episodename": message.get("episodeName", "")
                #                    }
                #                try:
                #                    title_name_logger = format_string.format(**values)
                #                except KeyError as e:
                #                    missing_key = e.args[0]
                #                    values[missing_key] = ""
                #                    title_name_logger = format_string.format(**values)
                #            logger.info(f" + {title_name_logger}", extra={"service_name": "Abema"})
                #else:
                #    if response["seasons"]["episodeGroups"]
                #    for season_num, i in enumerate(response["seasons"]):
                #        logger.info(f"Processing season {str(season_num+1)} | {i["name"]}", extra={"service_name": "Abema"})
                #        query_string = {
                #            "seasonId": i["id"],
                #            "limit": 100,
                #            "offset": 0,
                #            "orderType": "asc",
                #            "include": "liveEvent,slot"
                #        }
                #        response = session.get(f"https://api.p-c3-e.abema-tv.com/v1/contentlist/episodeGroups/{content_id}_eg0/contents", params=query_string).json()
                #        for message in response["episodeGroupContents"]:
                #            if id_type == "アニメ":
                #                format_string = config["format"]["anime"].replace("_{episodename}", "")
                #                values = {
                #                    "seriesname": i["name"],
                #                    "titlename": message["episode"].get("title", ""),
                #                }
                #                try:
                #                    title_name_logger = format_string.format(**values)
                #                except KeyError as e:
                #                    missing_key = e.args[0]
                #                    values[missing_key] = ""
                #                    title_name_logger = format_string.format(**values)
                #            if id_type == "劇場":
                #                format_string = config["format"]["movie"]
                #                if message.get("displayNo", "") == "":
                #                    format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
                #                    values = {
                #                        "seriesname": title_name,
                #                    }
                #                else:
                #                    values = {
                #                        "seriesname": i["name"],
                #                        "titlename": message["episode"].get("displayNo", ""),
                #                        #"episodename": message.get("episodeName", "")
                #                    }
                #                try:
                #                    title_name_logger = format_string.format(**values)
                #                except KeyError as e:
                #                    missing_key = e.args[0]
                #                    values[missing_key] = ""
                #                    title_name_logger = format_string.format(**values)
                #            logger.info(f" + {title_name_logger}", extra={"service_name": "Abema"})
        #status, meta_response = unext_downloader.get_title_metadata(url)
        #if status == False:
        #    logger.error("Failed to Get Series Json", extra={"service_name": "U-Next"})
        #    exit(1)
        #else:
        #    title_name = meta_response["titleName"]
        #    
        #status = unext.Unext_utils.check_single_episode(url)
        #logger.info("Get Video Type for URL", extra={"service_name": "U-Next"})
        #status_id, id_type = unext_downloader.get_id_type(url)
        #if status_id == False:
        #    logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
        #    exit(1)
        #logger.info(f" + Video Type: {id_type}", extra={"service_name": "U-Next"})
        #if status == False:
        #    logger.info("Get Title for Season", extra={"service_name": "U-Next"})
        #    status, messages = unext_downloader.get_title_parse_all(url)
        #    if status == False:
        #        logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
        #        exit(1)
        #        
        #    logger.info("Downloading All Episode Thumbnails...", extra={"service_name": "U-Next"})
        #    
        #    unext_downloader.get_thumbnail_list(meta_response["id"], message["id"], id_type, config, unixtime)
        #        
        #    for message in messages:
        #        if id_type[2] == "ノーマルアニメ":
        #            format_string = config["format"]["anime"]
        #            values = {
        #                "seriesname": title_name,
        #                "titlename": message.get("displayNo", ""),
        #                "episodename": message.get("episodeName", "")
        #            }
        #            try:
        #                title_name_logger = format_string.format(**values)
        #            except KeyError as e:
        #                missing_key = e.args[0]
        #                values[missing_key] = ""
        #                title_name_logger = format_string.format(**values)
        #        if id_type[2] == "劇場":
        #            format_string = config["format"]["movie"]
        #            if message.get("displayNo", "") == "":
        #                format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #                values = {
        #                    "seriesname": title_name,
        #                }
        #            else:
        #                values = {
        #                    "seriesname": title_name,
        #                    "titlename": message.get("displayNo", ""),
        #                    "episodename": message.get("episodeName", "")
        #                }
        #            try:
        #                title_name_logger = format_string.format(**values)
        #            except KeyError as e:
        #                missing_key = e.args[0]
        #                values[missing_key] = ""
        #                title_name_logger = format_string.format(**values)
        #        logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
        #    for message in messages:
        #        if id_type[2] == "ノーマルアニメ":
        #            format_string = config["format"]["anime"]
        #            values = {
        #                "seriesname": title_name,
        #                "titlename": message.get("displayNo", ""),
        #                "episodename": message.get("episodeName", "")
        #            }
        #            try:
        #                title_name_logger = format_string.format(**values)
        #            except KeyError as e:
        #                missing_key = e.args[0]
        #                values[missing_key] = ""
        #                title_name_logger = format_string.format(**values)
        #        if id_type[2] == "劇場":
        #            format_string = config["format"]["movie"]
        #            if message.get("displayNo", "") == "":
        #                format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #                values = {
        #                    "seriesname": title_name,
        #                }
        #            else:
        #                values = {
        #                    "seriesname": title_name,
        #                    "titlename": message.get("displayNo", ""),
        #                    "episodename": message.get("episodeName", "")
        #                }
        #            try:
        #                title_name_logger = format_string.format(**values)
        #            except KeyError as e:
        #                missing_key = e.args[0]
        #                values[missing_key] = ""
        #                title_name_logger = format_string.format(**values)
        #        
        #        if additional_info[2]: # ニコニコのコメントダウンロード時
        #            sate = {}
        #            sate["info"] = {
        #                "work_title": title_name,
        #                "episode_title": f"{message.get("displayNo", "")} {message.get("episodeName", "")}",
        #                "raw_text": f"{title_name} {message.get("displayNo", "")} {message.get("episodeName", "")}",
        #                "series_title": title_name,
        #                "episode_text": message.get("displayNo", ""),
        #                "episode_number": 1,
        #                "subtitle": message.get("episodeName", ""),
        #            }
        #            
        #            def get_niconico_info(stage, data):
        #                if stage == 1:
        #                    querystring = {
        #                        "q": data,
        #                        "_sort": "-startTime",
        #                        "_context": "NCOverlay/3.23.0/Mod For Yoimi",
        #                        "targets": "title,description",
        #                        "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
        #                        "filters[commentCounter][gt]": 0,
        #                        "filters[genre.keyword][0]": "アニメ",
        #                        "_offset": 0,
        #                        "_limit": 20,
        #                    }
        #                    
        #                    result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
        #                    return result
        #                elif stage == 2:
        #                    result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
        #                    return result
        #                elif stage == 3:
        #                    payload = {
        #                        "params":{
        #                            "targets": data[1],
        #                            "language":"ja-jp"},
        #                        "threadKey": data[0],
        #                        "additionals":{}
        #                    }
        #                    headers = {
        #                      "X-Frontend-Id": "6",
        #                      "X-Frontend-Version": "0",
        #                      "Content-Type": "application/json"
        #                    }
        #                    result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
        #                    return result
        #                
        #            logger.info(f"Getting Niconico Comment", extra={"service_name": "U-Next"})
        #            return_meta = get_niconico_info(1, sate["info"]["raw_text"])
        #            
        #            base_content_id = return_meta["data"][0]["contentId"]
        #            
        #            total_comment = 0
        #            total_comment_json = []
        #            total_tv = []
        #            
        #            for index in return_meta["data"]:
        #                return_meta = get_niconico_info(2, index["contentId"])
        #                    
        #                filtered_data = [
        #                    {"id": str(item["id"]), "fork": item["forkLabel"]}
        #                    for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
        #                ]
        #                
        #                return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
        #                for i in return_meta["data"]["globalComments"]:
        #                    total_comment = total_comment + i["count"]
        #                for i in return_meta["data"]["threads"]:
        #                    for i in i["comments"]:
        #                        total_comment_json.append(i)
        #                if index["tags"].__contains__("dアニメストア"):
        #                    total_tv.append("dアニメ")
        #                else:
        #                    total_tv.append("公式")
        #            
        #            def generate_xml(json_data):
        #                root = ET.Element("packet", version="20061206")
        #                
        #                for item in json_data:
        #                    chat = ET.SubElement(root, "chat")
        #                    chat.set("no", str(item["no"]))
        #                    chat.set("vpos", str(item["vposMs"] // 10))
        #                    timestamp = datetime.fromisoformat(item["postedAt"]).timestamp()
        #                    chat.set("date", str(int(timestamp)))
        #                    chat.set("date_usec", "0")
        #                    chat.set("user_id", item["userId"])
        #                    
        #                    if len(item["commands"]) > 1:
        #                        chat.set("mail", "small shita")
        #                    else:
        #                        chat.set("mail", " ".join(item["commands"]))
        #                    
        #                    chat.set("premium", "1" if item["isPremium"] else "0")
        #                    chat.set("anonymity", "0")
        #                    chat.text = item["body"]
        #                
        #                return ET.ElementTree(root)
        #            
        #            def save_xml_to_file(tree, base_filename="output.xml"):
        #                directory = os.path.dirname(base_filename)
        #                if directory and not os.path.exists(directory):
        #                    os.makedirs(directory)
        #                
        #                filename = base_filename
        #                counter = 1
        #                while os.path.exists(filename):
        #                    filename = f"{os.path.splitext(base_filename)[0]}_{counter}.xml"
        #                    counter += 1
        #            
        #                root = tree.getroot()
        #                ET.indent(tree, space="  ", level=0)
        #                
        #                tree.write(filename, encoding="utf-8", xml_declaration=True)
        #                return filename
        #            
        #            tree = generate_xml(total_comment_json)
        #            
        #            logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": "U-Next"})
        #            logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": "U-Next"})
        #            
        #            saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
        #            
        #            logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": "U-Next"})
        #            
        #            if additional_info[3]:
        #                continue
#
        #else:
        #    logger.info("Get Title for 1 Episode", extra={"service_name": "U-Next"})
        #    status, message, point = unext_downloader.get_title_parse_single(url)
        #    if status == False:
        #        logger.error("Failed to Get Episode Json", extra={"service_name": "U-Next"})
        #        exit(1)
        #    
        #    if id_type[2] == "ノーマルアニメ":
        #        format_string = config["format"]["anime"]
        #        values = {
        #            "seriesname": title_name,
        #            "titlename": message.get("displayNo", ""),
        #            "episodename": message.get("episodeName", "")
        #        }
        #        try:
        #            title_name_logger = format_string.format(**values)
        #        except KeyError as e:
        #            missing_key = e.args[0]
        #            values[missing_key] = ""
        #            title_name_logger = format_string.format(**values)
        #    if id_type[2] == "劇場":
        #        format_string = config["format"]["movie"]
        #        if message.get("displayNo", "") == "":
        #            format_string = format_string.replace("_{episodename}", "").replace("_{titlename}", "")
        #            values = {
        #                "seriesname": title_name,
        #            }
        #        else:
        #            values = {
        #                "seriesname": title_name,
        #                "titlename": message.get("displayNo", ""),
        #                "episodename": message.get("episodeName", "")
        #            }
        #        try:
        #            title_name_logger = format_string.format(**values)
        #        except KeyError as e:
        #            missing_key = e.args[0]
        #            values[missing_key] = ""
        #            title_name_logger = format_string.format(**values)
        #    logger.info(f" + {title_name_logger}", extra={"service_name": "U-Next"})
#
#
        #    if additional_info[2]: # ニコニコのコメントダウンロード時
        #        sate = {}
        #        sate["info"] = {
        #            "work_title": title_name,
        #            "episode_title": f"{message.get("displayNo", "")} {message.get("episodeName", "")}",
        #            "raw_text": f"{title_name} {message.get("displayNo", "")} {message.get("episodeName", "")}",
        #            "series_title": title_name,
        #            "episode_text": message.get("displayNo", ""),
        #            "episode_number": 1,
        #            "subtitle": message.get("episodeName", ""),
        #        }
        #        
        #        def get_niconico_info(stage, data):
        #            if stage == 1:
        #                querystring = {
        #                    "q": data,
        #                    "_sort": "-startTime",
        #                    "_context": "NCOverlay/3.23.0/Mod For Yoimi",
        #                    "targets": "title,description",
        #                    "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
        #                    "filters[commentCounter][gt]": 0,
        #                    "filters[genre.keyword][0]": "アニメ",
        #                    "_offset": 0,
        #                    "_limit": 20,
        #                }
        #                
        #                result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
        #                return result
        #            elif stage == 2:
        #                result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
        #                return result
        #            elif stage == 3:
        #                payload = {
        #                    "params":{
        #                        "targets": data[1],
        #                        "language":"ja-jp"},
        #                    "threadKey": data[0],
        #                    "additionals":{}
        #                }
        #                headers = {
        #                  "X-Frontend-Id": "6",
        #                  "X-Frontend-Version": "0",
        #                  "Content-Type": "application/json"
        #                }
        #                result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
        #                return result
        #            
        #        logger.info(f"Getting Niconico Comment", extra={"service_name": "U-Next"})
        #        return_meta = get_niconico_info(1, sate["info"]["raw_text"])
        #        
        #        base_content_id = return_meta["data"][0]["contentId"]
        #        
        #        total_comment = 0
        #        total_comment_json = []
        #        total_tv = []
        #        
        #        for index in return_meta["data"]:
        #            return_meta = get_niconico_info(2, index["contentId"])
        #                
        #            filtered_data = [
        #                {"id": str(item["id"]), "fork": item["forkLabel"]}
        #                for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
        #            ]
        #            
        #            return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
        #            for i in return_meta["data"]["globalComments"]:
        #                total_comment = total_comment + i["count"]
        #            for i in return_meta["data"]["threads"]:
        #                for i in i["comments"]:
        #                    total_comment_json.append(i)
        #            if index["tags"].__contains__("dアニメストア"):
        #                total_tv.append("dアニメ")
        #            else:
        #                total_tv.append("公式")
        #        
        #        def generate_xml(json_data):
        #            root = ET.Element("packet", version="20061206")
        #            
        #            for item in json_data:
        #                chat = ET.SubElement(root, "chat")
        #                chat.set("no", str(item["no"]))
        #                chat.set("vpos", str(item["vposMs"] // 10))
        #                timestamp = datetime.fromisoformat(item["postedAt"]).timestamp()
        #                chat.set("date", str(int(timestamp)))
        #                chat.set("date_usec", "0")
        #                chat.set("user_id", item["userId"])
        #                
        #                if len(item["commands"]) > 1:
        #                    chat.set("mail", "small shita")
        #                else:
        #                    chat.set("mail", " ".join(item["commands"]))
        #                
        #                chat.set("premium", "1" if item["isPremium"] else "0")
        #                chat.set("anonymity", "0")
        #                chat.text = item["body"]
        #            
        #            return ET.ElementTree(root)
        #        
        #        def save_xml_to_file(tree, base_filename="output.xml"):
        #            directory = os.path.dirname(base_filename)
        #            if directory and not os.path.exists(directory):
        #                os.makedirs(directory)
        #            
        #            filename = base_filename
        #            counter = 1
        #            while os.path.exists(filename):
        #                filename = f"{os.path.splitext(base_filename)[0]}_{counter}.xml"
        #                counter += 1
        #        
        #            root = tree.getroot()
        #            ET.indent(tree, space="  ", level=0)
        #            
        #            tree.write(filename, encoding="utf-8", xml_declaration=True)
        #            return filename
        #        
        #        tree = generate_xml(total_comment_json)
        #        
        #        logger.info(f" + Hit Channel: {', '.join(total_tv)}", extra={"service_name": "U-Next"})
        #        logger.info(f" + Total Comment: {str(total_comment)}", extra={"service_name": "U-Next"})
        #        
        #        saved_filename = save_xml_to_file(tree, base_filename=os.path.join(config["directorys"]["Downloads"], title_name, "niconico_comment", f"{title_name_logger}_[{base_content_id}]"+".xml"))
        #        
        #        logger.info(f" + XML data saved to: {saved_filename}", extra={"service_name": "U-Next"})
        #        
        #        if additional_info[3]:
        #            return
        ##        
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