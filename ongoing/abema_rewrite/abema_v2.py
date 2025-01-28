import os
import re
import yaml
import time
import shutil
import json
import logging
from datetime import datetime
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

#from ext.utils import unext
#from abema import abema
import abema

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
        
        auth_response = session.get(_ENDPOINT_CHECK_IP, params={"device": "android"}).json()
        
        end = time.time()
        time_elapsed = end - start
        time_elapsed = time_elapsed * 1000
        
        try:
            if auth_response["location"] != "JP":
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
                        logger.info(f" + Plan {f"{plan_num+1}".zfill(2)}: "+message["profile"]["userId"], extra={"service_name": "Abema"})
            else:
                logger.error("Please input token", extra={"service_name": "Abema"})
                exit(1)
        else:
            status, message = abema_downloader.authorize(email, password)
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
                    logger.info(f" + Plan {f"{plan_num+1}".zfill(2)}: "+message["profile"]["userId"], extra={"service_name": "Abema"})
            
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
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(v)
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))