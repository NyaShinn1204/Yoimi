import re
import os
import json
import requests
import xml.etree.ElementTree as ET

from datetime import datetime

class global_comment:
    def convert_kanji_to_int(self, string):
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
    def convert_int_to_kanji(self, num: int) -> str:
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
    def download_niconico_comment(self, logger, additional_info, title_name, episode_title, episode_number, config, title_name_logger, service_type="SERVICE_NAME_HERE"):
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
                        "_context": "NCOverlay/3.24.0/Modified by Yoimi",
                        "targets": "title,description",
                        "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
                        "filters[commentCounter][gt]": 0,
                        "filters[genre.keyword][0]": "アニメ",
                        "_offset": 0,
                        "_limit": 20,
                    }
                    
                    result = requests.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
                    return result
                elif stage == 2:
                    result = requests.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
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
                    result = requests.post("https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
                    return result
                
            logger.info("Getting Niconico Comment", extra={"service_name": service_type})
            return_meta = get_niconico_info(1, f'{sate["info"]["work_title"]} {sate["info"]["episode_number"]}話 OR {self.convert_int_to_kanji(sate["info"]["episode_number"])}話 OR エピソード{sate["info"]["episode_number"]} OR episode{sate["info"]["episode_number"]} OR ep{sate["info"]["episode_number"]} OR #{sate["info"]["episode_number"]} OR 第{sate["info"]["episode_number"]}話 OR "{sate["info"]["subtitle"]}"')
            
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