import json
import requests

sate = {}
sate["info"] = {
    "work_title": "時々ボソッとロシア語でデレる隣のアーリャさん",
    "episode_title": "第1話 ロシア語でデレるアーリャさん",
    "duration": 1479,
    "raw_text": "時々ボソッとロシア語でデレる隣のアーリャさん 第1話 ロシア語でデレるアーリャさん",
    "series_title": "時々ボソッとロシア語でデレる隣のアーリャさん",
    "episode_text": "第1話",
    "episode_number": 1,
    "subtitle": "ロシア語でデレるアーリャさん",
}

def get_niconico_info(stage, data):
    session = requests.Session()
    if stage == 1:
        querystring = {
            "q": data,
            "_sort": "-startTime",
            "_context": "NCOverlay/3.23.0/Mod For Yoimi",
            "targets": "title,description",
            "fields": "contentId,title,userId,channelId,viewCounter,lengthSeconds,thumbnailUrl,startTime,commentCounter,categoryTags,tags",
            "filters[commentCounter][gt]": 0,
            "filters[genre.keyword][0]": "アニメ",
            "_offset": 0,
            "_limit": 20,
        }
        
        result = session.get("https://snapshot.search.nicovideo.jp/api/v2/snapshot/video/contents/search", params=querystring).json()
        return result
    elif stage == 2:
        result = session.get(f"https://www.nicovideo.jp/watch/{data}?responseType=json").json()
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
        result = session.post(f"https://public.nvcomment.nicovideo.jp/v1/threads", data=json.dumps(payload), headers=headers).json()
        return result
    
return_meta = get_niconico_info(1, sate["info"]["raw_text"])

print(return_meta["data"][0])

total_comment = 0
total_comment_json = []
total_tv = []

for index in return_meta["data"]:
    return_meta = get_niconico_info(2, index["contentId"])
    
    print(return_meta["data"]["response"]["comment"]["threads"])
    
    filtered_data = [
        {"id": str(item["id"]), "fork": item["forkLabel"]}
        for item in return_meta["data"]["response"]["comment"]["threads"] if item["label"] != "easy"
    ]
    
    return_meta = get_niconico_info(3, [return_meta["data"]["response"]["comment"]["nvComment"]["threadKey"], filtered_data])
    print(return_meta)
    for i in return_meta["data"]["globalComments"]:
        total_comment = total_comment + i["count"]
    for i in return_meta["data"]["threads"]:
        total_comment_json.append(i["comments"])
    if index["tags"].__contains__("dアニメストア"):
        total_tv.append("dアニメ")
    else:
        total_tv.append("公式")

#print(total_comment_json)
print(total_comment)
print(total_tv)