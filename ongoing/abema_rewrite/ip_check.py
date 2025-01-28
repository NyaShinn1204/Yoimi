import requests

url = "https://api.p-c3-e.abema-tv.com/v1/ip/check"

querystring = { "device": "android" }

headers = {
    "authorization": "Bearer",
    "accept": "application/protobuf",
    "user-agent": "Mozilla/5.0 (Linux; Android 9; 23113RKC6C Build/PQ3B.190801.10101846;) App/2120046.840334a (AbemaTV;10.109.0;ja_JP;)",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip",
    "accept-charset": "UTF-8",
    "tracestate": "2634058@nr=0-2-2639890-247920748-68303168c29541c1----1738046076626",
    "newrelic": "eyJ2IjpbMCwyXSwiZCI6eyJ0eSI6Ik1vYmlsZSIsImFjIjoiMjYzOTg5MCIsImFwIjoiMjQ3OTIwNzQ4IiwidHIiOiI0MzU4NmJkYmRiOGE0ZWZlYmZiMDRlNGY4Y2ZiODZhNSIsImlkIjoiNjgzMDMxNjhjMjk1NDFjMSIsInRpIjoxNzM4MDQ2MDc2NjI2LCJ0ayI6IjI2MzQwNTgifX0=",
    "traceparent": "00-43586bdbdb8a4efebfb04e4f8cfb86a5-68303168c29541c1-00",
    "host": "api.p-c3-e.abema-tv.com"
}

response = requests.get(url, headers=headers, params=querystring)

from region_check_pb2 import RegionInfo  # 生成された Python クラスをインポート
from google.protobuf.json_format import MessageToJson

# Protocol Buffers メッセージをデコード
proto_message = RegionInfo()
proto_message.ParseFromString(response.content)  # response.content にバイナリデータを渡す

# JSON 形式に変換
json_obj = MessageToJson(proto_message)
print(json_obj)