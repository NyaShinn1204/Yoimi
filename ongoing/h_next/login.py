import re
import requests

email = ""
password = ""

session = requests.Session()

payload = {
    "login_id": email,
    "password": password
}

headers = {
    "connection": "keep-alive",
    "pragma": "no-cache",
    "cache-control": "no-cache",
    "baggage": "sentry-environment=prod-react,sentry-release=v105.0-2-gca2628b65,sentry-public_key=d46f18dd0cfb4b0cb210f8e67c535fe1,sentry-trace_id=730f3eadd3e747068f37c996e66e8635,sentry-sample_rate=0.0001,sentry-transaction=%2Flogin%2Fnormal,sentry-sampled=false",
    "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 japanview/1.0.6",
    "content-type": "application/json",
    "accept": "*/*",
    "x-requested-with": "com.japan_view",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "accept-encoding": "gzip, deflate",
    "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
}

login_response = session.post("https://tvh.unext.jp/api/1/login", json=payload, headers=headers)


# Sample download link:
# https://video.hnext.jp/title/AID0257926

url = "https://video.hnext.jp/title/AID0257926"

match = re.search(r"(AID\d+)", url)
if match:
    av_id = match.group(1)

def get_content_info(aid):
    try:
        url = "https://tvh.unext.jp/api/1/adult/titleDetail"
        queryparams = {"title_code": aid}
        
        content_info = session.get(url, params=queryparams)
        content_json = content_info.json()["data"]["title"]
        return content_json
    except:
        return None
    
content_info = get_content_info(av_id)

titlename = content_info["title_name"]
catch_comment = content_info["title_comment"]
release_date = content_info["release_month"]
vod_type = content_info["payment_badge_code"]

print("[+] Title:", titlename)
print("[+] Catch:", catch_comment)
print("[+] Release Date:", release_date)
print("[+] Vod Type:", vod_type)

if vod_type == "SVOD":
    pass
else:
    print("[-] OH THIS CONTENT IS REQUIRE coin/point")
    
