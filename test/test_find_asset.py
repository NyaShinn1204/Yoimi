import requests
import re

def extract_asset(url):
    media_id_match = re.search(r'/watch/(\d+)', url)
    if not media_id_match:
        return None
    media_id = media_id_match.group(1)

    response = requests.get(url, headers={
        ### このUser-Agentじゃないとはじかれる！！！
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    })
    if response.status_code != 200:
        print(f"Failed to fetch page: {response.status_code}")
        return None

    # asset:100145119 のような文字列をぬきたしします。
    pattern = rf'["\']?(asset:{media_id})["\']?'
    match = re.search(pattern, response.text)
    if match:
        return match.group(1)
    return None

url = "https://www.hulu.jp/watch/100145119"
result = extract_asset(url)
print(result)
