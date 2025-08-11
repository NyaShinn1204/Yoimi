import requests

base_link = (
    "https://api.tv.rakuten.co.jp/content/playinfo.json?"
    "device_id={}&content_id=496241&flagged_aes=0&trailer=0&auth=0&log=1&multi_audio_support=1"
)

headers = {
    "user-agent": "Rakuten TV AndroidMobile/7.4.3.0",
    "authorization": "Bearer",
    "access-token": "",
    "host": "api.tv.rakuten.co.jp",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip"
}

for i in range(31):
    resp = requests.get(base_link.format(i), headers=headers)
    data = resp.json()

    if data.get("status") == "error":
        print(f"device_id={i} -> not found")
        continue

    paths = data.get("result", {}).get("paths", [{}])[0]

    found     = bool(paths.get("path"))
    found_ss  = bool(paths.get("path_ss"))
    found_hls = bool(paths.get("path_hls"))
    found_dash = bool(paths.get("path_dash"))

    print(f"device_id={i} -> path={found}, ss={found_ss}, hls={found_hls}, dash={found_dash}")
