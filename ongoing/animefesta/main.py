import os
import requests
from urllib.parse import urljoin
from Crypto.Cipher import AES
from tqdm import tqdm

title_id = "1538"

session = requests.Session()
session.headers.update({"x-requested-with": "XMLHttpRequest"})

title_meta_data = session.get(f"https://api-animefesta.iowl.jp/v1/titles/{title_id}").json()

if title_meta_data["code"] != 2000:
    print("Hehe Error")
    print(title_meta_data)

title_name = title_meta_data["contents"]["name"]
print("Title:", title_name)
print("Summary:", title_meta_data["contents"]["summary"])
print("Copyright:", title_meta_data["contents"]["copyright"])
print("Premium?", title_meta_data["contents"]["has_premium"])

print("Parsing title...")

def download_binary(url):
    return session.get(url).content

def parse_key_info(line, base_url):
    attrs = dict(item.split("=", 1) for item in line.replace('#EXT-X-KEY:', '').split(','))
    method = attrs.get("METHOD")
    key_uri = attrs.get("URI").strip('"')
    key_url = urljoin(base_url, key_uri)
    return method, key_url

def decrypt_ts(content, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(content)

def download_and_decrypt_ts(segment_url, key, iv):
    encrypted = download_binary(segment_url)
    return decrypt_ts(encrypted, key, iv)

for single in title_meta_data["contents"]["episodes"]:
    episode_title = f"{title_name}_{single['prefix_name']}_{single['name']}".replace(" ", "_").replace("/", "_")
    episode_id = single["id"]
    print(" + " + episode_title)
    print("Get HLS link...")

    hls_link = session.get(f"https://api-animefesta.iowl.jp/v1/episodes/{episode_id}?image_quality=hd").json()["contents"]["playing_url"]
    print("HLS Link:", hls_link)

    # Get chunklist.m3u8
    master_m3u8_text = session.get(hls_link).text
    for line in master_m3u8_text.splitlines():
        if line and not line.startswith("#"):
            chunklist_url = urljoin(hls_link, line)
            break

    chunklist_text = session.get(chunklist_url).text
    chunklist_base = chunklist_url.rsplit('/', 1)[0] + "/"

    key = None
    iv = None
    ts_urls = []

    for line in chunklist_text.splitlines():
        if line.startswith("#EXT-X-KEY"):
            method, key_url = parse_key_info(line, chunklist_base)
            if method == "AES-128":
                key = download_binary(key_url)
        elif line and not line.startswith("#"):
            ts_urls.append(urljoin(chunklist_base, line))

    print(f"Downloading and decrypting {len(ts_urls)} segments...")

    os.makedirs("downloads", exist_ok=True)
    out_path = f"downloads/{episode_title}.ts"

    with open(out_path, "wb") as out_file:
        for i, ts_url in enumerate(tqdm(ts_urls, desc=episode_title)):
            iv = (i).to_bytes(16, byteorder='big')
            decrypted = download_and_decrypt_ts(ts_url, key, iv)
            out_file.write(decrypted)

    print(f"✅ Saved to {out_path}\n")
