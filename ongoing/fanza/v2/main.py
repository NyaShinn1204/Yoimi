import os
import requests

session = requests.Session()

hehe = {
    "header": {
        "result_code": "0",
        "response_id": "3c015cb3-44ae-433f-b4a4-e18371609b02",
    },
    "body": {
        "access_token": "",
        "token_type": "bearer",
        "expires_in": 1748938254,
        "scope": "openid session",
    },
}
user_id = "lVzxoGplD9zA35Ac"
default_header = {
    "x-app-name": "android_2d",
    "x-app-ver": "v4.1.0",
    "x-exploit-id": "uid:" + user_id,
    "authorization": "Bearer " + hehe["body"]["access_token"],
    "user-agent": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
}
session.headers.update(default_header)

license_uid = session.post(
    "https://gw.dmmapis.com/connect/v1/issueSessionId", json={"user_id": user_id}
).json()["body"]["unique_id"]

get_purchased_list = session.get(
    "https://video.digapi.dmm.com/purchased/list/text?limit=100&page=1&order=new&hidden_filter="
).json()

print("Getting Titles")

for single in get_purchased_list["list_info"]:
    print(
        " + "
        + single["title"]
        + " | "
        + single["quality_name"]
        + " | "
        + single["viewing_text"]
    )

print(
    "CAUTION: this tool is not support 8k. if you want download 8k, just use FantaVR(paid)"
)

print("Downloading 1 product")

select_product = get_purchased_list["list_info"][0]
print("Select Product:")
print(" + " + select_product["title"])
print(" + " + select_product["quality_name"])
print(" + " + select_product["viewing_text"])
print(" + " + select_product["product_id"])
print(" + " + str(select_product["mylibrary_id"]))

fanza_secret_key = "hp2Y944L"
fanza_vr_secret_key = "X1H8kJ9L2n7G5eF3"

# get license
import json
import hmac
import hashlib


def get_json(params: dict) -> str:
    # Javaの JSONObject.toString() に近い形式（余計なスペースを除く）
    return json.dumps(params, separators=(",", ":"), ensure_ascii=False)


def get_hash(data: str, key: str) -> str:
    return hmac.new(
        key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def set_post_params(message: str, params: dict, appid: str, secret_key: str) -> dict:
    post_data = {}
    post_data["message"] = message
    post_data["appid"] = appid
    json_data = get_json(params)
    post_data["params"] = json_data
    post_data["authkey"] = get_hash(json_data, secret_key)
    return post_data


params = {
    "exploit_id": "uid:"+ user_id,
    "mylibrary_id": str(select_product["mylibrary_id"]),
    "product_id": select_product["product_id"],
    "shop_name": "videoa",
    "device": "android",
    "HTTP_SMARTPHONE_APP": "DMM-APP",
    "message": "Digital_Api_Mylibrary.getDetail",
}
payload = set_post_params(
    message="Digital_Api_Mylibrary.getDetail",
    params=params,
    appid="android_movieplayer_app",
    secret_key=fanza_secret_key,
)

get_select_product_info = session.post(
    "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp", data=payload
).json()["data"]

params = {
    "android_drm": False,
    "bitrate": 0,
    "drm": False,
    "exploit_id": "uid:" + user_id,
    "chrome_cast": False,
    "isTablet": False,
    "licenseUID": license_uid,
    "parent_product_id": get_select_product_info["product_id"],
    "product_id": get_select_product_info["content_id"],
    "secure_url_flag": False,
    "service": "digital",
    "shop": "videoa",
    "smartphone_access": True,
    "transfer_type": "stream",
    "HTTP_USER_AGENT": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
    "device": "android",
    "HTTP_SMARTPHONE_APP": "DMM-APP",
    "message": "Digital_Api_Proxy.getURL",
}

payload = set_post_params(
    message="Digital_Api_Proxy.getURL",
    params=params,
    appid="android_movieplayer_app",
    secret_key=fanza_secret_key,
)

print("Getting License")
print(" + License Auth Key" + payload["authkey"])

auth_header = default_header.copy()

auth_header = {
    "user-agent": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
    "content-type": "application/x-www-form-urlencoded",
    "host": "www.dmm.com",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip",
}

license = session.post(
    "https://www.dmm.com/service/digitalapi/-/json/=/method=AndroidApp",
    data=payload,
    headers=auth_header,
)
# print(license.text)

print(" + License UID: " + license.json()["data"]["cookie"][0]["value"])

print("Get Playlist m3u8")
print(" + " + license.json()["data"]["redirect"])

m3u8_1 = session.get(license.json()["data"]["redirect"], allow_redirects=False)
m3u8_2 = session.get(m3u8_1.headers["Location"])

import parser as parser

global_parser = parser.global_parser()

a = global_parser.hls_parser(m3u8_2.text)
# print(a)
abc = global_parser.print_tracks(a)
print(abc)

get_best_track = global_parser.select_best_tracks(a)
# print(get_best_track)

print("Select Best Track")
print(
    f" + Video: [{get_best_track["video"]["resolution"]}] | {get_best_track["video"]["bitrate"]} kbps"
)

print(" + URL: " + get_best_track["video"]["url"])

content_link = m3u8_1.headers["Location"].replace(
    "playlist.m3u8", "chunklist_b" + str(get_best_track["video"]["bandwidth"]) + ".m3u8"
)

import m3u8
from Crypto.Cipher import AES


base_link = content_link.rsplit("/", 1)[0] + "/"
print(base_link)


def parse_m3u8(m3u8_url, base_link):
    # self.yuu_logger.debug('Requesting m3u8')
    r = session.get(m3u8_url)
    # self.yuu_logger.debug('Data requested')
    # if 'timeshift forbidden' in r.text:
    #    return None, None, None, 'This video can\'t be downloaded for now.'
    # if r.status_code == 403:
    #    return None, None, None, 'This video is geo-locked for Japan only.'
    # self.yuu_logger.debug('Parsing m3u8')
    x = m3u8.loads(r.text)
    files = x.files[1:]
    # if not files[0]:
    #    files = files[1:]
    # try:
    #    if 'tsda' in files[5]:
    #        # Assume DRMed
    #        return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
    # except Exception:
    #    try:
    #        if 'tsda' in files[-1]:
    #            # Assume DRMed
    #            return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
    #    except Exception:
    #        if 'tsda' in files[0]:
    #            # Assume DRMed
    #            return None, None, None, 'This video has a different DRM method and cannot be decrypted by yuu for now'
    # resgex = re.findall(r'(\d*)(?:\/\w+.ts)', files[0])[0]
    # print(x.keys[0])
    # keys_data = x.keys[0]
    # iv = x.keys[0].iv
    # ticket = x.keys[0].uri[18:]
    key_url = x.keys[0].uri
    # print(key_url)
    headers = {
        "user-agent": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
        "host": "www.dmm.com",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip",
    }
    key = session.get(key_url, headers=headers).content
    iv = bytes.fromhex("00000000000000000000000000000000")  # 必要に応じて調整
    # print(" Key:",key)
    # print(" IV:",iv)
    parsed_files = []
    for f in files:
        f = base_link + f
        parsed_files.append(f)
    # if self.resolution[:-1] != resgex:
    #    if not self.resolution_o:
    #        self.yuu_logger.warn('Changing resolution, from {} to {}p'.format(self.resolution, resgex))
    #    self.resolution = resgex + 'p'
    # self.yuu_logger.debug('Total files: {}'.format(len(files)))
    # self.yuu_logger.debug('IV: {}'.format(iv))
    # self.yuu_logger.debug('Ticket key: {}'.format(ticket))
    print("+ IV: " + str(iv))
    print("+ Key: " + str(key))
    # n = 0.0
    # for seg in x.segments:
    #    n += seg.duration
    # self.est_filesize = round((round(n) * self.bitrate_calculation[self.resolution]) / 1024 / 6, 2)
    return parsed_files, iv, key


files, iv, key = parse_m3u8(content_link, base_link)

from tqdm import tqdm


def setup_decryptor(iv, key):
    global _aes, return_iv
    return_iv = iv
    _aes = AES.new(key, AES.MODE_CBC, IV=return_iv)


def download_chunk(files, iv, key):
    iv = iv
    key = key
    downloaded_files = []
    setup_decryptor(iv, key)  # Initialize a new decryptor
    try:
        with tqdm(
            total=len(files), desc="Downloading", ascii=True, unit="file"
        ) as pbar:
            for tsf in files:
                outputtemp = os.path.join("tmep", os.path.basename(tsf))
                with open(outputtemp, "wb") as outf:
                    try:
                        vid = session.get(tsf)
                        vid = _aes.decrypt(vid.content)
                        outf.write(vid)
                    except Exception as err:
                        print("Problem occured\nreason: {}".format(err))
                        return None
                pbar.update()
                downloaded_files.append(outputtemp)
    except KeyboardInterrupt:
        print("User pressed CTRL+C, cleaning up...")
        return None
    return downloaded_files


dl_list = download_chunk(files, iv, key)

_out_ = "aaa.mp4"


def merge_video(path, output):
    """
    Merge every video chunk to a single file output
    """
    with open(output, "wb") as out:
        with tqdm(total=len(path), desc="Merging", ascii=True, unit="file") as pbar:
            for i in path:
                out.write(open(i, "rb").read())
                os.remove(i)
                pbar.update()


merge_video(dl_list, _out_)
