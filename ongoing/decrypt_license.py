#nhk+は正式に却下されました。理由はtempのauthorizationを取得するコードがどうしても見つからず作成できないからです。もしこの部分をどうにかできたらぜひプルリクでも、telegram，discordでもいいので教えてください。

import re
import base64
import struct
import requests

def find_moov_box(mp4_data):
    """MP4バイナリデータからmoovボックスをうあーする"""
    f = mp4_data
    i = 0
    while i < len(f):
        box_size, box_type = struct.unpack('>I4s', f[i:i+8])
        i += 8

        if box_type == b'moov':
            return f[i:i+box_size-8]

        i += box_size - 8

    return None

def parse_box(data, index=0):
    """指定されたデータからボックスをうあーして返す"""
    boxes = []
    while index < len(data):
        box_size, box_type = struct.unpack('>I4s', data[index:index+8])
        index += 8

        box = {
            'size': box_size,
            'type': box_type.decode('utf-8'),
            'data': data[index:index+box_size-8]
        }

        boxes.append(box)

        index += box_size - 8
    return boxes

def remove_duplicates_and_count(tracks):
    # ここでダブってるやつをぶっ飛ばす
    unique_tracks = {}
    duplicates_count = 0

    for track in tracks:
        try:
            if track["content_type"] == "video":
                track_key = (
                    track.get("url"),
                    track.get("bitrate"),
                )
            elif track["content_type"] == "audio":
                track_key = (
                    track.get("url"),
                    track.get("bitrate"),
                )
            elif track["content_type"] == "text":
                track_key = (
                    track.get("language"),
                )
            else:
                print("wtf", str(track))
    
            if track_key in unique_tracks:
                duplicates_count += 1  # 重複カウント
            else:
                unique_tracks[track_key] = track
        except:
            print("wtf", str(track))

    unique_track_list = list(unique_tracks.values())

    return unique_track_list

def select_tracks(tracks):
    # ここでビットレートが一番高いやつを盗んでreturnで殴る
    highest_bitrate_video = max(tracks["video_track"], key=lambda x: x["bitrate"])

    # オーディオトラックのnameがmainのやつを引っ張る。 mainっていうのは主音声、subは副音声優先のやつらしい
    main_audio = next((audio for audio in tracks["audio_track"] if audio["name"] == "main"), None)

    return {
        "video": highest_bitrate_video,
        "audio": main_audio
    }


def parse_m3u8(file_content):
    video_tracks = []
    audio_tracks = []
    text_tracks = []
    
    CODEC_MAP = {
        "avc1": "H.264",
        "mp4a": "AAC",
    }
    
    lines = file_content.splitlines()
    
    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF"):
            attributes = re.findall(r'([A-Z0-9\-]+)=("[^"]+"|[^,]+)', line)
            attr_dict = {key: value.strip('"') for key, value in attributes}
            bitrate = int(attr_dict.get("BANDWIDTH", 0)) // 1000  # bps to kbpsに変換
            codec = attr_dict.get("CODECS", "").split(",")[1]
            
            # なぜかvideoのやつだけurlが次の行に書かれてるので仕方なくやります。
            video_url = lines[i + 1] if i + 1 < len(lines) else "unknown"
            
            video_tracks.append({
                "content_type": "video",
                "bitrate": bitrate,
                "codec": CODEC_MAP.get(codec.split(".")[0], codec),
                "url": video_url,
            })
        elif line.startswith("#EXT-X-MEDIA"):
            attributes = re.findall(r'([A-Z0-9\-]+)=("[^"]+"|[^,]+)', line)
            attr_dict = {key: value.strip('"') for key, value in attributes}
            if attr_dict.get("TYPE") == "AUDIO":
                audio_tracks.append({
                    "content_type": "audio",
                    "language": attr_dict.get("LANGUAGE", "unknown"),
                    "name": attr_dict.get("NAME", "unknown"),
                    "url": attr_dict.get("URI", "unknown"),
                })
            elif attr_dict.get("TYPE") == "SUBTITLES":
                text_tracks.append({
                    "content_type": "text",
                    "language": attr_dict.get("LANGUAGE", "unknown"),
                    "name": attr_dict.get("NAME", "unknown"),
                    "url": attr_dict.get("URI", "unknown"),
                })

    return {
        "video_track": video_tracks,
        "audio_track": remove_duplicates_and_count(audio_tracks),  # 重複してるうやつをどか～ん
        "text_track": text_tracks,
    }

def print_tracks(tracks):
    output = ""
    # Video tracks まぁvideoやな
    output += f"{len(tracks['video_track'])} Video Tracks:\n"
    for i, video in enumerate(tracks["video_track"]):
        output += f"├─ VID | [{video['codec']}] | {video['bitrate']} kbps\n"
    
    # Audio tracks まぁaudioやな
    output += f"\n{len(tracks['audio_track'])} Audio Tracks:\n"
    for i, audio in enumerate(tracks["audio_track"]):
        output += f"├─ AUD | {audio['language']} | {audio['name']}\n"

    # Text tracks まぁsubやな
    output += f"\n{len(tracks['text_track'])} Text Tracks:\n"
    for i, text in enumerate(tracks["text_track"]):
        output += f"├─ SUB | [VTT] | {text['language']} | {text['name']}\n"
    
    print(output)



def transform_metadata(manifests):
    transformed = []

    for manifest in manifests:
        drm_type = manifest.get("drm_type", "")
        bitrate_limit_type = manifest.get("bitrate_limit_type", "")
        url = manifest.get("url", "")
        video_codec = manifest.get("video_codec", "H.264")
        dynamic_range = manifest.get("dynamic_range", "SDR")

        # birtareの文字の最初にmがついてればMulti、泣ければSingleらしい。
        bitrate_type = "Multi" if bitrate_limit_type.startswith("m") else "Single"
        bitrate_limit = int(bitrate_limit_type[1:]) if bitrate_limit_type[1:].isdigit() else 0

        # 取得したデータを整形
        transformed_manifest = {
            "drmType": drm_type,
            "bitrateLimit": bitrate_limit,
            "bitrateType": bitrate_type,
            "url": url,
            "videoCodec": "H.265" if video_codec == "H.265" else "H.264",
            "dynamicRange": "HDR" if dynamic_range == "HDR" else "SDR",
        }

        transformed.append(transformed_manifest)

    return transformed

def get_highest_bitrate_manifest(manifests):
    transformed = transform_metadata(manifests)
    if not transformed:
        return None
    return max(transformed, key=lambda x: x["bitrateLimit"])

session = requests.Session()

def parse_private_key():
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    import base64
    
    encrypted_data = "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\n9LsiyQ=="
    
    iv = base64.b64decode('3vh8IpHEcjJYUYhobRBcsQ==')  # IV
    key = base64.b64decode('tK1rb8W9cDAVvf1zKDXVYw==')  # Key
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
    
    header = "-----BEGIN RSA PRIVATE KEY-----\n"
    footer = "\n-----END RSA PRIVATE KEY-----"
    
    return_dec = decrypted.decode('utf-8')
    
    return_dec = header + return_dec + footer
    
    return_dec
    
    return return_dec

def jwt_gen():
    import jwt
    from datetime import datetime, timedelta, timezone
    
    private_key = parse_private_key()
        
    payload = {
        "iss": "app.nhkplus",
        "sub": "AppToken",
        "aud": "ctl.npd.plus.nhk.jp",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        "iat": datetime.now(timezone.utc)
    }
    
    headers = {
        "kid": "008b6857-3801-492c-bc50-48531db4b936",
        "alg": "RS256",
    }
    
    # JWTを生成
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    
    # トークンの出力
    return token

#どーやってもこれだけ取得できなかったからセルフでお願いします。
temp_authorization_key = "Bearer " + jwt_gen()

print("[+] JWT生成成功！ｗｗｗやったね！！！ "+temp_authorization_key)

#アクセスキーをげっちゅ
access_key_json = session.post("https://ctl.npd.plus.nhk.jp/create-accesskey", json={}, headers={"authorization": temp_authorization_key}).json()

print(access_key_json)

print("[+] Get Aceess Token:",access_key_json["drmToken"])

print("[+] Getting Video Info...")
video_info = session.get("https://vod-npd2.cdn.plus.nhk.jp/npd2/7fe1-0408/20250103/4ba5-1-3-ce885a972faeabb45997cb96aa146c55_1min/videoinfo-9010f88ea4fc09eb32422de6039f3a4f.json").json()
print("[+] Get Video Info:")
print(" + allow_multispeed: "+str(video_info["allow_multispeed"]))
print(" + need_L1_hd: "+str(video_info["need_L1_hd"]))
print(" + total manifests: "+str(len(video_info["manifests"])))
print("[+] Convert Video Info...")
transformed_data = transform_metadata(video_info["manifests"])
print("[+] Convert Video Info")
#print(json.dumps(transformed_data, indent=4))
print("[+] Select Highest birate manifest")
highest_bitrate_manifest = get_highest_bitrate_manifest(video_info["manifests"])
#print(json.dumps(highest_bitrate_manifest, indent=4))
print("[+] Get m3u8")
m3u8_data = session.get(highest_bitrate_manifest["url"]).text
tracks = parse_m3u8(m3u8_data)
print_tracks(tracks)

def license_vd_ad(pssh, session):
    _WVPROXY = "https://drm.npd.plus.nhk.jp/widevine/license"
    from pywidevine.cdm import Cdm
    from pywidevine.device import Device
    from pywidevine.pssh import PSSH
    device = Device.load(
        "./l3.wvd"
    )
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
    response = session.post(f"{_WVPROXY}", data=bytes(challenge), headers={"authorization": "Bearer "+ access_key_json["drmToken"]})
    response.raise_for_status()

    cdm.parse_license(session_id, response.content)
    keys = [
        {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
        for key in cdm.get_keys(session_id)
    ]

    cdm.close(session_id)
            
    keys = {
        "key": keys,
    }
    
    return keys

get_best_track = select_tracks(tracks)
print("[+] Finding pssh...")

video_url = get_best_track["video"]["url"].replace("playlist.m3u8", "init_0000.mp4")
response = session.get(video_url)

video_data = response.content # バイナリデータをうあーする
moov_box = find_moov_box(video_data)

pssh_box = ""
count = 0
if moov_box:
    sub_boxes = parse_box(moov_box)
    for box in sub_boxes:
        if box["type"] == "pssh":
            if count == 0:
                pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                pssh_box = pssh_temp.replace("==", "")
                #pssh_box = pssh_temp // なぜかこれでもdecryptできる。謎
            else:
                pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                pssh_box = pssh_box + pssh_temp.replace("==", "====")
            count += 1


if pssh_box == "":
    print("[-] おい！psshどこやねん！殺すぞ！！！")
else:
    print("[+] GET PSSH: {}".format(pssh_box))
    keys = license_vd_ad(pssh_box, session)
    print("[+] Get Widevine Key:")
    for key in keys["key"]:
        if key["type"] == "CONTENT":
            print("[+] DECRYPT KEY: {}:{}".format(key["kid_hex"], key["key_hex"]))