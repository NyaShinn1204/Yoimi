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

#どーやってもこれだけ取得できなかったからセルフでお願いします。
temp_authorization_key = "Bearer " + "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImM2MTQ0YTFiLTk5OWQtNDM1YS1hMGUyLTdmYjVjNjFlNTM2MiJ9.eyJpc3MiOiJ3ZWIubmhrcGx1cyIsInN1YiI6IldlYlRva2VuIiwiYXVkIjoiY3RsLm5wZC5wbHVzLm5oay5qcCIsImV4cCI6MTczNTkwMDQ4NiwiaWF0IjoxNzM1ODY0NDc2fQ.D0Zt6O0Vk4pKxwAd6752RXGZknR1gxXZpX5RL7a1CGMhKRRNQ2IOcm8ruaWWN0mcsNfFdwgq701H95tH_4vukw18xktzuY_tspaYcdhdwczKqEqNX_uAyHEoXU7H0hDODaWQC2e6HpG6U3KbWdvvKSXJx2YRiZ20-kj9joWWpWhg_v22BA9nr2UhVzKfEAtI1tfzylmmyyzHnsaLlQnD_IAEwGZjqYdawE_sV8qU-RDJ9MOf7c0muHYz32t78ChJ2TEqa_lyMVsAZyx4gyxiuG2m8jlpcipd2MxyYGw8szUtIBTw_s482psJdNIudFIRldb4dAH_bk25hn5Jviws7Q"

#アクセスキーをげっちゅ
access_key_json = session.post("https://ctl.npd.plus.nhk.jp/create-accesskey", json={}, headers={"authorization": temp_authorization_key}).json()


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