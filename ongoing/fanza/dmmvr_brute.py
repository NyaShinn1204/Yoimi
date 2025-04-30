import itertools
import hmac
import hashlib

def generate_x_api_auth_code(data, secret_key):
    return hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()

def find_matching_auth_code(target_code, params, secret_key):
    keys = list(params.keys())
    tested = 0

    for r in range(1, len(keys)+1):
        for subset in itertools.combinations(keys, r):  # 部分集合
            for perm in itertools.permutations(subset):  # 順列
                # 通常のバージョン
                joined = ''.join(params[k] for k in perm)
                code = generate_x_api_auth_code(joined, secret_key)
                tested += 1
                if code == target_code:
                    print(f"✅ 一致: {perm} → {joined}")
                    print(f"（試行数: {tested}）")
                    return code
                else:
                    print(f"Not Match （試行数: {tested}）")

                # x-authorization が含まれている場合: Bearer を除去して再試行
                if "x-authorization" in perm:
                    modified_params = params.copy()
                    modified_params["x-authorization"] = params["x-authorization"].replace("Bearer ", "")
                    joined = ''.join(modified_params[k] for k in perm)
                    code = generate_x_api_auth_code(joined, secret_key)
                    tested += 1
                    if code == target_code:
                        print(f"✅ 一致（Bearerなし）: {perm} → {joined}")
                        return code

    print(f"❌ 一致するコードは見つかりませんでした（試行数: {tested}）")
    return None

params = {
    "mylibrary_id": "941873955",
    "part": "1",
    "quality_group": "high",
    "x-authorization": "Bearer Xd3fN2jwKF1nYAMb3wzYUselycL42z7Ck26SCRLBzMgFiG875J8ycDgIwGaflZFDQggbG2eSbqKovQmQUpnBSn5Dvock4BHi0v9d8m9sw9b",
    "x-exploit-id": "uid:lVzxoGplD9zA35Ac",
    "x-user-agent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
    "x-app-name": "android_vr_store"
}

secret_key = "X1H8kJ9L2n7G5eF3"
target_code = "ff88c0056151304cb1dbec900557955c9b36b6b7425df3f0d85cced27d127d6b"

result = find_matching_auth_code(target_code, params, secret_key)
if result:
    print(f"🎯 成功: {result}")
    print("Sent get requests for content metadata")
    import requests
    session = requests.Session()
    url = "https://vr.digapi.dmm.com/playableprovider/stream/vr"
    
    querystring = {
        "mylibrary_id": "941873955",
        "part": "1",
        "quality_group": "high"
    }
    
    headers = {
        "host": "vr.digapi.dmm.com",
        "user-agent": "UnityPlayer/2020.3.48f1 (UnityWebRequest/1.0, libcurl/7.84.0-DEV)",
        "accept": "*/*",
        "accept-encoding": "deflate, gzip",
        "x-authorization": "Bearer Xd3fN2jwKF1nYAMb3wzYUselycL42z7Ck26SCRLBzMgFiG875J8ycDgIwGaflZFDQggbG2eSbqKovQmQUpnBSn5Dvock4BHi0v9d8m9sw9b",
        "x-exploit-id": "uid:lVzxoGplD9zA35Ac",
        "x-app-name": "android_vr_store",
        "x-app-ver": "v2.0.5",
        "x-user-agent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
        "x-api-auth-code": result,
        "cache-control": "no-cache, no-store, must-revalidate",
        "pragma": "no-cache",
        "expires": "0",
        "x-unity-version": "2020.3.48f1"
    }
    
    response = session.get(url, headers=headers, params=querystring)
    
    metadata = response.json()
    
    print("+ Content m3u8:",metadata["content_info"]["redirect"])
    print("+ License UID:",metadata["cookie_info"]["value"])
    
    print("Send m3u8 parse")
    
    m3u8_url = metadata["content_info"]["redirect"]+"&licenseUID="+metadata["cookie_info"]["value"]+"&smartphone_access=1"
    headers = {
        "user-agent": "AVProMobileVideo/2.0.5 (Linux;Android 12) ExoPlayerLib/2.8.4",
        "host": "str.dmm.com",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    }
    m3u8_content = session.get(m3u8_url, headers=headers, params=querystring, allow_redirects=True)
    m3u8_url = m3u8_content.url
    m3u8_content = m3u8_content.text
    
import m3u8
import requests
from Crypto.Cipher import AES
import os
import subprocess
from urllib.parse import urljoin
    
master_m3u8 = m3u8.loads(m3u8_content)
best_stream = max(master_m3u8.playlists, key=lambda x: x.stream_info.bandwidth)
best_stream_url = urljoin(m3u8_url, best_stream.uri)
print(f"最も高品質のプレイリストを取得: {best_stream_url}")

# チャンクリスト取得
media_m3u8 = m3u8.load(best_stream_url)

# 鍵取得（あれば）
key = None
iv = None
if media_m3u8.keys and media_m3u8.keys[0]:
    key_info = media_m3u8.keys[0]
    key_url = urljoin(best_stream_url, key_info.uri)
    print(key_url)
    headers = {
        "user-agent": "AVProMobileVideo/2.0.5 (Linux;Android 12) ExoPlayerLib/2.8.4",
        "host": "www.dmm.com",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    }
    key = session.get(key_url, headers=headers).content
    iv = bytes.fromhex("00000000000000000000000000000000")  # 必要に応じて調整
print(" Key:",key)
print(" IV:",iv)
# 作業ディレクトリ
os.makedirs("segments", exist_ok=True)

segment_files = []

for i, segment in enumerate(media_m3u8.segments):
    segment_url = urljoin(best_stream_url, segment.uri)
    segment_path = f"segments/seg_{i:04d}.ts"
    
    print(f"ダウンロード: {segment_url}")
    res = session.get(segment_url,headers=headers)
    data = res.content
    
    print(data[:10])

    # 復号（AES-128 CBC）
    if key:
        iv_bytes = iv if iv else i.to_bytes(16, 'big')
        cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
        data = cipher.decrypt(data)

    with open(segment_path, "wb") as f:
        f.write(data)
    
    segment_files.append(segment_path)

# tsファイル結合
with open("segments/concat.txt", "w") as f:
    for seg in segment_files:
        f.write(f"file '{os.path.abspath(seg)}'\n")

# ffmpegでmp4に変換
subprocess.run([
    "ffmpeg", "-f", "concat", "-safe", "0", "-i", "segments/concat.txt",
    "-c", "copy", "output.mp4"
])

print("✅ ダウンロードと結合完了: output.mp4")