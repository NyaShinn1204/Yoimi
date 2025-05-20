import json
import hmac
import hashlib

def get_json(params: dict) -> str:
    # Javaの JSONObject.toString() に近い形式（余計なスペースを除く）
    return json.dumps(params, separators=(',', ':'), ensure_ascii=False)

def get_hash(data: str, key: str) -> str:
    return hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()

def set_post_params(message: str, params: dict, appid: str, secret_key: str) -> dict:
    post_data = {}
    post_data["message"] = message
    post_data["appid"] = appid
    json_data = get_json(params)
    post_data["params"] = json_data
    post_data["authkey"] = get_hash(json_data, secret_key)
    return post_data

params = {
    "android_drm": False,
    "bitrate": 0,
    "drm": False,
    "exploit_id": "uid:lVzxoGplD9zA35Ac",
    "chrome_cast": False,
    "isTablet": False,
    "licenseUID": "fe2f51ae-1ac7-4829-806b-77e33dd43063",
    "parent_product_id": "h_1558csdx00006dl7",
    "product_id": "h_1558csdx00006",
    "secure_url_flag": False,
    "service": "digital",
    "shop": "videoa",
    "smartphone_access": True,
    "transfer_type": "stream",
    "HTTP_USER_AGENT": "DMMPLAY movie_player (94, 4.1.0) API Level:35 PORTALAPP Android",
    "device": "android",
    "HTTP_SMARTPHONE_APP": "DMM-APP",
    "message": "Digital_Api_Proxy.getURL"
}

payload = set_post_params(
    message="Digital_Api_Proxy.getURL",
    params=params,
    appid="android_movieplayer_app",
    secret_key="hp2Y944L"
)

print(payload["authkey"])  # cb38c66b8281f7a509d2b9892c6b347423f83c162b6b2eda171ef9da5688d3c6 になるはず
