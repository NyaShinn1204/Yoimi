import requests

session = requests.Session()

def get_playaccess_token():
    _API_URL = "https://www.videomarket.jp/graphql"
    
    _PAYLOAD = {
        "operationName":"PlayingAccessToken",
        "variables": {},
        "query": "query PlayingAccessToken { playingAccessToken }"
    }
    
    response = session.post(_API_URL, json=_PAYLOAD, headers={"app-version": "tv.4.1.14"})
    token = response.json()["data"]["playingAccessToken"]
    return token

def get_playtoken(play_access_token, story_id, pack_id):
    _API_URL = "https://www.videomarket.jp/graphql"
    
    _PAYLOAD = {
        "operationName":"playingToken",
        "variables":{
            "fullStoryId":story_id,
            "fullPackId":pack_id,
            "qualityType":3,
            "token": play_access_token
        },
        "query":"query playingToken($fullStoryId: String!, $fullPackId: String!, $qualityType: Int!, $token: String!) {\n  playingToken(\n    fullStoryId: $fullStoryId\n    fullPackId: $fullPackId\n    qualityType: $qualityType\n    token: $token\n  )\n}\n"
    }
    
    response = session.post(_API_URL, json=_PAYLOAD, headers={"app-version": "tv.4.1.14"})
    token = response.json()["data"]["playingToken"]
    return token

def gen_token():
    _AUTH_DEVICE_URL = "https://auth.videomarket.jp/v1/authorize/device"
    
    payload = {
        "api_key": "43510DE69546794606805E74F797CA84FB8C0938",
        "site_type": 7 # 3 = android, 7 = androidTV
    }    
    headers = {
        "user-agent": "okhttp/4.12.0",
        "content-type": "application/json; charset=utf-8",
        "accept-encoding": "gzip",
        "host": "auth.videomarket.jp"
    }
    
    response = session.post(_AUTH_DEVICE_URL, json=payload, headers=headers)
    
    print(response.text)
    id_token = response.json()["id_token"]
    refrest_token = response.json()["refresh_token"]
    session.headers.update({"Authorization": "Bearer "+id_token})
    
def get_episode_mpd(play_access_token, play_token, story_id):
    _EPISODE_META_URL = "https://pf-api.videomarket.jp/v1/play/vm/streaming/app/tv"
    
    payload = {
        "userId": "",
        "playToken": play_token,
        "fullStoryId": story_id
    }
    headers = {
        "accept": "application/json",
        "authorization": "Bearer "+play_access_token,
        "vm-device-info": "{\"model\":\"AOSP TV on x86\",\"deviceCode\":\"generic_x86_arm\",\"brand\":\"google\",\"platform\":\"Android TV OS\",\"platformVer\":\"13\",\"sdkVer\":33,\"hdcpVer\":1}",
        "vm-app-info": "{\"ver\":\"tv.4.1.14\"}",
        "vm-codec-info": "{\"isHdr\":false,\"isDdp\":false,\"isAtmos\":false,\"isUhd\":false,\"isHevc\":false}",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 13; AOSP TV on x86 Build/TTT5.221206.003)",
        "host": "pf-api.videomarket.jp",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    }
    
    meta_list = session.post(_EPISODE_META_URL, json=payload, headers=headers).json()
    print(meta_list)
gen_token()
playaccess_token = get_playaccess_token()
play_token = get_playtoken(playaccess_token, "300H5R001", "A300H5R001999H01")

print(play_token)

episode_lsit = get_episode_mpd(playaccess_token, play_token, "300H5R001")