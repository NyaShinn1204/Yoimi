# util/unext/abema/main.py
import re
import requests

def create_temp_token():
    import data.setting as setting


    import hmac
    import time
    import uuid
    import hashlib
    from base64 import urlsafe_b64encode
    
    session = requests.Session()
    def key_secret(devid):
        SECRETKEY = (b"v+Gjs=25Aw5erR!J8ZuvRrCx*rGswhB&qdHd_SYerEWdU&a?3DzN9B"
                    b"Rbp5KwY4hEmcj5#fykMjJ=AuWz5GSMY-d@H7DMEh3M@9n2G552Us$$"
                    b"k9cD=3TxwWe86!x#Zyhe")
        deviceid = devid.encode("utf-8")
        ts_1hour = (int(time.time()) + 60 * 60) // 3600 * 3600
        time_struct = time.gmtime(ts_1hour)
        ts_1hour_str = str(ts_1hour).encode("utf-8")
        h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
        h.update(SECRETKEY)
        tmp = h.digest()
        for _ in range(time_struct.tm_mon):
            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()
        h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
        h.update(urlsafe_b64encode(tmp).rstrip(b"=") + deviceid)
        tmp = h.digest()
        for _ in range(time_struct.tm_mday % 5):
            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()
        h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
        h.update(urlsafe_b64encode(tmp).rstrip(b"=") + ts_1hour_str)
        tmp = h.digest()
        for _ in range(time_struct.tm_hour % 5):  # utc hour
            h = hmac.new(SECRETKEY, digestmod=hashlib.sha256)
            h.update(tmp)
            tmp = h.digest()
        finalize = urlsafe_b64encode(tmp).rstrip(b"=").decode("utf-8")
        return finalize
    
    deviceid = str(uuid.uuid4())
    json_data = {"deviceId": deviceid, "applicationKeySecret": key_secret(deviceid)}
    res = session.post(setting.abema_url_list()["runtimeConfig"]["USER_LOGIN_API"], json=json_data).json()
    try:
        token = res['token']
    except:
        return None, 'Failed to get user token.'
    return token, deviceid

def check_email(email, password):
    import data.setting as setting
    
    temp_token, deviceid = create_temp_token()
    
    '''クッキーをテストするコード'''
    check_json = {
        "email": email,
        "password": password
    }
    try:
        test_cookie = requests.post(setting.abema_url_list()["runtimeConfig"]["USER_LOGIN_EMAIL_API"], json=check_json, headers={"authorization": f"Bearer {temp_token}"})   
        return_json = test_cookie.json()
        print(return_json)
        #print()
        #print(test_cookie.text)
        if return_json["subscriptions"][0]["productId"] == "subscription_premium":
            return True, return_json["profile"][0]["userId"], "premium"
        else:
            return True, return_json["profile"][0]["userId"], "normal"
    except Exception as e:
        print(e)
        return False, None, None
    
def get_auth_token_abema(email, password):
    import data.setting as setting
    
    temp_token, deviceid = create_temp_token()
    
    '''クッキーをテストするコード'''
    check_json = {
        "email": email,
        "password": password
    }
    try:
        test_cookie = requests.post(setting.abema_url_list()["runtimeConfig"]["USER_LOGIN_EMAIL_API"], json=check_json, headers={"authorization": f"Bearer {temp_token}"})   
        return_json = test_cookie.json()
        auth_token = f"Bearer {return_json["token"]}"
        return auth_token, deviceid
    except Exception as e:
        return None
    
def get_title_metadata(title_id):
    import data.setting as setting
    '''メタデータを取得するコード'''
    meta_json = {
        "includes": "liveEvent,slot"   
    }
    try:   
        metadata_response = requests.get(setting.abema_url_list()["runtimeConfig"]["SERIES_META_API"]+"/series/"+title_id, params=meta_json, headers={"authorization": setting.abema_auth["email"]["token"]})   
        return_json = metadata_response.json()
        if return_json != None:
            return True, return_json, None
        else:
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None

def get_episode_metadata(season_id, epsiode_group_id):
    import data.setting as setting
    '''エピソードのタイトルについて取得するコード'''
    meta_json = {
        "seasonId": season_id,
        "limit": "100",
        "offset": "0",
        "orderType": "asc",
        "includes": "liveEvent,slot"
    }
    try:    
        metadata_response = requests.get(setting.abema_url_list()["runtimeConfig"]["SERIES_META_API"]+"/episodeGroups/"+epsiode_group_id+"/contents", params=meta_json, headers={"authorization": setting.abema_auth["email"]["token"]})   
        return_json = metadata_response.json()
        if return_json["episodeGroupContents"] != None:
            return True, return_json["episodeGroupContents"], None
        else:
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None

def get_episode_title(content_id):
    import data.setting as setting
    '''エピソードのタイトルについて取得するコード'''
    meta_json = {
        "division": "0",
        "includes": "tvod"   
    }
    try:   
        metadata_response = requests.get(setting.abema_url_list()["runtimeConfig"]["VIDEO_API"]+"/programs/"+content_id, params=meta_json, headers={"authorization": setting.abema_auth["email"]["token"]})   
        return_json = metadata_response.json()
        if return_json != None:
            return True, return_json, None
        else:
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None
    
def parse_titlename(name):
    '''Windowsで作成できない文字列などを変換するコード'''
    name = name.replace('\u3000', ' ')
    return re.sub(r'[\\/:\*\?"<>\|]', '_', name)