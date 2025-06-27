import time
import requests

session = requests.Session()
session.headers.update({
    "user-agent": "Lemino/7.2.2(71) A7S;AndroidTV;10",
    "accept-encoding": "gzip",
    "charset": "UTF-8",
    "content-type": "application/json",
})

terminal_type = {
    "android_tv": "1",
    "android": "3"
}

service_token = session.post("https://if.lemino.docomo.ne.jp/v1/session/init", json={"terminal_type": terminal_type["android_tv"]}).headers["X-Service-Token"]

session.headers.update({"X-Service-Token": service_token})

def login_qr():
    get_loginkey = session.post("https://if.lemino.docomo.ne.jp/v1/user/auth/loginkey/create")
    get_loginkey.raise_for_status()
    
    if get_loginkey.json()["result"] == "0":
        pass
    else:
        return
    
    login_key = get_loginkey.json()["loginkey"]
    
def login_email():
    # Android, AndroidTV SSL Traffic is patched. fuck you docomo
    # Unsupported :(
    return None

def check_login():
    while True:
        payload = {
            "member": True,
            "profile": True
        }
        login_result = session.post("https://if.lemino.docomo.ne.jp/v1/user/loginkey/userinfo/profile", json=payload)
        login_result.raise_for_status()
        
        if login_result.json()["member"]["account_type"] != None:
            return True, login_result.json()
        else:
            time.sleep(5)
            continue
        
def get_user_info():
    url = "https://if.lemino.docomo.ne.jp/v1/user/userinfo/profile"
    
    payload = {
        "member": True,
        "profile": True
    }
    user_info_result = session.post(url, json=payload)
    user_info_result.raise_for_status()
    
    return user_info_result.json()
def get_subscription_info():
    url = "https://if.lemino.docomo.ne.jp/v1/user/userinfo/subscribelist"
    
    payload = {
        "prconsistent_read_flagofile": False
    }
    subscription_result = session.post(url, json=payload)
    subscription_result.raise_for_status()
    
    return subscription_result.json()
def get_dmarket_info():
    url = "https://if.lemino.docomo.ne.jp/limited/v1/user/userinfo/dmarket"
    
    dmarket_info_result = session.post(url)
    dmarket_info_result.raise_for_status()
    
    return dmarket_info_result.json()
# content get
def get_content_info(crid):
    url = "https://if.lemino.docomo.ne.jp/v1/meta/contents"
    
    querystring = {
        #"crid": "crid://plala.iptvf.jp/vod/0000000000_00m7wo6mux",
        "crid": crid,
        "filter": "{\"target_age\":[\"G\",\"R-12\",\"R-15\"],\"avail_status\":[\"1\"]}"
    }
    contentinfo_result = session.get(url, params=querystring)
    contentinfo_result.raise_for_status()
    
    return contentinfo_result.json()

def get_mpd_info(cid, lid, crid):
    payload = {
      "play_type": 1,
      "avail_status": "1",
      "terminal_type": 4,
      "content_list": [
        {
          "kind": "main",
          "cid": cid,
          "lid": lid,
          "crid": crid,
          "auto_play": 1,
          "trailer": 0,
          "preview": 0,
          "stop_position": 0
        }
      ]
    }
    play_list_result = session.post("https://if.lemino.docomo.ne.jp/v1/user/delivery/watch/ready", json=payload)
    play_list_result.raise_for_status()
    
    play_list_json = play_list_result.json()
    
    play_token = play_list_json["play_token"]
    content_list = play_list_json["play_list"]
    return play_token, content_list


def widevine_license(custom_data):
    url = "https://drm.lemino.docomo.ne.jp/widevine_license"
    headers = {
        "acquirelicenseassertion": custom_data,
        "user-agent": "inidrmagent/2.0 (Android 10; jp.ne.docomo.lemino.androidtv)",
        "content-type": "application/octet-stream",
        "host": "drm.lemino.docomo.ne.jp",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    }
    # Widevine License Logic HERE


def send_stop_signal(play_token, duratation):
    payload = {
        "paly_token": play_token,
        "dur": str(duratation),
        "stop_position": "0"
    }

def update_session():
    url = "https://if.lemino.docomo.ne.jp/v1/session/update"
    
    update_session = session.post(url)
    update_session.raise_for_status()
    
    session.headers.update({"X-Service-Token": update_session.headers["X-Service-Token"]})
    
    return True