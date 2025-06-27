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
    get_loginkey.raise_for_status
    
    if get_loginkey.json()["result"] == "0":
        pass
    else:
        return
    
    login_key = get_loginkey.json()["loginkey"]
    
def login_email():
    # Android, AndroidTV SSL Traffic is patched. fuck you docomo
    # Unsupported :(
    return None