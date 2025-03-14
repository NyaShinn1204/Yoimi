import requests

LOGIN_URL = "https://account-api.bandainamcoid.com/v3/login/idpw"
REDIRECT_URI = "https://www.bandainamcoid.com/v2/oauth2/auth?back=v3&client_id=bnid_b_ch&scope=JpGroupAll&redirect_uri=https://www.b-ch.com/mbr/auth2v3.php?refer=&text="

class Client:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()

    def login(self):
        data = {
            "client_id": "bnid_b_ch",
            "redirect_uri": REDIRECT_URI,
            "customize_id": "",
            "login_id": self.username,
            "password": self.password,
            "shortcut": "0",
            "retention": "0",
            "language": "ja",
            "cookie": '{"language":"ja"}',
            "prompt": ""
        }
        
        response = self.session.post(LOGIN_URL, data=data)
        if response.status_code != 200:
            raise Exception("Failed to login")
        
        login_response = response.json()
        redirect_url = login_response.get("redirect")
        if not redirect_url:
            raise Exception("No redirect URL found")
        
        auth_response = self.session.get(redirect_url)
        if auth_response.status_code != 200:
            raise Exception("Failed to authenticate")
        
        return auth_response

    def get_cookie_jar(self):
        return self.session.cookies

def new_cookie_jar(username, password):
    client = Client(username, password)
    client.login()
    return client.get_cookie_jar()

# Example usage
jar = new_cookie_jar("popo004@cocoro.uk", "popo004@cocoro.uk1")
print(jar["BCHWWW"])

import requests

url = "https://appsvr.b-ch.com/api/mbauth/ajax_session_check"

payload = "mbssn_key="+jar["BCHWWW"]
headers = {
    "host": "appsvr.b-ch.com",
    "connection": "keep-alive",
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "accept": "application/json",
    "sec-ch-ua": "\"Chromium\";v=\"134\", \"Not:A-Brand\";v=\"24\", \"Brave\";v=\"134\"",
    "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    "sec-ch-ua-mobile": "?0",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.7",
    "origin": "https://www.b-ch.com",
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://www.b-ch.com/",
    "accept-encoding": "gzip, deflate, br, zstd"
}

response = requests.post(url, data=payload, headers=headers)

print(response.text)