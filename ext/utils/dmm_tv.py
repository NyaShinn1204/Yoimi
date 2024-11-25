import re
import random
import string
import base64
import requests
from urllib.parse import urlparse, parse_qs

class Dmm_TV_utils:
    def random_name(length):
        return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    def recaptcha_v3_bypass(anchor_url):
        url_base = 'https://www.google.com/recaptcha/'
        post_data = "v={}&reason=q&c={}&k={}&co={}"
        
        session = requests.Session()
        session.headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        
        matches = re.findall('([api2|enterprise]+)\/anchor\?(.*)', anchor_url)[0]
        url_base += matches[0]+'/'
        params = matches[1]
        
        res = session.get(url_base+'anchor', params=params)
        token = re.findall(r'"recaptcha-token" value="(.*?)"', res.text)[0]
        
        params = dict(pair.split('=') for pair in params.split('&'))
        post_data = post_data.format(params["v"], token, params["k"], params["co"])
        
        res = session.post(url_base+'reload', params=f'k={params["k"]}', data=post_data)
        
        answer = re.findall(r'"rresp","(.*?)"', res.text)[0]
        
        return answer

class Dmm_TV_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self):
        login_recaptcha_token = Dmm_TV_utils.recaptcha_v3_bypass("https://www.google.com/recaptcha/enterprise/anchor?ar=1&k=6LfZLQEVAAAAAC-8pKwFNuzVoJW4tfUCghBX_7ZE&co=aHR0cHM6Ly9hY2NvdW50cy5kbW0uY29tOjQ0Mw..&hl=ja&v=pPK749sccDmVW_9DSeTMVvh2&size=invisible&cb=nswb324ozwnh")
        
        client_id = "S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi"
        client_secret = "zEq95QPlzmugWhHKayXK2hcGS5z8DYwP"
        
        querystring = {
            "client_id": client_id,
            "parts": ["regist", "snslogin", "darkmode"]
        }
        
        headers = {
            "host": "accounts.dmm.com",
            "connection": "keep-alive",
            "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Android\"",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        
        res1 = self.session.get("https://accounts.dmm.com/app/service/login/password", params=querystring, headers=headers)
        
        login_page = res1.text
        token_match = re.search(r'name="token" value="([^"]*)"/>', login_page)
        token = token_match.group(1) if token_match else None

        _auth = {
            "token": token,
            "login_id": "dokyopeyu@sendnow.win",
            "password": "Paicha0721",
            "use_auto_login": "1",
            "recaptchaToken": login_recaptcha_token,
            "clientId": client_id,
            "parts": ["regist", "snslogin", "darkmode"]
        }

        res = self.session.post("https://accounts.dmm.com/app/service/login/password/authenticate", data=_auth, allow_redirects=False)
        auth_url = res.text
        redirect_auth_url = self.session.get(auth_url, allow_redirects=False).headers.get("Location")
        
        headers = {
            "authorization": "Basic "+base64.b64encode((client_id+":"+client_secret).encode()).decode(),
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 9; V2338A Build/PQ3B.190801.10101846)",
            "host": "gw.dmmapis.com",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        
        _auth = {
            "grant_type": "authorization_code",
            "code": redirect_auth_url.replace("dmmtv://android/auth/?code=", ""),
            "redirect_uri": "dmmtv://android/auth/"
        }
                
        token_response = self.session.post("https://gw.dmmapis.com/connect/v1/token", json=_auth, headers=headers)
        
        print(token_response.text)
        print("[+] Success to login Dmm-TV")

aiueo = Dmm_TV_downloader(requests.Session())
aiueo.authorize()