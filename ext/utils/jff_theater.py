import time
import string
import random

class JFF_Theater:
    def __init__(self, session):
        self.session = session
        self.common_headers = {
            "host": "www.jff.jpf.go.jp",
            "connection": "keep-alive",
            "sec-ch-ua-platform": "\"Windows\"",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
            "accept": "application/json, text/plain, */*",
            "sec-ch-ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
            "content-type": "application/json",
            "sec-ch-ua-mobile": "?0",
            "sec-gpc": "1",
            "accept-language": "ja;q=0.7",
            "origin": "https://www.jff.jpf.go.jp",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.jff.jpf.go.jp/mypage/register_account/",
            "accept-encoding": "gzip, deflate, br, zstd",
        }
    def authorize(self, email_or_id, password):
        if email_or_id and password == None:
            status, info = self.create_temp_account()
            return status, info
        payload = {
          "username": email_or_id,
          "password": password
        }
        headers = self.common_headers.copy()
        sent_login_req = self.session("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        if sent_login_req.json()["message"] == "正常終了":
            pass
        else:
            return False, None
        
        temp_token = sent_login_req.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json()
        
    def create_temp_account(self):
        def random_string(length):
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
        def generate_username():
            return str(int(time.time() * 1000))+random_string(6) # not support "_"
        
        def generate_password():
            return str(random.randint(0,9))+random_string(7)+"YO!M!"
        
        username = generate_username()
        password = generate_password()
        
        querystring = { "lang": "ja" }
        
        payload = {
            "nickName": username,
            "email": random_string(10)+"@Yoimi.net",
            "password": password,
            "passwordConfirm": password,
            "country": "jp",
            "newsLetter": "ja",
            "informationCountry1": "",
            "informationCountry2": "",
            "informationCountry3": ""
        }
        
        send_create_req = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts", json=payload, headers=self.common_headers, params=querystring)
        
        temp_key = send_create_req.json()["data"]["temporaryKey"]
        headers = self.common_headers.copy()
        headers.update({
            "referer": "https://www.jff.jpf.go.jp/mypage/definitive_register_account/?key="+temp_key,
        })
        payload = { "key": temp_key }
        apply_email_verify = self.session("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        #print(apply_email_verify.json()["message"])
        if apply_email_verify.json()["message"] == "正常終了":
            pass
        else:
            return False, None
        
        temp_token = apply_email_verify.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json()