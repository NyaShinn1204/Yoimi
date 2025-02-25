import time
import string
import random
from lxml import etree

class Jff_utils:
    def parse_mpd_logic(content):
        try:
            # Ensure the content is in bytes
            if isinstance(content, str):
                content = content.encode('utf-8')
    
            # Parse XML
            root = etree.fromstring(content)
            namespaces = {
                'mpd': 'urn:mpeg:dash:schema:mpd:2011',
                'cenc': 'urn:mpeg:cenc:2013'
            }
    
            # Extract video information
            videos = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    videos.append({
                        'resolution': f"{representation.get('width')}x{representation.get('height')}",
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract audio information
            audios = []
            for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
                for representation in adaptation_set.findall('mpd:Representation', namespaces):
                    audios.append({
                        'audioSamplingRate': representation.get('audioSamplingRate'),
                        'codec': representation.get('codecs'),
                        'mimetype': representation.get('mimeType')
                    })
    
            # Extract PSSH values
            pssh_list = []
            for content_protection in root.findall('.//mpd:ContentProtection', namespaces):
                pssh_element = content_protection.find('cenc:pssh', namespaces)
                if pssh_element is not None:
                    pssh_list.append(pssh_element.text)
    
            # Build the result
            result = {
                "main_content": content.decode('utf-8'),
                "pssh": pssh_list
            }
    
            return result
    
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid MPD content: {e}")
        except Exception as e:
            raise RuntimeError(f"An unexpected error occurred: {e}")

class Jff_license:
    def license_vd_ad(pssh, session, drm_key):
        _WVPROXY = "https://widevine-dash.ezdrm.com/widevine-php/widevine-foreignkey.php?pX=D6F9EE&key={}".format(drm_key) # pXは固定
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
    
        challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
        response = session.post(f"{_WVPROXY}", data=bytes(challenge))
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


class Jff_downloader:
    def __init__(self, session, config):
        self.session = session
        self.config = config
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
            status, info, temp_token = self.create_temp_account()
            return status, info, temp_token
        payload = {
          "username": email_or_id,
          "password": password
        }
        headers = self.common_headers.copy()
        sent_login_req = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        if sent_login_req.json()["message"] == "正常終了":
            pass
        else:
            return False, None, None
        
        temp_token = sent_login_req.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json(), temp_token
        
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
        apply_email_verify = self.session.post("https://www.jff.jpf.go.jp/jff-api/accounts_registration", json=payload, headers=headers)
        
        #print(apply_email_verify.json()["message"])
        if apply_email_verify.json()["message"] == "正常終了":
            pass
        else:
            return False, None, None
        
        temp_token = apply_email_verify.json()["data"]["accessToken"]
        self.session.headers.update({"Authorization": "Bearer " + temp_token})
        
        account_info = self.session.get("https://www.jff.jpf.go.jp/jff-api/auth/me", headers=headers)
        
        #print(account_info.text)
        return True, account_info.json(), temp_token
    
    def get_content_info(self, url):
        response = self.session.get("https://www.jff.jpf.go.jp/jff-api/contents")
        content_list = response.json().get("data", [])
    
        matched_content = next(
            (single for single in content_list if single.get("detailUrl") and single["detailUrl"] in url),
            None
        )
    
        if matched_content:
            content_code = matched_content.get("contentsCode")
            if content_code:
                single_content_info = self.session.get(f"https://www.jff.jpf.go.jp/jff-api/contents/{content_code}")
                return True, single_content_info.json().get("data")
        
        return False, None
            
    def check_play_ep(self, ep_id):
        drm_info = self.session.get(f"https://www.jff.jpf.go.jp/jff-api/contents/{ep_id}/drm").json()
        if drm_info["data"]["message"] == None:
            if drm_info["data"]["status"] == "outsideArea":
                message = "Region Lock"
                return False, message
            elif drm_info["data"]["status"] == "viewable":
                return True, drm_info
            else:
                return False, drm_info["data"]["message"]
        else:
            return False, drm_info["data"]["message"]