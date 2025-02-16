import uuid
import time
import random
import requests

class Crunchyroll_utils:
    def random_select_ua() -> str:
        android_version = str(random.randint(13, 15))
        okhttp_version = f"4.{random.randint(10, 12)}.{random.randint(0, 9)}"
        user_agent = f"Crunchyroll/3.74.2 Android/{android_version} okhttp/{okhttp_version}"
        return user_agent

class Crunchyroll_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email, password):
        retries = 0
        while retries < 3:
            try:
                self.session.headers = {
                    "Authorization": "Basic ZG1yeWZlc2NkYm90dWJldW56NXo6NU45aThPV2cyVmtNcm1oekNfNUNXekRLOG55SXo0QU0=",
                    "Connection": "Keep-Alive",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "ETP-Anonymous-ID": str(uuid.uuid4()),
                    "Host": "www.crunchyroll.com",
                    "User-Agent": Crunchyroll_utils.random_select_ua(),
                    "X-Datadog-Sampling-Priority": "0",
                }
                payload = {
                    "username": email,
                    "password": password,
                    "grant_type": "password",
                    "scope": "offline_access",
                    "device_id": str(uuid.uuid4()),
                    "device_name": "sdk_gphone64_x86_64",
                    "device_type": "Google sdk_gphone64_x86_64"
                }
                response = self.session.post('https://www.crunchyroll.com/auth/v1/token', data=payload)
                if response.status_code == 200:
                    token = response.json()["access_token"]
                    if token:
                        self.session.headers['Authorization'] = f"Bearer {token}"
                        return token
                    return None
                if response.status_code == 401:
                    print(f"Invalid credentials. {response.text}")
                    return None
                if response.status_code == 500:
                    print(f"Internal server error. {response.text}")
                    return None
                
                if response.status_code == 403:
                    print("Flagged IP address.")
                    return None
                
                if response.status_code == 429:
                    retries += 1
                    print(f"Rate limited, retrying with new proxy (Attempt {retries}/3)")
                    time.sleep(2)
                    continue
                
                return None
                
            except Exception as e:
                print(f"Catch Error: {e}")
                retries += 1
                if retries < 3:
                    time.sleep(2)
                    continue
        return None
        
crunchyroll_downloader = Crunchyroll_downloader(requests.Session())
email = ""
password = ""
crunchyroll_downloader.authorize(email, password)