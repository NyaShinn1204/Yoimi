import re
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
    def find_guid_by_locale(data, locale):
        en_us_guid = None
        
        for version in data["versions"]:
            if version["audio_locale"] == locale:
                return version["guid"]
            if version["audio_locale"] == "en-US":
                en_us_guid = version["guid"]
        
        return en_us_guid

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
                        self.session.headers["Authorization"] = f"Bearer {token}"
                        user_info = self.get_account_info()
                        return True, user_info
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
    def get_account_info(self):
        user_info = self.session.get("https://www.crunchyroll.com/accounts/v1/me").json()
        return user_info
    def get_info(self, url):
        match = re.search(r'"?https?://www\.crunchyroll\.com/series/([^/"]+)', url)
        self.series_content_id = match.group(1) if match else None
        
        #copyright_info = self.session.get(f"https://static.crunchyroll.com/copyright/{self.series_content_id}.json").json()
        default_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/series/{self.series_content_id}?preferred_audio_language=en-US&locale=en-US").json()
        seasons_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/series/{self.series_content_id}/seasons?force_locale=&preferred_audio_language=en-US&locale=en-US").json()
        
        self.season_content_id = Crunchyroll_utils.find_guid_by_locale(seasons_info["data"][0], "ja-JP")
        
        season_id_info = self.session.get(f"https://www.crunchyroll.com/content/v2/cms/seasons/{self.season_content_id}/episodes?preferred_audio_language=en-US&locale=en-US").json()
        
        print("total episode:", season_id_info["total"])
        for i in season_id_info["data"]:
            #season_number episode_number
            print(i["season_title"] + " " + "S" + str(i["season_number"]).zfill(2) + "E" + str(i["episode_number"]).zfill(2) + " - " + i["title"])
            #print("title:", i["title"], "ID:", i["id"])

session = requests.Session()
crunchyroll_downloader = Crunchyroll_downloader(session)
email = ""
password = ""
#print(crunchyroll_downloader.authorize(email, password))
status, message = crunchyroll_downloader.authorize(email, password)
try:
    print("Get Token: "+session.headers["Authorization"])
except:
    print("Failed to login")
if status == False:
    print(message)
    exit(1)
else:
    print("Loggined Account")
    print(" + ID: "+message["account_id"][:10]+"*****")

crunchyroll_downloader.get_info("https://www.crunchyroll.com/series/G1XHJV0XM/alya-sometimes-hides-her-feelings-in-russian")