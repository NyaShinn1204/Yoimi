import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
def main_command(session, url):
    login_status = False
    def get_title_id(url):
        path_parts = urlparse(url).path.strip('/').split('/')
        if len(path_parts) > 1 and path_parts[0] == "titles":
            title_id = path_parts[1]
            #print(title_id)  # 出力: 1202
            return title_id
    def get_title_json(id):
        title_json = session.get(f"https://www.b-ch.com/json/titles/{id}.json").json()
        return title_json
    def get_title_name(url):
        html = session.get(url).content # .textだと文字化けする
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.find('h2', class_='bch-c-heading-2__ttl').get_text()
        return text
    title_name = get_title_name(url)
    title_id = get_title_id(url)
    title_json = get_title_json(title_id)
    
    for single in title_json:
        vod_status = ""
        if single["prod"][0]["free_f"] == "1":
            vod_status = "FREE"
        elif single["prod"][0]["mbauth_f"] == "1" and login_status:
            vod_status = "FREE"
        else:
            vod_status = "PREMIUM"
        print(title_name+"_"+single["strysu_txt"]+"_"+single["strytitle_txt"]+f" | [ID: {title_id+"/"+str(single["stry_sq"]).zfill(3)} SEC: {str(single["length_sec"])} FREE: {vod_status}]")
        
session = requests.Session()
url = "https://www.b-ch.com/titles/1202/"
main_command(session, url)
    