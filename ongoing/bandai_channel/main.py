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
        
        if vod_status == "FREE":
            print("pass")
        else:
            print("[-] クソが！プレミアムが必要だわボケ")
            continue
        
        soup = BeautifulSoup(session.get(f"https://www.b-ch.com/titles/{title_id}/{str(single["stry_sq"]).zfill(3)}").content, 'html.parser')
        
        # `section` -> `div.bch-p-hero` -> `div#bchplayer-box` -> `video-js`
        video_tag = soup.select_one('section.bch-l-hero div.bch-p-hero div#bchplayer-box video-js')
        
        if video_tag:
            data_auth = video_tag.get('data-auth')
            data_auth = data_auth.replace("\n", "")
        
        if login_status:
            cookie = None
            metainfo_url = f"https://pbifcd.b-ch.com/v1/playbackinfo/ST/70/{title_id}/{str(single["stry_sq"])}?mbssn_key="+cookie["BCHWWW"]
        else:
            metainfo_url = f"https://pbifcd.b-ch.com/v1/playbackinfo/ST/70/{title_id}/{str(single["stry_sq"])}?mbssn_key="
            
        metainfo_json = session.get(metainfo_url, headers={"X-API-KEY": data_auth}).json()
        
        #print(metainfo_json)
        
        if metainfo_json["bc"]["text_tracks"] != []:
            print("sub detect")
        
        duration_ms = metainfo_json["bc"]["duration"]
        
        print("[+] 解像度リスト")
        for single_track in metainfo_json["bch"]["rendition"]:
            print(str(single_track["width"])+"x"+str(single_track["height"]))
            
        #print(metainfo_json["bc"]["sources"])
        urls = []
        for source in metainfo_json["bc"]["sources"]:
            if "key_systems" in source and "manifest.mpd" in source["src"] and "https" in source["src"]:
                urls.append(source["src"])
                if source["key_systems"]:
                    widevine_url = source["key_systems"].get("com.widevine.alpha", {}).get("license_url", None)
                    playready_url = source["key_systems"].get("com.microsoft.playready", {}).get("license_url", None)
                #else:
                #    widevine_url = None
                #    playready_url = None
                
        print("[+] うお！暗号化リンクゲット！")
        print(urls[0])
session = requests.Session()
url = "https://www.b-ch.com/titles/1202/"
main_command(session, url)
    