import requests
from bs4 import BeautifulSoup

session = requests.Session()

base_url = "https://www.b-ch.com/titles/1202/001"

soup = BeautifulSoup(session.get(base_url).text, 'html.parser')

# `section` -> `div.bch-p-hero` -> `div#bchplayer-box` -> `video-js`
video_tag = soup.select_one('section.bch-l-hero div.bch-p-hero div#bchplayer-box video-js')

if video_tag:
    data_auth = video_tag.get('data-auth')
    print("data-auth token:", data_auth)

headers = {
    "X-API-kEY": data_auth
}
session.get("https://pbifcd.b-ch.com/v1/playbackinfo/ST/70/1202/1?mbssn_key=", headers=headers)