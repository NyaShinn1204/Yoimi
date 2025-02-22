from bs4 import BeautifulSoup
from curl_cffi import requests

def login(email, password):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    common_headers = {
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-GPC": "1",
        "Accept-Language": "ja;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Sec-CH-UA": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": "\"Windows\"",
        "Accept-Encoding": "gzip, deflate, br, zstd",
    }
    
    session = requests.Session()
    url = "https://animestore.docomo.ne.jp/animestore/login"
    baseauth_url = ""
    for _ in range(4):  # Combined redirect handling
        response = session.get(url, headers=common_headers, allow_redirects=False)
        if response.status_code not in (301, 302):
            break #exit the loop if there is no redirect
        url = response.headers["Location"]
        if "baseauth" in url:
            baseauth_url = url
            break
        print(f"Redirect: {response.status_code} to {url}") #print redirect status
    else:
        raise Exception("Too many redirects or no redirect URL found.")
    
    print("\n")
    
    common_headers["Host"] = "cfg.smt.docomo.ne.jp"
    tempsession_id_response = session.get(baseauth_url, headers=common_headers)
    temp_session_id = BeautifulSoup(tempsession_id_response.text, "html.parser").find("input", {"id": "tempSessionId"})["value"]
    print("Temp Session Id", temp_session_id)

login(None, None)