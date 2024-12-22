import requests

url = "https://i.fod.fujitv.co.jp/apps/api/lineup/detail/"

querystring = {
    "lu_id": "70v8",
    "is_premium": "true",
    "dv_type": "web",
    "is_kids": "false"
}

headers = {
    "host": "i.fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "x-authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJGT0QiLCJ1aWQiOiJxSWo1MThndVdZSEV4VVRpMnRYWGNHSDBiMTJhOGRaZGFJdlZxZUpJZE0yZWxNMWVMLzk4MDBXemdaMVlFTERhemIyaW5hVldNcnh5M3pMVEVtMkFZdz09IiwiZHZfdHlwZSI6IndlYiIsImR2X2lkIjoiTWljcm9zb2Z0IFdpbmRvd3MgTlQgMTAuMC4xNzc2My4wX0Nocm9tZTEzMS4wIn0.8ubF0DqSTqBVrCg51q_34EK7XiRk3AM6PykLh0VA_Rg",
    "sec-ch-ua-mobile": "?0",
    "origin": "https://fod.fujitv.co.jp",
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://fod.fujitv.co.jp/",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh,en-US;q=0.9,en;q=0.8,ja;q=0.7"
}

response = requests.get(url, headers=headers, params=querystring)

print(response.text)