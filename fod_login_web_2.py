import requests

session = requests.Session()

email = ""
password = ""

_AUTH_MAIN_PAGE = "https://fod.fujitv.co.jp/auth/login/"
_AUTH_TEST_1 = "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth"
_AUTH_USER_STATUS = "https://fod.fujitv.co.jp/apps/api/1/user/status"
_AUTH_SENT_CODE = "https://fod.fujitv.co.jp/renew/auth/mail_auth/?p=1&ac={code}"
_AUTH_REDIRECT_URL = "https://fod.fujitv.co.jp/loginredir?r="


default_headers = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.9",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd"
}

response = session.get(_AUTH_MAIN_PAGE, headers=default_headers)

#print(response.text)
if response.status_code == 200:
    pass

payload = {
    "__VIEWSTATE": "/wEPDwUKMTg3MDE5MjkwMGRkEfaWBoEUg7eeX65kHUFYgWAdPZo=",
    "__VIEWSTATEGENERATOR": "89E00937",
    "email": email,
    "password": password,
    "ctl00$ContentMain$hdnServerEnv": "",
    "ctl00$ContentMain$hdnFodMail": email,
    "ctl00$ContentMain$hdnFodPass": password,
    "ctl00$ContentMain$hdnFodLogin": "",
    "ctl00$ContentMain$hdnAmazonSignature": "xUOgugvm8yRVgfHrD1pgITydjpHWNJU8622JOK2pVh3h7mIFzuIy7SQHWTHmxjCQOXMZEL6SY1O4JEtjwS2Q+Xc455EZMwnHOJq6aZ+rx4yuEWFEdKxFM8n5j40JA3pqrcfbC/WnySQDEIqKuzPVtAmtC2IvDAPDAEmo+ieNa/ExDkzp7R1v5anxmDsYeU2+UwiAXvRLjax2RPm7vsyOA5FIliOePMIhZcv9p9fmbBsgxBvMWD7KsxX7NpH/uay7XpFiVqzoO2CabtyW0GkyHyuKPM8Zl3qAtjoxakc3dQze1nmSaQdyQtyk9j5XIRBMpRH3q478WuVBr/o3EI/Cqg==",
    "ctl00$ContentMain$hdnAmazonPayload": "{\"storeId\":\"amzn1.application-oa2-client.0fa212ac2e9e494197af4fc8b09d096e\",\"webCheckoutDetails\":{\"checkoutReviewReturnUrl\":\"https://fod.fujitv.co.jp/\"},\"chargePermissionType\":\"Recurring\",\"recurringMetadata\":{\"frequency\":{\"unit\":\"Month\",\"value\":1},\"amount\":{\"amount\":0,\"currencyCode\":\"JPY\"}}}",
    "ctl00$ContentMain$btnFodId": ""
}
headers = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "cache-control": "max-age=0",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "origin": "https://fod.fujitv.co.jp",
    "content-type": "application/x-www-form-urlencoded",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.9",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "referer": "https://fod.fujitv.co.jp/auth/login/",
    "accept-encoding": "gzip, deflate, br, zstd",
}
response = session.post(_AUTH_MAIN_PAGE, data=payload, headers=headers, allow_redirects=False)

if response.status_code == 302:
    print("[+] Get Redirect URL: "+response.headers["Location"])
    pass
else:
    print("fuck")
    
response = session.get(response.headers["Location"], headers=headers)

if response.status_code == 200:
    #print("[+] mail_auth headers: ", response.headers)
    print("[+] sent mail_auth_code")
    pass
else:
    print(response.status_code)
    
response = session.get(_AUTH_TEST_1, headers=headers)

if response.status_code == 200:
    #print("[+] loginredir headers: ", response.headers)
    print("[+] loginredir!")
    pass
else:
    print(response.status_code)

headers_xauth = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "x-authorization": "Bearer "+response.cookies.get("UT"),
    "sec-ch-ua-mobile": "?0",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.9",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://fod.fujitv.co.jp/loginredir/?r=https%3A%2F%2Ffod.fujitv.co.jp%2Fauth%2Fmail_auth",
    "accept-encoding": "gzip, deflate, br, zstd",
}
    
response = session.get(_AUTH_USER_STATUS, headers=headers_xauth)

if response.status_code == 200:
    print("[+] user_status_1: "+response.text)
    pass
else:
    print(response.status_code)
    
mail_auth_code = input("MAIL AUTH CODE : ")
if mail_auth_code == None:
    exit(1)
else:
    pass

response = session.get(_AUTH_SENT_CODE.format(code=mail_auth_code), headers=headers)

if response.status_code == 200:
    print("[+] login_status_1: "+response.text)
    pass
else:
    print(response.status_code)
    
response = session.get(_AUTH_REDIRECT_URL, headers=headers)

if response.status_code == 200:
    #print("[+] login headers: ", response.headers)
    print("[+] Get Temp token: ", response.cookies.get("UT"))
    pass
else:
    print(response.status_code)
    
headers_xauth = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "x-authorization": "Bearer "+response.cookies.get("UT"),
    "sec-ch-ua-mobile": "?0",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.9",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://fod.fujitv.co.jp/loginredir?r=",
    "accept-encoding": "gzip, deflate, br, zstd",
}
    
response = session.get(_AUTH_USER_STATUS, headers=headers_xauth)

if response.status_code == 200:
    print("[+] user_status_2: "+response.text)
    print("[+] GET REAL TOKEN!!!: ", response.cookies.get("UT"))
    pass
else:
    print(response.status_code)