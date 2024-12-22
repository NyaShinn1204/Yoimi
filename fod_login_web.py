import requests

url = "https://fod.fujitv.co.jp/auth/login/"

payload = {
    "__VIEWSTATE": "/wEPDwUKMTg3MDE5MjkwMGRkEfaWBoEUg7eeX65kHUFYgWAdPZo=",
    "__VIEWSTATEGENERATOR": "89E00937",
    "email": "",
    "password": "",
    "ctl00$ContentMain$hdnServerEnv": "",
    "ctl00$ContentMain$hdnFodMail": "",
    "ctl00$ContentMain$hdnFodPass": "",
    "ctl00$ContentMain$hdnFodLogin": "",
    "ctl00$ContentMain$hdnAmazonSignature": "SloZpdCxwibW9s8gutHcPkZkVIXl9069dtWlerRvZBudQUUh8S6jqBg9sV+dcjFdivJgHX4pJAaAekO3F714MNjttqStDRi5reHSCv4IC4mMLwBDCNHBAxTl/FgVwkCDL6oDPnHd7VYk5YP9P5A/Hfsvs95bcCg/rBKIdaorncwWQfY0PGmuKtwLiFpclk9S3HiOLnfoLmrEQ58ButvSVpbbInfFroipOvPvoB4rZPZUgOkYf9LiDFlKGMVSnkcWP/hVy3H3VmQxJxMBOgAVoYPpp2QLvJgHzFr5HCRAG8f4zG+/dDjspBtH1DwnTtrv5yUSAAFNohKSlRns4fMHVA==",
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
    "accept-language": "ja;q=0.6",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "referer": "https://fod.fujitv.co.jp/auth/login/",
    "accept-encoding": "gzip, deflate, br, zstd",
}

session = requests.Session()

response = session.post(url, data=payload, headers=headers)

print(response.text)

answeR_input = input("code: ")

url = "https://fod.fujitv.co.jp/renew/auth/mail_auth/"

querystring = {
    "p": "1",
    "ac": answeR_input
}

headers = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua-platform": "\"Windows\"",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.6",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "referer": "https://fod.fujitv.co.jp/auth/mail_auth",
    "accept-encoding": "gzip, deflate, br, zstd",
}

response = session.get(url, headers=headers, params=querystring)

print(response.text)


url = "https://fod.fujitv.co.jp/loginredir"

querystring = { "r": "" }

headers = {
    "host": "fod.fujitv.co.jp",
    "connection": "keep-alive",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.6",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "referer": "https://fod.fujitv.co.jp/auth/mail_auth",
    "accept-encoding": "gzip, deflate, br, zstd",
}

#response = session.get(url, headers=headers, params=querystring)

#print(response.text)

print(session.cookies["UT"])

print(session.get("https://fod.fujitv.co.jp/apps/api/1/user/status").text)