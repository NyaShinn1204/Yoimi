import requests

url = "https://accounts.dmm.com/app/service/login/password/authenticate"

payload = {
    "token": "c597fbe88da7e34c4913c999f7e4b88c1734090032",
    "login_id": "rumiadayo@na-cat.com",
    "password": "rumiadayo",
    "recaptchaToken": "03AFcWeA6nFqixtZ3e4DOzkv3DgkTZuE7183Te-EvmFuDjY6Io58xUucV4HVOOHm2gEhQMlCXfUGUtgnU2bF_Kha6UYyGSF_yAA-TAFrlr-_NHpAwl3WgTX-PJmPIc5bfKVEoEnndAXy_dRVkuZmqZYmGDkJJlH5sQadbK_7DxfP6KSLqTADedX_5CUJXHSXedZuBTQISvtxHPBY8Sn30aByQVDRJbTFoyUPaYvC9e5D_TMtkSShW6qQvblBCBquOUN8Bx3Bf2W0sODOVNTMRoJoaHmXNU7D9VpublcdGiqf6mivFSWZvSt_iLBOXP7eoNgifJA4_l5NfR-0wMnZFzJ98X-et7DrKqQLYBY0sclMUNOW8sFslqaIFnNrMwRByy2aCBcpW4VHeO7LagcaomE44N3eXiBtvFEgYXEKBR_QQsuBL9W2Wff215DBcnXeGrkR0ZCIWzFRhChXV3z-KwUo9jAAtafmQ1Og59RHsYAgJ275gzIdnOeebrGuApR7gUnHStQ2SXRUrSb782esJyNJXGSN2As2mLTxgxesUho_crxju4eJY4CDWBOpgtnGuB5mwjF0idFY4qrWjUdH8AAxXjKsBDDHbMxaTUflUmNDV9AljKlRhhj5F2yClL5zc5Qmf-z-bIeBk0KQGokiJJzeOWbOLwdWU1IrDnML9jvgQ6PFGz0DDQknpBUqfDBO8sHQWkuCnQhRmycLfB9r3z66Hs4CaWpmQANhntKfUT3Qs2AtO3-yOuLRH_2-7CauN_hteP0ggdWv9q7zLbCCtg1lLJlLlrc6jMeN0YuMbp0QhqdTA5QHZ7tB4UcCNnvYOdatOnuVDMGHkzYvuNJTO4S0wnsFJ6pyWrBaorBg8ehf4tyaZPUlHY6telWm-lLYUBnnOMXwRX2Lvp2aKPe6hRYhgZfH0qSUfCaLwjItN6bCCYtp1LouSuuYkt_p4a6_zq0hPTyXLfXpdTq2yLyRWHVyKm3HY83zsnEO7aOYcQ5dmaD803EpszqdPHHpatKUHOs5SWxNnOc4UlkNlEVISCE1mt_gL8kvYUorvBVbzUzMhsVWR8uuc4q0FRCDA_dN3l5owm5d27R-XlajGmyplREn9f4GfENBHm0Z7C5iU8Fx_sLoqgNtEUGeOIpzXFhy1thx1ASq34elf4bOc_8j9IjzmYIH5jOYb21Q_wBiLhMqZZgf1qbk5406iIryNpTgu39p9eP7jWF7_8tlTMLRe4QCS-5KJ6PJN_bV6v9TIHFNlfauLwQoSVj5Bpfd4Mhszspglp51qEcikT5F3fzxexSXfb53incWUF24K-amxlS-bdExmtXf_nedhLymXuyqVEASOyU-ZrLr8epZskaTKvahKNAFIfPHXZMfflPtr12P7lkOKU99Z3-4x5m7pS4pKxI6eDH0K_WIghD5hsRTZKJlUpa3hWRxov1Dxu3mQQs08iaEg6SrZtSr1VwXkHqaaqKZNweId_QhocACCwg_HyVmDrpLiqO6J1COEecszEY0Bws4KvGNMy_l5oRre6rIBHwEJ29-2gzhuYjDw7iiSJ6DP4YXDqjPZvmSVRUQ1ErVu0IdRkBYyr8Omp_7VUM_g5v0wE7kCi4b6g6rovOxwWUH7W2pTWKhevzJXKjd7IBEXBazhAfSA4KlwrILbd-7YqS86JzFriIFlzihlNuwL7IzE2ylpMPDJoHncEtSZDhye4szMKUTQhwllwEjw0MmZdi87f4qg2bQSxXdseU3vfuxtfkl_fXRpNlPGzaZ9gOwccpe8yGpFMku8c04MB51OnqfWcLd3RQvGn1QTxZzrOWu95NZDOZN4kZ9bTdbWuk--DYe684RRs51D97qSxKC-F9h4x-W_qwZabtJ_F0tm9duarKBwIMQK0hsRICCV81OndMvoiMT0JuInliPUDIm6UbU_bj4Zwn00FtyoyuTFFLi7BfelofDJTcg",
    "clientId": "S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi",
    "parts": ["regist", "snslogin", "darkmode"]
}
headers = {
    "cookie": "ckcy=1; cklg=ja; i3_ab=34f7f31a-78c5-4869-9908-093952f537a8; rieSh3Ee_ga=GA1.1.2115625759.1732515167; FPID=FPID2.2.Gf8e9eNYE%2BFJ4rkGHV76BKWWnH%2BdoRCb9vJHEYSFiEY%3D.1732515167; FPAU=1.2.1971568096.1732515166; alcb=true; check_done_login=true; subscription_members_status=non; latestlogin=email; secid=c2ff18927c360afd7f0ea9c93b8a2704; login_secure_id=c2ff18927c360afd7f0ea9c93b8a2704; connect.sid=s%3AA6NafxfwQoEhS-Ly9qzUWUb1S9dL-Wvs.UtLv8pevnbkt31I4Lt53LFzTHf6hxnbXsDp1Lqj1mvE; FPLC=OhBPtpeBs5Hmk%2FSy%2By6jCF0%2FNWBI7N0%2FuBZBsO%2B7AaCH1KwOAYwtijxSh7U9UlOyAR4UJJDaAqlqg0BxhHXlGh8Tl89jXB07fITgx7BpPBu1kO%2BLcGaTU12WtmG6Vg%3D%3D; FPGSID=1.1734090035.1734090035.G-KQYE0DE5JW.hvyzjcWQI2aQOhAcFnMRCg; rieSh3Ee_ga_KQYE0DE5JW=GS1.1.1734090037.4.0.1734090039.0.0.1991823790; _dd_s=logs=1&id=2ca2ffde-fd45-4aef-8ddf-32ebce08454a&created=1734090036817&expire=1734090952781",
    "host": "accounts.dmm.com",
    "connection": "keep-alive",
    "cache-control": "max-age=0",
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Android\"",
    "upgrade-insecure-requests": "1",
    "origin": "https://accounts.dmm.com",
    "content-type": "application/x-www-form-urlencoded",
    "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "referer": "https://accounts.dmm.com/app/service/login/password?client_id=S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi&parts=regist&parts=snslogin&parts=darkmode",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"
}

session = requests.Session()

response = session.post(url, data=payload, headers=headers)

url = "https://www.dmm.com/my/-/authorize/?parts%5B%5D=regist&parts%5B%5D=snslogin&parts%5B%5D=darkmode&response_type=code&client_id=S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi&from_domain=accounts"

querystring = {
    "parts[]": ["regist", "snslogin", "darkmode"],
    "response_type": "code",
    "client_id": "S5wqksTne9ZGYLH1YeIaWcSYSkYvDtjOEi",
    "from_domain": "accounts"
}

headers = {
    "cookie": "ckcy=1; cklg=ja; i3_ab=34f7f31a-78c5-4869-9908-093952f537a8; rieSh3Ee_ga=GA1.1.2115625759.1732515167; FPID=FPID2.2.Gf8e9eNYE%2BFJ4rkGHV76BKWWnH%2BdoRCb9vJHEYSFiEY%3D.1732515167; FPAU=1.2.1971568096.1732515166; alcb=true; check_done_login=true; FPLC=OhBPtpeBs5Hmk%2FSy%2By6jCF0%2FNWBI7N0%2FuBZBsO%2B7AaCH1KwOAYwtijxSh7U9UlOyAR4UJJDaAqlqg0BxhHXlGh8Tl89jXB07fITgx7BpPBu1kO%2BLcGaTU12WtmG6Vg%3D%3D; FPGSID=1.1734090035.1734090035.G-KQYE0DE5JW.hvyzjcWQI2aQOhAcFnMRCg; INT_SESID=Ag4DXBkVDwReRjZ7IhoIFV9XVAMTAlAAAAAMBAAbUQRQBh1SWgAMGgVSVlBLDwcFA1RWCAUFDVwOEA5AWQMNEDBgcTQ2RA5eXlVUAVIIClZVUVMCQlkNXhV7e2c8ZXJhKnASXQNcAg0fF1kBXBpmLyFGWUoLUAJeFQIFClMOAwUCGVJRVlIYA1RXUB9fCQMCSAZbXAICVVdUVA0EVBQMQVkNCkQPA1hVARY8WwIaCBVfVVADEycFVAdKRwIKUkNWUxYLFVhTDxUABjxbAhoIFV9VWBsBQQ8XDQUPERZFUkA8XVREWRUPBlJeQUsydFgwECcUVAhVBjdcVw0RWEUNC1kWURMWDmpDDQkGEF1RCVdSV1YJCFMEUQYJRglSBw0QB0FACgsFVEMNCw0QXUsJVl9GQAJCWQVcDRBcQDxXUVQKWFkHFgNqWBMKBkBEA1FcVV8fRA%3D%3D; INT_SESID_SECURE=Ag4DXBkVDwReRjZ7IhoIFV9XVAMTAlAAAAAMBAAbUQRQBh1SWgAMGgVSVlBLDwcFA1RWCAUFDVwOEA5AWQMNEDBgcTQ2RA5eXlVUAVIIClZVUVMCQlkNXhV7e2c8ZXJhKnASXQNcAg0fF1kBXBpmLyFGWUoLUAJeFQIFClMOAwUCGVJRVlIYA1RXUB9fCQMCSAZbXAICVVdUVA0EVBQMQVkNCkQPA1hVARY8WwIaCBVfVVADEycFVAdKRwIKUkNWUxYLFVhTDxUABjxbAhoIFV9VWBsBQQ8XDQUPERZFUkA8XVREWRUPBlJeQUsydFgwECcUVAhVBjdcVw0RWEUNC1kWURMWDmpDDQkGEF1RCVdSV1YJCFMEUQYJRglSBw0QB0FACgsFVEMNCw0QXUsJVl9GQAJCWQVcDRBcQDxXUVQKWFkHFgNqWBMKBkBEA1FcVV8fRA%3D%3D; secid=40b473baf2efa31f9b82dddbe32ce00e; login_secure_id=40b473baf2efa31f9b82dddbe32ce00e; login_session_id=0090847a-b744-4033-910d-b9e3aa3cf877; i3_opnd=yTLkVuCvm962Ske8; subscription_members_status=trial; ckcy_remedied_check=ktkrt_argt; rieSh3Ee_ga_KQYE0DE5JW=GS1.1.1734090037.4.1.1734090054.0.0.1991823790",
    "host": "www.dmm.com",
    "connection": "keep-alive",
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Android\"",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "same-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
    "referer": "https://accounts.dmm.com/app/service/login/password/authenticate",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7"
}

response = session.get(url, headers=headers, params=querystring, allow_redirects=False)

print(response.headers["Location"])