import time
import random
import requests

def get_uuid():
    e = int(time.time() * 1000 + time.perf_counter() * 1000)

    hash_str = ''
    for _ in range(12):
        n = int((e + random.random() * 16) % 16)
        e = e // 16
        hash_str += format(n, 'x')

    return hash_str
    # Original Code:
    # Ly = function() {
    #     let e = new Date().getTime();
    #     return window.performance && typeof window.performance.now == "function" && (e += performance.now()),
    #     "xxxxxxxxxxxx".replace(/[x]/g, function(r) {
    #         let n = (e + Math.random() * 16) % 16 | 0;
    #         return e = Math.floor(e / 16),
    #         (r == "x" ? n : n & 3 | 8).toString(16)
    #     })
    # }


## HEHE. Reequire cf_clearance
# Sample Cookie:
# cf_clearance=3SV6.IfNOkAAdawbmub2qPDGRGzj6xtFCR84pBtTEek-1744272252-1.2.1.1-D8jr_4Yse2c9dqAcsEIfbQtkVSypSf82ox.HzEQO5oQ5oCf1pePkJc3dbGBsldyg6o1B6K89h14KtrFhTIBnkfUr6TwGz2eUMx0ke0sXx94QIl6Q36yqWbiu1Czn8H1eqSi9oqBC27vPeyv1m.FLlytXXSndSJjsREpV.m6b1Z16ETtWeJoXORHlWD2b3C_1bcfs2ILulfIiXnHPvwGhlB5aCyy1A4x3flnvYLNN9zHM_Hz7Kw50QOyp_rk3iUKsc1ef6gXhKsmoBiyBg4UZr0w_YV7qzHccFefOtvrQHwlGl6pRasW_aJFbDFog0ZfNJnJXzb3.xLVn.sgL35OTaI6Hdz7yE.8ruy_vYOjZxVbU7AiPYCZJg1QP4uXYMXFP
device_id = requests.get("https://ani.gamer.com.tw/ajax/getdeviceid.php").json()["deviceid"]

sn_id = "42881"
uuid = get_uuid()

get_token = requests.get("https://ani.gamer.com.tw/ajax/token.php?adID=undefined&sn={}&device={}&hash={}".format(sn_id, device_id, uuid))
print(get_token.text)