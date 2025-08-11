import requests

base_link = "https://api.tv.rakuten.co.jp/youbora/account.json?device_id={}"

for i in range(31):
    test = requests.get(base_link.format(i))
    print(test.json()["result"])