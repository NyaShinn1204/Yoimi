import requests

url = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser"

querystring = { "key": "AIzaSyBe_15y9U6lSJm0gBxIzRMH2UH3Dr_B9Hc" }

payload = { "clientType": "CLIENT_TYPE_ANDROID" }
headers = {
    "content-type": "application/json",
    "x-android-package": "fan.gera.app",
    "accept-language": "ja-JP, en-US",
    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; A7S Build/QP1A.190711.020)",
    "host": "www.googleapis.com",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip"
}

response = requests.post(url, json=payload, headers=headers, params=querystring)

print(response.json()["idToken"])
print(response.json()["refreshToken"])
refresh_token = response.json()["refreshToken"]







### Refresh Token
# url = "https://securetoken.googleapis.com/v1/token?key=AIzaSyBe_15y9U6lSJm0gBxIzRMH2UH3Dr_B9Hc"
# payload = {
#     "grantType": "refresh_token",
#     "refreshToken": refresh_token
# }

# response = requests.post(url, json=payload, headers=headers, params=querystring)

# print(response.json()["access_token"])
# print(response.json()["id_token"])
# print(response.json()["refresh_token"])

session = requests.Session()
session.headers.update({
    "authorization": "Bearer "+response.json()["idToken"]
})

### Get Content List

channel_id = "Ug6x2HAAQbBlAyRhbkai"

url = "https://asia-northeast1-gera-prd.cloudfunctions.net/v1-listEpisodesByChannelId"

payload = {
  "data": {
    "channelId": channel_id
  }
}
headers = {
    "content-type": "application/json; charset=utf-8",
    "host": "asia-northeast1-gera-prd.cloudfunctions.net",
    "connection": "Keep-Alive",
    "accept-encoding": "gzip",
    "user-agent": "okhttp/3.12.13"
}

response = session.post(url, json=payload, headers=headers)

channel_name = response.json()["result"][0]["channel"]["name"]

print("Channel Name:", channel_name)
print("Episode list:")
for single in response.json()["result"]:
    print(" + "+single["episode"]["name"])
    print(" | audioUrl: " + single["episode"]["audioUrl"])