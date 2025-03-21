import os
import uuid
import requests

email = "yumu333@heisei.be"
password = "yumu333@heisei.beA"

session = requests.Session()

app_client_id = "7u36u43euliqbfljf035tq5jjc"
demo_app_client_id = "28pqh52lqencckhada7dran5h1"
test_app_client_id = "28r429lrhor2u0amviituuc467"
user_pool_id = "ap-northeast-1_PsTlZi7OG"
x_device_id = str(uuid.uuid4())
session.headers.update({
    "x-device-id": x_device_id,
    "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)" # Emulator UA
})

email_check = session.get("https://api-videopass-login.kddi-video.com/v1/account/openid/email-mapping?email={email}".format(email=email)).json()
if email_check["status"]["type"] != "OK":
    print("failed to check email", email_check)
    exit(1)
else:
    pass

random_username = email_check["data"]
import boto3
import boto3.session
import srp
import warrant.aws_srp as warrant
bytes_to_hex = lambda x: "".join("{:02x}".format(c) for c in x)
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
n_hex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' \
        + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' \
        + 'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' \
        + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' \
        + 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' \
        + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' \
        + '83655D23DCA3AD961C62F356208552BB9ED529077096966D' \
        + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' \
        + 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' \
        + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' \
        + '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' \
        + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' \
        + 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' \
        + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' \
        + 'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' \
        + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
g_hex = '2'

#password = 'placeholder'
awssession = boto3.session.Session()
os.environ['AWS_DEFAULT_REGION'] = 'ap-northeast-1'
client = awssession.client('cognito-idp')
aws_srp = warrant.AWSSRP(username=random_username, password=password, pool_id=user_pool_id, client_id=app_client_id, client=client)
srp_user = srp.User(random_username, password, hash_alg=srp.SHA256, ng_type=srp.NG_CUSTOM, n_hex=n_hex, g_hex=g_hex )
_, srp_a = srp_user.start_authentication()
srp_a_hex = bytes_to_hex(srp_a)

def generate_encoded_data(username, app_client_id):
    import json
    import base64
    import hmac
    import hashlib
    import time
    import textwrap
    class UserContextDataProvider:
        VERSION_VALUE = "ANDROID20171114"
    
        def __init__(self, context_data, pool_id, client_id):
            self.context_data = context_data
            self.pool_id = pool_id
            self.client_id = client_id
            self.timestamp = str(int(time.time() * 1000))  # ミリ秒単位のタイムスタンプ
    
        def get_json_payload(self, username):
            """ユーザー情報を含むペイロードJSONを作成"""
            payload = {
                "contextData": self.context_data,
                "username": username,
                "userPoolId": self.pool_id,
                "timestamp": self.timestamp
            }
            return json.dumps(payload, separators=(',', ':'))  # JSONを文字列化（空白削除）
    
        def get_json_response(self, payload, signature):
            """最終レスポンスJSONを作成"""
            response = {
                "payload": payload,
                "signature": signature,
                "version": self.VERSION_VALUE
            }
            return json.dumps(response, separators=(',', ':'))
    
        def get_encoded_context_data(self, username):
            """ペイロード作成、署名、Base64エンコード"""
            try:
                json_payload = self.get_json_payload(username)
                signature = SignatureGenerator.generate_signature(json_payload, self.client_id, self.VERSION_VALUE)
                json_response = self.get_json_response(json_payload, signature)
                return self.base64_encode(json_response)
            except Exception as e:
                print("Exception in creating JSON from context data:", e)
                return None
    
        @staticmethod
        def base64_encode(data):
            """Base64エンコード（76文字ごとに改行）"""
            encoded = base64.b64encode(data.encode()).decode()
            return '\n'.join(textwrap.wrap(encoded, 76))
    
    class SignatureGenerator:
        HMAC_SHA_256 = "HmacSHA256"
    
        @staticmethod
        def generate_signature(data, secret, version):
            """HMAC-SHA256で署名し、Base64エンコード"""
            try:
                mac = hmac.new(secret.encode(), digestmod=hashlib.sha256)
                mac.update(version.encode())  # バージョン情報を更新
                mac.update(data.encode())    # 署名対象データを更新
                signature = base64.b64encode(mac.digest()).decode()
                return signature
            except Exception as e:
                print("Exception while completing context data signature:", e)
                return ""
    context_data = {
        "ApplicationName": "TELASA",
        "ApplicationTargetSdk": "34",
        "ApplicationVersion": "4.0.131-master",
        "DeviceBrand": "Redmi",
        "DeviceFingerprint": "samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys",
        "DeviceHardware": "qcom",
        "DeviceName": "22081212C",
        "Product": "22081212C",
        "BuildType": "user",
        "DeviceOsReleaseVersion": "9",
        "DeviceSdkVersion": "28",
        "ClientTimezone": "09:00",
        "Platform": "ANDROID",
        "ThirdPartyDeviceId": "android_id",
        "DeviceId": f"{uuid.uuid4()}:{int(time.time() * 1000)}",
        "DeviceLanguage": "ja_JP",
        "ScreenHeightPixels": "900",
        "ScreenWidthPixels": "1600"
    }
        
    provider = UserContextDataProvider(context_data, user_pool_id, app_client_id)
    encoded_data = provider.get_encoded_context_data(username)
    return encoded_data

url = "https://cognito-idp.ap-northeast-1.amazonaws.com/"

#payload = {
#  "AuthFlow": "USER_SRP_AUTH",
#  "AuthParameters": {
#    "USERNAME": random_username,
#    "SRP_A": srp_a_hex
#  },
#  "ClientId": app_client_id,
#  "ClientMetadata": {
#      "UserPoolId": user_pool_id 
#  },
#  "UserContextData": {
#    "EncodedData": generate_encoded_data(random_username, app_client_id)
#  }
#}
print(srp_a_hex)
encode_data = generate_encoded_data(random_username, app_client_id)
response = client.initiate_auth(
  AuthFlow = "USER_SRP_AUTH",
  AuthParameters = {
    "USERNAME": random_username,
    "SRP_A": srp_a_hex,
  },
  ClientId = app_client_id,
  ClientMetadata =  {
      "UserPoolId": user_pool_id,
  },
  UserContextData = {
    "EncodedData": encode_data,
  },
)

import hmac
import base64
import hashlib
import binascii
import datetime as dt

challenges_info = {
   'SALT': binascii.a2b_hex(response['ChallengeParameters']['SALT']),
   'SRP_B': binascii.a2b_hex(response['ChallengeParameters']['SRP_B']),
   'SECRET_BLOCK': response['ChallengeParameters']['SECRET_BLOCK'],
   'USER_ID': response['ChallengeParameters']['USER_ID_FOR_SRP']
}

# process Cognito challenge to obtain session key
session_key = srp_user.process_challenge(challenges_info['SALT'], challenges_info['SRP_B'])
M = aws_srp.get_password_authentication_key(random_username, password, \
    warrant.hex_to_long(response['ChallengeParameters']['SRP_B']), \
    response['ChallengeParameters']['SALT'])

print(f'Result session_key={binascii.b2a_base64(session_key, newline=False).decode()}')
print(f'Result M={binascii.b2a_base64(session_key, newline=False).decode()}')

now = dt.datetime.now(dt.UTC)+dt.timedelta(seconds=3)
now_str = now.strftime('%a %b %d %H:%M:%S UTC %Y')
print(f'Timestamp for challenge: {now_str}')


secret_block_bytes = base64.standard_b64decode(challenges_info['SECRET_BLOCK'])

hmac_obj = hmac.new(M, digestmod=hashlib.sha256)
hmac_obj.update(user_pool_id.split('_')[1].encode('utf-8'))
hmac_obj.update(challenges_info['USER_ID'].encode('utf-8'))
hmac_obj.update(secret_block_bytes)
hmac_obj.update(now_str.encode('utf-8'))

challenges_response = {
   'TIMESTAMP': now_str,
   'USERNAME': challenges_info['USER_ID'],
   'PASSWORD_CLAIM_SECRET_BLOCK': challenges_info['SECRET_BLOCK'],
   'PASSWORD_CLAIM_SIGNATURE': base64.standard_b64encode(hmac_obj.digest()).decode('utf-8'),
}

# challenges_response = aws_srp.process_challenge(response['ChallengeParameters'])
print(challenges_response)
response = client.respond_to_auth_challenge(
   ClientId=app_client_id,
   ChallengeName='PASSWORD_VERIFIER',
   ChallengeResponses=challenges_response,
   UserContextData = {
       "EncodedData": encode_data,
   }
)
print(response)