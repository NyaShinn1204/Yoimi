import re
import uuid
import boto3
import boto3.session
from pycognito import AWSSRP
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

import ext.utils.telasa_util.aws_function as aws_function

class Telasa_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email_or_id, password):
        x_device_id = str(uuid.uuid4())
        self.session.headers.update({
            "x-device-id": x_device_id,
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)" # Emulator UA
        })
        
        email_check = self.session.get("https://api-videopass-login.kddi-video.com/v1/account/openid/email-mapping?email={email}".format(email=email_or_id)).json()
        if email_check["status"]["type"] != "OK":
            return False, "Email check failed", email_check["status"]["message"]
        else:
            pass
        
        username = email_check["data"]
        
        region = 'ap-northeast-1'
        userpool = "ap-northeast-1_PsTlZi7OG"
        clientid = "7u36u43euliqbfljf035tq5jjc"
        
        amz_session = boto3.Session()
        cognito = amz_session.client('cognito-idp', region_name=region)
        aws_srp = AWSSRP(
            username=username,
            password=password,
            pool_id=userpool,
            client_id=clientid,
            client=cognito
        )
        auth_params = aws_srp.get_auth_params()
        try:
            response = cognito.initiate_auth(
                ClientId=clientid,
                AuthFlow='USER_SRP_AUTH',
                AuthParameters=auth_params
            )
        except ClientError as e:
            return False, "Failed to auth", e
        challenge_response = aws_srp.process_challenge(response["ChallengeParameters"], auth_params)
        response = cognito.respond_to_auth_challenge(
            ClientId=clientid,
            ChallengeName='PASSWORD_VERIFIER',
            ChallengeResponses=challenge_response
        )
        auth_result = response['AuthenticationResult']
        
        access_token = auth_result['AccessToken']
        id_token = auth_result['IdToken']
        refresh_token = auth_result['RefreshToken']
        access_token_expiry = datetime.now() + timedelta(seconds=auth_result['ExpiresIn'])
        #print(access_token, id_token, refresh_token, access_token_expiry)
        
        #user_info = self.session.post("https://cognito-idp.ap-northeast-1.amazonaws.com/", headers={"X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser", "X-Amz-User-Agent": "aws-amplify/5.0.4 auth framework/2", "Content-Type": "application/x-amz-json-1.1"}, json={"AccessToken": access_token}).json()
        #print(user_info)
        
        #new_token = aws_util.refresh_access_token(refresh_token, clientid)
        
        self.session.headers.update({"Authorization": "Bearer "+access_token})
        url = "https://api-videopass.kddi-video.com/v1/users/me"
        
        headers = {
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "x-device-id": x_device_id,
            "accept-encoding": "compress, gzip",
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        
        response = self.session.get(url, headers=headers).json()

        return True, None, response["data"]
    def check_token(self, token):
        url = "https://api-videopass.kddi-video.com/v1/users/me"
        
        headers = {
            "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)",
            "x-device-id": str(uuid.uuid4()),
            "accept-encoding": "compress, gzip",
            "authorization": "Bearer "+token,
            "host": "api-videopass.kddi-video.com",
            "connection": "Keep-Alive"
        }
        
        response = self.session.get(url, headers=headers).json()
        
        if response["type"] != "OK":
            return False, None
        else:
            return True, response["data"]
    def refresh_token(self, refresh_token):
        clientid = "7u36u43euliqbfljf035tq5jjc"
        
        aws_util = aws_function.aws_fun()
        self.session.headers.update({"Authorization": "Bearer "+aws_util.refresh_access_token(refresh_token, clientid)})
        return True
    def get_id_type(self, url):
        genre_list = []
        more_info = []
        match = re.search(r'/videos/(\d+)', url)
        if match:
            video_id = match.group(1)
            payload = {"video_ids":[video_id]}
            get_video_info = self.session.post("https://api-videopass-anon.kddi-video.com/v3/batch/query", json=payload, headers={"x-device-id": str(uuid.uuid4())}).json()
            genre_tag = get_video_info["data"]["items"][0]["data"]["genres"]
            more_info.append(get_video_info["data"]["items"][0]["data"]["year_of_production"])
            more_info.append(get_video_info["data"]["items"][0]["data"]["copyright"])
            #print(genre_tag)
            for si in genre_tag:
                if si["id"] == 280:
                    genre_list.append("劇場")
                else:
                    for i in si["parent_genre"]:
                        if i["id"] == 256:
                            genre_list.append("ノーマルアニメ")
            #if 280 in genre_tag:
            #    genre_list.append("劇場")
            #elif 256 in genre_tag:
            #    genre_list.append("ノーマルアニメ")
            return True, genre_list, more_info
        return False, None, None
    def get_title_parse_single(self, url):
        match = re.search(r'/videos/(\d+)', url)
        if match:
            video_id = match.group(1)
            payload = {"video_ids":[video_id]}
            get_video_info = self.session.post("https://api-videopass-anon.kddi-video.com/v3/batch/query", json=payload, headers={"x-device-id": str(uuid.uuid4())}).json()
            return True, get_video_info["data"]["items"][0]
        return False, None