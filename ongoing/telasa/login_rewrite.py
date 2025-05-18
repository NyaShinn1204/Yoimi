import uuid
import requests
import boto3
import boto3.session
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from pycognito import AWSSRP

class aws_fun:
    """AWS Function
    SRC: https://qiita.com/yukiaprogramming/items/3dd00722c55ead86dc97
    """
    region = 'ap-northeast-1'
    def refresh_access_token(refresh_token, client_id):
        """Refresh the Cognito access token using the provided refresh token and client ID.
        
        Args:
            refresh_token (str): The refresh token.
            client_id (str): The client ID associated with the Cognito user pool.
            
        Returns:
            str: The new access token.
        """
        client = boto3.client("cognito-idp", region_name=region)
        response = client.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
            ClientId=client_id,
        )
        access_token = response["AuthenticationResult"]["AccessToken"]
        return access_token

email = "yumu333@heisei.be"
password = "yumu333@heisei.beA"

session = requests.Session()
x_device_id = str(uuid.uuid4())
session.headers.update({
    "x-device-id": x_device_id,
    "user-agent": "com.kddi.android.videopass/4.0.131-master (build:40000131; model:22081212C; device:star2qltechn; mcc:310; mnc:005; os:Android; tablet:1; osv:samsung/star2qltezh/star2qltechn:9/PQ3B.190801.10101846/G9650ZHU2ARC6:user/release-keys; appId:Videopass2;)" # Emulator UA
})

email_check = session.get("https://api-videopass-login.kddi-video.com/v1/account/openid/email-mapping?email={email}".format(email=email)).json()
print(email_check)
if email_check["status"]["type"] != "OK":
    print("failed to check email", email_check)
    exit(1)
else:
    pass

username = email_check["data"]
region = 'ap-northeast-1'
userpool = "ap-northeast-1_PsTlZi7OG"
clientid = "7u36u43euliqbfljf035tq5jjc"
clientsecret= False

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
    print(e)
userid = response['ChallengeParameters']['USERNAME']
challenge_response = aws_srp.process_challenge(response["ChallengeParameters"], auth_params)
response = cognito.respond_to_auth_challenge(
    ClientId=clientid,
    ChallengeName='PASSWORD_VERIFIER',
    ChallengeResponses=challenge_response
)
auth_result = response['AuthenticationResult']

access_token = auth_result['AccessToken']
id_token = auth_result['IdToken']
refresh_token =auth_result['RefreshToken']
access_token_expiry = datetime.now() + timedelta(seconds=auth_result['ExpiresIn'])
#print(access_token, id_token, refresh_token, access_token_expiry)

user_info = session.post("https://cognito-idp.ap-northeast-1.amazonaws.com/", headers={"X-Amz-Target": "AWSCognitoIdentityProviderService.GetUser", "X-Amz-User-Agent": "aws-amplify/5.0.4 auth framework/2", "Content-Type": "application/x-amz-json-1.1"}, json={"AccessToken": access_token}).json()
print(user_info)

new_token = aws_fun.refresh_access_token(refresh_token, clientid)
print("success update token. "+new_token)