import boto3

class aws_fun:
    """
    AWS Function
    SRC: https://qiita.com/yukiaprogramming/items/3dd00722c55ead86dc97
    """
    def __init__(self):
        self.region = 'ap-northeast-1'
    def refresh_access_token(self, refresh_token, client_id):
        """Refresh the Cognito access token using the provided refresh token and client ID.
        
        Args:
            refresh_token (str): The refresh token.
            client_id (str): The client ID associated with the Cognito user pool.
            
        Returns:
            str: The new access token.
        """
        client = boto3.client("cognito-idp", region_name=self.region)
        response = client.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
            ClientId=client_id,
        )
        access_token = response["AuthenticationResult"]["AccessToken"]
        return access_token