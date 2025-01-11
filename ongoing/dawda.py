import base64
import jwt

class JwtHandler:
    def __init__(self):
        # Secret key (Base64 encoded)
        base64_secret_key = (
            "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"
        )
        
        # Decode the Base64 secret key
        key_bytes = base64.b64decode(base64_secret_key)
        
        # Create the HMAC key (using pyjwt)
        self.key = key_bytes
        
        # Initialize JWT Parser and Builder (pyjwt uses the same key for signing and verification)
        self.jwt_parser = jwt
        self.jwt_builder = jwt

    def parse_token(self, token):
        # Decode the JWT and verify using the key
        return self.jwt_parser.decode(token, self.key, algorithms=["HS256"])

    def build_token(self, payload):
        # Create JWT with HS256 algorithm
        return self.jwt_builder.encode(payload, self.key, algorithm="HS256")

jwt_handler = JwtHandler()

# Create a token
payload = {"user": "example"}
token = jwt_handler.build_token(payload)
print("JWT Token:", token)

# Parse the token
decoded_payload = jwt_handler.parse_token(token)
print("Decoded Payload:", decoded_payload)