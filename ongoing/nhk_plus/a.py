import jwt
from datetime import datetime, timedelta, timezone

# 必要な情報
with open("private_key.pem", "r") as f:
    public_key = f.read()

payload = {
    "iss": "app.nhkplus",
    "sub": "AppToken",
    "aud": "ctl.npd.plus.nhk.jp",
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    "iat": datetime.now(timezone.utc)
}

headers = {
    "kid": "008b6857-3801-492c-bc50-48531db4b936",
    "alg": "RS256",
}

# JWTを生成
token = jwt.encode(payload, public_key, algorithm="RS256", headers=headers)

# トークンの出力
print("Generated JWT:")
print(token)
