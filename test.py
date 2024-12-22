import jwt
import base64
encrypt_payload = {
  "iss": "FOD",
  "uid": "qIj518guWYHExUTi2tXXcGH0b12a8dZdaIvVqeJIdM2elM1eL/9800WzgZ1YELDac1EBiui9dF5GHcV9bYQJqw==",
  "dv_type": "android",
  "dv_id": "star2qltechn_android_9"
}
WHATKEY = "jwk"

print(jwt.encode(encrypt_payload, WHATKEY, algorithm="HS256")) # HOW TO CRAETE THIS)

# eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJGT0QiLCJ1aWQiOiJxSWo1MThndVdZSEV4VVRpMnRYWGNHSDBiMTJhOGRaZGFJdlZxZUpJZE0yZWxNMWVMXC85ODAwV3pnWjFZRUxEYWMxRUJpdWk5ZEY1R0hjVjliWVFKcXc9PSIsImR2X3R5cGUiOiJhbmRyb2lkIiwiZHZfaWQiOiJzdGFyMnFsdGVjaG5fYW5kcm9pZF85In0.4J0VPKNmbGZ6GnjOY1jk_19Zb7UnINhJcik_EbtaMJw
# になれば成功です。