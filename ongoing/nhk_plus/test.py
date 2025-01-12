import base64
import json
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Base64デコードヘルパー
def base64_decode(data):
    return base64.b64decode(data)

# AES-CBCで復号する関数
def aes_cbc_decrypt(key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data

# トークン生成関数
def create_web_token():
    # 暗号化されたキーとIV
    encrypted_key = bytes.fromhex("0b18c5d87e525e7232b23347217ea4ae")
    iv = bytes.fromhex("51e49ba148691705e3231c56ea1caa8b")
    
    # 暗号化された秘密鍵データ
    encrypted_data = base64_decode(
        "9ETJznOtg8qSPi+o8LLuuYf5ZmuUcFouV8I9z39BMU50KaapvGrC3H8M8NyfYbCR..."
    )
    
    # AES-CBCで復号
    decrypted_private_key = aes_cbc_decrypt(encrypted_key, iv, encrypted_data)
    
    # 復号した秘密鍵をPEM形式に変換
    private_key_pem = f"-----BEGIN PRIVATE KEY-----\n{base64.b64encode(decrypted_private_key).decode()}\n-----END PRIVATE KEY-----"
    
    print(private_key_pem)
    
    # JWTペイロードの作成
    payload = {
        "iss": "web.nhkplus",
        "sub": "WebToken",
        "aud": "ctl.npd.plus.nhk.jp",
        "exp": int(time.time()) + 36000,
        "iat": int(time.time()) - 10
    }

    # JWT署名作成
    private_key = load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
    header = {"alg": "RS256", "typ": "JWT", "kid": "c6144a1b-999d-435a-a0e2-7fb5c61e5362"}
    
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    message = f"{encoded_header}.{encoded_payload}".encode()

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip('=')

    # 完成したJWTを返す
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

# 実行例
jwt = create_web_token()
print(jwt)
