import hashlib
import hmac
import binascii

def byte_to_string(byte_array):
    """バイト配列を16進数文字列に変換する"""
    return ''.join(['%02x' % b for b in byte_array])

def encrypt(text):
    """文字列をHMACSHA256で暗号化する"""
    key = b"X1H8kJ9L2n7G5eF3"
    msg = text.encode('utf-8')
    h = hmac.new(key, msg, hashlib.sha256)
    return byte_to_string(h.digest()).lower()

def generate_auth_code(user_agent, quality, mylibrary_id, part, access_token, exploit_id):
    """API認証コードを生成する"""
    params = [
        user_agent,
        quality,
        str(mylibrary_id),
        str(part),
        access_token,
        exploit_id
    ]
    combined_string = "".join(params)  # 区切り文字なしで結合
    return encrypt(combined_string)

# テスト
if __name__ == "__main__":
    user_agent = "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)"
    quality = "high"
    mylibrary_id = 941873955
    part = 1
    access_token = "Xd3fN2jwKF1nYAMb3wzYUselycL42z7Ck26SCRLBzMgFiG875J8ycDgIwGaflZFDQggbG2eSbqKovQmQUpnBSn5Dvock4BHi0v9d8m9sw9b"
    exploit_id = "uid:lVzxoGplD9zA35Ac"

    auth_code = generate_auth_code(user_agent, quality, mylibrary_id, part, access_token, exploit_id)
    print(f"生成された認証コード: {auth_code}")