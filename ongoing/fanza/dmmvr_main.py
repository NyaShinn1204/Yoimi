import hmac
import hashlib

def generate_x_api_auth_code(params, secret_key):
    data = (
        params["x-authorization"]
        + params["mylibrary_id"]
        + params["x-exploit-id"]
        + params["x-user-agent"]
        + params["quality_group"]
        + params["part"]
    )

    hmac_hash = hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()
    return hmac_hash


params = {
    "x-authorization": "Bearer Xd3fN2jwKF1nYAMb3wzYUselycL42z7Ck26SCRLBzMgFiG875J8ycDgIwGaflZFDQggbG2eSbqKovQmQUpnBSn5Dvock4BHi0v9d8m9sw9b",
    "mylibrary_id": "941873955",
    "x-exploit-id": "uid:lVzxoGplD9zA35Ac",
    "x-user-agent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
    "quality_group": "high",
    "part": "1",
}
key = "X1H8kJ9L2n7G5eF3"
auth_code = generate_x_api_auth_code(params, key)
print(auth_code)
