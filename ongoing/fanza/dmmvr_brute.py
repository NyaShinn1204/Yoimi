import itertools
import hmac
import hashlib

def generate_x_api_auth_code(data, secret_key):
    return hmac.new(secret_key.encode(), data.encode(), hashlib.sha256).hexdigest()

def find_matching_auth_code(target_code, params, secret_key):
    keys = list(params.keys())
    tested = 0

    for r in range(1, len(keys)+1):
        for subset in itertools.combinations(keys, r):  # 部分集合
            for perm in itertools.permutations(subset):  # 順列
                # 通常のバージョン
                joined = ''.join(params[k] for k in perm)
                code = generate_x_api_auth_code(joined, secret_key)
                tested += 1
                if code == target_code:
                    print(f"✅ 一致: {perm} → {joined}")
                    print(f"（試行数: {tested}）")
                    return code
                else:
                    print(f"Not Match （試行数: {tested}）")

                # x-authorization が含まれている場合: Bearer を除去して再試行
                if "x-authorization" in perm:
                    modified_params = params.copy()
                    modified_params["x-authorization"] = params["x-authorization"].replace("Bearer ", "")
                    joined = ''.join(modified_params[k] for k in perm)
                    code = generate_x_api_auth_code(joined, secret_key)
                    tested += 1
                    if code == target_code:
                        print(f"✅ 一致（Bearerなし）: {perm} → {joined}")
                        return code

    print(f"❌ 一致するコードは見つかりませんでした（試行数: {tested}）")
    return None

params = {
    "mylibrary_id": "941873955",
    "part": "1",
    "quality_group": "high",
    "x-authorization": "Bearer Xd3fN2jwKF1nYAMb3wzYUselycL42z7Ck26SCRLBzMgFiG875J8ycDgIwGaflZFDQggbG2eSbqKovQmQUpnBSn5Dvock4BHi0v9d8m9sw9b",
    "x-exploit-id": "uid:lVzxoGplD9zA35Ac",
    "x-user-agent": "ANDROIDSTORE_DMMVRPLAY 2.0.5 (sdk_gphone64_x86_64; Android 12; en_US; sdk_gphone64_x86_64)",
    "x-app-name": "android_vr_store"
}

secret_key = "X1H8kJ9L2n7G5eF3"
target_code = "ff88c0056151304cb1dbec900557955c9b36b6b7425df3f0d85cced27d127d6b"

result = find_matching_auth_code(target_code, params, secret_key)
if result:
    print(f"🎯 成功: {result}")
