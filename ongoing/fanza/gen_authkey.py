import hmac
import hashlib

def get_hash(json_str, hash_key):
    hmac_sha256 = hmac.new(hash_key.encode('utf-8'), json_str.encode('utf-8'), hashlib.sha256)
    return hmac_sha256.hexdigest()

# 例:
json_data = '{"exploit_id":"uid:4OOoRg8Nqkdbzm71","mylibrary_id":488544666,"product_id":"hmn00012dl6","shop_name":"videoa","device":"android","HTTP_SMARTPHONE_APP":"DMM-APP","message":"Digital_Api_Mylibrary.getDetail"}'
print(json_data)
hash_key = "hp2Y944L"
authkey = get_hash(json_data, hash_key)

print("Generated authkey:", authkey)