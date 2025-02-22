import base64
import base58
import binascii
import pythonmonkey as pm
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def hex_to_bytes(hex_str):
    """ 16進文字列をバイト列に変換 """
    return binascii.unhexlify(hex_str)

def decrypt_key(original_json, O, y, x):
    # O は 16進数なのでデコード
    iv = hex_to_bytes(O)  # IV（16バイト）
    key = bytes(y)        # AES 鍵（16バイト）
    
    # x が memoryview の場合は bytes に変換
    if isinstance(x, memoryview):
        x = x.tobytes()
    ciphertext = bytes(x) # 暗号文

    # 長さチェック
    print("IV length:", len(iv))
    print("Key length:", len(key))
    print("Ciphertext length:", len(ciphertext))

    # 16バイト単位でなければエラー
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")

    # AES-CBC 復号
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_raw = cipher.decrypt(ciphertext)

    # 復号結果を表示
    print("Decrypted raw bytes:", decrypted_raw)

    # パディング解除を試す
    try:
        decrypted_bytes = unpad(decrypted_raw, AES.block_size)
        decrypted_text = decrypted_bytes.decode('utf-8')
    except ValueError as e:
        print("Padding error:", e)
        decrypted_text = "[Padding error: Raw data not decodable]"

    # JSON のキーを更新
    original_json["keys"][0]["k"] = decrypted_text
    original_json["keys"][0]["alg"] = "A128KW"
    
    return original_json

def get_x(input):
    decoded_bytes = base58.b58decode(input)
    decoded_list = list(decoded_bytes)
    return decoded_list

def get_y(kid, user_id, y_slice):
    kr = [
        [200, 196, 157, 49, 219, 232, 69, 76, 83, 241, 90, 229, 150, 242, 92, 15, 84, 148, 229, 112, 54, 1, 119, 2, 169, 57, 211, 105, 136, 202, 103, 168],
        [234, 169, 154, 104, 251, 227, 123, 14, 69, 153, 122, 248, 216, 214, 90, 81, 11, 135, 195, 113, 29, 23, 116, 2, 161, 38, 253, 115, 142, 200, 42, 189],
        [200, 165, 201, 110, 242, 224, 40, 65, 59, 242, 81, 195, 162, 188, 101, 3, 79, 254, 234, 10, 16, 95, 72, 35, 164, 67, 164, 71, 240, 227, 121, 199],
        [245, 130, 172, 48, 216, 131, 115, 127, 66, 236, 28, 185, 136, 252, 90, 79, 119, 243, 179, 12, 72, 39, 98, 61, 137, 71, 249, 115, 214, 177, 21, 172],
        [89, 223, 151, 248, 170, 122, 131, 80, 144, 118, 56, 163, 241, 252, 134, 140, 142, 29, 185, 213, 230, 84, 127, 54, 179, 36, 10, 155, 207, 175, 138, 50],
        [14, 100, 3, 93, 159, 22, 163, 57, 95, 210, 206, 203, 142, 255, 17, 137, 104]
    ]
    
    Er = [44, 128, 188, 10, 35, 20]
    def Dr(r):
        import numpy as np
        def J(r):
            return np.array(r, dtype=np.uint8)
        
        def mr(r, n):
            t = J(range(256))
            o = 0
            for i in range(256):
                o = (o + t[i] + r[i % len(r)]) % 256
                t[i], t[o] = t[o], t[i]
            
            i = 0
            o = 0
            s = []
            for a in range(len(n)):
                i = (i + 1) % 256
                o = (o + t[i]) % 256
                t[i], t[o] = t[o], t[i]
                s.append(n[a] ^ t[(t[i] + t[o]) % 256])
            
            return s
        
        def W(r):
            return ''.join(chr(c) for c in r)
        
        return W(mr(Er, kr[r]))
    def F(a, b, c):
        get_f = pm.require("./ext/utils/abema_util/get_f")
        return get_f.get_f_data(a,b,c)
    def Rr(r):
        return mr(Er, kr[r])
    def string_to_char_codes(s):
        return [ord(c) for c in s]
    def mr(r, n):
        # Initialize variables
        t = list(range(256))
        o = 0
        u = 0
    
        # Key scheduling
        for i in range(256):
            o = (o + t[i] + r[i % len(r)]) % 256
            t[i], t[o] = t[o], t[i]
    
        # Pseudo-random generation
        i = 0
        o = 0
        s = []
        for a in range(len(n)):
            i = (i + 1) % 256
            o = (o + t[i]) % 256
            t[i], t[o] = t[o], t[i]
            s.append(n[a] ^ t[(t[i] + t[o]) % 256])
    
        return s
    def u(func, value):
        return func(value)
    def s(func, value1, value2):
        return func(value1, value2)
    def Ir(r,n):
        return r+n
    
    ir = pm.require("./ext/utils/abema_util/get_ir")
    yr = pm.require("./ext/utils/abema_util/get_yr")
    
    t = kid
    i = user_id
    
    g = y_slice[-1]
    
    _r = 256
    a = Dr(4)
    c = F(_r, a, t+i)
    f = F(_r, c, i)
    d = F(_r, c, t)
    l = mr(u(Rr, 5), string_to_char_codes(f))
    w = mr(Rr(5), u(string_to_char_codes, d))
    v = list(base58.b58decode(y_slice[:-1]))
    v = mr(w, v)
    #return v
    
    p = {
        'RPJda': lambda r, n, e: r(n, e),
        'pNEvf': lambda r, n, e, t: r(n, e, t),
        'BQVuz': lambda r, n: r(n),
        'OZmeD': lambda r, n: r(n)
    }
    
    if g == "5":
        a = Dr(4)
        c = F(_r, a, t + i)
        f = F(_r, c, i)
        d = F(_r, c, t)
        l = mr(u(Rr, 5), string_to_char_codes(f))
        w = s(mr, Rr(5), u(string_to_char_codes, d))
        v = list(base58.b58decode(y_slice[:-1]))
        v = mr(w, v)
        return ir.return_ir(v, l)
    elif g == "4":
        t = F(_r, Dr(3), p["RPJda"](Ir, Dr(2), kid))
        i = F(_r, t, Ir(user_id, kid))
        o = p["pNEvf"](F, _r, t, Ir(Dr(2), user_id))
        u = list(base58.b58decode(y_slice))
        s = yr.return_yr(string_to_char_codes(o), u)
        return ir.return_ir(s, string_to_char_codes(i))
    else:
        t = F(_r, Dr(1), Ir(kid, p["BQVuz"](Dr, 0)))
        i = F(_r, t, p["RPJda"](Ir, kid, user_id))
        o = F(_r, t, Ir(user_id, Dr(0)))
        u = list(base58.b58decode(y_slice))
        s = ir.return_ir(u, p["BQVuz"](string_to_char_codes, i))
        return yr.return_yr(p["OZmeD"](string_to_char_codes, o), s)
# テストデータ
original_json = {"keys": [{}]}

k_slice = "5dsoHFacTLTg97PfqdnXWwvyDrBUyonXeKjhGvnAyp6u"
y_slice = "9cdXNBXpLM2ZvDXGi3qmRC5"
O_slice = "e47db351fd034ea7897e0c552b2428eb"

O = O_slice
y = get_y(kid="V7Nb7eeQT2-aLLjTyarytw", user_id="BbF3mTMoCNMDC3", y_slice="9cdXNBXpLM2ZvDXGi3qmRC5")
y = [int(x_d) for x_d in y]
x = get_x(k_slice)

print("y:",y) # [ 91, 180, 202, 254, 110, 54, 148, 201, 3, 128, 2, 240, 231, 144, 197, 95 ]になれば成功
print("x:",x) # こっちは成功

result = decrypt_key(original_json, O, y, x)
temp_d = result["keys"][0]["k"].replace('_', '/').replace('-', '+')

while len(temp_d) % 4 != 0:
    temp_d += '='

raw1 = base64.b64decode(temp_d)

result_key = ''.join(format(c, '02x') for c in raw1)

print("Decrypt Key!")
print(f"{result_key}")