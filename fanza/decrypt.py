from Crypto.Cipher import AES

import base64
key =  base64.b64decode("x+8V+2xDK0dPMr987AK2Og==") # 16バイト固定

with open("sample00427zerovrv18khia1.wsdcf", "rb") as f:
    data = f.read()

# 先頭7行をスキップ
lines = data.split(b'\n', 7)
# lines[7]以降が暗号文（先頭7行を飛ばす）
ciphertext = lines[7]

# IVが暗号文先頭に埋め込まれている場合
iv = ciphertext[:16]
ciphertext = ciphertext[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# PKCS#7 パディング削除
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

with open("test_decrypted.bin", "wb") as f:
    f.write(plaintext)
