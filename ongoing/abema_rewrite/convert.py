import pythonmonkey as pm

data = {
    "keys": [
        {
            "kty": "oct",
            "k": "GF5kEzJ57JMwj4ANiVjXK96YmupfqKJEGoRxcEr5D2xc.DyE8UXxDHTRoHqSFv8MnVv5.4a9dd24b59a7b15308a1fe46e31c7fa8",
            "kid": "uIFdYNVYShGCkN8ufLd0mA"
        }
    ],
    "type": "temporary"
}
userid = "EX4EKv39PYnRJF"

k_value = data["keys"][0]["k"]
hash = k_value.split(".")[-1]
k_slice = k_value.split(".")[0]
y_slice = k_value.split(".")[1]
decrypt = pm.require("./test")

x = decrypt.get_x(k_slice)

y = decrypt.get_y(data["keys"][0]["kid"], userid, y_slice)

t = hash
e = [int(z) for z in y]
n = [int(z) for z in x]
print(decrypt.decrypt_key(data, t, e, n))