import requests
from urllib.parse import urlparse, parse_qs

class fingerprint:
    def map_values(func, arr):
        return [func(item) for item in arr]
    
    def x64multiply(a, b):
        a0, a1 = a
        b0, b1 = b
        lo = (a0 * b0) & 0xFFFFFFFF
        hi = (a1 * b1) & 0xFFFFFFFF
        return lo, hi
    
    def x64rotl(val, shift):
        lo, hi = val
        shift = shift % 64
        if shift == 32:
            return hi, lo
        elif shift > 32:
            shift = shift - 32
            lo = ((lo << shift) | (hi >> (32 - shift))) & 0xFFFFFFFF
            hi = (hi << shift) & 0xFFFFFFFF
        else:
            lo = ((lo << shift) | (hi >> (32 - shift))) & 0xFFFFFFFF
            hi = (hi << shift) & 0xFFFFFFFF
        return lo, hi
    
    def x64xor(a, b):
        return (a[0] ^ b[0]) & 0xFFFFFFFF, (a[1] ^ b[1]) & 0xFFFFFFFF
    
    def x64add(a, b):
        lo = (a[0] + b[0]) & 0xFFFFFFFF
        hi = (a[1] + b[1]) & 0xFFFFFFFF
        return lo, hi
    
    def x64leftshift(a, shift):
        lo, hi = a
        lo = (lo << shift) & 0xFFFFFFFF
        hi = (hi << shift) & 0xFFFFFFFF
        return lo, hi
    
    def x64fmix(val):
        lo, hi = val
        lo = (lo ^ (lo >> 33)) * 0xff51afd7ed558ccd
        lo = (lo ^ (lo >> 33)) * 0xc4ceb9fe1a85ec53
        lo = lo ^ (lo >> 33)
        hi = (hi ^ (hi >> 33)) * 0xff51afd7ed558ccd
        hi = (hi ^ (hi >> 33)) * 0xc4ceb9fe1a85ec53
        hi = hi ^ (hi >> 33)
        return lo & 0xFFFFFFFF, hi & 0xFFFFFFFF
    
    def x64hash128(key, seed=0):
        key = key or ''
        seed = seed or 0
        remainder = len(key) % 16
        bytes = len(key) - remainder
        h1 = [0, seed]
        h2 = [0, seed]
        c1 = [0x87c37b91, 0x114253d5]
        c2 = [0x4cf5ad43, 0x2745937f]
    
        for i in range(0, bytes, 16):
            k1 = [
                (ord(key[i+4]) & 0xff) | ((ord(key[i+5]) & 0xff) << 8) | ((ord(key[i+6]) & 0xff) << 16) | ((ord(key[i+7]) & 0xff) << 24),
                (ord(key[i]) & 0xff) | ((ord(key[i+1]) & 0xff) << 8) | ((ord(key[i+2]) & 0xff) << 16) | ((ord(key[i+3]) & 0xff) << 24)
            ]
            k2 = [
                (ord(key[i+12]) & 0xff) | ((ord(key[i+13]) & 0xff) << 8) | ((ord(key[i+14]) & 0xff) << 16) | ((ord(key[i+15]) & 0xff) << 24),
                (ord(key[i+8]) & 0xff) | ((ord(key[i+9]) & 0xff) << 8) | ((ord(key[i+10]) & 0xff) << 16) | ((ord(key[i+11]) & 0xff) << 24)
            ]
            
            k1 = fingerprint.x64multiply(k1, c1)
            k1 = fingerprint.x64rotl(k1, 31)
            k1 = fingerprint.x64multiply(k1, c2)
            h1 = fingerprint.x64xor(h1, k1)
            h1 = fingerprint.x64rotl(h1, 27)
            h1 = fingerprint.x64add(h1, h2)
            h1 = fingerprint.x64add(fingerprint.x64multiply(h1, [0, 5]), [0, 0x52dce729])
    
            k2 = fingerprint.x64multiply(k2, c2)
            k2 = fingerprint.x64rotl(k2, 33)
            k2 = fingerprint.x64multiply(k2, c1)
            h2 = fingerprint.x64xor(h2, k2)
            h2 = fingerprint.x64rotl(h2, 31)
            h2 = fingerprint.x64add(h2, h1)
            h2 = fingerprint.x64add(fingerprint.x64multiply(h2, [0, 5]), [0, 0x38495ab5])
    
        k1 = [0, 0]
        k2 = [0, 0]
    
        for j in range(remainder):
            k2 = fingerprint.x64xor(k2, fingerprint.x64leftshift([0, ord(key[bytes+j])], (8 * (remainder - j - 1))))
    
        k2 = fingerprint.x64multiply(k2, c2)
        k2 = fingerprint.x64rotl(k2, 33)
        k2 = fingerprint.x64multiply(k2, c1)
        h2 = fingerprint.x64xor(h2, k2)
    
        h1 = fingerprint.x64xor(h1, [0, len(key)])
        h2 = fingerprint.x64xor(h2, [0, len(key)])
        h1 = fingerprint.x64add(h1, h2)
        h2 = fingerprint.x64add(h2, h1)
    
        h1 = fingerprint.x64fmix(h1)
        h2 = fingerprint.x64fmix(h2)
        h1 = fingerprint.x64add(h1, h2)
        h2 = fingerprint.x64add(h2, h1)
    
        return f"{h1[0]:08x}{h1[1]:08x}{h2[0]:08x}{h2[1]:08x}"
    
    def process_fingerprint(components, options=None):
        if options is None:
            options = {}
    
        new_components = []
    
        for component in components:
            if component['value'] == options.get('NOT_AVAILABLE', 'not available'):
                new_components.append({'key': component['key'], 'value': 'unknown'})
            elif component['key'] == 'plugins':
                new_components.append({
                    'key': 'plugins',
                    'value': ','.join([
                        f"{p[0]}::{p[1]}::{','.join([mt if isinstance(mt, str) else '~'.join(mt) for mt in p[2]])}"
                        for p in component['value']
                    ])
                })
            elif component['key'] in ['canvas', 'webgl'] and isinstance(component['value'], list):
                new_components.append({'key': component['key'], 'value': '~'.join(component['value'])})
            elif component['key'] in ['sessionStorage', 'localStorage', 'indexedDb', 'addBehavior', 'openDatabase']:
                if component['value']:
                    new_components.append({'key': component['key'], 'value': 1})
            else:
                if component['value']:
                    new_components.append({
                        'key': component['key'],
                        'value': ';'.join(component['value']) if isinstance(component['value'], list) else component['value']
                    })
                else:
                    new_components.append({'key': component['key'], 'value': component['value']})
    
        murmur = fingerprint.x64hash128('~~~'.join([str(component['value']) for component in new_components]), 31)
    
        return murmur, new_components
    
    
    def get_fingerprint():
        components = [
            {'key': 'plugins', 'value': [['plugin1', 'description1', ['mimeType1', 'mimeType2']], ['plugin2', 'description2', ['mimeType3']]]},
            {'key': 'canvas', 'value': ['data1', 'data2']},
            {'key': 'localStorage', 'value': True},
            {'key': 'sessionStorage', 'value': None},
        ]
        
        options = {'NOT_AVAILABLE': 'not available'}
        
        murmur, new_components = fingerprint.process_fingerprint(components, options)
        print("Fingerprint:", murmur)
        print("なんかこんぽ:", new_components)
        
        return murmur
    

session = requests.Session()
headers = {
    "host": "pid.nhk.or.jp",
    "connection": "keep-alive",
    "sec-ch-ua": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "sec-gpc": "1",
    "accept-language": "ja;q=0.7",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd"
}

response = session.get("https://pid.nhk.or.jp/account/update/info.do", headers=headers, allow_redirects=False)

print("----RESPONSE----")
print(response.headers)
print("----END RESPONSE--")

headers["host"] = "hh.pid.nhk.or.jp"
response = session.get(response.headers["Location"], headers=headers, allow_redirects=False)

print("----RESPONSE----")
print(response.headers)
print("----END RESPONSE--")

headers["host"] = "agree.pid.nhk.or.jp"
response = session.get(response.headers["Location"], headers=headers, allow_redirects=False)

print("----RESPONSE----")
print(response.headers)
print("----END RESPONSE--")

headers["host"] = "agree.pid.nhk.or.jp"
response = session.get(response.headers["Location"], headers=headers, allow_redirects=False)

print("----RESPONSE----")
print(response.headers)
print("----END RESPONSE--")

headers["host"] = "login.auth.nhkid.jp"
end_login_url = response.headers["Location"]

parsed_url = urlparse(end_login_url)
parameters = parse_qs(parsed_url.query)
response_parameter = {key: value[0] for key, value in parameters.items()}

response = session.get(end_login_url, headers=headers, allow_redirects=False)

print("----RESPONSE----")
print(response.text)
print(response.headers)
print("----END RESPONSE--")

#get_fingerprint = fingerprint.get_fingerprint()
get_fingerprint = "091ecc531b43fad280513c7b92b1eb46"

print("GEN FINGERPRINT:", get_fingerprint)

headers["Referer"] = end_login_url
payload = {
    "AUTH_TYPE":"AUTH_OP",
    "SITE_ID":"co_site",
    "MESSAGE_AUTH":response_parameter["MESSAGE_AUTH"],
    "AUTHENTICATED":response_parameter["AUTHENTICATED"],
    "snsid":"undefined",
    "Fingerprint":get_fingerprint
}
sent_auth = session.post("https://login.auth.nhkid.jp/auth/login", headers=headers, data=payload)
print("----RESPONSE----")
print(sent_auth.text)
print(sent_auth.headers)
print("----END RESPONSE--")