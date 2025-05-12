import requests
import decrypt_subtitle as decrypt

print(decrypt.parse_binary_content(requests.get("https://s3.happyon.jp/uploads/standard/f20da47d-b1f6-46a4-9896-a0df61c6299e.vtt?ts=1736492603").content))