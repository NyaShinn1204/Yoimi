import base64
import requests

BASE_API = "https://pr-api.cdrm-project.com"
API_KEY = ""

challenge = requests.post(
    BASE_API + "/get_challenge",
    json = {
        "init_data": "vgEAAAEAAQC0ATwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADMALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAFMAPgA8AEsASQBEACAAQQBMAEcASQBEAD0AIgBBAEUAUwBDAEIAQwAiACAAVgBBAEwAVQBFAD0AIgBBAEEAQQBBAEEARAB3AHoAdgBlADUAagBOAGkAQQBnAEkAQwBBAGcASQBBAD0APQAiAD4APAAvAEsASQBEAD4APAAvAEsASQBEAFMAPgA8AC8AUABSAE8AVABFAEMAVABJAE4ARgBPAD4APAAvAEQAQQBUAEEAPgA8AC8AVwBSAE0ASABFAEEARABFAFIAPgA="
    },
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY 
    },
)

data = challenge.json()

response = requests.post(
    "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)",
    data = base64.b64decode(data['data']),
    headers = {
            'Content-Type': 'text/xml; charset=UTF-8',
    }
)

lic_resp = requests.post(
    BASE_API + "/get_keys",
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY 
    },
    json = {
        "lic_resp": base64.b64encode(response.text.encode()).decode()
    },
).json()

print(lic_resp)