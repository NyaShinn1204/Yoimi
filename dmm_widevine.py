import requests

def license(pssh, _WVPROXY, session):
    from pywidevine.cdm import Cdm
    from pywidevine.device import Device
    from pywidevine.pssh import PSSH
    device = Device.load(
        "./l3.wvd"
    )
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    challenge = cdm.get_license_challenge(session_id, PSSH(pssh))
    response = session.post(f"{_WVPROXY}", data=bytes(challenge))
    print(response.text)
    response.raise_for_status()

    cdm.parse_license(session_id, response.content)
    keys = [
        {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
        for key in cdm.get_keys(session_id)
    ]

    cdm.close(session_id)
    
    keys = {
        "key": keys,
    }
    
    return keys

session = requests.Session()

cookies = "i3_ab=d257bb8d-ef44-4789-ba77-a9c1ad3f8a01; ckcy=1; cklg=ja; adpf_uid=qwwRvyiXyyRPBdJT; alcb=true; check_done_login=true; subscription_members_status=non; cdp_id=0KaDLiEyUrZGxeIc; rieSh3Ee_ga=GA1.1.1054476538.1731884741; FPID=FPID2.2.okAIR%2BwwnDCN1tChU7VXrysVbOfznPqcl1aIfwxt8Qk%3D.1731884741; FPAU=1.2.1377844907.1731884735; _gcl_au=1.1.175875588.1731884742; _yjsu_yjad=1731884742.29ee9256-8abe-47dc-9d4d-009cf7da0ddf; FPLC=6Dv9zA5TCNkAjEj63nGEnIjaFpSzNZAPObnXHY17pjtV54HXrjGhHQMSJZYt9K%2BPQGjoQSemP3druqt1I%2FvdTRlKeE25My%2BuO8t9TROjfHpLVinZe7F5GmEoyeQZJA%3D%3D; _fbp=fb.1.1731884745878.76890560489377709; _tt_enable_cookie=1; _ttp=EAvFEBPiIn2TSvARQLjvQ2ZYaJf.tt.1; _a1_f=6ac224fa-2827-4099-b0a3-48ddd7880db5; ab.storage.deviceId.77621d63-b475-4831-aa6a-fdc165b89763=%7B%22g%22%3A%2213d79f03-4bb5-e7d4-5f5c-6a0e94dbc700%22%2C%22c%22%3A1731884741969%2C%22l%22%3A1731898243199%7D; ab.storage.userId.77621d63-b475-4831-aa6a-fdc165b89763=%7B%22g%22%3A%220KaDLiEyUrZGxeIc%22%2C%22c%22%3A1731884741952%2C%22l%22%3A1731898243202%7D; INT_SESID=Ag4DXBkVDwReRjZ7IhoIFV9XVAMTBgQFBAtRC1UbUQpTAB1SVAIAGgVdAVFLDVJTXVADDQEGDAdREA5AWQMNEDBgcTQ2RA5eXlVUAVcBA1RVU1YCQlkNXhV7e2c8ZXJhKnASXQNcAg0fF1kBXBpmLyFGWUoLUAJeFQYHBVBVAApaGQQAUgMYAwUAWh8EXgVSSAdUXVdTVlwABlECUxQMQVkNCkQPA1hVARY8WwIaCBVfVVADEycFVAcKAlBbDkJTBxYLFVhTDxUABjxbAhoIFV9VWBsFQQ8XDQUPERZFUkA8XVREWRUPBlJeQQItWXcqDCEbbEM5cxxSe1YRWEUNC1kWURMWDmpDDQkGEF1RCVdSV1MAAVEEUwIJRglSBw0QB0FACgsFVEMNCw0QXUsJVl9GQAJCWQVcDRBcQDxXUVQKWFkHFgNqWBMKBkBEA1FcVF8fRA%3D%3D; INT_SESID_SECURE=Ag4DXBkVDwReRjZ7IhoIFV9XVAMTBgQFBAtRC1UbUQpTAB1SVAIAGgVdAVFLDVJTXVADDQEGDAdREA5AWQMNEDBgcTQ2RA5eXlVUAVcBA1RVU1YCQlkNXhV7e2c8ZXJhKnASXQNcAg0fF1kBXBpmLyFGWUoLUAJeFQYHBVBVAApaGQQAUgMYAwUAWh8EXgVSSAdUXVdTVlwABlECUxQMQVkNCkQPA1hVARY8WwIaCBVfVVADEycFVAcKAlBbDkJTBxYLFVhTDxUABjxbAhoIFV9VWBsFQQ8XDQUPERZFUkA8XVREWRUPBlJeQQItWXcqDCEbbEM5cxxSe1YRWEUNC1kWURMWDmpDDQkGEF1RCVdSV1MAAVEEUwIJRglSBw0QB0FACgsFVEMNCw0QXUsJVl9GQAJCWQVcDRBcQDxXUVQKWFkHFgNqWBMKBkBEA1FcVF8fRA%3D%3D; secid=4e5e90a628b6473201729b776f417a3b; login_secure_id=4e5e90a628b6473201729b776f417a3b; login_session_id=4263c789-4f0e-4ad9-bf64-c6df0b874d10; i3_opnd=0KaDLiEyUrZGxeIc; ckcy_remedied_check=ktkrt_argt; FPGSID=1.1731900382.1731902107.G-KQYE0DE5JW.Tt5nOslo-LUVq79aSOXWaw; rieSh3Ee_ga_KQYE0DE5JW=GS1.1.1731895264.2.1.1731902125.0.0.120120175; ab.storage.sessionId.77621d63-b475-4831-aa6a-fdc165b89763=%7B%22g%22%3A%229ff2a2fc-99dc-47ed-0c24-2e14f11590c9%22%2C%22e%22%3A1731903926546%2C%22c%22%3A1731898243190%2C%22l%22%3A1731902126546%7D; cto_bundle=XoS1pF9qNGszQUx6cjZiWTZ1WXIyJTJGRXpDV1o3MWJnbUFtVG5Rclpwb3NRdnBadGdwR1lsSVgwSjU4VDBObnVaYzFwTFo0ZmdZOU5WTnZWZE43TzcwJTJGTGlsaU05MHhFYlA2ak5jSkxQcFlpVUNMV2NFeHdXVEdJTlI1MGpBdXowR1o4M29GN2ZYZk5WUTlBZ1RtdXdwbXZJRTBBJTNEJTNE".encode("utf-8")
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".encode("utf-8")

session.headers.update({"Cookie": cookies})
session.headers.update({"Authorization": user_agent})
session.headers.update({"Origin": "https://tv.dmm.com/"})
session.headers.update({"Referer": "https://tv.dmm.com/"})
session.headers.update({"Host": "mlic.dmm.com"})
pssh = "AAAA5nBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAMYSEKC2G/vyDT4vlp0654iDHU0isQF7InYiOiIyIiwiZmlkIjoiNTc0NWRyYW1hMDAwMTdkdDAyIiwic3ZpZCI6ImxhdW5jaHBhZCIsInBsIjoiZXlKa1pXeHBkbVZ5ZVY5MGVYQmxJam94TENKeGRXRnNhWFI1SWpveUxDSjBaV1VpT21aaGJITmxMQ0pvWkdOd1gybGtJam94ZlEiLCJjcyI6IjQ5MDZmNjk2MjVhNDc5NDQ4YjhlMTE2Y2IxNjZkOTNiIn0="
wvproxy_url = "https://mlic.dmm.com/drm/widevine/license"
print(license(pssh, wvproxy_url, session))