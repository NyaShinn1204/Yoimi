# util/unext/utils/modules/widevine/get_license.py

import requests
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH

def get_license_unext(pssh, playtoken):
    import data.setting as setting
    pssh = PSSH(pssh)
    device = Device.load(
        "./data/widevine/l3/google_sdk/google_sdk_gphone64_x86_64_17.0.0_9691cff8_28926_l3.wvd"
    )
    cdm = Cdm.from_device(device)
    session_id = cdm.open()

    challenge = cdm.get_license_challenge(session_id, pssh)
    response = requests.post(f"{setting.unext_url_list()["runtimeConfig"]["WIDEVINE_PROXY_URL"]}/proxy?play_token={playtoken}", data=challenge)
    print(response.text)
    
    response.raise_for_status()

    cdm.parse_license(session_id, response.content)
    keys = [
        {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
        for key in cdm.get_keys(session_id)
    ]

    cdm.close(session_id)
    return keys


def license_vd_ad(video_pssh, audio_pssh, playtoken):
    import data.setting as setting
    device = Device.load(
        "./data/widevine/l3/google_sdk/google_sdk_gphone64_x86_64_17.0.0_9691cff8_28926_l3.wvd"
    )
    cdm = Cdm.from_device(device)
    session_id_video = cdm.open()
    session_id_audio = cdm.open()

    challenge_video = cdm.get_license_challenge(session_id_video, PSSH(video_pssh))
    challenge_audio = cdm.get_license_challenge(session_id_audio, PSSH(audio_pssh))
    response_video = setting.unext_session.post(f"{setting.unext_url_list()["runtimeConfig"]["WIDEVINE_PROXY_URL"]}/proxy?play_token={playtoken}", data=challenge_video)    
    response_video.raise_for_status()
    response_audio = setting.unext_session.post(f"{setting.unext_url_list()["runtimeConfig"]["WIDEVINE_PROXY_URL"]}/proxy?play_token={playtoken}", data=challenge_audio)    
    response_audio.raise_for_status()

    cdm.parse_license(session_id_video, response_video.content)
    cdm.parse_license(session_id_audio, response_audio.content)
    video_keys = [
        {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
        for key in cdm.get_keys(session_id_video)
    ]
    audio_keys = [
        {"type": key.type, "kid_hex": key.kid.hex, "key_hex": key.key.hex()}
        for key in cdm.get_keys(session_id_audio)
    ]

    cdm.close(session_id_video)
    cdm.close(session_id_audio)
    
    keys = {
        "video_key": video_keys,
        "audio_key": audio_keys
    }
    
    return keys