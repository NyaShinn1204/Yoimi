from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
class license_util:
    def widevine_license(widevine_pssh, widevine_url, headers, session, config):
        # Widevine License Logic HERE
        device = Device.load(
            config["cdms"]["widevine"]
        )
        cdm = Cdm.from_device(device)
        session_id = cdm.open()    

        challenge = cdm.get_license_challenge(session_id, PSSH(widevine_pssh))
        response = session.post(widevine_url, data=bytes(challenge), headers=headers)
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