from pywidevine.cdm import Cdm as WVCdm
from pywidevine.device import Device as WVDecice
from pywidevine.pssh import PSSH as WVPSSH
from pyplayready.cdm import Cdm as PRCdm
from pyplayready.device import Device as PRDevice
from pyplayready.system.pssh import PSSH as PRPSSH

class license_util:
    def widevine_license(widevine_pssh, widevine_url, headers, session, config):
        # Widevine License Logic HERE
        device = WVDecice.load(
            config["cdms"]["widevine"]
        )
        cdm = WVCdm.from_device(device)
        session_id = cdm.open()    

        challenge = cdm.get_license_challenge(session_id, WVPSSH(widevine_pssh))
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
    def playready_license(playready_pssh, playready_url, headers, session, config):
        # Playready License Logic HERE
        device = PRDevice.load(
            config["cdms"]["playready"]
        )
        cdm = PRCdm.from_device(device)
        session_id = cdm.open()    

        challenge = cdm.get_license_challenge(session_id, PRPSSH(playready_pssh).wrm_headers[0])
        response = session.post(playready_url, data=challenge, headers=headers)
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