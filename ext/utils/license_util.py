from rich.console import Console

from pywidevine.cdm import Cdm as WVCdm
from pywidevine.device import Device as WVDecice
from pywidevine.pssh import PSSH as WVPSSH
from pyplayready.cdm import Cdm as PRCdm
from pyplayready.device import Device as PRDevice
from pyplayready.system.pssh import PSSH as PRPSSH

class license_logic:
    def decrypt_license(transformed_data, manifest_info, headers, session, config, logger, debug=False):
        widevine_pssh = transformed_data.get("pssh_list", {}).get("widevine")
        playready_pssh = transformed_data.get("pssh_list", {}).get("playready")
    
        if widevine_pssh and (config["cdms"]["widevine"] != ""):
            if headers != {}:
                use_headers = headers["widevine"]
            widevine_result = license_logic.widevine_license(widevine_pssh, manifest_info["widevine"], use_headers, session, config, debug=debug)
            if widevine_result and all(v is not None for v in widevine_result.values()):
                return widevine_result
            else:
                logger.error("Widevine Decrypt Failed")
    
        if playready_pssh and (config["cdms"]["playready"] != ""):
            if headers != {}:
                use_headers = headers["playready"]
            playready_result = license_logic.playready_license(playready_pssh, manifest_info["playready"], use_headers, session, config, debug=debug)
            if playready_result and all(v is not None for v in playready_result.values()):
                return playready_result
            else:
                logger.error("Playready Decrypt Failed")
    
        logger.error("Decrypt Failed")
        return None
    
    def widevine_license(widevine_pssh, widevine_url, headers, session, config, debug=False):
        # Widevine License Logic HERE
        try:
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
                "type": "widevine",
                "key": keys,
            }
            
            return keys
        except:
            if debug:
                console = Console()
                console.print_exception()
            return {"key": None}
    def playready_license(playready_pssh, playready_url, headers, session, config, debug=False):
        try:
            # Playready License Logic HERE
            device = PRDevice.load(
                config["cdms"]["playready"]
            )
            cdm = PRCdm.from_device(device)
            session_id = cdm.open()    
    
            challenge = cdm.get_license_challenge(session_id, PRPSSH(playready_pssh).wrm_headers[0])
            headers["Content-Type"] = 'text/xml; charset=UTF-8'
            response = session.post(playready_url, data=challenge, headers=headers)
            response.raise_for_status()    
    
            cdm.parse_license(session_id, response.text)
            keys = []
            for key in cdm.get_keys(session_id):
                keys.append(f"{key.key_id.hex}:{key.key.hex()}")  
    
            cdm.close(session_id)
            
            keys = {
                "type": "playready",
                "key": keys,
            }
            
            return keys
        except:
            if debug:
                console = Console()
                console.print_exception()
            return {"key": None}