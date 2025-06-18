import os
from typing import Union, List, Dict, Any

class command_create:
    def command_mp4decrypt(decrypt_keys, config):
        if os.name == 'nt': # Windows
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else: # Linux or else
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
        for key in decrypt_keys:
            if key["type"] == "CONTENT":
                mp4decrypt_command.extend(
                    [
                        "--show-progress",
                        "--key",
                        "{}:{}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return mp4decrypt_command
    def command_shaka_packager(decrypt_keys, config):
        if os.name == 'nt': # Windows
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "3.4.2_packager-win-x64.exe")]
        else: # Linux or else
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "3.4.2_packager-linux-arm64")]
        for key in decrypt_keys:
            if key["type"] == "CONTENT":
                shaka_decrypt_command.extend(
                    [
                        "--enable_raw_key_decryption",
                        "--keys",
                        "key_id={}:key={}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return shaka_decrypt_command
    
class main_decrypt:
    
    def _decrypt_single(self, license_keys, input_path, output_path, config, service_name):
        print(f"[Single] input: {input_path}, output: {output_path}")

    def _decrypt_multi(self, license_keys, input_paths, output_paths, config, service_name):
        print(f"[Multi] input: {input_paths}, output: {output_paths}")
        if len(input_paths) != len(output_paths):
            raise ValueError("Not same input path and output path")
    
    
    def decrypt(self, license_keys: list, input_path: Union[os.PathLike, List[os.PathLike]], output_path: Union[os.PathLike, List[os.PathLike]], config: Dict[str, Any], service_name: str = ""):
        if isinstance(input_path, (str, os.PathLike)) and isinstance(output_path, (str, os.PathLike)):
            self._decrypt_single(license_keys, input_path, output_path, config, service_name)
        elif isinstance(input_path, (list, tuple)) and isinstance(output_path, (list, tuple)):
            self._decrypt_multi(license_keys, input_path, output_path, config, service_name)
        else:
            raise ValueError("Input or Output Path is invalid")