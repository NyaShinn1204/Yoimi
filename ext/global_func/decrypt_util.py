import os

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