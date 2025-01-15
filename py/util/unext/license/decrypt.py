# util/unext/utils/license/decrypt.py

import os
import subprocess

def mp4decrypt(keys):
    import data.setting as setting
    mp4decrypt_command = [os.path.join(setting.folders["binaries"], "mp4decrypt.exe")]
    for key in keys:
        if key["type"] == "CONTENT":
            mp4decrypt_command.extend(
                [
                    "--show-progress",
                    "--key",
                    "{}:{}".format(key["kid_hex"], key["key_hex"]),
                ]
            )
    return mp4decrypt_command


def decrypt_content(keys, input_file, output_file):
    mp4decrypt_command = mp4decrypt(keys)
    mp4decrypt_command.extend([input_file, output_file])
    subprocess.run(mp4decrypt_command)