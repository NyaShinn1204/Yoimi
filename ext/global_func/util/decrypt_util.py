import os
import re
import subprocess
from tqdm import tqdm
from datetime import datetime
from typing import Union, List, Dict, Any

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class comamnd_util:
    def create_mp4decrypt(decrypt_keys, config):
        if os.name == "nt": # Windows
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")]
        else: # Linux or else
            mp4decrypt_command = [os.path.join(config["directorys"]["Binaries"], "mp4decrypt")]
        for key in decrypt_keys.get("key", []):
            if key["type"] == "CONTENT":
                mp4decrypt_command.extend(
                    [
                        "--show-progress",
                        "--key",
                        "{}:{}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return mp4decrypt_command
    def create_shaka_packager(decrypt_keys, config):
        if os.name == "nt": # Windows
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "shaka_packager_win.exe")]
        else: # Linux or else
            shaka_decrypt_command = [os.path.join(config["directorys"]["Binaries"], "shaka_packager_linux_arm64")]
        for key in decrypt_keys.get("key", []):
            if key["type"] == "CONTENT":
                shaka_decrypt_command.extend(
                    [
                        "--enable_raw_key_decryption",
                        "--keys",
                        "key_id={}:key={}".format(key["kid_hex"], key["key_hex"]),
                    ]
                )
        return shaka_decrypt_command
    
    def check_command(config):
        if os.name == "nt": # Windows
            mp4decrypt_path = os.path.join(config["directorys"]["Binaries"], "mp4decrypt.exe")
            shaka_path = os.path.join(config["directorys"]["Binaries"], "shaka_packager_win.exe")
        else:
            mp4decrypt_path = os.path.join(config["directorys"]["Binaries"], "mp4decrypt")
            shaka_path = os.path.join(config["directorys"]["Binaries"], "shaka_packager_linux_arm64")
    
        mp4decrypt_ok = False
        shaka_ok = False
    
        try:
            subprocess.run([mp4decrypt_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            mp4decrypt_ok = True
        except subprocess.CalledProcessError:
            mp4decrypt_ok = True
        except Exception as e:
            pass
    
        try:
            subprocess.run([shaka_path, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shaka_ok = True
        except:
            pass
    
        if mp4decrypt_ok and shaka_ok:
            status = "all"
        elif shaka_ok:
            status = "shaka"
        elif mp4decrypt_ok:
            status = "mp4decrypt"
        else:
            status = "none"
            
        return status
    
class main_decrypt:
    def __init__(self, logger):
        self.logger = logger
    
    
    def _decrypt_single(self, license_keys, input_path, output_path, config, service_name):
        self.logger.debug(f"[Single] input: {input_path}, output: {output_path}", extra={"service_name": service_name})
        status = comamnd_util.check_command(config)
        
        if status == "shaka":
            command = comamnd_util.create_shaka_packager(license_keys, config)
            if "video" in output_path:
                command.extend([f"input={input_path},stream=video,output={output_path}"])
            if "audio" in output_path:
                command.extend([f"input={input_path},stream=audio,output={output_path}"])
        elif status == "mp4decrypt":
            command = comamnd_util.create_mp4decrypt(license_keys, config)
            command.extend([input_path, output_path])
        elif status == "all":
            command = comamnd_util.create_shaka_packager(license_keys, config)
            if "video" in output_path:
                command.extend([f"input={input_path},stream=video,output={output_path}"])
            if "audio" in output_path:
                command.extend([f"input={input_path},stream=audio,output={output_path}"])
        else:
            raise Exception("Decryptor not found")
        
        self.logger.debug(f"[COMMAND] command: {command}", extra={"service_name": service_name})
        
        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:
                if status == "mp4decrypt":
                    for line in process.stdout:
                        match = re.search(r"(ｲ+)", line)
                        if match:
                            progress_count = len(match.group(1))
                            inner_pbar.n = progress_count
                            inner_pbar.refresh()
                process.wait()
                if process.returncode == 0:
                    inner_pbar.n = 100
                    inner_pbar.refresh()
    def _decrypt_multi(self, license_keys, input_paths, output_paths, config, service_name):
        self.logger.debug(f"[Multi] input: {input_paths}, output: {output_paths}", extra={"service_name": service_name})
        
        if len(input_paths) != len(output_paths):
            raise ValueError("Not same input path and output path")
        with tqdm(total=len(input_paths), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            for i, _ in enumerate(input_paths):
                self._decrypt_single(license_keys, input_paths[i], output_paths[i], config, service_name)
                outer_pbar.update(1)
    
    
    def decrypt(self, license_keys: list, input_path: Union[os.PathLike, List[os.PathLike]], output_path: Union[os.PathLike, List[os.PathLike]], config: Dict[str, Any], service_name: str = ""):
        if isinstance(input_path, (str, os.PathLike)) and isinstance(output_path, (str, os.PathLike)):
            self._decrypt_single(license_keys, input_path, output_path, config, service_name)
        elif isinstance(input_path, (list, tuple)) and isinstance(output_path, (list, tuple)):
            self._decrypt_multi(license_keys, input_path, output_path, config, service_name)
        else:
            raise ValueError("Input or Output Path is invalid")