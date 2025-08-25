import os
import re
import subprocess
from tqdm import tqdm
from Crypto.Cipher import AES
from datetime import datetime
from typing import Union, List, Dict, Any

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class comamnd_util:
    def create_mp4decrypt(decrypt_keys, config, input_path, output_path):
        if os.name == "nt": # Windows
            mp4decrypt_command = [os.path.join(config["directories"]["Binaries"], "mp4decrypt.exe")]
        else: # Linux or else
            mp4decrypt_command = [os.path.join(config["directories"]["Binaries"], "mp4decrypt")]
    
        for key in decrypt_keys.get("key", []):
            if key["type"] == "CONTENT":
                mp4decrypt_command.extend([
                    "--key",
                    f'{key["kid_hex"]}:{key["key_hex"]}',
                ])
    
        mp4decrypt_command.append(input_path)
        mp4decrypt_command.append(output_path)
    
        return mp4decrypt_command
    
    
    def create_shaka_packager(decrypt_keys, config, input_path, output_path, stream_type="video"):
        if os.name == "nt": # Windows
            shaka_command = [os.path.join(config["directories"]["Binaries"], "shaka_packager_win.exe")]
        else: # Linux or else
            shaka_command = [os.path.join(config["directories"]["Binaries"], "shaka_packager_linux")]
    
        shaka_command.append(f"input={input_path},stream={stream_type},output={output_path}")
        shaka_command.append("--enable_raw_key_decryption")
    
        for key in decrypt_keys.get("key", []):
            if key["type"] == "CONTENT":
                shaka_command.extend([
                    "--keys",
                    f'key_id={key["kid_hex"]}:key={key["key_hex"]}',
                ])
    
        return shaka_command
    
    
    def check_command(config, second_status=None):
        if os.name == "nt": # Windows
            mp4decrypt_path = os.path.join(config["directories"]["Binaries"], "mp4decrypt.exe")
            shaka_path = os.path.join(config["directories"]["Binaries"], "shaka_packager_win.exe")
        else:
            mp4decrypt_path = os.path.join(config["directories"]["Binaries"], "mp4decrypt")
            shaka_path = os.path.join(config["directories"]["Binaries"], "shaka_packager_linux")
    
        mp4decrypt_ok = False
        shaka_ok = False
        
                
        if second_status == "all":
            try:
                subprocess.run([mp4decrypt_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                mp4decrypt_ok = True
            except subprocess.CalledProcessError:
                mp4decrypt_ok = True
            except Exception:
                pass
            if mp4decrypt_ok:
                status = "mp4decrypt"
            else:
                status = "none"
            return status
        elif second_status == "mp4decrypt":
            try:
                subprocess.run([shaka_path, "--version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                shaka_ok = True
            except:
                pass
            if shaka_ok:
                status = "shaka"
            else:
                status = "none"
            return status
        elif second_status == "shaka":
            try:
                subprocess.run([mp4decrypt_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                mp4decrypt_ok = True
            except subprocess.CalledProcessError:
                mp4decrypt_ok = True
            except Exception:
                pass
            if mp4decrypt_ok:
                status = "mp4decrypt"
            else:
                status = "none"
            return status
        
        
        try:
            subprocess.run([mp4decrypt_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            mp4decrypt_ok = True
        except subprocess.CalledProcessError:
            mp4decrypt_ok = True
        except Exception:
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
    
    def _decrypt_single_aes(self, license_keys, input_path, output_path, config, service_name):
        def _unpad_pkcs7(data: bytes) -> bytes:
            pad = data[-1]
            if pad < 1 or pad > 16:
                return data
            if data[-pad:] != bytes([pad]) * pad:
                raise ValueError("PKCS#7 Padding is invalid.")
            return data[:-pad]
        self.logger.debug(f"[Single] input: {input_path}, output: {output_path}", extra={"service_name": service_name})


        method = license_keys.get("method", "").upper()
        key = license_keys.get("key")
        iv  = license_keys.get("iv")

        if method not in ("AES128CBC", "AES192CBC", "AES256CBC", "AESCBC"):
            self.logger.error(f"Unsupported Encryption type: {method}", extra={"service_name": service_name})
            return
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        file_size = os.path.getsize(input_path)
        desc = (
            f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
            f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
        )
    
        block_size = 16
        buf_tail = b""
    
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout, tqdm(total=file_size, desc=desc, leave=False) as pbar:
            while True:
                chunk = fin.read(1024 * 1024)  # 1MB
                if not chunk:
                    break
    
                data = buf_tail + chunk
                cut = len(data) - (len(data) % block_size)
                if cut > 0:
                    fout.write(cipher.decrypt(data[:cut]))
                    pbar.update(cut)
                buf_tail = data[cut:]
    
            # 最後のブロックを復号してパディング除去 nice だね
            if buf_tail:
                last = cipher.decrypt(buf_tail)
            else:
                last = b""
    
            try:
                last = _unpad_pkcs7(last)
            except Exception as e:
                self.logger.warning(f"Failed unpadding: {e}", extra={"service_name": service_name})
    
            fout.write(last)
            pbar.n = pbar.total
            pbar.refresh()
    def _decrypt_single(self, license_keys, input_path, output_path, config, service_name):
        self.logger.debug(f"[Single] input: {input_path}, output: {output_path}", extra={"service_name": service_name})
        status = comamnd_util.check_command(config)
        
        if status == "shaka":
            stream_type = "video" if "video" in output_path else "audio"
            command = comamnd_util.create_shaka_packager(license_keys, config, input_path, output_path, stream_type=stream_type)
        elif status == "mp4decrypt":
            command = comamnd_util.create_mp4decrypt(license_keys, config, input_path, output_path)
        elif status == "all":
            stream_type = "video" if "video" in output_path else "audio"
            command = comamnd_util.create_shaka_packager(license_keys, config, input_path, output_path, stream_type=stream_type)
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
                elif process.returncode != 0:
                    inner_pbar.close()
                    second_status = comamnd_util.check_command(config, second_status=status)
                    if second_status == "none":
                        self.logger.error("Failed decrpyt. Exiting...", extra={"service_name": service_name})
                        exit(1)
                    else:
                        self.logger.debug("Failed decrypt. Changing command...", extra={"service_name": service_name})
                        if status == "shaka":
                            command = comamnd_util.create_mp4decrypt(license_keys, config, input_path, output_path)
                        elif status == "mp4decrypt":
                            stream_type = "video" if "video" in output_path else "audio"
                            command = comamnd_util.create_shaka_packager(license_keys, config, input_path, output_path, stream_type=stream_type)
                        elif status == "all":
                            command = comamnd_util.create_mp4decrypt(license_keys, config, input_path, output_path)
                        
                        self.logger.debug(f"[COMMAND] command: {command}", extra={"service_name": service_name})
                        with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", leave=False) as inner_pbar:
                            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, encoding="utf-8") as process:
                                for line in process.stdout:
                                    print(line)
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
                                elif process.returncode != 0:
                                    inner_pbar.close()
                                    self.logger.error("Failed decrpyt. Exiting...", extra={"service_name": service_name})
                                    exit(1)
    def _decrypt_multi(self, license_keys, input_paths, output_paths, config, service_name):
        self.logger.debug(f"[Multi] input: {input_paths}, output: {output_paths}", extra={"service_name": service_name})
        
        if len(input_paths) != len(output_paths):
            raise ValueError("Not same input path and output path")
        with tqdm(total=len(input_paths), desc=f"{COLOR_GREEN}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ") as outer_pbar:
            for i, _ in enumerate(input_paths):
                self._decrypt_single(license_keys, input_paths[i], output_paths[i], config, service_name)
                outer_pbar.update(1)
    
    
    def decrypt(self, license_keys: list, input_path: Union[os.PathLike, List[os.PathLike]], output_path: Union[os.PathLike, List[os.PathLike]], config: Dict[str, Any], service_name: str = ""):
        try:
            if license_keys["iv"] != None and license_keys["key"] != None:
                pass

            if "aes" in license_keys["method"].lower():
                self._decrypt_single_aes(license_keys, input_path, output_path, config, service_name)
        except:
            if isinstance(input_path, (str, os.PathLike)) and isinstance(output_path, (str, os.PathLike)):
                self._decrypt_single(license_keys, input_path, output_path, config, service_name)
            elif isinstance(input_path, (list, tuple)) and isinstance(output_path, (list, tuple)):
                self._decrypt_multi(license_keys, input_path, output_path, config, service_name)
            else:
                raise ValueError("Input or Output Path is invalid")