import os
import re
import subprocess

from tqdm import tqdm
from datetime import datetime

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class main_mux:
    def __init__(self, logger):
        self.logger = logger
        
    def mux_content(self, video_input: os.PathLike, audio_input: os.PathLike, output_path: os.PathLike, duration: int, service_name: str = ""):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        compile_command = [
            "ffmpeg",
            "-i", video_input,
            "-i", audio_input,
            "-c:v", "copy", 
            "-c:a", "copy", 
            "-b:a", "192k", 
            "-strict", "experimental",
            "-y",
            "-progress", "pipe:1",
            "-nostats",
            output_path,
        ]
    
        try:
            with tqdm(total=100, desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ", unit="%") as pbar:
                ffmpeg_output = []
    
                with subprocess.Popen(compile_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8") as process:
                    for line in process.stdout:
                        ffmpeg_output.append(line.strip())
                        match = re.search(r"time=(\d+):(\d+):(\d+\.\d+)", line)
                        if match:
                            hours = int(match.group(1))
                            minutes = int(match.group(2))
                            seconds = float(match.group(3))
                            current_time = hours * 3600 + minutes * 60 + seconds
    
                            progress = (current_time / duration) * 100
                            pbar.n = int(progress)
                            pbar.refresh()
    
                    process.wait()
    
                if process.returncode == 0:
                    pbar.n = 100
                    pbar.refresh()
                else:
                    raise subprocess.CalledProcessError(process.returncode, compile_command, output="\n".join(ffmpeg_output))
    
        except subprocess.CalledProcessError as e:
            self.logger.error(f"ffmpeg failed with return code {e.returncode}", extra={"service_name": service_name})
            self.logger.error(f"ffmpeg output:\n{e.output}", extra={"service_name": service_name})
            raise Exception(f"Failde to muxing")