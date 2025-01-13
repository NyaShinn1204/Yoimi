import os
import re
import json
import subprocess
from datetime import datetime
from bs4 import BeautifulSoup

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class Anime3rb_utils:
    def parse_search_result(text):
        links = []
        soup = BeautifulSoup(text, "html.parser")
        titles = soup.find_all("h2", class_="pt-1 text-[1.06rem] text-ellipsis whitespace-nowrap overflow-hidden rtl:text-right")
        for j in range(len(titles)):
            name = titles[j].get_text().replace(" ", "-").replace(":", "-").replace("--", "-").lower() # nic ecode
            links.append(f"https://anime3rb.com/titles/{name}")
        return titles, links

class Anime3rb_downloader:
    def __init__(self, session):
        self.session = session
    def search(self, query):
        '''検索結果を返すコード'''
        try:
            metadata_response = self.session.get("https://anime3rb.com/search", params={ "q": query })
                        
            result, links = Anime3rb_utils.parse_search_result(metadata_response.text)
            
            return result, links
            
        except Exception as e:
            print(e)
            return None     
    def get_info(self, url):
        '''infoを返すコード'''
        try:
            metadata_response = self.session.get(url)
                        
            soup = BeautifulSoup(metadata_response.text, 'html.parser')
            
            result = soup.find('span', {'dir': 'ltr'})
            h2_tags = soup.find_all('h2', class_='rounded')
            
            if result:
                en_title = result.get_text()
            jp_title = None
            for tag in h2_tags:
                if re.search(r'[\u3040-\u30FF\u4E00-\u9FFF]', tag.get_text()):
                    jp_title = tag.get_text()
                    break
            
            if jp_title:
                pass
            
            target = soup.find('p', class_='font-light text-sm', string='الحلقات')
            if target:
                episode_num = target.find_next('p', class_='text-lg leading-relaxed').get_text()
            
            return [en_title,jp_title], [url, episode_num]
            
        except Exception as e:
            print(e)
            return None     
    def get_player_info(self, url):
        '''playerの情報を返すコード'''
        try:
            metadata_response = self.session.get(url)
                        
            soup = BeautifulSoup(metadata_response.text, 'html.parser')
            
            section_tag = soup.find('section', id='player-section')
            x_data_content = section_tag.get('x-data', '')
            
            match = re.search(r"videoSource:\s*'([^']+)'", x_data_content)
            if match:
                video_source = match.group(1).replace('\\/', '/') 
                return video_source
            
        except Exception as e:
            print(e)
            return None     
    def get_player_meta(self, url):
        '''メタデータを殴って返します。'''
        try:
            metadata_response = self.session.get(url)
                        
            soup = BeautifulSoup(metadata_response.text, "lxml")
            
            scripts = soup.find_all("script")
            videos_data = None
            
            for script in scripts:
                if script.string and "var videos =" in script.string:
                    js_code = script.string
                    match = re.search(r"var videos = (\[.*?\]);", js_code, re.DOTALL)
                    if match:
                        videos_data = match.group(1)
                        break
            

            if videos_data:
                videos_data = re.sub(r"(\w+):", r'"\1":', videos_data)
                videos_data = videos_data.replace("'", '"')
                videos_data = re.sub(r'"https"://', r'https://', videos_data)
                videos_data = re.sub(r",\s*]", "]", videos_data)
                
            
                videos = json.loads(videos_data)
                result = [{"label": video["label"], "src": video["src"]} for video in videos]
                return result
            
        except Exception as e:
            print(e)
            return None  
    def update_progress(self, process, service_name="Anime3rb"):
        total_size = None
        downloaded_size = 0

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if line.startswith("[#") and "ETA:" in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        downloaded_info = parts[1]
                        downloaded, total = downloaded_info.split('/')

                        # 単位を正規表現で取得
                        downloaded_match = re.search(r"([\d.]+)\s*(MiB|GiB)", downloaded)
                        total_match = re.search(r"([\d.]+)\s*(MiB|GiB)", total)

                        if downloaded_match and total_match:
                            downloaded_value = float(downloaded_match.group(1))
                            downloaded_unit = downloaded_match.group(2)
                            total_value = float(total_match.group(1))
                            total_unit = total_match.group(2)

                            # 単位をMiBに揃える
                            if downloaded_unit == "GiB":
                                downloaded_value *= 1024
                            if total_unit == "GiB":
                                total_value *= 1024

                            if total_size is None:
                                total_size = total_value

                            downloaded_size = downloaded_value

                            percentage = (downloaded_size / total_size) * 100
                            bar = f"{percentage:.0f}%|{'#' * int(percentage // 10)}{'-' * (10 - int(percentage // 10))}|"

                            # GBとMBの判定による表示
                            if total_size >= 1024:  # GBの場合
                                size_info = f" {downloaded_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
                            else:  # MBの場合
                                size_info = f" {downloaded_size:.1f}/{total_size:.1f} MiB"

                            log_message = (
                                f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                                f"{bar}{size_info}"
                            )

                            print(f"\r{log_message}", end="", flush=True)

                    except (IndexError, ValueError, AttributeError) as e:
                        print(f"Error parsing line: {line} - {e}")
                else:
                    print(f"Unexpected format in line: {line}")

        if total_size:
            if total_size >= 1024:  # GBの場合
                final_size_info = f" {total_size / 1024:.1f}/{total_size / 1024:.1f} GiB"
            else:  # MBの場合
                final_size_info = f" {total_size:.1f}/{total_size:.1f} MiB"

            print(
                f"\r{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
                f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
                f"100%|{'#' * 10}|{final_size_info}",
                flush=True
            )
    def aria2c(self, url, output_file_name, config, unixtime, title_name):
        output_temp_directory = os.path.join(config["directorys"]["Temp"], "content", unixtime)

        if not os.path.exists(output_temp_directory):
            os.makedirs(output_temp_directory, exist_ok=True)
        if os.name == 'nt':
            aria2c = os.path.join(config["directorys"]["Binaries"], "aria2c.exe")
        else:
            aria2c = "aria2c"
        
        if os.name == 'nt':
            if not os.path.isfile(aria2c) or not os.access(aria2c, os.X_OK):
                print(f"aria2c binary not found or not executable: {aria2c}")
            
        aria2c_command = [
            aria2c,
            url,
            "-d",
            os.path.join(config["directorys"]["Downloads"], title_name),
            "-j16",
            "-o", output_file_name,
            "-s16",
            "-x16",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "--allow-overwrite=false",
            "--async-dns=false",
            "--auto-file-renaming=false",
            "--console-log-level=warn",
            "--retry-wait=5",
            "--summary-interval=1",
        ]

        process = subprocess.Popen(
            aria2c_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            encoding='utf-8'
        )

        self.update_progress(process)

        process.wait()

        return os.path.join(config["directorys"]["Temp"], "content", unixtime, output_file_name)