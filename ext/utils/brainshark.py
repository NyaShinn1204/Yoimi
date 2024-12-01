import re
import requests

import subprocess

import os
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

class Brainshark_downloader:
    def __init__(self, session):
        self.session = session
    def download_video(self, url, notkey, video_key, title, slide_id, config):
        
        default_directory = "download"
        base_dir = "video"
        download_dir = os.path.join(default_directory, str(slide_id), base_dir)
        
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
            
        temp_directory = os.path.join("temp", str(slide_id))
        
        if not os.path.exists(temp_directory):
            os.makedirs(temp_directory)

        #notkey = notkey.replace("Manifest(aac_und_2_127999_2_1,format=m3u8-cmaf)", "")
        #notkey = notkey.replace("Manifest(video,format=m3u8-cmaf)", "")
        notkey = re.sub(r"Manifest\(video,format=m3u8-cmaf\)", "", notkey)
        #print(notkey)
        text = self.session.get(url)
        #print(url)
        
        with open(os.path.join(download_dir, "avc1.m3u8"), mode="wb") as f:
            f.write(text.content)
        
        #print(text)
        # 正規表現を使用して Fragments の部分を抽出
        pattern = re.compile(r'Fragments\([^\)]*\)')
        fragments = pattern.findall(text.text)
        
        # 結果を表示
        
        #for fragment in fragments[:1]:


        print(f"[+] Downloading title: {title} total: {len(fragments)}s")

        def download_image(url):
            tries = 3  # Number of retry attempts
            for attempt in range(tries):
                try:
                    response = self.session.get(notkey+url+"?"+video_key)
                    response.raise_for_status()  # Raise an exception for bad status codes
                    filename = os.path.join(download_dir, os.path.basename(url))
                    with open(filename, 'wb') as file:
                        file.write(response.content)
                    return url, True
                except requests.RequestException:
                    print(f"[-] Error downloading {url}, attempt {attempt + 1} of {tries}")
                    if attempt == tries - 1:
                        return url, False
        # マルチスレッドで画像をダウンロード
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(download_image, url) for url in fragments]
            for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading", unit="file"):
                url, success = future.result()
                if not success:
                    print(f"[-] Failed to download {url}")

        print(f"[+] Download complete title: {title}")
        
        def compile_mp4(output_file, slide_id, config):
            compile_command = [
                "ffmpeg",
                "-allowed_extensions",
                "ALL",
                "-i",
                "avc1.m3u8",
                "-c",
                "copy",
                "-bsf:a",
                "aac_adtstoasc",
                os.path.join(config["directorys"]["Temp"], str(slide_id), output_file),
            ]
            subprocess.run(compile_command, cwd=os.path.join(download_dir))
            
        compile_mp4(f"video-{slide_id}.mp4", slide_id, config)
        
    def download_audio(self, url, notkey, video_key, title, slide_id, config):
        
        default_directory = "download"
        base_dir = "audio"
        download_dir = os.path.join(default_directory, str(slide_id), base_dir)
        
        if not os.path.exists(download_dir):
            os.makedirs(download_dir)
            
        temp_directory = os.path.join("temp", str(slide_id))
        
        if not os.path.exists(temp_directory):
            os.makedirs(temp_directory)
            
        notkey = re.sub(r"Manifest\(aac_und_2_\d+_2_1,format=m3u8-cmaf\)", "", notkey)
        #notkey = notkey.replace("Manifest(video,format=m3u8-cmaf)", "")
        #print(notkey)
        text = self.session.get(url)
        print(text.content)
        
        with open(os.path.join(download_dir, "avc1.m3u8"), mode="wb") as f:
            f.write(text.content)
        
        #print(text)
        # 正規表現を使用して Fragments の部分を抽出
        pattern = re.compile(r'Fragments\([^\)]*\)')
        fragments = pattern.findall(text.text)
        
        # 結果を表示
        
        #for fragment in fragments[:1]:


        print(f"[+] Downloading title: {title} total: {len(fragments)}s")

        def download_image(url):
            tries = 3  # Number of retry attempts
            for attempt in range(tries):
                try:
                    response = self.session.get(notkey+url+"?"+video_key)
                    response.raise_for_status()  # Raise an exception for bad status codes
                    filename = os.path.join(download_dir, os.path.basename(url))
                    with open(filename, 'wb') as file:
                        file.write(response.content)
                    return url, True
                except requests.RequestException:
                    print(f"[-] Error downloading {notkey+url+"?"+video_key}, attempt {attempt + 1} of {tries}")
                    if attempt == tries - 1:
                        return url, False
        # マルチスレッドで画像をダウンロード
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(download_image, url) for url in fragments]
            for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading", unit="file"):
                url, success = future.result()
                if not success:
                    print(f"[-] Failed to download {url}")

        print(f"[+] Download complete title: {title}")
        
        def compile_mp4(output_file, slide_id, config):
            compile_command = [
                "ffmpeg",
                "-allowed_extensions",
                "ALL",
                "-i",
                "avc1.m3u8",
                "-c",
                "copy",
                "-bsf:a",
                "aac_adtstoasc",
                os.path.join(config["directorys"]["Temp"], str(slide_id), output_file),
            ]
            subprocess.run(compile_command, cwd=os.path.join(download_dir))
            
        compile_mp4(f"audio-{slide_id}.aac", slide_id, config)
        
    def compile_mp4(self, audio_file, video_file, output_file_name, slide_id, config):
        compile_command = [
            "ffmpeg",
            "-i",
            video_file,
            "-i",
            audio_file,
            "-c:v",
            "copy",
            "-c:a",
            "aac",
            "-strict",
            "experimental",
            os.path.join(config["directorys"]["Downloads"], output_file_name),
        ]
        subprocess.run(compile_command, cwd=os.path.join(config["directorys"]["Temp"], str(slide_id)))
        
    def clean_folder(self, slide_id, config):
        for file_name in os.listdir(config["directorys"]["Temp"]+"/"+str(slide_id)):
            file_path = os.path.join(config["directorys"]["Temp"], str(slide_id), file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
        os.rmdir(os.path.join(config["directorys"]["Temp"], str(slide_id)))
        for file_name in os.listdir(config["directorys"]["Downloads"]+"/"+str(slide_id)+"/audio"):
            file_path = os.path.join(config["directorys"]["Downloads"], str(slide_id), "audio", file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
        for file_name in os.listdir(config["directorys"]["Downloads"]+"/"+str(slide_id)+"/video"):
            file_path = os.path.join(config["directorys"]["Downloads"], str(slide_id), "video", file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                os.rmdir(file_path)
        os.rmdir(os.path.join(config["directorys"]["Downloads"], str(slide_id), "audio"))
        os.rmdir(os.path.join(config["directorys"]["Downloads"], str(slide_id), "video"))