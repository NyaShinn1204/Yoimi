import re
import yaml
import time
import requests
import logging
from datetime import datetime

from ext.utils import brainshark

COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"

class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_message = super().format(record)
    
        if hasattr(record, "service_name"):
            log_message = log_message.replace(
                record.service_name, f"{COLOR_BLUE}{record.service_name}{COLOR_RESET}"
            )
        
        log_message = log_message.replace(
            record.asctime, f"{COLOR_GREEN}{record.asctime}{COLOR_RESET}"
        )
        log_message = log_message.replace(
            record.levelname, f"{COLOR_GRAY}{record.levelname}{COLOR_RESET}"
        )
        
        return log_message

def set_variable(session, LOG_LEVEL):
    global logger, config, unixtime
    
    unixtime = str(int(time.time()))
    
    logger = logging.getLogger('YoimiLogger')
    if LOG_LEVEL == "DEBUG":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    formatter = CustomFormatter(
        '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    with open('config.yml', 'r') as yml:
        config = yaml.safe_load(yml)
        
    session.headers.update({"User-Agent": config["headers"]["User-Agent"]})

def main_command(session, url, email, password, LOG_LEVEL, additional_info):
    try:
        #global media_code, playtoken
        set_variable(session, LOG_LEVEL)
        logger.info("Decrypt U-Next, Abema, Dmm-TV, Brainshark Content for Everyone", extra={"service_name": "Yoimi"})
        
        brainshark_downloader = brainshark.Brainshark_downloader(session)
        
        api_response = requests.get(url)
        
        # URL Sample: https://www.brainshark.com/brainshark/brainshark.services.player/api/v1.0/Presentation?pi=256678204&sn=1&pahsetid=529444969&sid=2176710&sky=34bb6e8f376a44cfb3dd13e292ae2d88&uid=0&ie11Fallback=0
        
        for slide in api_response.json()["slides"]["slide"][5:6]:
            slide_id = slide["id"]
            seconds = slide["seconds"]
            title = slide["title"]
            video_url = slide["attachment"]["videourl"]
            video_key = slide["attachment"]["videosectok"]
            
            video_url = video_url.replace("Manifest(format=mpd-time-csf)", "Manifest(format=m3u8-cmaf)")
            
            origin_video_url = slide["attachment"]["originalvideourl"]
            
            video_moto = requests.get(video_url+"?"+video_key).text
            
            stream_inf_pattern = re.compile(r'#EXT-X-STREAM-INF:BANDWIDTH=(\d+).*?\n(QualityLevels\(\d+\)/Manifest\(video.*?\))')
            audio_pattern = re.compile(r'#EXT-X-MEDIA:TYPE=AUDIO.*?URI="(QualityLevels\(\d+\)/Manifest.*?)"')
            
            streams = stream_inf_pattern.findall(video_moto)
            
            audio_uri = audio_pattern.search(video_moto)
            
            max_bandwidth_stream = max(streams, key=lambda x: int(x[0]))
            
            logger.debug("Max Video Bandwidth: "+max_bandwidth_stream[1], extra={"service_name": "Brainshark"})
            logger.debug("Max Video Bandwidth: "+audio_uri.group(1), extra={"service_name": "Brainshark"})
        
            real_video_m3u8 = origin_video_url+"/"+max_bandwidth_stream[1]+"?"+video_key
            real_audio_m3u8 = origin_video_url+"/"+audio_uri.group(1)+"?"+video_key
            
            #print(real_video_m3u8+"\n"+real_audio_m3u8)
            
            brainshark_downloader.download_video(real_video_m3u8, origin_video_url+"/"+max_bandwidth_stream[1], video_key, title, slide_id, config)
            brainshark_downloader.download_audio(real_audio_m3u8, origin_video_url+"/"+audio_uri.group(1), video_key, title, slide_id, config)
            
            if "mp4" not in title:
                title = title+".mp4"
            
            brainshark_downloader.compile_mp4(f"video-{slide_id}.mp4", f"audio-{slide_id}.aac", title, slide_id, config)
            
            brainshark_downloader.clean_folder(slide_id, config)
            #print("[+] ダウンロード完了")
            logger.info("Finished download", extra={"service_name": "Brainshark"})
    
    except Exception as error:
        import traceback
        import sys
        t, v, tb = sys.exc_info()
        print(traceback.format_exception(t,v,tb))
        print(traceback.format_tb(error.__traceback__))