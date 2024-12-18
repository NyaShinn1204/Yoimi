# 解像度とaudio未選択だったら
# please select

# 選択積みなら処理を続ける
# parse_mpdを修正する

import threading
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor


from util.unext.utils.main import *
from util.unext.utils.analyze import *
from util.unext.utils.modules.widevine.get_license import *
from util.unext.utils.modules.widevine.decrypt import *

class mpd_parse:
    @staticmethod
    def extract_video_info(mpd_content, value):
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = ET.fromstring(mpd_content)
    
        for adaptation_set in root.findall('.//AdaptationSet', namespaces):
            content_type = adaptation_set.get('contentType', '')
            
            if content_type == 'video':  # Ensure we're looking at the video AdaptationSet
                for representation in adaptation_set.findall('Representation', namespaces):
                    width = representation.get('width')
                    height = representation.get('height')
                    codecs = representation.get('codecs')
                    resolution = f"{width}x{height} mp4 {codecs}"
                    
                    if resolution == value:  # Matching the resolution
                        base_url_element = representation.find('BaseURL', namespaces)
                        base_url = base_url_element.text if base_url_element is not None else None
                        
                        # Find the pssh for the current AdaptationSet
                        pssh_elements = adaptation_set.findall('ContentProtection', namespaces)
                        pssh_list = []
                        for pssh_element in pssh_elements:
                            pssh = pssh_element.find('cenc:pssh', namespaces)
                            if pssh is not None:
                                pssh_list.append(pssh.text)
                        return {"pssh": pssh_list, "base_url": base_url}
        return None

    @staticmethod
    def extract_audio_info(mpd_content, value):
        namespaces = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
        root = ET.fromstring(mpd_content)
    
        # Split the value into separate components (audio_sampling_rate, mimeType, and codecs)
        audio_sampling_rate, mime_type, codecs = value.split()
    
        # Find the audio AdaptationSet
        audio_adaptation_set = root.find(".//AdaptationSet[@contentType='audio']", namespaces)
    
        if audio_adaptation_set is not None:
            for representation in audio_adaptation_set.findall('Representation', namespaces):
                # Check if the audioSamplingRate and codecs match
                if (representation.get('audioSamplingRate') == audio_sampling_rate and 
                    representation.get('codecs') == codecs):
                    
                    base_url_element = representation.find('BaseURL', namespaces)
                    base_url = base_url_element.text if base_url_element is not None else None
                    
                    # Find the pssh for the current AdaptationSet
                    pssh_elements = audio_adaptation_set.findall('ContentProtection', namespaces)
                    pssh_list = []
                    for pssh_element in pssh_elements:
                        pssh = pssh_element.find('cenc:pssh', namespaces)
                        if pssh is not None:
                            pssh_list.append(pssh.text)
                    return {"pssh": pssh_list, "base_url": base_url}
    
        return None

video_done = threading.Event()
audio_done = threading.Event()

def download_video(episode_meta_json, value, original_response, episode_license, episode_about, except_resource):
    if value == None:
        from CTkMessagebox import CTkMessagebox
        CTkMessagebox(title="Warning", message="videoとaudioの値が設定されていません")
    else:
        threading.Thread(target=download_video_main, args=(episode_meta_json, value, original_response, episode_license, episode_about, except_resource)).start()

def download_video_main(episode_meta_json, value, original_response, episode_license, episode_about, except_resource):
    import data.setting as setting
    global video_downloaded
        
    if except_resource != None:
        meta_episodes = except_resource
    else:
        meta_episodes = get_video_episode_meta(episode_meta_json["id"])
    video_info = mpd_parse.extract_video_info(episode_about["main_content"], value)
    
    if video_info:
        decrypt_license_key_video = episode_license["video_key"]
    else:
        print("No matching video representation found.")
        return
    
    temp_title = meta_episodes["subTitle"].replace(" ", "_")
    encrypte_video_filename = f"{original_response['titleName']}_{temp_title}_video_encrypted.mp4"
    setting.downloader_status.set("Video Downloading")
    video_downloaded = aria2c(video_info['base_url'], encrypte_video_filename.replace(":", ""))
    
    setting.downloader_status.set("Video Download Complete")
    
    setting.downloader_status.set("Starting Decrypt...")
    decrypt_content(decrypt_license_key_video, video_downloaded, video_downloaded.replace("_encrypted", ""))
    
    setting.downloader_status.set("Video Decrypt Complete")
    setting.downloader_status.set("Video Download Complete")
    video_done.set()  # Set the video_done event to signal that video is done

def download_audio(episode_meta_json, value, original_response, episode_license, episode_about, except_resource):
    if value == None:
        from CTkMessagebox import CTkMessagebox
        CTkMessagebox(title="Warning", message="videoとaudioの値が設定されていません")
    else:
        threading.Thread(target=download_audio_main, args=(episode_meta_json, value, original_response, episode_license, episode_about, except_resource)).start()

def download_audio_main(episode_meta_json, value, original_response, episode_license, episode_about, except_resource):
    import data.setting as setting
    global audio_downloaded   
     
    if except_resource != None:
        meta_episodes = except_resource
    else:
        meta_episodes = get_video_episode_meta(episode_meta_json["id"])
    audio_info = mpd_parse.extract_audio_info(episode_about["main_content"], value)
    
    if audio_info:
        decrypt_license_key_audio = episode_license["audio_key"]
    else:
        print("No matching audio representation found.")
        return
    
    temp_title = meta_episodes["subTitle"].replace(" ", "_")
    encrypte_audio_filename = f"{original_response['titleName']}_{temp_title}_audio_encrypted.mp4"
    print(encrypte_audio_filename)
    setting.downloader_status.set("Audio Downloading")
    print(audio_info['base_url'])
    audio_downloaded = aria2c(audio_info['base_url'], encrypte_audio_filename.replace(":", ""))
    
    setting.downloader_status.set("Audio Download Complete")
    
    setting.downloader_status.set("Starting Decrypt...")
    decrypt_content(decrypt_license_key_audio, audio_downloaded, audio_downloaded.replace("_encrypted", ""))
    
    setting.downloader_status.set("Audio Decrypt Complete")
    setting.downloader_status.set("Audio Download Complete")
    audio_done.set()  # Set the audio_done event to signal that audio is done

def download_episode(episode_meta_json, value_video, value_audio, episode_license, episode_about, original_response):
    if value_video and value_audio == None:
        from CTkMessagebox import CTkMessagebox
        CTkMessagebox(title="Warning", message="videoとaudioの値が設定されていません")
    else:
        threading.Thread(target=download_episode_main, args=(episode_meta_json, value_video, value_audio, episode_license, episode_about, original_response)).start()

def download_episode_main(episode_meta_json, value_video, value_audio, episode_license, episode_about, original_response):
    import data.setting as setting
    except_resource = get_video_episode_meta(episode_meta_json["id"])
    
    # Start video and audio download in separate threads
    download_video(episode_meta_json, value_video, original_response, episode_license, episode_about, except_resource)    
    video_done.wait()
    download_audio(episode_meta_json, value_audio, original_response, episode_license, episode_about, except_resource)
    audio_done.wait()
    
    # Call compile_mp4 when both downloads and decryption are completed
    #compile_mp4()
    setting.downloader_status.set("Episode Marging...")
    
    compile_mp4(video_downloaded.replace("_encrypted", ""),audio_downloaded.replace("_encrypted", ""),f"{original_response['titleName']}_{except_resource["subTitle"].replace(" ", "_")}.mp4",original_response['titleName'])
    
    setting.downloader_status.set("Episode Download Complete")
    video_done.clear()
    audio_done.clear()

def series_download(episode_meta_json, value_video, value_audio, original_response, episode_license, episode_about):
    if value_video and value_audio == None:
        from CTkMessagebox import CTkMessagebox
        CTkMessagebox(title="Warning", message="videoとaudioの値が設定されていません")
    else:
        threading.Thread(target=series_download_main, args=(episode_meta_json, value_video, value_audio, original_response, episode_license, episode_about)).start()

def series_download_main(episode_meta_json, value_video, value_audio, original_response, episode_license, episode_about):
    # Skip the 0th episode
    episodes_to_download = episode_meta_json[1:]
    i = 0
    for episode in episodes_to_download:
        download_episode_main(episode, value_video, value_audio, episode_license[i], episode_about[i], original_response)
        video_done.wait()  # Wait until video download is done
        audio_done.wait()  # Wait until audio download is done
        # Optionally, reset the events if you are reusing them
        #video_done.clear()
        #audio_done.clear()
        i = i + 1
    
    print("[+] 多分ダウンロード完了")
