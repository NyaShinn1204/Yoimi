import os
import requests

def get_wrapped_lines_count(text_widget):
    import tkinter as tk
    
    temp_label = tk.Label(text_widget, font=text_widget.cget("font"))
    content = text_widget.get("1.0", "end-1c")
    lines = content.splitlines()
    widget_width = text_widget.winfo_width()
    wrapped_line_count = 0
    for line in lines:
        temp_label.config(text=line)
        text_width = temp_label.winfo_reqwidth()
        if text_width > widget_width:
            wrapped_line_count += (text_width // widget_width) + 1
        else:
            wrapped_line_count += 1
    return wrapped_line_count
    
def update_wrapped_lines(text_widget, numbers_widget):
    lines_count = get_wrapped_lines_count(text_widget)
    
    numbers_widget.delete("1.0", "end")
    
    line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
    numbers_widget.insert("1.0", line_numbers)
    numbers_widget.configure(state="disabled")
    
def format_chapter_list(chapter_list, max_width=50):
    formatted_chapters = []
    formatted_chapters.append("ALL")
    for chapter, timestamp in chapter_list:
        total_length = len(chapter) + len(timestamp)
        if total_length < max_width:
            spaces_needed = max_width - total_length
            formatted_chapters.append(f"{chapter}{' ' * spaces_needed}{timestamp}")
        else:
            formatted_chapters.append(f"{chapter} {timestamp}")
    return formatted_chapters


def download_image(url, download_dir):
    tries = 3
    for attempt in range(tries):
        try:
            response = requests.get("https://"+url)
            response.raise_for_status()
            filename = os.path.join(download_dir, os.path.basename(url))
            with open(filename, 'wb') as file:
                file.write(response.content)
            return url, True
        except requests.RequestException:
            print(f"[-] Error downloading {"https://"+url}, attempt {attempt + 1} of {tries}")
            if attempt == tries - 1:
                return url, False
            
def parse_mpd(content, playtoken, url_code):
    '''mpdファイルから解像度もろもろ取得'''
    from xml.etree import ElementTree as ET
    from lxml import etree    
    if isinstance(content, str):
        content = content.encode('utf-8')  # contentをbytes型に変換
    root = etree.fromstring(content)
    namespaces = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
    
    videos = []
    for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
        for representation in adaptation_set.findall('mpd:Representation', namespaces):
            resolution = f"{representation.get('width')}x{representation.get('height')}"
            codec = representation.get('codecs')
            mimetype = representation.get('mimeType')
            videos.append({
                'resolution': resolution,
                'codec': codec,
                'mimetype': mimetype
            })
    
    audios = []
    for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
        for representation in adaptation_set.findall('mpd:Representation', namespaces):
            audio_sampling_rate = representation.get('audioSamplingRate')
            codec = representation.get('codecs')
            mimetype = representation.get('mimeType')
            audios.append({
                'audioSamplingRate': audio_sampling_rate,
                'codec': codec,
                'mimetype': mimetype
            })
    
    namespace = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
    root = ET.fromstring(content)
    
    audio_pssh_list = root.findall('.//AdaptationSet[@contentType="audio"]/ContentProtection/cenc:pssh', namespace)
    video_pssh_list = root.findall('.//AdaptationSet[@contentType="video"]/ContentProtection/cenc:pssh', namespace)
    
    audio_pssh = audio_pssh_list[-1] if audio_pssh_list else None
    video_pssh = video_pssh_list[-1] if video_pssh_list else None
    result = {
        "main_content": content,
        "playtoken": playtoken,
        "video_pssh": video_pssh.text,
        "audio_pssh": audio_pssh.text,
        "url_code": url_code,
        "video": videos,
        "audio": audios[0] if audios else {}
    }
    
    return result