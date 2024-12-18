# util/abema/gui.py
import re
import os
import time
import threading
import tkinter as tk
import data.setting as setting
import customtkinter as ctk
from util.root.CTkDropdownTest import *
from CTkMessagebox import CTkMessagebox
from PIL import Image

from util.abema.utils.main import *
from util.abema.utils.analyze import *
from util.abema.utils.modules.downloader import *

from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    frame.pack_forget()

def init_gui(frame_scroll, root):
    def analyze_test():
        def main():
            global dropdown_video, dropdown_audio
            global episode_content, abema_get_series_id
            global abema_all_episode_meta
            global content_default
            global meta_response
            global episode_about, episode_license
            global download_dir, thumbnail_image_list
            global get_json
            global abema_m3u8_list, video_resolution, audio_resolution, outputs
            global video_now, audio_now
            global title_name_real
            url = url_label.get()
            url_nochange = url_label.get()
            url_match = re.search(r'(\d{2,3}-\d{2,3}(?:_[\w-]+)?)', url)
            if url_match:
                matches = re.findall(r'(\d{2,3}-\d{2,3}(?:_[\w-]+)?)', url)
                if matches:
                    abema_get_series_id = max((match for match in matches if '_' in match), default=None)
                    if abema_get_series_id is None:  # サフィックス付きがなければ最初のマッチを選択
                        abema_get_series_id = max(matches, key=len)
                else:
                    exit("except error unknown error lol moment")
                print(abema_get_series_id)
                abema_get_series_id_only = re.sub(r'_s\d+', '', abema_get_series_id)
                if abema_get_series_id.__contains__("_p"):
                    print("episode download")
                    cleaned_id = re.sub(r'(_\w+)$', '', abema_get_series_id)
                    print(cleaned_id)
                    status, meta_response, error = get_title_metadata(cleaned_id)
                    if status == True:
                        abema_get_series_id_extract_episode = re.match(r"(\d+-\d+_s\d+)", abema_get_series_id).group(1)
                        found_json = next((item for item in meta_response["seasons"] if item['id'] == abema_get_series_id_extract_episode), None)
                        if found_json is not None:
                            print(found_json)
                            try:
                                title_name_real = found_json["name"]
                            except KeyError:
                                title_name_real = meta_response["title"]
                            title_label.configure(state="normal")
                            title_label.delete(0, ctk.END)
                            title_label.insert(0, title_name_real)
                            title_label.configure(state="disabled")
                            
                            download_location_label.configure(state="normal")
                            download_location_label.delete(0, ctk.END)
                            download_location_label.insert(0, f"/output/{parse_titlename(title_name_real)}/")
                            download_location_label.configure(state="disabled")
                            
                            video_menu.configure(state="disabled")
                            audio_menu.configure(state="disabled")
                            
                            download_video_button.configure(state="disabled")
                            download_audio_button.configure(state="disabled")
                            
                            first_id = found_json["id"]
                            episode_group_id = found_json["episodeGroups"][0]["id"]
                            status, get_json, error = get_episode_metadata(first_id, episode_group_id)
                            print("\n[GET EPISODE INFO]")
                            for i in get_json:
                                print(i["id"]+"\n"+i["episode"]["title"]+"\n"+i["episode"]["content"]+"\n"+str(i["info"]["duration"])+"\n")
                        
                            ## ここ
                            print("aaaaaa")
                            
                            episode_content = []
                            episode_about = []
                            
                            thumbnail_image_list = []
                            
                            download_dir = os.path.join(setting.folders["temp"], "thumbnail", abema_get_series_id, str(setting.unixtime))
                            
                            if not os.path.exists(download_dir):
                                os.makedirs(download_dir, exist_ok=True)
                            
                            def download_image(url, image_filename, episode_id):
                                tries = 3  # Number of retry attempts
                                for attempt in range(tries):
                                    try:
                                        response = requests.get(url)
                                        response.raise_for_status()
                                        url_encode = re.sub(r'[?&]version=\d+', '', url)
                                        url_encode = url_encode.replace(image_filename, episode_id+".png")
                                        filename = os.path.join(download_dir, os.path.basename(url_encode))
                                        with open(filename, 'wb') as file:
                                            file.write(response.content)
                                        return url, True
                                    except requests.RequestException:
                                        print(f"[-] Error downloading {url}, attempt {attempt + 1} of {tries}")
                                        if attempt == tries - 1:
                                            return url, False
                            
                            root.title(setting.title+f"メタデータの取得中 -> 0/{len(get_json)}")
                            
                            episode_num = 1
                            
                            print("\n\n\n"+str(get_json))
                            
                            for episode_json in get_json:
                                thumbnail_image_list.append(episode_json["thumbComponent"]["urlPrefix"]+"/"+episode_json["thumbComponent"]["filename"]+"?"+episode_json["thumbComponent"]["query"])
                                get_meta_content = f"""\
{meta_response["title"]}

{episode_json["episode"]["title"]}

ストーリー:
{meta_response["content"]}

エピソード紹介:
{episode_json["episode"]["content"]}
"""
                                episode_content.append(get_meta_content)
                                
                                root.title(setting.title+f"メタデータの取得中 -> {episode_num}/{len(get_json)}")
                                
                                episode_num = episode_num + 1
                            
                            time.sleep(1)
                            root.title(setting.title)
                            print("\n\n\n\n")    
                            
                            print(meta_response)
                            print()
                            
                            tries = 3
                            for attempt in range(tries):
                                try:
                                    response = requests.get(meta_response["thumbComponent"]["urlPrefix"]+"/"+meta_response["thumbComponent"]["filename"]+"?"+meta_response["thumbComponent"]["query"])
                                    response.raise_for_status()
                                    filename = os.path.join(download_dir, f"standard_thumbnail-{abema_get_series_id}.png")
                                    with open(filename, 'wb') as file:
                                        file.write(response.content)
                                except requests.RequestException:
                                    print(f"[-] Error downloading {meta_response["thumbComponent"]["urlPrefix"]+"/"+meta_response["thumbComponent"]["filename"]+"?"+meta_response["thumbComponent"]["query"]}, attempt {attempt + 1} of {tries}")
                                    if attempt == tries - 1:
                                        return url, False
                                
                            with ThreadPoolExecutor() as executor:
                                futures = [executor.submit(download_image, url, episode_json["thumbComponent"]["filename"], episode_json["id"]) for url, episode_json in zip(thumbnail_image_list, get_json)]
                                for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading", unit="file"):
                                    url, success = future.result()
                                    if not success:
                                        print(f"[-] Failed to download {url}")
                            
                            print("[+] Success Download all thumbnail")
                            
                            print("[~] Analyzing video, audio files, Other")
                                 
                            chapters = [
                                
                            ]
                            
                            for get_all_episode_json in get_json:
                                chapters.append((get_all_episode_json["episode"]["title"], ""))
                            
                            def format_chapter_list(chapter_list, max_width=50):
                                formatted_chapters = []
                                #formatted_chapters.append("ALL")
                                for chapter, timestamp in chapter_list:
                                    total_length = len(chapter) + len(timestamp)
                                    if total_length < max_width:
                                        spaces_needed = max_width - total_length
                                        formatted_chapters.append(f"{chapter}{' ' * spaces_needed}{timestamp}")
                                    else:
                                        formatted_chapters.append(f"{chapter} {timestamp}")
                                return formatted_chapters
                            
                            formatted_chapters = format_chapter_list(chapters, max_width=50)
                            
                            setting.abema_chapter = formatted_chapters
                            chapter_menu.configure(values=setting.abema_chapter)
                            chapter_menu.configure(state="normal")
                            chapter_menu.set(setting.abema_chapter[0])
                            
                            thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, f"standard_thumbnail-{abema_get_series_id}.png")),size=(410, 232)))
                            content_widget.configure(state="normal")
                            numbers_widget.configure(state="normal")
                            
                            season_download_button.configure(state="normal")
                        
                            content_widget.delete("1.0", "end")  # 既存の内容を削除
                            content_widget.insert(tk.END, episode_content[0])
                            
                            content_widget.configure(state="disabled")
                            
                            root.update_idletasks()
                            lines_count = get_wrapped_lines_count(content_widget)
                            
                            numbers_widget.delete("1.0", "end")
                            
                            line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
                            numbers_widget.insert("1.0", line_numbers)
                            numbers_widget.configure(state="disabled")
                            
                            root.title(setting.title+f"解像度の取得中 -> 0/{len(get_json)}")
                            
                            video_resolution, audio_resolution, m3u8_list, outputs = get_video_resoltion(url_nochange, root, str(len(get_json)))
                            #video_resolution, audio_resolution, m3u8_list, outputs = get_single_resoltion(url_nochange, root, str(len(get_json)))
                            
                            time.sleep(1)
                            
                            root.title(setting.title)
                            
                            abema_m3u8_list = m3u8_list
        
                            dropdown_video = CTkDropdownTest(
                                attach=video_menu,
                                height=200,
                                width=610,
                                values=setting.abema_video_meta[0],
                                tree_colum=["Resolution", "Video Quality"],
                                tree_bg_color="#2d2d2d",
                                tree_fg_color="white",
                                command=on_dropdown_select_video
                            )                    
                            dropdown_audio = CTkDropdownTest(
                                attach=audio_menu,
                                height=200,
                                width=610,
                                values=setting.abema_audio_meta[0],
                                tree_colum=["Audio Quality"],
                                tree_bg_color="#2d2d2d",
                                tree_fg_color="white",
                                command=on_dropdown_select_audio,
                            )
                            video_menu.set("best")
                            audio_menu.set("best")
                            
                            video_now = "best"
                            audio_now = "best"
                else:
                    status, meta_response_first, error = get_title_metadata(abema_get_series_id_only)
                    if status == True:
                        print(len(meta_response_first["seasons"]))
                    if abema_get_series_id.__contains__("_s") and not len(meta_response_first["seasons"]) == 1 and not abema_get_series_id.__contains__("_p"):
                        cleaned_id = re.sub(r'(_\w+)$', '', abema_get_series_id)
                        status, meta_response, error = get_title_metadata(cleaned_id)
                        if status == True:
                            #print(meta_response["seasons"])
                            found_json = next((item for item in meta_response["seasons"] if item['id'] == abema_get_series_id), None)
                            if found_json is not None:
                                #print("found")
                                print(found_json)
                                try:
                                    title_name_real = found_json["name"]
                                except KeyError:
                                    title_name_real = meta_response["title"]
                                title_label.configure(state="normal")
                                title_label.delete(0, ctk.END)
                                title_label.insert(0, title_name_real)
                                title_label.configure(state="disabled")
            
                                download_location_label.configure(state="normal")
                                download_location_label.delete(0, ctk.END)
                                download_location_label.insert(0, f"/output/{parse_titlename(title_name_real)}/")
                                download_location_label.configure(state="disabled")
                                
                                video_menu.configure(state="disabled")
                                audio_menu.configure(state="disabled")
                                
                                download_video_button.configure(state="disabled")
                                download_audio_button.configure(state="disabled")
                                
                                first_id = found_json["id"]
                                episode_group_id = found_json["episodeGroups"][0]["id"]
                                status, get_json, error = get_episode_metadata(first_id, episode_group_id)
                                for i in get_json:
                                    print(i["id"]+"\n"+i["episode"]["title"]+i["episode"]["content"]+"\n"+str(i["info"]["duration"])+"\n")
                            else:
                                print("except error unknwon error lol moment")
                    else:
                        if abema_get_series_id.__contains__("_s1"):
                            status, meta_response, error = get_title_metadata(abema_get_series_id.replace("_s1",""))
                            url_nochange = re.sub(r'\?.*', '', url_nochange.replace("_s1", ""))                        
                        else:
                            status, meta_response, error = get_title_metadata(abema_get_series_id)
                        if status == True:
                            print("AAAIONIOSNIDOAW: "+str(len(meta_response["seasons"])))
                            title_name_real = meta_response["title"]
                            print(meta_response)
                            title_label.configure(state="normal")
                            title_label.delete(0, ctk.END)
                            title_label.insert(0, meta_response["title"])
                            title_label.configure(state="disabled")
        
                            download_location_label.configure(state="normal")
                            download_location_label.delete(0, ctk.END)
                            download_location_label.insert(0, f"/output/{meta_response["title"]}/")
                            download_location_label.configure(state="disabled")
                            
                            video_menu.configure(state="disabled")
                            audio_menu.configure(state="disabled")
                            
                            download_video_button.configure(state="disabled")
                            download_audio_button.configure(state="disabled")
                            
                            first_id = meta_response["seasons"][0]["id"]
                            episode_group_id = meta_response["seasons"][0]["episodeGroups"][0]["id"]
                            status, get_json, error = get_episode_metadata(first_id, episode_group_id)
    
                        episode_content = []
                        episode_about = []
                        
                        thumbnail_image_list = []
                        
                        download_dir = os.path.join(setting.folders["temp"], "thumbnail", abema_get_series_id, str(setting.unixtime))
                        
                        if not os.path.exists(download_dir):
                            os.makedirs(download_dir, exist_ok=True)
                        
                        def download_image(url, image_filename, episode_id):
                            tries = 3  # Number of retry attempts
                            for attempt in range(tries):
                                try:
                                    response = requests.get(url)
                                    response.raise_for_status()
                                    url_encode = re.sub(r'[?&]version=\d+', '', url)
                                    url_encode = url_encode.replace(image_filename, episode_id+".png")
                                    filename = os.path.join(download_dir, os.path.basename(url_encode))
                                    with open(filename, 'wb') as file:
                                        file.write(response.content)
                                    return url, True
                                except requests.RequestException:
                                    print(f"[-] Error downloading {url}, attempt {attempt + 1} of {tries}")
                                    if attempt == tries - 1:
                                        return url, False
                        
                        root.title(setting.title+f"メタデータの取得中 -> 0/{len(get_json)}")
                        
                        episode_num = 1
                        
                        print("\n\n\n"+str(get_json))
                        
                        for episode_json in get_json:
                            thumbnail_image_list.append(episode_json["thumbComponent"]["urlPrefix"]+"/"+episode_json["thumbComponent"]["filename"]+"?"+episode_json["thumbComponent"]["query"])
                            
                            content_default = f"""\
{meta_response["title"]}

ストーリー:
{meta_response["content"]}
"""
                                           
                            get_meta_content = f"""\
{meta_response["title"]}

{episode_json["episode"]["title"]}

ストーリー:
{meta_response["content"]}

エピソード紹介:
{episode_json["episode"]["content"]}
"""
                            episode_content.append(get_meta_content)
                            
                            root.title(setting.title+f"メタデータの取得中 -> {episode_num}/{len(get_json)}")
                            
                            episode_num = episode_num + 1
                        
                        time.sleep(1)
                        root.title(setting.title)
                        print("\n\n\n\n")    
                        
                        print(meta_response)
                        print()
                        
                        tries = 3
                        for attempt in range(tries):
                            try:
                                response = requests.get(meta_response["thumbComponent"]["urlPrefix"]+"/"+meta_response["thumbComponent"]["filename"]+"?"+meta_response["thumbComponent"]["query"])
                                response.raise_for_status()
                                filename = os.path.join(download_dir, f"standard_thumbnail-{abema_get_series_id}.png")
                                with open(filename, 'wb') as file:
                                    file.write(response.content)
                            except requests.RequestException:
                                print(f"[-] Error downloading {meta_response["thumbComponent"]["urlPrefix"]+"/"+meta_response["thumbComponent"]["filename"]+"?"+meta_response["thumbComponent"]["query"]}, attempt {attempt + 1} of {tries}")
                                if attempt == tries - 1:
                                    return url, False
                            
                        with ThreadPoolExecutor() as executor:
                            futures = [executor.submit(download_image, url, episode_json["thumbComponent"]["filename"], episode_json["id"]) for url, episode_json in zip(thumbnail_image_list, get_json)]
                            for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading", unit="file"):
                                url, success = future.result()
                                if not success:
                                    print(f"[-] Failed to download {url}")
                        
                        print("[+] Success Download all thumbnail")
                        
                        print("[~] Analyzing video, audio files, Other")
                             
                        chapters = [
                            
                        ]
                        
                        for get_all_episode_json in get_json:
                            chapters.append((get_all_episode_json["episode"]["title"], ""))
                        
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
                        
                        formatted_chapters = format_chapter_list(chapters, max_width=50)
                        
                        setting.abema_chapter = formatted_chapters
                        chapter_menu.configure(values=setting.abema_chapter)
                        chapter_menu.configure(state="normal")
                        chapter_menu.set(setting.abema_chapter[0])
                        
                        thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, f"standard_thumbnail-{abema_get_series_id}.png")),size=(410, 232)))
                        content_widget.configure(state="normal")
                        numbers_widget.configure(state="normal")
                        
                        season_download_button.configure(state="normal")
                    
                        content_widget.delete("1.0", "end")  # 既存の内容を削除
                        content_widget.insert(tk.END, content_default)
                        
                        content_widget.configure(state="disabled")
                        
                        root.update_idletasks()
                        lines_count = get_wrapped_lines_count(content_widget)
                        
                        numbers_widget.delete("1.0", "end")
                        
                        line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
                        numbers_widget.insert("1.0", line_numbers)
                        numbers_widget.configure(state="disabled")
                        
                        root.title(setting.title+f"解像度の取得中 -> 0/{len(get_json)}")
                        
                        video_resolution, audio_resolution, m3u8_list, outputs = get_video_resoltion(url_nochange, root, str(len(get_json)))
                        
                        time.sleep(1)
                        
                        root.title(setting.title)
                        
                        abema_m3u8_list = m3u8_list
    
                        dropdown_video = CTkDropdownTest(
                            attach=video_menu,
                            height=200,
                            width=610,
                            values=setting.abema_video_meta[0],
                            tree_colum=["Resolution", "Video Quality"],
                            tree_bg_color="#2d2d2d",
                            tree_fg_color="white",
                            command=on_dropdown_select_video
                        )                    
                        dropdown_audio = CTkDropdownTest(
                            attach=audio_menu,
                            height=200,
                            width=610,
                            #values=values,
                            values=setting.abema_audio_meta[0],
                            tree_colum=["Audio Quality"],
                            tree_bg_color="#2d2d2d",
                            tree_fg_color="white",
                            command=on_dropdown_select_audio,
                        )
                        video_menu.set("best")
                        audio_menu.set("best")
                        
                        video_now = "best"
                        audio_now = "best"
            else:
                CTkMessagebox(title="失敗", message="URLからIDを取得できませんでした\nURLを確認してください", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
        threading.Thread(target=main).start()
    def get_wrapped_lines_count(text_widget):
        # Create a temporary label to measure text width
        temp_label = tk.Label(text_widget, font=text_widget.cget("font"))
        
        # テキストウィジェットの内容を取得
        content = text_widget.get("1.0", "end-1c")
        
        # テキストを行ごとに分割
        lines = content.splitlines()
        
        # ウィジェットの幅を取得
        widget_width = text_widget.winfo_width()
        
        wrapped_line_count = 0
        
        # 各行のテキストを処理
        for line in lines:
            temp_label.config(text=line)
            text_width = temp_label.winfo_reqwidth()
            
            # 折り返しがあった場合の行数を計算
            if text_width > widget_width:
                wrapped_line_count += (text_width // widget_width) + 1
            else:
                wrapped_line_count += 1
        
        print(wrapped_line_count)
        return wrapped_line_count
    
    top_frame = ctk.CTkFrame(frame_scroll, fg_color="#232323", bg_color="#232323", width=1150, height=30)
    top_frame.place(x=0,y=4)
    
    url_label = ctk.CTkEntry(top_frame, placeholder_text="URL", width=1008, font=("BIZ UDゴシック", 13, "normal"))
    url_label.place(x=12,y=0)
    
    clipboad_check_button = ctk.CTkButton(master=top_frame, image=ctk.CTkImage(Image.open("data/downloader_image/clipboard_icon.png"),size=(15, 15)), compound="left", fg_color="#0f1314", bg_color="#343434", hover_color="#343434", corner_radius=2, text="", width=25, height=25, font=("Roboto", 16, "bold"), anchor="w", command= lambda: print("a"))
    clipboad_check_button.place(x=1025,y=2)
    
    analyze_button = ctk.CTkButton(master=top_frame, image=ctk.CTkImage(Image.open("data/downloader_image/analyze_icon.png"),size=(15, 15)), compound="left", fg_color="#0f1314", bg_color="#343434", hover_color="#343434", corner_radius=2, text="Analyze", width=85, height=25, font=("Roboto", 14, "bold"), anchor="w", command= lambda: analyze_test())
    analyze_button.place(x=1050,y=2)
    
    # right window
    right_frame = ctk.CTkFrame(frame_scroll, width=712, height=738, bg_color="#232323", fg_color="#232323")
    right_frame.place(x=0,y=34)
    
    title_label = ctk.CTkEntry(right_frame, width=696, state="disabled", font=("BIZ UDゴシック", 13, "normal"))
    title_label.place(x=12,y=0)
    
    content_frame = tk.Frame(right_frame, bd=1, relief="solid", background="#3e3e3e")
    content_frame.place(x=30, y=32, width=679, height=578)
    
    content_widget = tk.Text(content_frame, wrap="word", background="#272727", foreground="#fff", font=("BIZ UDゴシック", 10))
    content_widget.pack(fill="both", expand=True)
    
    content = ""
    
    content_widget.insert("1.0", content)
    
    root.update_idletasks()
    lines_count = get_wrapped_lines_count(content_widget)
    
    line_frame = tk.Frame(right_frame, width=17, bd=1, relief="solid", background="#343434")
    line_frame.place(x=12, y=32)
    
    numbers_widget = tk.Text(line_frame, wrap="none", font=("BIZ UDゴシック", 10), width=2, height=44, background="#272727", foreground="#878787")
    numbers_widget.pack(side="left", fill="y")
    
    line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
    numbers_widget.insert("1.0", line_numbers)
    
    numbers_widget.configure(state="disabled")
    content_widget.configure(state="disabled")
    
    # right down window
    right_down_frame = ctk.CTkFrame(frame_scroll, width=712, height=120, bg_color="#232323", fg_color="#232323")
    right_down_frame.place(x=0,y=648)
    
    ctk.CTkLabel(master=right_down_frame, text_color="#fff", fg_color="#232323", text="Chapters", width=15, height=15, font=("Roboto", 13)).place(x=12,y=12)
    ctk.CTkLabel(master=right_down_frame, text_color="#fff", fg_color="#232323", text="Video", width=15, height=15, font=("Roboto", 13)).place(x=30,y=34)
    ctk.CTkLabel(master=right_down_frame, text_color="#fff", fg_color="#232323", text="Audio", width=15, height=15, font=("Roboto", 13)).place(x=30,y=56)
    
    
    
    #ctk.set_appearance_mode("dark")  # Set the appearance mode to dark to match the style
    
    # Use a monospaced font
    monospace_font = ("BIZ UDゴシック", 12)  # You can adjust the font size as needed
        
    # Dropdown function to display selected chapter and timestamp
    def chapter_selected(selected):
        global index
        if selected in setting.abema_chapter:
            index = setting.abema_chapter.index(selected)
            
            print(index)
            
            #print(setting.abema_video_meta)
            #print(setting.abema_audio_meta)      
            
            if index > 0:
                #print(setting.unext_video_meta[index-1]) # [['704x396', 'avc1.4d401e', 'video/mp4'], ['1280x720', 'avc1.4d401f', 'video/mp4'], ['1920x1080', 'avc1.4d4028', 'video/mp4']]
                #print(setting.unext_audio_meta[index-1]) # [['48000', 'mp4a.40.2', 'audio/mp4']]
                #
                print(setting.abema_video_meta[index])
                print(setting.abema_audio_meta[index])
                
                dropdown_video.configure(values=setting.abema_video_meta[index])
                dropdown_audio.configure(values=setting.abema_audio_meta[index])
                
                thumbnail.configure(text="")
                
                episode_data = get_json[index - 1]
                image_filename = episode_data["thumbComponent"]["filename"]
                episode_id = episode_data["id"]
                
                # URL の `image_filename` を `episode_id` に置換
                url_encode = re.sub(r'[?&]version=\d+', '', thumbnail_image_list[index - 1])
                url_encode = url_encode.replace(image_filename, episode_id + ".png")
                
                thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, os.path.basename(url_encode))), size=(410, 232)))
                                
                print(episode_content[index-1])
                
                content_widget.configure(state="normal")
                numbers_widget.configure(state="normal")
                season_download_button.configure(state="normal")
                
                
                content_widget.delete("1.0", "end")  # 既存の内容を削除
                content_widget.insert(tk.END, episode_content[index-1])
                
                content_widget.configure(state="disabled")
                
                root.update_idletasks()
                lines_count = get_wrapped_lines_count(content_widget)
                
                numbers_widget.delete("1.0", "end")
                
                line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
                numbers_widget.insert("1.0", line_numbers)
                numbers_widget.configure(state="disabled")
    
                video_menu.configure(state="normal")
                audio_menu.configure(state="normal")
                
                download_episode_button.configure(state="normal")
                #download_video_button.configure(state="normal")
                #download_audio_button.configure(state="normal")
            else:
                thumbnail.configure(text="")
                thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, f"standard_thumbnail-{abema_get_series_id}.png")), size=(410, 232)))
                content_widget.configure(state="normal")
                numbers_widget.configure(state="normal")
                
                content_widget.delete("1.0", "end")  # 既存の内容を削除
                content_widget.insert(tk.END, content_default)
                
                dropdown_video.configure(values=setting.abema_video_meta[0])
                dropdown_audio.configure(values=setting.abema_audio_meta[0])
                
                content_widget.configure(state="disabled")
                season_download_button.configure(state="normal")
                
                root.update_idletasks()
                lines_count = get_wrapped_lines_count(content_widget)
                
                numbers_widget.delete("1.0", "end")
                
                line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
                numbers_widget.insert("1.0", line_numbers)
                numbers_widget.configure(state="disabled")
            #print(index)
        
    def on_dropdown_select_video(result):
        global video_now
        print("Columns:", result["columns"])
        print("Selected Values:", result["values"])
        
        video_now = list(result["values"])
        
        print("Video_now: "+str(video_now))
        
        encode_result = ' '.join(result["values"])
        video_menu.set(encode_result)
    
    def on_dropdown_select_audio(result):
        global audio_now
        print("Columns:", result["columns"])
        print("Selected Values:", result["values"])
        
        audio_now = list(result["values"])
        
        print("Audio_now: "+str(audio_now))
        
        encode_result = ' '.join(result["values"])
        audio_menu.set(encode_result)
    
    video_dropdown_menu = tk.StringVar()
    video_dropdown_menu.set("")
    audio_dropdown_menu = tk.StringVar()
    audio_dropdown_menu.set("")
    
    chapter_menu = ctk.CTkOptionMenu(right_down_frame, values=setting.abema_chapter, command=chapter_selected, font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled")
    chapter_menu.place(x=67,y=10)
    
    download_episode_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", 

        command= lambda:
        download_episode(video_now, audio_now, abema_m3u8_list[index-1], index-1, outputs, title_name_real, abema_get_series_id), 
        #download_episode(
        #""),
    state="disabled")
    download_episode_button.place(x=678,y=10) 
    
    video_menu = ctk.CTkOptionMenu(right_down_frame, values=[""], font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled", variable=video_dropdown_menu)
    video_menu.place(x=67,y=32)
    
        
    download_video_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", 
        #command= lambda: 
        #download_video(
        #""),
    state="disabled")
    download_video_button.place(x=678,y=32) 
    
    audio_menu = ctk.CTkOptionMenu(right_down_frame, values=[""], font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled", variable=audio_dropdown_menu)
    audio_menu.place(x=67,y=54)
        
    download_audio_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", 
        #command= lambda: 
        #download_audio(
        #""),
    state="disabled")
    download_audio_button.place(x=678,y=54) 
    
    download_location_label = ctk.CTkEntry(right_down_frame, width=696, state="disabled", font=("BIZ UDゴシック", 11, "bold"))
    download_location_label.place(x=12,y=80)
                    
    # left frame    
    left_frame = ctk.CTkFrame(frame_scroll, width=440, height=738, fg_color="#272727")
    left_frame.place(x=712,y=34)
    
    thumbnail = ctk.CTkLabel(master=left_frame, text="Thumbnail", width=410, height=232)
    thumbnail.place(x=0,y=0)
    
    duration_var = tk.StringVar()
    duration_var.set("")  # Default text
    font_style = ctk.CTkFont(family="BIZ UDゴシック", size=12)
    thumbnail_seconds = ctk.CTkLabel(master=left_frame, textvariable=duration_var, fg_color="#4D4D4D", bg_color="#4D4D4D", text_color="#fff", anchor="e", font=font_style, height=18)
    thumbnail_seconds.place(x=0,y=213)
    
    ctk.CTkLabel(master=left_frame, width=200, text="").place(x=0,y=232)
    
    thumbnail_checkbox = ctk.CTkCheckBox(master=left_frame, text_color="#fff", fg_color="#232323", hover_color="#232323", text="Download Thumbnail", width=15, height=15, checkbox_width=15, checkbox_height=15, corner_radius=1, border_width=1, variable=setting.unext_thumbnail_dl)
    thumbnail_checkbox.place(x=0,y=240)
    
    
    
    # left down frame
    left_down_frame = ctk.CTkFrame(frame_scroll, width=420, height=125, fg_color="#272727")
    left_down_frame.place(x=712,y=595)
    
    ctk.CTkLabel(master=left_down_frame, text="Downloader:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=40)

    ctk.CTkLabel(master=left_down_frame, text="Downloaded:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=55)

    ctk.CTkLabel(master=left_down_frame, text="Total:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=70)

    ctk.CTkLabel(master=left_down_frame, text="Speed:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=85)

    ctk.CTkLabel(master=left_down_frame, text="Elapsed:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=100)
    
    ctk.CTkLabel(master=left_down_frame, text="Status:", font=("Roboto", 10, "bold"), height=10).place(x=5,y=115)

    downloader_downloader_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_downloader, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_downloader_label.place(x=70,y=40)

    downloader_downloaded_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_downloaded, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_downloaded_label.place(x=70,y=55)

    downloader_total_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_total, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_total_label.place(x=70,y=70)

    downloader_speed_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_speed, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_speed_label.place(x=70,y=85)

    downloader_elapsed_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_elapsed, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_elapsed_label.place(x=70,y=100)
    
    downloader_status_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=setting.downloader_status, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_status_label.place(x=70,y=115)
    
    left_down_button_frame = ctk.CTkFrame(frame_scroll, width=100, height=80, fg_color="#272727") #420 -> 100
    left_down_button_frame.place(x=712,y=720)
    
    season_download_button = ctk.CTkButton(master=left_down_button_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", hover_color="#3f3f3f", corner_radius=5, border_width=1, border_color="#404040", text="Download", width=85, height=28, font=("Roboto", 12, "bold"), anchor="w", 
        command= lambda:
        download_series(video_now, audio_now, abema_m3u8_list, outputs, title_name_real), 
        #command= lambda: 
        #download_audio(
        #""),
    state="disabled")
    season_download_button.place(x=0,y=8)
    
    return frame_scroll

## 次はここかな？
## Abemaって暗号化ざるすぎるからぶっちゃけねぇ....