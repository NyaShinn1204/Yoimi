# util/unext/gui.py
import re
import tkinter as tk
import customtkinter as ctk
from PIL import Image
from util.root.CTkDropdownTest import *
#from util.unext.unext import *
#from util.unext.utils.analyze import *

from util.unext.license.get_license import *

#from util.unext.utils.modules.downloader import *
import util.unext.utils.downloader as downloader

import data.setting as setting
from util.unext.utils.__init__ import *
import util.unext.utils.gui_utils as gui_utils
import util.unext.utils.analyze as analyze_utils


from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    frame.pack_forget()

def init_gui(frame_scroll, root):
    unext_instance = setting.Unext()
    def analyze_test():
        def main():
            global dropdown_video, dropdown_audio
            global episode_content, unext_get_series_id
            global unext_all_episode_meta
            global content_default
            global meta_response
            global episode_about, episode_license
            global download_dir, thumbnail_image_list
            url = url_label.get()
            url_match = re.search(r"SID\d{7}", url)
            if url_match:
                unext_get_series_id = url_match.group()
                print(unext_get_series_id)
                status, meta_response, error = analyze_utils.get_title_metadata(unext_get_series_id)
                if status == True:
                    print(meta_response)
                    title_label.configure(state="normal")
                    title_label.delete(0, ctk.END)
                    title_label.insert(0, meta_response["titleName"])
                    title_label.configure(state="disabled")

                    download_location_label.configure(state="normal")
                    download_location_label.delete(0, ctk.END)
                    download_location_label.insert(0, f"/output/{meta_response["titleName"]}/")
                    download_location_label.configure(state="disabled")
                    
                    video_menu.configure(state="disabled")
                    audio_menu.configure(state="disabled")
                    
                    download_video_button.configure(state="disabled")
                    download_audio_button.configure(state="disabled")
                        
                    status, meta_episode_response, error = analyze_utils.get_episode_metadata(unext_get_series_id)
                    
                    episode_content = []
                    episode_about = []
                    episode_license = []
                    
                    thumbnail_image_list = []
                    
                    download_dir = os.path.join(unext_instance.folders["temp"], "thumbnail", unext_get_series_id, str(unext_instance.unixtime))
                    
                    if not os.path.exists(download_dir):
                        os.makedirs(download_dir, exist_ok=True)
                    
                    root.title(unext_instance.title+f"メタデータとライセンスの取得中 -> 0/{len(meta_episode_response["episodes"])}")
                    
                    episode_num = 1
                    
                    #print(unext_instance.session.headers)
                    
                    for episode_json in meta_episode_response["episodes"]:
                        thumbnail_image_list.append(episode_json["thumbnail"]["standard"])
                        
                        playtoken, url_code = analyze_utils.get_playlist_url(episode_json["id"])
                        print(playtoken, url_code)
                        
                        mpd_content = analyze_utils.get_mpd_content(url_code, playtoken)
                        parse_json = gui_utils.parse_mpd(mpd_content, playtoken, url_code)
                        episode_about.append(parse_json)
                        
                        get_license_temp = license_vd_ad(parse_json["video_pssh"], parse_json["audio_pssh"], parse_json["playtoken"])
                        episode_license.append(get_license_temp)
                        
                        print(get_license_temp)
                        
                        config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
                        if config_downloader_end["login_method"] == "email":
                            response = unext_instance.session.get(f"https://beacon.unext.jp/beacon/interruption/{url_code}/1/?play_token={playtoken}")
                            response = unext_instance.session.get(f"https://beacon.unext.jp/beacon/stop/{url_code}/1/?play_token={playtoken}&last_viewing_flg=0")
                        else:
                            response = unext_instance.session.get(f"https://beacon.unext.jp/beacon/stinterruptionop/{url_code}/1/?play_token={playtoken}", cookies=unext_instance.auth_cookie)
                            response = unext_instance.session.get(f"https://beacon.unext.jp/beacon/stop/{url_code}/1/?play_token={playtoken}&last_viewing_flg=0", cookies=unext_instance.auth_cookie)
                        
                        content_default = (
                            f"{meta_response['titleName']}\n"
                            "",
                            "キャッチフレーズ:\n",
                            f"{meta_response['catchphrase']}\n"
                            "",
                            "見どころ:\n",
                            f"{meta_response['attractions']}\n"
                            "",
                            "ストーリー:\n",
                            f"{meta_response['story']}\n"
                        )
                        
                        get_meta_content = (
                            f"{meta_response['titleName']}\n"
                            "",
                            f"{episode_json['displayNo']}: {episode_json['episodeName']}\n"
                            "",
                            "キャッチフレーズ:\n",
                            f"{meta_response['catchphrase']}\n"
                            "",
                            "見どころ:\n",
                            f"{meta_response['attractions']}\n"
                            "",
                            "ストーリー:\n",
                            f"{meta_response['story']}\n"
                            "",
                            "エピソード紹介:\n",
                            f"{episode_json['introduction']}\n"
                        )

                        episode_content.append(get_meta_content)
                        
                        root.title(unext_instance.title+f"メタデータとライセンスの取得中 -> {episode_num}/{len(meta_episode_response["episodes"])}")
                        
                        episode_num = episode_num + 1
                    
                    time.sleep(1)
                    root.title(unext_instance.title)
                    print("Getted All playtoken, mediacode\n\n\n\n")
                    #print(episode_content)
                        
                    tries = 3  # Number of retry attempts
                    for attempt in range(tries):
                        try:
                            response = requests.get("https://"+meta_response["thumbnail"]["standard"] )
                            response.raise_for_status()  # Raise an exception for bad status codes
                            filename = os.path.join(download_dir, f"standard_thumbnail-{unext_get_series_id}.png")
                            with open(filename, 'wb') as file:
                                file.write(response.content)
                        except requests.RequestException:
                            print(f"[-] Error downloading {"https://"+url}, attempt {attempt + 1} of {tries}")
                            if attempt == tries - 1:
                                return url, False
                        
                    # マルチスレッドで画像をダウンロード
                    with ThreadPoolExecutor() as executor:
                        futures = [executor.submit(gui_utils.download_image, url, download_dir) for url in thumbnail_image_list]
                        for future in tqdm(as_completed(futures), total=len(futures), desc="Downloading", unit="file"):
                            url, success = future.result()
                            #print(f"[+] Success Download thumbnail {meta_episode_response["episodes"][]}")
                            if not success:
                                print(f"[-] Failed to download {url}")
                    
                    print("[+] Success Download all thumbnail")
                    print("[~] Analyzing video, audio files, Other")
                    
                    unext_all_episode_meta = analyze_utils.get_video_episodes(unext_get_series_id)
                    print(unext_all_episode_meta)
                    
                    chapters = []
                    
                    title_json, get_all_episode_json = analyze_utils.get_all_episode_title(unext_get_series_id)
                    for get_all_episode_json in get_all_episode_json:
                        chapters.append((get_all_episode_json["displayNo"], get_all_episode_json["episodeName"]))
                    
                    formatted_chapters = gui_utils.format_chapter_list(chapters, max_width=50)
                    
                    unext_instance.unext_chapters = formatted_chapters
                    chapter_menu.configure(values=unext_instance.unext_chapters)
                    
                    print(formatted_chapters)
                    print(episode_content)
                    #print(episode_about)
                    
                    chapter_menu.configure(state="normal")
                    chapter_menu.set(unext_instance.unext_chapters[0])
                                        
                    unext_instance.unext_video_meta = []
                    unext_instance.unext_audio_meta = []
                    
                    print(episode_about)
                    
                    for video_mpd in episode_about:
                        video_value_tmp = []
                        audio_value_tmp = []
                        for video_i in video_mpd["video"]:
                            video_value_tmp_tt = [video_i["resolution"], video_i["mimetype"].replace("video/", ""), video_i["codec"]]
                            video_value_tmp.append(video_value_tmp_tt)
                        audio_value_tmp_tt = [video_mpd["audio"]["audioSamplingRate"], video_mpd["audio"]["mimetype"].replace("audio/", ""), video_mpd["audio"]["codec"]]
                        audio_value_tmp.append(audio_value_tmp_tt)
                        unext_instance.unext_video_meta.append(video_value_tmp)
                        unext_instance.unext_audio_meta.append(audio_value_tmp)
                    
                    print(unext_instance.unext_video_meta)
                    print(unext_instance.unext_audio_meta)
                    
                    dropdown_video = CTkDropdownTest(
                        attach=video_menu,
                        height=200,
                        width=610,
                        values=[],
                        tree_colum=["Resolution", "Ext.", "Codec"],
                        tree_bg_color="#2d2d2d",
                        tree_fg_color="white",
                        command=on_dropdown_select_video
                    )
                    dropdown_audio = CTkDropdownTest(
                        attach=audio_menu,
                        height=200,
                        width=610,
                        #values=values,
                        values=[""],
                        tree_colum=["ASR", "Ext.", "Codec"],
                        tree_bg_color="#2d2d2d",
                        tree_fg_color="white",
                        command=on_dropdown_select_audio,
                    )
                    
                    thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, f"standard_thumbnail-{unext_get_series_id}.png")),size=(410, 232)))
                    content_widget.configure(state="normal")
                    numbers_widget.configure(state="normal")

                
                    content_widget.delete("1.0", "end")  # 既存の内容を削除
                    content_widget.insert(tk.END, content_default)
                    
                    content_widget.configure(state="disabled")
                    
                    root.update_idletasks()
                    lines_count = gui_utils.get_wrapped_lines_count(content_widget)
                    
                    numbers_widget.delete("1.0", "end")
                    
                    line_numbers = "\n".join([f"{i:>2}" for i in range(1, lines_count + 1)])
                    numbers_widget.insert("1.0", line_numbers)
                    numbers_widget.configure(state="disabled")
            else:
                CTkMessagebox(title="失敗", message="URLからIDを取得できませんでした\nURLを確認してください", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
        threading.Thread(target=main).start()
        
    # top window
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
    lines_count = gui_utils.get_wrapped_lines_count(content_widget)
    
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
    
    def chapter_selected(selected):
        global index
        if selected in unext_instance.unext_chapters:
            index = unext_instance.unext_chapters.index(selected)
            if index > 0:
                print(unext_instance.unext_video_meta[index-1]) # [['704x396', 'avc1.4d401e', 'video/mp4'], ['1280x720', 'avc1.4d401f', 'video/mp4'], ['1920x1080', 'avc1.4d4028', 'video/mp4']]
                print(unext_instance.unext_audio_meta[index-1]) # [['48000', 'mp4a.40.2', 'audio/mp4']]
                
                dropdown_video.configure(values=unext_instance.unext_video_meta[index-1])
                dropdown_audio.configure(values=unext_instance.unext_audio_meta[index-1])
                
                thumbnail.configure(text="")
                thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, os.path.basename(thumbnail_image_list[index-1]))), size=(410, 232)))
                                
                print(episode_content[index-1])
                
                content_widget.configure(state="normal")
                numbers_widget.configure(state="normal")
                season_download_button.configure(state="normal")
                
                
                content_widget.delete("1.0", "end")  # 既存の内容を削除
                content_widget.insert(tk.END, episode_content[index-1])
                
                content_widget.configure(state="disabled")
                
                root.update_idletasks()
                gui_utils.update_wrapped_lines(content_widget, numbers_widget)
    
                video_menu.configure(state="normal")
                audio_menu.configure(state="normal")
                
                download_episode_button.configure(state="normal")
                download_video_button.configure(state="normal")
                download_audio_button.configure(state="normal")
            else:
                thumbnail.configure(text="")
                thumbnail.configure(image=ctk.CTkImage(Image.open(os.path.join(download_dir, f"standard_thumbnail-{unext_get_series_id}.png")), size=(410, 232)))
                content_widget.configure(state="normal")
                numbers_widget.configure(state="normal")
                
                content_widget.delete("1.0", "end")
                content_widget.insert(tk.END, content_default)
                
                dropdown_video.configure(values=unext_instance.unext_video_meta[1])
                dropdown_audio.configure(values=unext_instance.unext_audio_meta[1])
                
                content_widget.configure(state="disabled")
                season_download_button.configure(state="normal")
                
                root.update_idletasks()
                gui_utils.update_wrapped_lines(content_widget, numbers_widget)
            print(index)
    
    def on_dropdown_select_video(result):
        print("Columns:", result["columns"])
        print("Selected Values:", result["values"])
        
        encode_result = ' '.join(result["values"])
        video_menu.set(encode_result)
    
    def on_dropdown_select_audio(result):
        print("Columns:", result["columns"])
        print("Selected Values:", result["values"])
        
        encode_result = ' '.join(result["values"])
        audio_menu.set(encode_result)
    
    video_dropdown_menu = tk.StringVar()
    video_dropdown_menu.set("")
    audio_dropdown_menu = tk.StringVar()
    audio_dropdown_menu.set("")
    
    monospace_font = ("BIZ UDゴシック", 12)
    
    chapter_menu = ctk.CTkOptionMenu(right_down_frame, values=unext_instance.unext_chapters, command=chapter_selected, font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled")
    chapter_menu.place(x=67,y=10)
    
    download_episode_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", command= lambda: downloader.download_episode(
        unext_all_episode_meta[index-1], video_dropdown_menu.get(), audio_dropdown_menu.get(), episode_license[index-1], episode_about[index-1], meta_response
    ), state="disabled")
    download_episode_button.place(x=678,y=10) 
    
    video_menu = ctk.CTkOptionMenu(right_down_frame, values=[""], font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled", variable=video_dropdown_menu)
    video_menu.place(x=67,y=32)
    
        
    download_video_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", command= lambda: downloader.download_video(
        unext_all_episode_meta[index-1], video_dropdown_menu.get(), meta_response, episode_license[index-1], episode_about[index-1], None
    ), state="disabled")
    download_video_button.place(x=678,y=32) 
    
    audio_menu = ctk.CTkOptionMenu(right_down_frame, values=[""], font=monospace_font, dropdown_font=monospace_font, width=610, height=20, corner_radius=0, fg_color="#2d2d2d", button_color="#2d2d2d", button_hover_color="#3f3f3f", dropdown_hover_color="#274f62", state="disabled", variable=audio_dropdown_menu)
    audio_menu.place(x=67,y=54)
        
    download_audio_button = ctk.CTkButton(master=right_down_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", corner_radius=2, border_width=1, hover_color="#3f3f3f", border_color="#404040", text="", width=20, height=20, anchor="w", command= lambda: downloader.download_audio(
        unext_all_episode_meta[index-1], audio_dropdown_menu.get(), meta_response, episode_license[index-1], episode_about[index-1], None
    ), state="disabled")
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
    thumbnail_seconds = ctk.CTkLabel(master=left_frame, textvariable=duration_var, fg_color="#4D4D4D", bg_color="#4D4D4D", text_color="#fff", anchor="e", font=monospace_font, height=18)
    thumbnail_seconds.place(x=0,y=213)
    
    ctk.CTkLabel(master=left_frame, width=200, text="").place(x=0,y=232)
    
    thumbnail_checkbox = ctk.CTkCheckBox(master=left_frame, text_color="#fff", fg_color="#232323", hover_color="#232323", text="Download Thumbnail", width=15, height=15, checkbox_width=15, checkbox_height=15, corner_radius=1, border_width=1, variable=unext_instance.unext_thumbnail_dl)
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

    downloader_downloader_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_downloader, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_downloader_label.place(x=70,y=40)

    downloader_downloaded_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_downloaded, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_downloaded_label.place(x=70,y=55)

    downloader_total_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_total, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_total_label.place(x=70,y=70)

    downloader_speed_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_speed, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_speed_label.place(x=70,y=85)

    downloader_elapsed_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_elapsed, font=("Roboto", 10, "bold"), height=10, width=350, anchor="e")
    downloader_elapsed_label.place(x=70,y=100)
    
    downloader_status_label = ctk.CTkLabel(master=left_down_frame, text="None", textvariable=unext_instance.downloader_status, font=("Roboto", 10, "bold"), height=12, width=350, anchor="e")
    downloader_status_label.place(x=70,y=115)
    
    left_down_button_frame = ctk.CTkFrame(frame_scroll, width=420, height=80, fg_color="#272727")
    left_down_button_frame.place(x=712,y=720)
    
    season_download_button = ctk.CTkButton(master=left_down_button_frame, image=ctk.CTkImage(Image.open("data/downloader_image/download_icon.png"),size=(10, 10)), compound="left", fg_color="#2d2d2d", bg_color="#2d2d2d", hover_color="#3f3f3f", corner_radius=5, border_width=1, border_color="#404040", text="Download", width=85, height=28, font=("Roboto", 12, "bold"), anchor="w", command= lambda: downloader.series_download(
        unext_all_episode_meta, video_dropdown_menu.get(), audio_dropdown_menu.get(), meta_response, episode_license, episode_about
    ), state="disabled")
    season_download_button.place(x=0,y=8)
    
    return frame_scroll
