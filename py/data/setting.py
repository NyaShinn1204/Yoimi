import os
import time
import json
import requests
import tkinter as tk
import customtkinter as ctk

first_title = "Hotaru-WV v0.0.2"

title = "Hotaru-WV v0.0.2 | "

unixtime = str(int(time.time())) ## use to create temp file

output_type = ctk.StringVar()
output_type.set("streamfab")
fast_download = ctk.BooleanVar()
fast_download.set(True)
global_cookie = {}
image_references = []
image_references_episode = []

url_list = []
meta_list = {"title_ids":[]}
title_list = {"title_ids":[]}

unext_auth_url = "https://account.unext.jp/login"
unext_auth_cookie = {}
unext_session = requests.Session()

unext_chapters = [""]
unext_video_meta = []
unext_audio_meta = []

unext_downloader_video = []
unext_downloader_audio = []

unext_thumbnail_dl = ctk.BooleanVar()
unext_thumbnail_dl.set(True)

abema_chapter = [""]
abema_video_meta = []
abema_audio_meta = []
abema_session = requests.Session()

downloader_downloader = tk.StringVar()
downloader_downloader.set("None")
downloader_downloaded = tk.StringVar()
downloader_downloaded.set("None")
downloader_total = tk.StringVar()
downloader_total.set("None")
downloader_speed = tk.StringVar()
downloader_speed.set("None")
downloader_elapsed = tk.StringVar()
downloader_elapsed.set("None")
downloader_status = tk.StringVar()
downloader_status.set("None")

class Unext:
    cwd = os.getcwd()
    folders = {
        "download": os.path.join(cwd, "download"),
        "binaries": os.path.join(cwd, "binaries"),
        "output": os.path.join(cwd, "output"),
        "temp": os.path.join(cwd, "temp"),
    }
    session = requests.Session()
    unixtime = unixtime
    auth_cookie = {}
    title = "Hotaru-WV v0.0.2 | U-Next | "
    downloader_downloader = tk.StringVar()
    downloader_downloader.set("None")
    downloader_downloaded = tk.StringVar()
    downloader_downloaded.set("None")
    downloader_total = tk.StringVar()
    downloader_total.set("None")
    downloader_speed = tk.StringVar()
    downloader_speed.set("None")
    downloader_elapsed = tk.StringVar()
    downloader_elapsed.set("None")
    downloader_status = tk.StringVar()
    downloader_status.set("None")
    unext_thumbnail_dl = ctk.BooleanVar()
    unext_thumbnail_dl.set(True)
    unext_chapters = [""]
    unext_chapters = [""]
    unext_video_meta = []
    unext_audio_meta = []

    def unext_url_list(self):
        json_open = open("data/service_api_list/unext.json", "r")
        json_load = json.load(json_open)
        return json_load

# Define folders
cwd = os.getcwd()
folders = {
    "download": os.path.join(cwd, "download"),
    "binaries": os.path.join(cwd, "binaries"),
    "output": os.path.join(cwd, "output"),
    "temp": os.path.join(cwd, "temp"),
}

if not os.path.exists(folders["temp"]):
    os.makedirs(folders["temp"], exist_ok=True)

api_list = {
    "unext": "https://cc.unext.jp",
}

unext_auth = {
    "email": {
        "token": ""
    },
    "cookie": {
        "cookie_here": ""
    }
}

abema_auth = {
    "email": {
        "token": "",
        "deviceid": ""
    },
    "cookie": {
        "cookie_here": ""
    }
}

def unext_url_list():
    import json
    json_open = open("data/service_api_list/unext.json", "r")
    json_load = json.load(json_open)
    return json_load

def abema_url_list():
    import json
    json_open = open("data/service_api_list/abema.json", "r")
    json_load = json.load(json_open)
    return json_load

def get_json():
    import json
    with open('./data/config.json', 'r', encoding='utf-8') as f:
        config_data = json.load(f)
    
    return config_data