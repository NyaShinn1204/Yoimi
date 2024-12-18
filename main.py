import os
import json
import time
import requests
import threading
import tkinter as tk
import customtkinter as ctk
from pystyle import Colorate, Colors
from xml.etree import ElementTree as ET
from tkinter import ttk
from PIL import Image, ImageDraw, ImageOps
from tkinter import filedialog
from CTkMessagebox import CTkMessagebox

from playwright.sync_api import sync_playwright

version = "0.0.2"

def printl(num, data):
  filename = os.path.basename(__file__)
  if num == "error":
    print(f"["+Colorate.Horizontal(Colors.red_to_blue, "Error")+"]"+f"[{filename}] " + data)
  if num == "debug":
    print(f"["+Colorate.Horizontal(Colors.cyan_to_blue, "Debug")+"]"+f"[{filename}] " + data)
  if num == "info":
    print(f"["+Colorate.Horizontal(Colors.white_to_blue, "Info")+"]"+f"[{filename}] " + data)

root = ctk.CTk()

import data.setting as setting

import util.abema as downloader_abema
import util.unext as downloader_unext

root.title(setting.first_title)
root.geometry("1366x768")
root.resizable(0, 0)
ctk.set_appearance_mode("dark")

module_frame = None
prev_frame = None

def clear_frame(frame):
  for widget in frame.winfo_children():
    widget.destroy()
  frame.pack_forget()

def check_config(downloader_type):
  printl("info", "Checking Config")
  try:
    if os.path.exists(r"data/config.json"):
      config_downloader_fir = json.load(open('./data/config.json', 'r', encoding="utf-8"))
      config_downloader_end = config_downloader_fir["downloader_setting"][downloader_type]
      printl("info", "Checked Config")
      print(config_downloader_end["login_method"])

      if config_downloader_end["login_method"] == "" or config_downloader_end["login_method"] not in ["email", "cookie", "token"]:
        if config_downloader_end["no_account_downloader"] == "True":
          if config_downloader_end["login_method_list"] == "email/cookie":
            login_method = CTkMessagebox(title="初期設定", message="アカウントログイン方法を教えてください", font=("BIZ UDゴシック", 13, "normal"), width=625, icon="question", option_1="メールアドレスを用いたログイン", option_2="クッキーを用いたログイン", option_3="アカウントを使用しない")
            login_method_get = login_method.get()
            if login_method_get == "メールアドレスを用いたログイン":
              config_downloader_end["login_method"] = "email"
            if login_method_get == "クッキーを用いたログイン":
              config_downloader_end["login_method"] = "cookie"
            if login_method_get == "アカウントを使用しない":
              config_downloader_end["login_method"] = "none"
          if config_downloader_end["login_method_list"] == "email/token":
            login_method = CTkMessagebox(title="初期設定", message="アカウントログイン方法を教えてください", font=("BIZ UDゴシック", 13, "normal"), width=625, icon="question", option_1="メールアドレスを用いたログイン", option_2="トークンを用いたログイン", option_3="アカウントを使用しない")
            login_method_get = login_method.get()
            if login_method_get == "メールアドレスを用いたログイン":
              config_downloader_end["login_method"] = "email"
            if login_method_get == "トークンを用いたログイン":
              config_downloader_end["login_method"] = "token"
            if login_method_get == "アカウントを使用しない":
              config_downloader_end["login_method"] = "none"
        else:
          if config_downloader_end["login_method_list"] == "email/cookie":
            login_method = CTkMessagebox(title="初期設定", message="アカウントログイン方法を教えてください", font=("BIZ UDゴシック", 13, "normal"), icon="question", option_1="メールアドレスを用いたログイン", option_2="クッキーを用いたログイン")
            login_method_get = login_method.get()
            if login_method_get == "メールアドレスを用いたログイン":
              config_downloader_end["login_method"] = "email"
            if login_method_get == "クッキーを用いたログイン":
              config_downloader_end["login_method"] = "cookie"
          if config_downloader_end["login_method_list"] == "email/token":
            login_method = CTkMessagebox(title="初期設定", message="アカウントログイン方法を教えてください", font=("BIZ UDゴシック", 13, "normal"), icon="question", option_1="メールアドレスを用いたログイン", option_2="トークンを用いたログイン")
            login_method_get = login_method.get()
            if login_method_get == "メールアドレスを用いたログイン":
              config_downloader_end["login_method"] = "email"
            if login_method_get == "トークンを用いたログイン":
              config_downloader_end["login_method"] = "token"
        with open("./data/config.json", "w") as file:
          json.dump(config_downloader_fir, file, indent=2)
        print(config_downloader_end["login_method"])
      else:
        if downloader_type == "unext":
          unext_instance = setting.Unext()
          if config_downloader_end["login_method"] == "email" and config_downloader_end["email"] != "" and config_downloader_end["password"] != "":
            root.title(unext_instance.title+"ログイン中...")
            def get_auth_token():
              import random, string, json
              from bs4 import BeautifulSoup
              from urllib.parse import urlparse, parse_qs
              def random_name(length):
                return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

              use_header = {"User-Agent": "U-NEXT Phone App Android7.1.2 5.29.0 SM-G955N"}
              session = requests.Session()

              state = random_name(43)
              nonce = random_name(43)
              url = f"https://oauth.unext.jp/oauth2/auth?state={state}&scope=offline%20unext&nonce={nonce}&response_type=code&client_id=unextAndroidApp&redirect_uri=jp.unext%3A%2F%2Fpage%3Doauth_callback"

              response = session.get(url, headers=use_header)
              soup = BeautifulSoup(response.text, "html.parser")

              script_tag = soup.find("script", {"id": "__NEXT_DATA__"})
              json_data = json.loads(script_tag.string)
              challenge_id = json_data.get("props", {}).get("challengeId")

              config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"]
              email = config_downloader_end["email"]
              password = config_downloader_end["password"]

              payload = {
                "id": email,
                "password": password,
                "challenge_id": challenge_id,
                "device_code": "920",
                "scope": ["offline", "unext"],
              }

              first_login_response = session.post("https://oauth.unext.jp/oauth2/login", headers=use_header, json=payload)
              post_auth_endpoint = first_login_response.json().get("post_auth_endpoint")
              oauth_url_repsonse = session.post(f"https://oauth.unext.jp{post_auth_endpoint}", headers=use_header, allow_redirects=False)

              redirect_oauth_url = oauth_url_repsonse.headers.get("Location")
              parsed_url = urlparse(redirect_oauth_url)
              query_params = parse_qs(parsed_url.query)
              code = query_params.get('code', [None])[0]

              payload = {
                "code": code,
                "grant_type": "authorization_code",
                "client_id": "unextAndroidApp",
                "client_secret": "unextAndroidApp",
                "code_verifier": None,
                "redirect_uri": "jp.unext://page=oauth_callback"
              }

              token_response = session.post("https://oauth.unext.jp/oauth2/token", headers=use_header, data=payload)

              auth_token = f"Bearer {token_response.json().get("access_token")}"

              unext_instance.session.headers.update({"Authorization": auth_token})
              unext_instance.session.headers.update({"User-Agent": "U-NEXT Phone App Android7.1.2 5.29.0 SM-G955N"})
              #print(auth_token)
              #setting.unext_auth["email"]["token"] = auth_token
              root.title(unext_instance.title+"ログイン成功")
              #print(unext_instance.session.headers)
            threading.Thread(target=get_auth_token).start()

          if config_downloader_end["login_method"] == "cookie" and config_downloader_end["cookie_path"] != "":
            def load_cookie():
              parse_cookie = downloader_unext.utils.parse_cookiefile(config_downloader_end["cookie_path"])
              if parse_cookie != None:
                status, id, message = downloader_unext.utils.check_cookie(parse_cookie)
                if status == True:
                  CTkMessagebox(title="成功", message=f"クッキーが有効です\nユーザーID: {id}", font=("BIZ UDゴシック", 13, "normal"))
                  setting.unext_auth_cookie = parse_cookie
                if status == False and message == None:
                  CTkMessagebox(title="失敗", message="クッキーが無効です", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
                if status == False and message == "Expired":
                  CTkMessagebox(title="失敗", message="クッキーの期限が切れています\n再度取得してください", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
              else:
                CTkMessagebox(title="失敗", message="クッキーを正常に読み込めませんでした", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))

            threading.Thread(target=load_cookie).start()
        if downloader_type == "abema":
          if config_downloader_end["login_method"] == "email" and config_downloader_end["email"] != "" and config_downloader_end["password"] != "":
            root.title(setting.title+"ログイン中...")
            def get_auth_token():
              import util.abema.utils.main as abema_anlyze
              auth_token, deviceid = abema_anlyze.get_auth_token_abema(config_downloader_end["email"], config_downloader_end["password"])
              if auth_token is None:
                CTkMessagebox(title="失敗", message=f"ユーザー名またはパスワードが無効です。", font=("BIZ UDゴシック", 13, "normal"))
              setting.abema_auth["email"]["token"] = auth_token
              setting.abema_auth["email"]["deviceid"] = deviceid

              #print(auth_token, deviceid)

              setting.abema_session.headers.update({"Authorization": auth_token})
              root.title(setting.title+"ログイン成功")
            threading.Thread(target=get_auth_token).start()

      return config_downloader_end
    else:
      printl("error", "Config Not Found")
      printl("error", "Please point to it manually.")
  except Exception as error:
    printl("error", "Config Check Error")
    printl("error", error)

def setup_cotent_sidebar(num1, num2, num3):
  global module_frame, prev_frame

  frame = None

  frame_scroll = module_frame = ctk.CTkFrame(root, fg_color="#232323", bg_color="#232323", width=1150, height=768)
  module_frame.place(x=230, y=0)
  clear_frame(frame_scroll)
  if prev_frame is not None:
    clear_frame(prev_frame)
  if num1 == 1:
    if num2 == 1:
      if num3 == 1:
        check_config("abema")
        frame = downloader_abema.gui.init_gui(frame_scroll, root)

        printl("info", "Open Abema Downloader")
      if num3 == 2:
        check_config("unext")
        frame = downloader_unext.gui.init_gui(frame_scroll, root)

        printl("info", "Open U-next Downloader")
      if num3 == None:
        image_paths = ["data/service_image/abema.jpg","data/service_image/unext.jpg"]

        def on_image_click(index):
          setup_cotent_sidebar(1, 1, index)

        for i, path in enumerate(image_paths):
          img = Image.open(path)
          img = ctk.CTkImage(img, size=(175, 100))
          label = ctk.CTkLabel(master=frame_scroll, image=img, text="")
          label.configure(cursor="hand2")

          label.bind("<Button-1>", lambda event, idx=i: on_image_click(idx+1))
          label.grid(row=i // 5, column=i % 5, padx=10, pady=10)
        printl("info", "Open All Downloader")
    if num2 == 2:
      if num3 == 1:
        printl("info", "Open Download List")
      if num3 == 2:
        printl("info", "Open Already Download List")
  if num1 == 2:
    if num2 == 1:
      printl("info", "Open About Tab")
  
  prev_frame = frame

def setup_sidebar():
  original_image = Image.open("./data/icon.png").convert("RGBA")
  size = (50, 50)
  image_resized = original_image.resize(size, Image.LANCZOS)
  mask = Image.new("L", size, 0)
  draw = ImageDraw.Draw(mask)
  draw.ellipse((0, 0, size[0], size[1]), fill=255)
  image_circular = ImageOps.fit(image_resized, mask.size, centering=(0.5, 0.5))
  image_circular.putalpha(mask)
  background_color = (104, 143, 191)
  background = Image.new("RGBA", size, background_color)
  background.paste(image_circular, (0, 0), image_circular)
  logo_image = ctk.CTkImage(background, size=size)

  tk.Label(root, bg="#688fbf", width=32, height=720).place(x=0,y=0)

  ctk.CTkLabel(master=root,image=logo_image,text="").place(x=15,y=5)
  tk.Label(root, bg="#688fbf", text="Hotaru-WV", fg="#fff", font=("Dubai Medium", 13, "normal")).place(x=70,y=0)
  tk.Label(root, bg="#688fbf", text=version, fg="#505b5e", font=("Dubai Medium", 13, "normal")).place(x=70,y=25)

  modulelist = ctk.CTkFrame(master=root, width=230, height=720, corner_radius=0, fg_color="#688fbf")
  modulelist.place(x=0,y=100)

  def on_enter_home(event):
    button_home.configure(image=ctk.CTkImage(Image.open("data/icon_home_activate.png"),size=(20, 20)))

  def on_leave_home(event):
    button_home.configure(image=ctk.CTkImage(Image.open("data/icon_home_disable.png"),size=(20, 20)))

  def on_enter_library(event):
    button_library.configure(image=ctk.CTkImage(Image.open("data/icon_library_activate.png"),size=(20, 20)))

  def on_leave_library(event):
    button_library.configure(image=ctk.CTkImage(Image.open("data/icon_library_disable.png"),size=(20, 20)))

  def on_enter_library_already(event):
    button_library_already.configure(image=ctk.CTkImage(Image.open("data/icon_library_activate.png"),size=(20, 20)))

  def on_leave_library_already(event):
    button_library_already.configure(image=ctk.CTkImage(Image.open("data/icon_library_disable.png"),size=(20, 20)))

  button_home = ctk.CTkButton(master=modulelist, command=lambda: setup_cotent_sidebar(1, 1, None), image=ctk.CTkImage(Image.open("data/icon_home_disable.png"),size=(20, 20)), compound="left", fg_color="#0f1314", hover_color="#2b373a", corner_radius=15, text="ホーム", width=215, height=40, font=("BIZ UDゴシック", 16, "normal"), anchor="w")
  button_home.bind('<Enter>', on_enter_home, add='+')
  button_home.bind("<Leave>", on_leave_home, add='+')
  button_home.place(x=5,y=12)

  librarylist = ctk.CTkFrame(master=root, width=230, height=384, corner_radius=0, fg_color="#688fbf")
  librarylist.place(x=0,y=384)

  tk.Label(librarylist, bg="#688fbf", text="ライブラリー", fg="#fff", font=("BIZ UDゴシック", 13, "normal")).place(x=15,y=0)

  button_library = ctk.CTkButton(master=librarylist, command=lambda: setup_cotent_sidebar(1, 2, 1), image=ctk.CTkImage(Image.open("data/icon_library_disable.png"),size=(20, 20)), compound="left", fg_color="#0f1314", hover_color="#2b373a", corner_radius=15, text="ダウンロードリスト", width=215, height=40, font=("BIZ UDゴシック", 14, "normal"), anchor="w")
  button_library.bind('<Enter>', on_enter_library, add='+')
  button_library.bind("<Leave>", on_leave_library, add='+')
  button_library.place(x=5,y=24)

  button_library_already = ctk.CTkButton(master=librarylist, command=lambda: setup_cotent_sidebar(1, 2, 2), image=ctk.CTkImage(Image.open("data/icon_library_disable.png"),size=(20, 20)), compound="left", fg_color="#0f1314", hover_color="#2b373a", corner_radius=15, text="ダウンロード済みリスト", width=215, height=40, font=("BIZ UDゴシック", 14, "normal"), anchor="w")
  button_library_already.bind('<Enter>', on_enter_library_already, add='+')
  button_library_already.bind("<Leave>", on_leave_library_already, add='+')
  button_library_already.place(x=5,y=69)
def setup_content():
  print()

printl("info", "Loading GUI")

setup_sidebar()
setup_cotent_sidebar(2, 1, None)
#setup_content() // ここにAboutでも乗っけるかね？


root.mainloop()
