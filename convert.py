import os
import random
import xml.etree.ElementTree as ET
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import moviepy.editor as mpy
import cv2

# 動画ファイルとXMLファイルのパス
input_video_path = "input.mp4"
input_xml_path = "so44387838.xml"
output_video_path = "output.mp4"

# フォント設定
fonts = {
    "default": "msgothic.ttc",  # デフォルトフォント
    "defont": "msgothic.ttc",  # MSPゴシック
    "mincho": "yumin.ttf",    # 游明朝体
}

# フォントサイズ設定
font_sizes = {
    "default": {
        "big": 39,
        "medium": 27,
        "small": 18
    },
    "resized": {
        "big": 20,
        "medium": 14,
        "small": 10
    },
    "defont": 600,
    "mincho": 400,
    "default_size":400, # デフォルトのサイズ
    "shita": 18
}

font_size_default = font_sizes["default"]["medium"]


# 動画情報を取得
cap = cv2.VideoCapture(input_video_path)
fps = int(cap.get(cv2.CAP_PROP_FPS))
width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
duration = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) / fps
cap.release()

# コマンド解析マッピング
COMMANDS = {
    "small": {"size": "small"},
    "medium": {"size": "medium"},
    "big": {"size": "big"},
    "ue": {"position": "top"},
    "shita": {"position": "bottom"},
    "naka": {"position": "middle"},
    "white": {"color": "#FFFFFF"},
    "red": {"color": "#FF0000"},
    "pink": {"color": "#FF8080"},
    "orange": {"color": "#FFC000"},
    "yellow": {"color": "#FFFF00"},
    "green": {"color": "#00FF00"},
    "cyan": {"color": "#00FFFF"},
    "blue": {"color": "#0000FF"},
    "purple": {"color": "#C000FF"},
    "black": {"color": "#000000"},
    "defont": {"font": "defont"},
    "mincho": {"font": "mincho"},
    # ニコニコ独自のカラーバリエーション
    "white2": {"color": "#CCCC99"},
    "red2": {"color": "#CC0033"},
    "pink2": {"color": "#FF33CC"},
    "orange2": {"color": "#FF6600"},
    "yellow2": {"color": "#999900"},
    "green2": {"color": "#00CC66"},
    "cyan2": {"color": "#00CCCC"},
    "blue2": {"color": "#3399FF"},
    "purple2": {"color": "#6633CC"},
    "black2": {"color": "#666666"}
}

# コメントデータをXMLから読み込む
def parse_comments(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    comments = []
    for chat in root.findall("chat"):
        mail = chat.get("mail", "").split()  # コマンドの取得
        commands = {}
        for cmd in mail:
            command = COMMANDS.get(cmd)
            if command:
                commands.update(command)  # 有効なコマンドを追加
        color = commands.get("color", "#FFFFFF")
        size_key = commands.get("size", "medium") # default sizeをmediumにする
        font_key = commands.get("font", "default")  # フォントのキーを取得
        position = commands.get("position", "middle")
        comments.append({
            "vpos": int(chat.get("vpos")),  # コメントの表示タイミング（vposから計算）
            "text": chat.text or "",
            "color": color,
            "size_key": size_key, # sizeをkeyとして保存
            "font_key": font_key,
            "position": position,
            "x": width,  # 初期位置を右端に設定
            "shita": "shita" in mail, # shitaコマンドがあるか
            "y_init": random.randint(0,height),
        })
    return comments

comments = parse_comments(input_xml_path)


# コメント描画用関数
def draw_comments(frame_num, canvas, comments):
    draw = ImageDraw.Draw(canvas)
    vpos = (frame_num / fps) * 100  # フレームからvposに変換
    
    # コメントをshita有無で分類
    shita_comments = [comment for comment in comments if comment["shita"] ]
    non_shita_comments = [comment for comment in comments if not comment["shita"] ]
    
    # shitaコメントの位置を計算
    shita_y = height - 50
    for comment in reversed(shita_comments): # 下から表示するために逆順にする
      
        if vpos >= comment["vpos"]:
            
            font_path = fonts[comment["font_key"]]
            font_size = font_sizes.get("shita")
            font = ImageFont.truetype(font_path, font_size)
            
            bbox = draw.multiline_textbbox((0, 0), comment["text"], font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            #y座標を計算
            comment["y"]=shita_y
           
            # 画面中央に表示
            comment_x = (width - text_width) // 2
            # 画面外に出ないようにチェック
            if comment["y"] > -text_height:
                draw.multiline_text((comment_x, comment["y"]), comment["text"], fill=comment["color"], font=font)
                shita_y -= text_height + 5
            

    # shitaなしコメントを描画
    for comment in non_shita_comments:
        if vpos >= comment["vpos"]:
            font_path = fonts[comment["font_key"]]
            font_size = font_sizes.get(comment["font_key"],font_sizes.get("default_size")) if isinstance(font_sizes.get(comment["font_key"],font_sizes.get("default_size")), int) else font_sizes.get("resized" if width < 600 else "default").get(comment["size_key"]) # サイズを取得

            font = ImageFont.truetype(font_path, font_size)
            bbox = draw.multiline_textbbox((0, 0), comment["text"], font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            move_speed = 15
            comment["x"] -= move_speed
            
            # y座標を中央に設定
            if "y" not in comment:
                comment["y"] = (height - text_height) // 2
                comment["y"] = min(max(0, comment["y_init"] - text_height//2 ), height - text_height) #はみ出ないようにする
           
            
            text_position = {
                "top": (comment["x"], 50),
                "middle": (comment["x"], comment["y"]),
                "bottom": (comment["x"], height - text_height - 50),
            }[comment["position"]]
            
            # 画面外に出ないようにチェック
            if comment["x"] > -text_width:
                #shitaコメントと被らないようにチェック
                is_conflict = False
                for shita_comment in shita_comments:
                    if vpos >= shita_comment["vpos"] and abs(comment["y"] - shita_comment["y"]) < text_height :
                        is_conflict= True
                        break
                if not is_conflict:
                   draw.multiline_text(text_position, comment["text"], fill=comment["color"], font=font)


# フレーム生成関数
def make_frame(t):
    frame_num = int(t * fps)
    canvas = Image.new("RGB", (width, height), "black")
    draw_comments(frame_num, canvas, comments)
    return np.array(canvas)

# 動画レンダリング
video = mpy.VideoClip(make_frame, duration=duration)
video.write_videofile(output_video_path, fps=fps)

print(f"動画を保存しました: {output_video_path}")