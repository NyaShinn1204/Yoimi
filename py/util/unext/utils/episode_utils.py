# util/unext/utils/episode_utils.py
import os
import requests
import threading
import subprocess

def parse_cookiefile(file_path):
    '''クッキーを辞書形式に変換するコード'''
    
    cookies = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if not line.strip():
                    continue
                
                parts = line.strip().split('\t')
                if len(parts) < 6:
                    continue
                name = parts[5]
                value = parts[6] if len(parts) > 6 else ''
                
                if name == '_flog':
                    continue
                
                cookies[name] = value

    except FileNotFoundError:
        return None
    except Exception as e:
        return None

    return cookies

def check_cookie(load_cookie):
    import data.setting as setting
    unext_instance = setting.Unext()
    '''クッキーをテストするコード'''
    check_json = {
        "operationName":"cosmo_userInfo",
        "variables":{},
        "query":"query cosmo_userInfo {\n  userInfo {\n    id\n    multiAccountId\n    userPlatformId\n    userPlatformCode\n    superUser\n    age\n    otherFunctionId\n    points\n    hasRegisteredEmail\n    billingCaution {\n      title\n      description\n      suggestion\n      linkUrl\n      __typename\n    }\n    blockInfo {\n      isBlocked\n      score\n      __typename\n    }\n    siteCode\n    accountTypeCode\n    linkedAccountIssuer\n    isAdultPermitted\n    needsAdultViewingRights\n    __typename\n  }\n}\n"
    }
    #print(load_cookie)
    try:    
        test_cookie = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=check_json, cookies=load_cookie)
        return_json = test_cookie.json()
        #print(return_json)
        if return_json["data"]["userInfo"]["hasRegisteredEmail"] == True:
            return True, return_json["data"]["userInfo"]["id"], None
        else:
            if return_json["errors"][1]["message"] == "Token Expired":
                return False, None, "Expired"
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None

def compile_mp4(video_file, audio_file, output_file, title_name):
    import data.setting as setting
    unext_instance = setting.Unext()
    
    output_directory = os.path.join(unext_instance.folders["output"], title_name)
    
    if not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)

    compile_command = [
        os.path.join(unext_instance.folders["binaries"], "ffmpeg.exe"),
        "-i",
        video_file,
        "-i",
        audio_file,
        "-y",
        "-c:v",
        "copy",
        "-c:a",
        "copy",
        "-strict",
        "experimental",
        os.path.join(output_directory, output_file),
    ]
    subprocess.run(compile_command)

## downloader main program
def update_progress(total_var, speed_var, downloaded_var, remaining_time_var, process):
    for line in iter(process.stdout.readline, ''):
        line = line.strip()
        if line.startswith("[#") and "ETA:" in line:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    downloaded_info = parts[1]
                    downloaded, total = downloaded_info.split('/')

                    downloaded_var.set(downloaded)
                    total_var.set(total.split('(')[0])

                    speed_var.set(parts[3].replace("DL:", ""))

                    remaining_time_var.set(parts[4].replace("ETA:", "").replace("]", ""))

                except (IndexError, ValueError) as e:
                    print(f"Error parsing line: {line} - {e}")
            else:
                print(f"Unexpected format in line: {line}")

    downloaded_var.set(total_var.get())
    remaining_time_var.set("0s")
    speed_var.set("0")


def aria2c(url, output_file_name):
    import data.setting as setting
    unext_instance = setting.Unext()
    
    output_temp_direcotry = os.path.join(unext_instance.folders["temp"], "content", unext_instance.unixtime)
    
    if not os.path.exists(output_temp_direcotry):
        os.makedirs(output_temp_direcotry, exist_ok=True)
    
    aria2c = os.path.join(unext_instance.folders["binaries"], "aria2c.exe")
    aria2c_command = [
        aria2c,
        url,
        "-d",
        os.path.join(unext_instance.folders["temp"], "content", unext_instance.unixtime),
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
        encoding='utf-8'  # ここでエンコーディングを指定
    )

    # エラーメッセージをリアルタイムに表示
    threading.Thread(target=log_errors, args=(process,), daemon=True).start()
    
    unext_instance.downloader_downloader.set("Aria2c")

    # 別スレッドで進行状況を更新
    threading.Thread(target=update_progress, args=(unext_instance.downloader_total, unext_instance.downloader_speed, unext_instance.downloader_downloaded, unext_instance.downloader_elapsed, process), daemon=True).start()

    process.wait()  # ダウンロードの終了を待つ

    # プロセスが終了したらファイルパスを返す
    return os.path.join(unext_instance.folders["temp"], "content", unext_instance.unixtime, output_file_name)


def log_errors(process):
    for error in iter(process.stderr.readline, ''):
        print(f"Error: {error.strip()}")