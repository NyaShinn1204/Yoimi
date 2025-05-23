import os
import re
import json
import subprocess
from ruamel.yaml import YAML
from pathlib import Path

from tqdm import tqdm

__version__ = "1.2.0"

def get_parser(url):
    """
    Function that is called first time to check if it's a valid supported link

    :return: A class of one of supported website
    """
    valid_abema = r'^["\']?http(?:|s)://(?:abema\.tv)/(?:channels|video)/(?:\w*)(?:/|-\w*/)((?P<slot>slots/)|)(?P<video_id>.*[^-_])["\']?$'
    valid_gyao = r'(?isx)^["\']?http(?:|s)://gyao.yahoo.co.jp/(?:player|p|title[\w])/(?P<p1>[\w]*.*)["\']?$'
    valid_aniplus = r'^["\']?http(?:|s)://(?:www\.|)aniplus-asia\.com/episode/(?P<video_id>[\w]*.*)["\']?$'
    valid_unext = r'^https?://(?:video|video-share)\.unext\.jp/(?:play|title|freeword)/.*(?:SID[0-9]+|ED[0-9]+)'
    valid_dmm_tv = r'^["\']?https?://tv\.dmm\.com/vod(?:/playback(?:/[^?]*)?)?/\?.*season=(?P<season>[^&?]+)(?:&.*content=(?P<content>[^&?]+)|)["\']?$'
    valid_brainshark = r'^["\']?https?://www\.brainshark\.com/brainshark/brainshark\.services\.player/api/v1\.0/Presentation\?([^&]*&)*pi=(?P<pi>[^&]+)(&|$)'
    valid_fod = r'^["\']?http(?:|s)://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+/?)?["\']?$'
    valid_anime3rb = r'^["\']?http(?:|s)://anime3rb\.com/(?:titles|episode)/([\w-]+)/.*|search\?q=[^"\']+["\']?$'
    valid_crunchyroll = r'^["\']?https?://www\.crunchyroll\.com/(series|watch)/[^/]+/[^"\']+["\']?$'
    valid_b_ch = r'^["\']?https?://www\.b-ch\.com/titles/\d+(/\d+)?/?["\']?$'
    valid_telasa = r'^["\']?http(?:s)?://(?:www\.)?telasa\.jp/(?:videos|play|series)/\d+["\']?$'
    valid_videomarket = r'^["\']?https?://(?:www\.)?videomarket\.jp/(?:title|player)/[0-9A-Z]+(?:/[0-9A-Z]+)?["\']?$'
    valid_hulu_jp = r'^["\']?https?://(?:www\.)?hulu\.jp/(?:watch/)?[^"\']+["\']?$'

    if re.match(valid_abema, url) and "-v1" in url:
        from ext import abematv as AbemaTV
        return AbemaTV, "abemav1"
    elif re.match(valid_abema, url):
        from ext import abematv_v2 as AbemaTV_v2
        return AbemaTV_v2, "abema"
    elif re.match(valid_gyao, url):
        from ext import gyao as GYAO
        return GYAO, "gyao"
    elif re.match(valid_aniplus, url):
        from ext import aniplus as Aniplus
        return Aniplus, "aniplus"
    elif re.match(valid_unext, url):
        from ext import unext_v2 as Unext_v2
        return Unext_v2, "unext"
    elif re.match(valid_dmm_tv, url):
        from ext import dmm_tv as Dmm_tv
        return Dmm_tv, "dmm_tv"
    elif re.match(valid_brainshark, url):
        from ext import brainshark as Brainshark
        return Brainshark, "brainshark"
    elif re.match(valid_fod, url):
        from ext import fod as FOD
        return FOD, "fod"
    elif re.match(valid_anime3rb, url) or "anime3rb.com/search?q=" in url:
        from ext import anime3rb as Anime3rb
        return Anime3rb, "anime3rb"
    elif re.match(valid_crunchyroll, url):
        from ext import crunchyroll as Crunchyroll
        return Crunchyroll, "Crunchyroll"
    elif "plus.nhk.jp" in url:
        from ext import nhk_plus as Nhk_plus
        return Nhk_plus, "NHK+"
    elif "jff.jpf.go.jp" in url:
        from ext import jff_theater as Jff_Theater
        return Jff_Theater, "Jff Theater"
    elif "wod.wowow.co.jp" in url:
        from ext import wowow as WOD_Wowow
        return WOD_Wowow, "WOD-WOWOW"
    elif re.match(valid_b_ch, url):
        from ext import bandai_ch as Bandai_ch
        return Bandai_ch, "Bandai-Ch"
    elif re.match(valid_telasa, url):
        from ext import telasa as Telasa
        return Telasa, "Telasa"
    elif re.match(valid_videomarket, url):
        from ext import videomarket as VideoMarket
        return VideoMarket, "VideoMarket"
    elif re.match(valid_hulu_jp, url):
        from ext import hulu_jp as Hulu_jp
        return Hulu_jp, "Hulu-jp"
    return None, None


def version_check(session):
    data = session.get("https://pastebin.com/raw/ajb3We1w").json()
    if __version__ != data["version"]:
        print("New Version Detect, Please update! https://github.com/NyaShinn1204/Yoimi/releases/tag/{}".format(data["version"]))
        print('====== Changelog v{} ======'.format(data["version"]))
        print(data["changelog_ja"])
        print("\n")
        print(data["changelog_en"])

def find_files_with_extension(folder, extension):
    if not os.path.isdir(folder):
        return []
    return [
        os.path.abspath(os.path.join(folder, f))
        for f in os.listdir(folder)
        if f.endswith(extension)
    ]


def cdms_check(config):
    wv_folder = "./cdms/wv/"
    pr_folder = "./cdms/pr/"

    wvd_files = find_files_with_extension(wv_folder, ".wvd")
    prd_files = find_files_with_extension(pr_folder, ".prd")

    result = {
        "wvd": wvd_files,
        "prd": prd_files
    }

    if (not wvd_files or not prd_files) or config["cdms"]["widevine"] == "":
        yaml = YAML()
        yaml.preserve_quotes = True
        
        config_path = Path('config.yml')
        
        if not wvd_files and config["cdms"]["widevine"] == "":
            print("Please check whether the WVD file is located inside `./cdms/wv`")
            exit(1)
        if len(wvd_files) == 1 and config["cdms"]["widevine"] == "":
            selected_file = wvd_files[0]
            print(f"Update config to use {os.path.basename(selected_file)} cdm")
            config["cdms"]["widevine"] = selected_file
            with config_path.open('w', encoding='utf-8') as f:
                yaml.dump(config, f)
        if len(wvd_files) > 1 and config["cdms"]["widevine"] == "":
            print("Available Widevine CDM:")
            for i, path in enumerate(wvd_files, 1):
                print(f"{i}. {os.path.basename(path)}")
            
            while True:
                try:
                    choice = int(input("Enter the number of the file you want to use: "))
                    if 1 <= choice <= len(wvd_files):
                        selected_file = wvd_files[choice - 1]
                        break
                    else:
                        print("Invalid number. Please re-try.")
                except ValueError:
                    print("Please type number.")
        
            print(f"Update config to use {os.path.basename(selected_file)} cdm")
            config["cdms"]["widevine"] = selected_file
            with config_path.open('w', encoding='utf-8') as f:
                yaml.dump(config, f)
    
    return result
def merge_video(path, output):
    """
    Merge every video chunk to a single file output
    """
    with open(output, 'wb') as out:
        with tqdm(total=len(path), desc="Merging", ascii=True, unit="file") as pbar:
            for i in path:
                out.write(open(i, 'rb').read())
                os.remove(i)
                pbar.update()


def mux_video(old_file, muxfile):
    """
    Mux .ts or .mp4 or anything to a .mkv

    It will try to use ffmpeg first, if it's not in the PATH, then it will try to use mkvmerge
    If it's doesn't exist too, it just gonna skip.
    """
    # MkvMerge/FFMPEG check
    use_ffmpeg = False
    use_mkvmerge = False
    
    check_ffmpeg = subprocess.run(['ffmpeg', '-version'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    check_mkvmerge = subprocess.run(['mkvmerge', '-V'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    if check_mkvmerge.returncode == 0:
        use_mkvmerge = True
    if check_ffmpeg.returncode == 0:
        use_ffmpeg = True
    else:
        return "Error"
    
    fn_, _ = os.path.splitext(old_file)
    if use_mkvmerge:
        subprocess.run(['mkvmerge', '-o', '{f}.{e}'.format(f=fn_, e=muxfile), old_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if use_ffmpeg:
        subprocess.run(['ffmpeg', '-i', old_file, '-c', 'copy', '{f}.{e}'.format(f=fn_, e=muxfile)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return '{f}.{e}'.format(f=fn_,e=muxfile)


def get_yuu_folder():
    if os.name == "nt":
        yuu_folder = os.path.join(os.getenv('LOCALAPPDATA'), 'yuu_data')
    else:
        yuu_folder = os.path.join(os.getenv('HOME'), '.yuu_data')
    if not os.path.isdir(yuu_folder):
        os.mkdir(yuu_folder)
    return yuu_folder


def _prepare_yuu_data():
    yuu_folder = get_yuu_folder()

    if not os.path.isfile(os.path.join(yuu_folder, 'yuu_download.json')):
        with open(os.path.join(yuu_folder, 'yuu_download.json'), 'w') as f:
            json.dump({}, f)
