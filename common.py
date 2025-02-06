import json
import os
import re
import subprocess

from tqdm import tqdm

from ext import *
from ext import abematv_v2 as AbemaTV_v2
from ext import unext_v2 as Unext_v2
from ext import dmm_tv as Dmm_tv
from ext import brainshark as Brainshark
from ext import fod as FOD
from ext import anime3rb as Anime3rb

__version__ = "0.9.0"

def get_parser(url):
    """
    Function that is called first time to check if it's a valid supported link

    :return: A class of one of supported website
    """
    valid_abema = r'^["\']?http(?:|s)://(?:abema\.tv)/(?:channels|video)/(?:\w*)(?:/|-\w*/)((?P<slot>slots/)|)(?P<video_id>.*[^-_])["\']?$'
    valid_gyao = r'(?isx)^["\']?http(?:|s)://gyao.yahoo.co.jp/(?:player|p|title[\w])/(?P<p1>[\w]*.*)["\']?$'
    valid_aniplus = r'^["\']?http(?:|s)://(?:www\.|)aniplus-asia\.com/episode/(?P<video_id>[\w]*.*)["\']?$'
    valid_unext = r'^["\']?http(?:|s)://video\.unext\.jp/(?:play|title|freeword).*(?:SID(?P<sid>[0-9]+)|ED(?P<ed>[0-9]+))["\']?$'
    valid_dmm_tv = r'^["\']?http(?:s)?://tv\.dmm\.com/vod(?:/playback)?/\?.*season=(?P<season>[^&?]+)(?:&.*content=(?P<content>[^&?]+)|)["\']?$'
    valid_brainshark = r'^["\']?https?://www\.brainshark\.com/brainshark/brainshark\.services\.player/api/v1\.0/Presentation\?([^&]*&)*pi=(?P<pi>[^&]+)(&|$)'
    valid_fod = r'^["\']?http(?:|s)://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+/?)?["\']?$'
    valid_anime3rb = r'^["\']?http(?:|s)://anime3rb\.com/(?:titles|episode)/([\w-]+)/.*|search\?q=[^"\']+["\']?$'
    
    if re.match(valid_abema, url):
        return AbemaTV_v2, "abema"
    elif re.match(valid_gyao, url):
        return GYAO, "gyao"
    elif re.match(valid_aniplus, url):
        return Aniplus, "aniplus"
    elif re.match(valid_unext, url):
        return Unext_v2, "unext"
    elif re.match(valid_dmm_tv, url):
        return Dmm_tv, "dmm_tv"
    elif re.match(valid_brainshark, url):
        return Brainshark, "brainshark"
    elif re.match(valid_fod, url):
        return FOD, "fod"
    elif re.match(valid_anime3rb, url) or url.__contains__("anime3rb.com/search?q="):
        return Anime3rb, "anime3rb"
    return None, None


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
