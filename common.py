import json
import os
import re
import subprocess

from tqdm import tqdm

from ext import *

def get_parser(url):
    """
    Function that are called first time to check if it's a valid supported link

    :return: A class of one of supported website
    """
    valid_abema = r'http(?:|s)://(?:abema\.tv)/(?:channels|video)/(?:\w*)(?:/|-\w*/)((?P<slot>slots/)|)(?P<video_id>.*[^-_])'
    valid_gyao = r'(?isx)http(?:|s)://gyao.yahoo.co.jp/(?:player|p|title[\w])/(?P<p1>[\w]*.*)'
    valid_aniplus = r'http(?:|s)://(?:www\.|)aniplus-asia\.com/episode/(?P<video_id>[\w]*.*)'
    valid_unext = r'http(?:|s)://video\.unext\.jp/(?:play|title|freeword).*(?:SID(?P<sid>[0-9]+)|ED(?P<ed>[0-9]+))'
    if re.match(valid_abema, url):
        return AbemaTV
    elif re.match(valid_gyao, url):
        return GYAO
    elif re.match(valid_aniplus, url):
        return Aniplus
    elif re.match(valid_unext, url):
        return UNext
    return None


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
