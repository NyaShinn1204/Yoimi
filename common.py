import os
import re
import json
import subprocess
from pathlib import Path
from ruamel.yaml import YAML
from urllib.parse import urlparse, parse_qs

from tqdm import tqdm

__version__ = "1.2.2"

def path_check(input_path):
    # Windows Input Check
    invalid_chars = r'[<>:"|?*]'
    if re.search(invalid_chars, input_path):
        return False

    if not input_path.strip():
        return False

    has_extension = bool(os.path.splitext(input_path)[1])
    looks_like_path = '/' in input_path or '\\' in input_path

    return has_extension or looks_like_path
def get_parser(url):
    """
    Function that is called first time to check if it's a valid supported link

    :return: A class of one of supported website
    """
    valid_abema = r'^["\']?http(?:|s)://(?:abema\.tv)/(?:channels|video)/(?:\w*)(?:/|-\w*/)((?P<slot>slots/)|)(?P<video_id>.*[^-_])["\']?$'
    valid_gyao = r'(?isx)^["\']?http(?:|s)://gyao.yahoo.co.jp/(?:player|p|title[\w])/(?P<p1>[\w]*.*)["\']?$'
    valid_aniplus = r'^["\']?http(?:|s)://(?:www\.|)aniplus-asia\.com/episode/(?P<video_id>[\w]*.*)["\']?$'
    valid_unext = r'^https?://(?:video|video-share)\.unext\.jp/(?:play|title|freeword)/.*(?:SID[0-9]+|ED[0-9]+)' #    r'^https?://(?:video(?:-share)?\.(?:unext|hnext)\.jp)/(?:play|title|freeword)/.*(?:SID\d+|ED\d+|AID\d+)'
    valid_hnext = r'^https?://video\.hnext\.jp/(?:play|title)/.*(?:AID\d+|AED\d+)'
    valid_dmm_tv = r'^["\']?https?://tv\.dmm\.com/(?:vod(?:/playback(?:/[^?]*)?)?|shorts)/\?.*season=(?P<season>[^&?]+)(?:&.*content=(?P<content>[^&?]+)|)["\']?$'
    valid_brainshark = r'^["\']?https?://www\.brainshark\.com/brainshark/brainshark\.services\.player/api/v1\.0/Presentation\?([^&]*&)*pi=(?P<pi>[^&]+)(&|$)'
    valid_fod = r'^["\']?https?://fod\.fujitv\.co\.jp/title/(?P<title_id>[0-9a-z]+)/?(?P<episode_id>[0-9a-z]+/?)?(?:\?.*)?["\']?$'
    valid_anime3rb = r'^["\']?http(?:|s)://anime3rb\.com/(?:titles|episode)/([\w-]+)/.*|search\?q=[^"\']+["\']?$'
    valid_crunchyroll = r'^["\']?https?://www\.crunchyroll\.com/(series|watch)/[^/]+/[^"\']+["\']?$'
    valid_b_ch = r'^["\']?https?://www\.b-ch\.com/titles/\d+(/\d+)?/?["\']?$'
    valid_telasa = r'^["\']?http(?:s)?://(?:www\.)?telasa\.jp/(?:videos|play|series)/\d+["\']?$'
    valid_videomarket = r'^["\']?https?://(?:www\.)?videomarket\.jp/(?:title|player)/[0-9A-Z]+(?:/[0-9A-Z]+)?["\']?$'
    valid_hulu_jp = r'^["\']?https?://(?:www\.)?hulu\.jp/(?:watch/)?[^"\']+["\']?$'
    valid_fanza = r'^["\']?https?://www\.dmm\.(?:com|co\.jp)/digital/-/(?:player)/=/.*["\']?$'
    valid_dmm_gravure = r'^["\']?https?://tv\.dmm\.com/vod/restrict(?:/(?:list|detail))?/\?(?:[^&]*&)*season=(?P<season>[^&]+)(?:&|$)'
    valid_hiyahtv = r'^["\']?https?://(?:www\.)?hiyahtv\.com(?:/[\w\-]+)+(?:/videos/[\w\-]+)?["\']?$' 
    valid_lemino = r'^["\']?https?://lemino\.docomo\.ne\.jp/(?:(?:contents|search/word)/[^"\']*?(?:\?[^"\']*?)?(?:crid=)?(?P<crid>[a-zA-Z0-9%=_\-]+))["\']?$'
    
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
    elif re.match(valid_hnext, url):
        from ext import hnext as Hnext
        return Hnext, "H-Next"
    elif re.match(valid_dmm_tv, url):
        if "restrict" in url:
            # CHECK VR OR REGULAR TYPE
            import requests
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            check_status = requests.post("https://api.tv.dmm.com/graphql", json = {
                "operationName":"FetchVideoContent",
                "variables":{"id":query_params.get("season", [None])[0],"playDevice":"BROWSER","isLoggedIn":False},
                "query":"query FetchVideoContent($id: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!) {\n  videoContent(id: $id) {\n    ...VideoEpisode\n    __typename\n  }\n}\n\nfragment VideoEpisode on VideoContent {\n  id\n  seasonId\n  sampleMovie\n  episodeType\n  episodeImage\n  episodeTitle\n  episodeDetail\n  episodeNumber\n  episodeNumberName\n  contentType\n  priority\n  isWakuwari\n  isAllowComment\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    audioRenditions\n    textRenditions\n    parts {\n      contentId\n      duration\n      number\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    resumePartNumber @include(if: $isLoggedIn)\n    tags\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isDownloadable\n    isStreamable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    windowsURLSchemes: appURLSchemes(app: WINDOWS_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    iosURLSchemes: appURLSchemes(app: IOS_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    androidURLSchemes: appURLSchemes(app: ANDROID_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    isBeingDelivered\n    contentId\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    seasonId\n    episodeTitle\n    episodeNumber\n    episodeNumberName\n    contentPriority\n    saleUnitPriority\n    contentType\n    saleUnitName\n    saleType\n    isPreOrder\n    isStreamable\n    isDownloadable\n    isBundleParent\n    isOnSale\n    isBeingDelivered\n    isPurchased @include(if: $isLoggedIn)\n    startDeliveryAt\n    endDeliveryAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    price {\n      productId\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    viewingExpiration {\n      ...ViewingExpirationForPurchaseModal\n      __typename\n    }\n    bundleProducts {\n      id\n      contentId\n      seasonId\n      episodeTitle\n      episodeNumber\n      episodeNumberName\n      contentPriority\n      saleUnitPriority\n      contentType\n      saleUnitName\n      saleType\n      isPreOrder\n      isStreamable\n      isDownloadable\n      isBundleParent\n      isOnSale\n      isPurchased @include(if: $isLoggedIn)\n      isBeingDelivered\n      startDeliveryAt\n      endDeliveryAt\n      campaign {\n        id\n        name\n        endAt\n        isLimitedPremium\n        __typename\n      }\n      price {\n        productId\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      viewingExpiration {\n        ...ViewingExpirationForPurchaseModal\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    startDeliveryAt\n    isBeingDelivered\n    contentId\n    __typename\n  }\n  hasBookmark @include(if: $isLoggedIn)\n  nextEpisode {\n    id\n    seasonId\n    episodeNumberName\n    episodeTitle\n    episodeDetail\n    episodeImage\n    freeProduct {\n      isBeingDelivered\n      contentId\n      __typename\n    }\n    svodProduct {\n      contentId\n      __typename\n    }\n    ppvProducts {\n      id\n      isOnSale\n      isBundleParent\n      price {\n        price\n        salePrice\n        __typename\n      }\n      __typename\n    }\n    ppvExpiration @include(if: $isLoggedIn) {\n      startDeliveryAt\n      __typename\n    }\n    priceSummary {\n      discountedLowestPrice\n      lowestPrice\n      highestPrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment ViewingExpirationForPurchaseModal on VideoViewingExpiration {\n  __typename\n  ... on VideoLegacyViewingExpiration {\n    expireDay\n    __typename\n  }\n  ... on VideoRentalViewingExpiration {\n    startLimitDay\n    expireDay\n    expireHour\n    __typename\n  }\n  ... on VideoFixedViewingExpiration {\n    expiresAt\n    __typename\n  }\n}\n"
                }
            )
            if check_status.status_code == 200:
                content_type = check_status.json()["data"]["videoContent"]["contentType"]
                if content_type == "VOD_VR":
                    from ext import fanza as Fanza
                    return Fanza.Fanza_VR, "Fanza-VR"
        from ext import dmm_tv as Dmm_tv
        return Dmm_tv, "dmm_tv"
    elif re.match(valid_brainshark, url):
        from ext import brainshark as Brainshark
        return Brainshark, "brainshark"
    elif re.match(valid_fod, url):
        from ext import fod_v2 as FOD_v2
        return FOD_v2, "fod"
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
    elif re.match(valid_fanza, url):
        from ext import fanza as Fanza
        return Fanza.Fanza, "Fanza"
    elif ("dmmvrplayerstreaming" in url) or ("vr-sample-player" in url):
        from ext import fanza as Fanza
        return Fanza.Fanza_VR, "Fanza-VR"
    elif (m := re.match(valid_dmm_gravure, url)):
        # CHECK VR OR REGULAR TYPE
        import requests
        check_status = requests.post("https://api.tv.dmm.com/graphql", json = {
            "operationName":"FetchVideoContent",
            "variables":{"id":m.group("season"),"playDevice":"BROWSER","isLoggedIn":False},
            "query":"query FetchVideoContent($id: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!) {\n  videoContent(id: $id) {\n    ...VideoEpisode\n    __typename\n  }\n}\n\nfragment VideoEpisode on VideoContent {\n  id\n  seasonId\n  sampleMovie\n  episodeType\n  episodeImage\n  episodeTitle\n  episodeDetail\n  episodeNumber\n  episodeNumberName\n  contentType\n  priority\n  isWakuwari\n  isAllowComment\n  drmLevel {\n    hasStrictProtection\n    __typename\n  }\n  priceSummary {\n    lowestPrice\n    highestPrice\n    discountedLowestPrice\n    isLimitedPremium\n    __typename\n  }\n  playInfo {\n    contentId\n    duration\n    highestQuality\n    isSupportHDR\n    highestAudioChannelLayout\n    audioRenditions\n    textRenditions\n    parts {\n      contentId\n      duration\n      number\n      resume @include(if: $isLoggedIn) {\n        point\n        isCompleted\n        __typename\n      }\n      __typename\n    }\n    resumePartNumber @include(if: $isLoggedIn)\n    tags\n    __typename\n  }\n  viewingRights(device: $playDevice) {\n    isDownloadable\n    isStreamable\n    downloadableFiles @include(if: $isLoggedIn) {\n      totalFileSize\n      quality {\n        name\n        displayName\n        displayPriority\n        __typename\n      }\n      parts {\n        partNumber\n        fileSize\n        __typename\n      }\n      __typename\n    }\n    windowsURLSchemes: appURLSchemes(app: WINDOWS_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    iosURLSchemes: appURLSchemes(app: IOS_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    androidURLSchemes: appURLSchemes(app: ANDROID_VR) @include(if: $isLoggedIn) {\n      partNumber\n      url\n      __typename\n    }\n    __typename\n  }\n  ppvExpiration @include(if: $isLoggedIn) {\n    expirationType\n    viewingExpiration\n    viewingStartExpiration\n    startDeliveryAt\n    __typename\n  }\n  freeProduct {\n    isBeingDelivered\n    contentId\n    __typename\n  }\n  ppvProducts {\n    id\n    contentId\n    seasonId\n    episodeTitle\n    episodeNumber\n    episodeNumberName\n    contentPriority\n    saleUnitPriority\n    contentType\n    saleUnitName\n    saleType\n    isPreOrder\n    isStreamable\n    isDownloadable\n    isBundleParent\n    isOnSale\n    isBeingDelivered\n    isPurchased @include(if: $isLoggedIn)\n    startDeliveryAt\n    endDeliveryAt\n    campaign {\n      id\n      name\n      endAt\n      isLimitedPremium\n      __typename\n    }\n    price {\n      productId\n      price\n      salePrice\n      isLimitedPremium\n      __typename\n    }\n    viewingExpiration {\n      ...ViewingExpirationForPurchaseModal\n      __typename\n    }\n    bundleProducts {\n      id\n      contentId\n      seasonId\n      episodeTitle\n      episodeNumber\n      episodeNumberName\n      contentPriority\n      saleUnitPriority\n      contentType\n      saleUnitName\n      saleType\n      isPreOrder\n      isStreamable\n      isDownloadable\n      isBundleParent\n      isOnSale\n      isPurchased @include(if: $isLoggedIn)\n      isBeingDelivered\n      startDeliveryAt\n      endDeliveryAt\n      campaign {\n        id\n        name\n        endAt\n        isLimitedPremium\n        __typename\n      }\n      price {\n        productId\n        price\n        salePrice\n        isLimitedPremium\n        __typename\n      }\n      viewingExpiration {\n        ...ViewingExpirationForPurchaseModal\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  svodProduct {\n    startDeliveryAt\n    isBeingDelivered\n    contentId\n    __typename\n  }\n  hasBookmark @include(if: $isLoggedIn)\n  nextEpisode {\n    id\n    seasonId\n    episodeNumberName\n    episodeTitle\n    episodeDetail\n    episodeImage\n    freeProduct {\n      isBeingDelivered\n      contentId\n      __typename\n    }\n    svodProduct {\n      contentId\n      __typename\n    }\n    ppvProducts {\n      id\n      isOnSale\n      isBundleParent\n      price {\n        price\n        salePrice\n        __typename\n      }\n      __typename\n    }\n    ppvExpiration @include(if: $isLoggedIn) {\n      startDeliveryAt\n      __typename\n    }\n    priceSummary {\n      discountedLowestPrice\n      lowestPrice\n      highestPrice\n      isLimitedPremium\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment ViewingExpirationForPurchaseModal on VideoViewingExpiration {\n  __typename\n  ... on VideoLegacyViewingExpiration {\n    expireDay\n    __typename\n  }\n  ... on VideoRentalViewingExpiration {\n    startLimitDay\n    expireDay\n    expireHour\n    __typename\n  }\n  ... on VideoFixedViewingExpiration {\n    expiresAt\n    __typename\n  }\n}\n"
            }
        )
        if check_status.status_code == 200:
            content_type = check_status.json()["data"]["videoContent"]["contentType"]
            if content_type == "VOD_VR":
                from ext import fanza as Fanza
                return Fanza.Fanza_VR, "Fanza-VR"
            elif content_type == "VOD_2D":
                from ext import fanza as Fanza
                return Fanza.Fanza, "Fanza"
    elif re.match(valid_hiyahtv, url):
        from ext import hiyahtv as Hi_YAH
        return Hi_YAH, "Hi-YAH!"
    elif re.match(valid_lemino, url):
        from ext import lemino as Lemino
        return Lemino, "Lemino"
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
