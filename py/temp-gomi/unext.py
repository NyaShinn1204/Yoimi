# util/unext/main.py
import os
import time
import requests

import util.unext.utils.main as util

import data.setting as setting

from tkinter import filedialog
from CTkMessagebox import CTkMessagebox
from playwright.sync_api import sync_playwright

def load_cookie():
    fTyp = [("クッキーファイル","*.txt")]
    iDir = os.path.abspath(os.path.dirname(__file__))
    file_name = filedialog.askopenfilename(filetypes=fTyp, initialdir=iDir, title="U-NEXTのクッキー設定(Netscape)")
    if len(file_name) == 0:
        print('選択をキャンセルしました')
    else:
        
        check_cookie = util.parse_cookiefile(file_name)
        #print(check_cookie)
        if check_cookie != None:
            status, id, message = util.check_cookie(check_cookie)
            if status == True:
                CTkMessagebox(title="成功", message=f"クッキーが有効です\nユーザーID: {id}", font=("BIZ UDゴシック", 13, "normal"))
                setting.global_cookie = check_cookie
            if status == False and message == None:
                CTkMessagebox(title="失敗", message="クッキーが無効です", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
            if status == False and message == "Expired":
                CTkMessagebox(title="失敗", message="クッキーの期限が切れています\n再度取得してください", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
        else:
            CTkMessagebox(title="失敗", message="クッキーを正常に読み込めませんでした", icon="cancel", font=("BIZ UDゴシック", 13, "normal"))
        
def get_title_metadata(title_id):
    import data.setting as setting
    '''メタデータを取得するコード'''
    meta_json = {
        "operationName": "cosmo_getVideoTitle",
        "variables": {"code": title_id},
        "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n",
    }
    try:   
        import json
        config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
        if config_downloader_end["login_method"] == "email":
            metadata_response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
        else:
            metadata_response = requests.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
        return_json = metadata_response.json()
        if return_json["data"]["webfront_title_stage"] != None:
            return True, return_json["data"]["webfront_title_stage"], None
        else:
            if return_json["errors"][1]["message"] == "Token Expired":
                return False, None, "Expired"
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None
    
def get_episode_metadata(title_id):
    import data.setting as setting
    '''エピソードのタイトルについて取得するコード'''
    meta_json = {
        "operationName": "cosmo_getVideoTitleEpisodes",
        "variables": {"code": title_id, "page": 1, "pageSize": 100},
        "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    try:    
        import json
        config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
        if config_downloader_end["login_method"] == "email":
            metadata_response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
        else:
            metadata_response = requests.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
        return_json = metadata_response.json()
        if return_json["data"]["webfront_title_titleEpisodes"] != None:
            return True, return_json["data"]["webfront_title_titleEpisodes"], None
        else:
            if return_json["errors"][1]["message"] == "Token Expired":
                return False, None, "Expired"
            return False, None, None
    except Exception as e:
        print(e)
        return False, None, None

def parse_mpd(content, playtoken, url_code, retries=3, delay=1):
    '''mpdファイルから解像度もろもろ取得'''
    from xml.etree import ElementTree as ET
    from lxml import etree    
    # リトライのループ
    for attempt in range(retries):
        try:
            # 文字列 (str) ではなく bytes としてパース
            if isinstance(content, str):
                content = content.encode('utf-8')  # contentをbytes型に変換
            root = etree.fromstring(content)
            break  # 成功した場合はループを抜ける
        except etree.XMLSyntaxError as e:
            print(f"XMLのパースに失敗しました: {e}. リトライ {attempt + 1}/{retries}")
            if attempt + 1 == retries:
                raise  # 最大リトライ回数に達した場合は例外を再送出
            time.sleep(delay)  # 次のリトライまで待機

    # 名前空間の定義
    namespaces = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
    
    # video情報を取得
    videos = []
    for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="video"]', namespaces):
        for representation in adaptation_set.findall('mpd:Representation', namespaces):
            resolution = f"{representation.get('width')}x{representation.get('height')}"
            codec = representation.get('codecs')
            mimetype = representation.get('mimeType')
            videos.append({
                'resolution': resolution,
                'codec': codec,
                'mimetype': mimetype
            })
    
    # audio情報を取得
    audios = []
    for adaptation_set in root.findall('.//mpd:AdaptationSet[@contentType="audio"]', namespaces):
        for representation in adaptation_set.findall('mpd:Representation', namespaces):
            audio_sampling_rate = representation.get('audioSamplingRate')
            codec = representation.get('codecs')
            mimetype = representation.get('mimeType')
            audios.append({
                'audioSamplingRate': audio_sampling_rate,
                'codec': codec,
                'mimetype': mimetype
            })
    
    # XMLをパース
    namespace = {'': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
    root = ET.fromstring(content)
    
    # 音声と映像のPSSHを取得
    audio_pssh_list = root.findall('.//AdaptationSet[@contentType="audio"]/ContentProtection/cenc:pssh', namespace)
    video_pssh_list = root.findall('.//AdaptationSet[@contentType="video"]/ContentProtection/cenc:pssh', namespace)
    
    audio_pssh = audio_pssh_list[-1] if audio_pssh_list else None
    video_pssh = video_pssh_list[-1] if video_pssh_list else None
    
    ## 結果を表示
    #if audio_pssh is not None:
    #    print("Audio PSSH:", audio_pssh.text)
    #else:
    #    print("Audio PSSH not found")
    #
    #if video_pssh is not None:
    #    print("Video PSSH:", video_pssh.text)
    #else:
    #    print("Video PSSH not found")
    
    # videoとaudio情報を辞書形式で構築
    result = {
        "main_content": content,
        "playtoken": playtoken,
        "video_pssh": video_pssh.text,
        "audio_pssh": audio_pssh.text,
        "url_code": url_code,
        "video": videos,
        "audio": audios[0] if audios else {}
    }
    
    return result