import json
import requests

config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 

def get_title_metadata(title_id):
    import data.setting as setting
    unext_instance = setting.Unext()
    '''メタデータを取得するコード'''
    meta_json = {
        "operationName": "cosmo_getVideoTitle",
        "variables": {"code": title_id},
        "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n",
    }
    try:
        if config_downloader_end["login_method"] == "email":
            metadata_response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
        else:
            metadata_response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
        return_json = metadata_response.json()
        if return_json["data"]["webfront_title_stage"] != None:
            return True, return_json["data"]["webfront_title_stage"], None
        else:
            if return_json["errors"][1]["message"] == "Token Expired":
                return False, None, "Expired"
            return False, None, None
    except Exception as e:
        print("[-] Error: "+e)
        return False, None, None
    
def get_episode_metadata(title_id):
    import data.setting as setting
    unext_instance = setting.Unext()
    '''エピソードのタイトルについて取得するコード'''
    meta_json = {
        "operationName": "cosmo_getVideoTitleEpisodes",
        "variables": {"code": title_id, "page": 1, "pageSize": 100},
        "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    try:
        if config_downloader_end["login_method"] == "email":
            metadata_response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
        else:
            metadata_response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
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
    
def get_playlist_url(episode_id):
    # ED00317285
    import data.setting as setting
    unext_instance = setting.Unext()
    meta_json = {
        "operationName": "cosmo_getPlaylistUrl",
        "variables": {
            "code": episode_id,
            "playMode": "dub",
            "bitrateLow": 1500,
            "bitrateHigh": None,
            "validationOnly": False,
        },
        "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    if config_downloader_end["login_method"] == "email":
        metadata_response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        metadata_response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
    if metadata_response.json()["data"]["webfront_playlistUrl"]["resultStatus"] == 475:
        print("[-] Session is invalid")
    if metadata_response.json()["data"]["webfront_playlistUrl"]["resultStatus"] == 462:
        print("[-] ほかのデバイスで再生なう")
    return (
        metadata_response.json()["data"]["webfront_playlistUrl"]["playToken"],
        metadata_response.json()["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"],
    ) 
    
def get_mpd_content(url_code, playtoken):
    # 18c529a7-04df-41ee-b230-07f95ecd2561 MEZ0000593320
    import data.setting as setting
    unext_instance = setting.Unext()
    if config_downloader_end["login_method"] == "email":
        response = unext_instance.session.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"})
    else:
        response = requests.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"}, cookies=unext_instance.auth_cookie)
    return response.text

def get_video_episodes(title_name):
    import data.setting as setting
    unext_instance = setting.Unext()
    meta_json = {
        "operationName": "cosmo_getVideoTitleEpisodes",
        "variables": {"code": title_name},
        "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
    return [
        {"id": ep["id"], "thumbnail": ep["thumbnail"]["standard"]}
        for ep in response.json()["data"]["webfront_title_titleEpisodes"][
            "episodes"
        ]
    ]
    
def get_all_episode_title(title_name):
    import data.setting as setting
    unext_instance = setting.Unext()
    meta_json = {
        "operationName": "cosmo_getTitle",
        "variables": {
            "id": title_name,
            "episodeCode": "",
            "episodePageSize": 1000,
            "episodePage": 1,
        },
        "query": "query cosmo_getTitle($id: ID!, $episodeCode: ID!, $episodePage: Int, $episodePageSize: Int) {\n  webfront_title_stage(id: $id) {\n    id\n    titleName\n    publishStyleCode\n    episode(id: $episodeCode) {\n      id\n      hasSubtitle\n      hasDub\n      __typename\n    }\n    __typename\n  }\n  webfront_title_titleEpisodes(\n    id: $id\n    page: $episodePage\n    pageSize: $episodePageSize\n  ) {\n    episodes {\n      id\n      episodeName\n      displayNo\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      interruption\n      completeFlag\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    if config_downloader_end["login_method"] == "email":
        response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
    return response.json()["data"]["webfront_title_stage"], response.json()["data"]["webfront_title_titleEpisodes"]["episodes"]

def get_video_episode_meta(episode_id):
    import data.setting as setting
    unext_instance = setting.Unext()
    meta_json = {
        "operationName": "cosmo_getPlaylistUrl",
        "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
        "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    if config_downloader_end["login_method"] == "email":
        response = unext_instance.session.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = requests.post(unext_instance.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=unext_instance.auth_cookie)
    return response.json()["data"]["webfront_playlistUrl"]