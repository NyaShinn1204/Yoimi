# util/unext/utils/analyze.py
import requests

def get_video_episodes(title_name):
    import data.setting as setting
    meta_json = {
        "operationName": "cosmo_getVideoTitleEpisodes",
        "variables": {"code": title_name},
        "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      results\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
    return [
        {"id": ep["id"], "thumbnail": ep["thumbnail"]["standard"]}
        for ep in response.json()["data"]["webfront_title_titleEpisodes"][
            "episodes"
        ]
    ]

def get_playlist_url(episode_id):
    # ED00317285
    import data.setting as setting
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
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
    return (
        response.json()["data"]["webfront_playlistUrl"]["playToken"],
        response.json()["data"]["webfront_playlistUrl"]["urlInfo"][0]["code"],
    ) 
    
def get_video_episode_meta(episode_id):
    import data.setting as setting
    meta_json = {
        "operationName": "cosmo_getPlaylistUrl",
        "variables": {"code": episode_id, "playMode": "dub", "bitrateLow": 1500},
        "query": "query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    subTitle\n    playToken\n    playTokenHash\n    beaconSpan\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    resultStatus\n    licenseExpireDate\n    urlInfo {\n      code\n      startPoint\n      resumePoint\n      endPoint\n      endrollStartPosition\n      holderId\n      saleTypeCode\n      sceneSearchList {\n        IMS_AD1\n        IMS_L\n        IMS_M\n        IMS_S\n        __typename\n      }\n      movieProfile {\n        cdnId\n        type\n        playlistUrl\n        movieAudioList {\n          audioType\n          __typename\n        }\n        licenseUrlList {\n          type\n          licenseUrl\n          __typename\n        }\n        __typename\n      }\n      umcContentId\n      movieSecurityLevelCode\n      captionFlg\n      dubFlg\n      commodityCode\n      movieAudioList {\n        audioType\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n",
    }
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
    return response.json()["data"]["webfront_playlistUrl"]

def get_mpd_content(url_code, playtoken):
    # 18c529a7-04df-41ee-b230-07f95ecd2561 MEZ0000593320
    import data.setting as setting
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = setting.unext_session.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"})
    else:
        response = setting.unext_session.get(f"https://playlist.unext.jp/playlist/v00001/dash/get/{url_code}.mpd/?file_code={url_code}&play_token={playtoken}", headers={"Referer": f"https://unext.jp/{url_code}?playtoken={playtoken}"}, cookies=setting.unext_auth_cookie)
    
    print(response.status_code)
    return response.text

def get_all_episode_title(title_name):
    import data.setting as setting
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
    
    import json
    config_downloader_end = json.load(open('./data/config.json', 'r', encoding="utf-8"))["downloader_setting"]["unext"] 
    if config_downloader_end["login_method"] == "email":
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json)
    else:
        response = setting.unext_session.post(setting.unext_url_list()["runtimeConfig"]["COMMAND_CENTER"], json=meta_json, cookies=setting.unext_auth_cookie)
    return response.json()["data"]["webfront_title_stage"], response.json()["data"]["webfront_title_titleEpisodes"]["episodes"]