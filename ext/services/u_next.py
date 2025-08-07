import re
import ast
import uuid
import time
import hashlib

__service_config__ = {
    "service_name": "U-Next",
    "require_account": True,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "enable_refresh": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cahce = True
        
        self.device_uuid = None
        self.user_token = None
        self.security_token = None
        
        self.default_payload = {
            "common":{
                "userInfo":{
                    "userToken":None,
                    "service_name":"unext",
                    "securityToken":None
                },
                "deviceInfo":{
                    "deviceType":"980",
                    "appVersion":"1",
                    "deviceUuid":None
                }
            },
            "data": {}
        }
        
        self.default_headers = {
            "user-agent": "U-NEXT TV App Android10 5.49.0 A7S",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)
    
    def parse_input(self, url_input, id = None):        
        if id:
            id = ast.literal_eval(id)
            sid_id = id[0]
            ed_id = id[1]
        else:
            sid_id = re.search(r"(SID\d+)", url_input).group(1)
            ed_id = re.search(r"(ED\d+)", url_input).group(1)
            if "/live/" in url_input:
                return "special"
        
        status, title_info = self.get_title_info(sid_id)
        
        status, all_list = self.get_all_episode(sid_id)
                
        for single in all_list:
            if single["id"] == ed_id:
                video_info = {
                    "raw": title_info,
                    "raw_single": single,
                    "content_type": title_info["mainGenreName"],
                    "title_name": title_info["titleName"],
                    "episode_count": title_info["publicMainEpisodeCount"],
                    "episode_name": single["episodeName"],
                    "episode_num": single["displayNo"],
                    "series_id": title_info["id"]
                }
                
                return video_info
        return "unexception_type_content"
    def parse_input_season(self, url_input):
        sid_id = re.search(r"(SID\d+)", url_input).group(1)
        
        status, title_info = self.get_title_info(sid_id)
        
        status, all_list = self.get_all_episode(sid_id)
        temp_list = []
        
        for single in all_list:
            temp_json = {}
            temp_json["raw"] = single
            temp_json["episode_name"] = single["episodeName"]
            temp_json["episode_num"] = single["displayNo"]
            temp_json["id_in_schema"] = [title_info["id"], single["id"]]
            temp_list.append(temp_json)
        
        video_info = {
            "raw": title_info,
            "episode_list": {
                "metas": temp_list
            }
        }
        
        self.logger.info(" + "+title_info["titleName"])
        
        return None, title_info["titleName"], video_info
    def authorize(self, email_or_id, password):
        _ENDPOINT_LOGIN = "https://napi.unext.jp/1/auth/login"
        
        device_uuid = str(uuid.uuid4())
        
        payload = {
          "common": {
            "userInfo": {
              "userToken": "",
              "service_name": "unext"
            },
            "deviceInfo": {
              "deviceType": "980",
              "appVersion": "1",
              "deviceUuid": device_uuid
            }
          },
          "data": {
            "loginId": email_or_id,
            "password": password
          }
        }
        
        response = self.session.post(_ENDPOINT_LOGIN, json=payload)
        
        user_response = response.json()
        
        if user_response["common"]["result"]["errorCode"] == "":
            
            user_token = user_response["common"]["userInfo"]["userToken"]
            security_token = user_response["common"]["userInfo"]["securityToken"]
            
            ### migrate token
            payload = {
                "client_id": "unextAndroidApp",
                "scope": [
                    "offline",
                    "unext"
                ],
                "portal_user_info": {
                    "securityToken": security_token
                }
            }
            response = self.session.post("https://oauth.unext.jp/oauth2/migration", json=payload)
            
            ### get token
            payload = {
                "client_id": "unextAndroidApp",
                "client_secret": "unextAndroidApp",
                "grant_type": "authorization_code",
                "code": response.json()["auth_code"],
                "redirect_uri": response.json()["redirect_uri"]
            }
            response = self.session.post("https://oauth.unext.jp/oauth2/token", data=payload, headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"})
            
            response = response.json()
            
            session_json = {
                "method": "LOGIN",
                "email": hashlib.sha256(email_or_id.encode()).hexdigest(),
                "password": hashlib.sha256(password.encode()).hexdigest(),
                "access_token": response["access_token"],
                "refresh_token": response["refresh_token"],
                "additional_info": {
                    "device_uuid": device_uuid,
                    "user_token": user_token,
                    "security_token": security_token,
                }
            }
            return True, user_response["common"]["userInfo"], True, session_json
        elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
            return False, 'Wrong Email or password', False, None
        elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
            return False, 'Require Japan VPN, Proxy', False, None
    def authorize_qr(self):
        _ENDPOINT_LOGIN = "https://login-delegation.unext.jp/"
        _ENDPOINT_LOGIN_U = "https://napi.unext.jp/1/auth/login"
       
        device_uuid = str(uuid.uuid4())
        
        payload = {
            "device": {
                "appVersion": "5.49.0",
                "deviceName": "Yoimi",
                "deviceType": "980",
                "deviceUuid": device_uuid,
                "location": "tokyo"
            }
        }
        
        response = self.session.post(_ENDPOINT_LOGIN+"session", json=payload)
        get_qr_link = response.json()
        
        session_check_data = {
          "code": get_qr_link["code"],
          "sessionId": get_qr_link["sessionId"]
        }
        
        print("Login URL:", get_qr_link["authPageUrlTemplate"])
        print("Code:", get_qr_link["code"])
        
        while True:
            send_checkping = self.session.post(_ENDPOINT_LOGIN+"session/poll", json=session_check_data)
            if send_checkping.status_code == 400:
                print("Waiting Login...")
                time.sleep(5)
            elif send_checkping.status_code == 200:
                print("Login Accept")
                                 
                one_time_token = send_checkping.json()["oneTimeToken"]
                
                payload = {
                  "common": {
                    "userInfo": {
                      "userToken": "",
                      "service_name": "unext"
                    },
                    "deviceInfo": {
                      "deviceType": "980",
                      "appVersion": "1",
                      "deviceUuid": device_uuid
                    }
                  },
                  "data": {
                    "onetimeToken": one_time_token
                  }
                }
                
                response = self.session.post(_ENDPOINT_LOGIN_U, json=payload)
                
                user_response = response.json()
                
                if user_response["common"]["result"]["errorCode"] == "":
                    
                    user_token = user_response["common"]["userInfo"]["userToken"]
                    security_token = user_response["common"]["userInfo"]["securityToken"]
                    
                    ### migrate token
                    payload = {
                        "client_id": "unextAndroidApp",
                        "scope": [
                            "offline",
                            "unext"
                        ],
                        "portal_user_info": {
                            "securityToken": security_token
                        }
                    }
                    response = self.session.post("https://oauth.unext.jp/oauth2/migration", json=payload)
                    
                    ### get token
                    payload = {
                        "client_id": "unextAndroidApp",
                        "client_secret": "unextAndroidApp",
                        "grant_type": "authorization_code",
                        "code": response.json()["auth_code"],
                        "redirect_uri": response.json()["redirect_uri"]
                    }
                    response = self.session.post("https://oauth.unext.jp/oauth2/token", data=payload, headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"})
                    
                    response = response.json()
                    
                    session_json = {
                        "method": "LOGIN",
                        "email": None,
                        "password": None,
                        "access_token": response["access_token"],
                        "refresh_token": response["refresh_token"],
                        "additional_info": {
                            "device_uuid": device_uuid,
                            "user_token": user_token,
                            "security_token": security_token,
                        }
                    }
                    return True, user_response["common"]["userInfo"], True, session_json
                elif user_response["common"]["result"]["errorCode"] == "GUN8030006":
                    return False, 'Wrong Email or password', False, None
                elif user_response["common"]["result"]["errorCode"] == "GAW0500003":
                    return False, 'Require Japan VPN, Proxy', False, None
            elif send_checkping.status_code == 403:
                print("Login request is expired")
                return False, None
    def check_token(self, token):
        self.default_payload = {
            "common":{
                "userInfo":{
                    "userToken":self.user_token,
                    "service_name":"unext",
                    "securityToken":self.security_token
                },
                "deviceInfo":{
                    "deviceType":"980",
                    "appVersion":"1",
                    "deviceUuid":self.device_uuid
                }
            },
            "data":{}
        }
        status, profile = self.get_userinfo()
        return status, profile
    def refresh_token(self, refresh_token, session_data):
        try:            
            payload = self.default_payload.copy()
            payload["data"] = {
                "securityToken": session_data["additional_info"]["security_token"]
            }
            refresh_json = self.session.get("https://napi.unext.jp/1/auth/login", json=payload)
            if refresh_json.json()["common"]["result"]["errorCode"] != "":
                return None
            else:
                session_json = {
                    "method": "LOGIN",
                    "email": None,
                    "password": None,
                    "access_token": None,
                    "refresh_token": None,
                    "additional_info": {
                        "device_uuid": payload["common"]["deviceInfo"]["deviceUuid"],
                        "user_token": refresh_json.json()["common"]["userInfo"]["userToken"],
                        "security_token": refresh_json.json()["common"]["userInfo"]["securityToken"],
                    }
                }
                
                self.default_payload = {
                    "common":{
                        "userInfo":{
                            "userToken":refresh_json.json()["common"]["userInfo"]["userToken"],
                            "service_name":"unext",
                            "securityToken":refresh_json.json()["common"]["userInfo"]["securityToken"],
                        },
                        "deviceInfo":{
                            "deviceType":"980",
                            "appVersion":"1",
                            "deviceUuid":payload["common"]["deviceInfo"]["deviceUuid"]
                        }
                    },
                    "data": {}
                }
                
                return session_json
        except:
            return None
    def get_userinfo(self):
        _USER_INFO_API = "https://napi.unext.jp/2/user/account/get"
        
        profile_resposne = self.session.get(_USER_INFO_API, json=self.default_payload)
        if profile_resposne.json()["common"]["result"]["errorCode"] != "":
            return False, None
        else:
            return True, profile_resposne.json()["common"]["userInfo"]
    
    def show_userinfo(self, user_data):
        profile_id = user_data["cuid"]
        self.logger.info("Logged-in Account")
        self.logger.info(" + id: " + profile_id)
        
    def judgment_watchtype(self, url):
        if "/play/" in url:
            return "single"
        if "/live/" in url:
            return "single"
        elif "/title/" in url:
            return "season"
        else:
            return None
    
    def get_title_info(self, sid_id):
        '''メタデータを取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": sid_id},
            "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n",
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                return True, return_json["data"]["webfront_title_stage"]
            else:
                return False, None
        except:
            return False, None
    def get_all_episode(self, sid_id):
        '''エピソードのタイトルについて取得するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitleEpisodes",
            "variables": {"code": sid_id, "page": 1, "pageSize": 1000},
            "query": "query cosmo_getVideoTitleEpisodes($code: ID!, $page: Int, $pageSize: Int) {\n  webfront_title_titleEpisodes(id: $code, page: $page, pageSize: $pageSize) {\n    episodes {\n      id\n      episodeName\n      purchaseEpisodeLimitday\n      thumbnail {\n        standard\n        __typename\n      }\n      duration\n      displayNo\n      interruption\n      completeFlag\n      saleTypeCode\n      introduction\n      saleText\n      episodeNotices\n      isNew\n      hasPackRights\n      minimumPrice\n      hasMultiplePrices\n      productLineupCodeList\n      isPurchased\n      purchaseEpisodeLimitday\n      __typename\n    }\n    pageInfo {\n      ...PageInfo\n      __typename\n    }\n    __typename\n  }\n}\n\nfragment PageInfo on PortalPageInfo {\n  page\n  pages\n  pageSize\n  results\n  __typename\n}\n"
        }
        try:
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_titleEpisodes"] != None:
                metadata_response_single = return_json['data']['webfront_title_titleEpisodes']['episodes']
                return True, metadata_response_single
            else:
                return False, None
        except:
            return False, None
    
    def check_buyed(self, sid_id):
        '''購入済みか確認するコード'''
        meta_json = {
            "operationName": "cosmo_getVideoTitle",
            "variables": {"code": sid_id},
            "query": "query cosmo_getVideoTitle($code: ID!) {\n  webfront_title_stage(id: $code) {\n    id\n    titleName\n    rate\n    userRate\n    productionYear\n    country\n    catchphrase\n    attractions\n    story\n    check\n    seriesCode\n    seriesName\n    publicStartDate\n    displayPublicEndDate\n    restrictedCode\n    copyright\n    mainGenreId\n    bookmarkStatus\n    thumbnail {\n      standard\n      secondary\n      __typename\n    }\n    mainGenreName\n    isNew\n    exclusive {\n      typeCode\n      isOnlyOn\n      __typename\n    }\n    isOriginal\n    lastEpisode\n    updateOfWeek\n    nextUpdateDateTime\n    productLineupCodeList\n    hasMultiprice\n    minimumPrice\n    country\n    productionYear\n    paymentBadgeList {\n      name\n      code\n      __typename\n    }\n    nfreeBadge\n    hasDub\n    hasSubtitle\n    saleText\n    currentEpisode {\n      id\n      interruption\n      duration\n      completeFlag\n      displayDurationText\n      existsRelatedEpisode\n      playButtonName\n      purchaseEpisodeLimitday\n      __typename\n    }\n    publicMainEpisodeCount\n    comingSoonMainEpisodeCount\n    missingAlertText\n    sakuhinNotices\n    hasPackRights\n    __typename\n  }\n}\n",
        }
        try:   
            metadata_response = self.session.post("https://cc.unext.jp", json=meta_json)
            return_json = metadata_response.json()
            if return_json["data"]["webfront_title_stage"] != None:
                if return_json["data"]["webfront_title_stage"]["paymentBadgeList"][0]["id"] == "BUY":
                    return True
                else:
                    return False 
            else:
                return False
        except:
            return False
        
    def get_play_token(self, episode_id, episode_type):
        '''メタデータを取得するコード'''
        payload = self.default_payload.copy()
        payload["data"] = {
            "code": episode_id,
            "bitrate_low": 192,
            "play_type": 2,
            "play_mode": episode_type, ## sub = caption, dub = dub
            "keyonly_flg": 0,
            "validation_flg": 0,
            "codec": [
                "H264",  ## hd flag
                "H265",  ## 4k flag
                "HDR10", ## 4k flag
                "SDR",   ## 4k flag
                "VISION",## 4k flag
                "HLG"    ## 4k flag
            ],
            "audio_type_list": [
                "ac-3",
                "ec-3"
            ]
        }
        try:   
            metadata_response = self.session.post("https://napi.unext.jp/3/cmsuser/playlisturl/file", json=payload)
            return_json = metadata_response.json()
            if return_json["common"]["result"]["errorCode"] == "":

                if ("movie_parts_position_list" in return_json["data"]["url_info"][0]):
                    movieparts = return_json["data"]["url_info"][0]["movie_parts_position_list"]
                else:
                    movieparts = None
                return True, return_json["data"]["play_token"], return_json["data"]["url_info"][0], [movieparts]
            else:
                return False, None, None, None
        except:
            return False, None, None, None
        
    def judgment_sub_dub(self, episode_id):
        payload = self.default_payload.copy()
        payload["data"] = {
            "code": episode_id,
            "bitrate_low": 192,
            "play_type": 2,
            "play_mode": "caption",
            "keyonly_flg": 1,
            "validation_flg": 1,
        }
        try:   
            metadata_response = self.session.post("https://napi.unext.jp/3/cmsuser/playlisturl/file", json=payload)
            return_json = metadata_response.json()
            if return_json["common"]["result"]["errorCode"] == "":
                check_support =return_json["data"]["supported_playmodes"]
                if check_support["has_subtitle"] and check_support["has_dub"]:
                    self.logger.info("Found Sub, Dub type")
                    input_episode_type = input("Please enter the type of the contetn you want to download (e.x: sub, dub) >> ")
                    if input_episode_type.lower() == "sub":
                        episode_type = "caption"
                    elif input_episode_type.lower() == "dub":
                        episode_type = "dub"
                if check_support["has_subtitle"]:
                    episode_type = "caption"
                if check_support["has_dub"]:
                    episode_type = "dub"
                
                
                return True, episode_type
            else:
                return False, None
        except:
            return False, None
    
    def open_session_get_dl(self, video_info):
        global url_info, play_token
        if video_info["raw_single"]["minimumPrice"] != -1:
            self.logger.info(f" ! This contetn require {video_info["raw_single"]["minimumPrice"]} point")
            is_buyed = self.check_buyed(video_info["series_id"])
            if is_buyed == True:
                self.logger.info(f" ! already purchased.")
            else:
                self.logger.error(" ! Please buy content at web.")
                raise Exception("Require rental/buy")
            
        status, episode_type = self.judgment_sub_dub(video_info["raw_single"]["id"])
        
        status, play_token, url_info, additional_meta = self.get_play_token(video_info["raw_single"]["id"], episode_type)
        
        
        if status == False:
            self.logger.error("Failed to get play_token")
            return None, None, None, None
        else:
            dash_profile = url_info["movie_profile"].get("dash")
            mpd_link = dash_profile["playlist_url"]
            if dash_profile.get("license_url_list"):
                widevine_url = dash_profile.get("license_url_list").get("widevine")+f"?play_token={play_token}"
                playready_url = dash_profile.get("license_url_list").get("playready")+f"?play_token={play_token}"
                
            mpd_response = self.session.get(mpd_link+f"&play_token={play_token}").text
            license_header = {
                "content-type": "application/octet-stream",
                "user-agent": "Beautiful_Japan_TV_Android/1.0.6 (Linux;Android 10) ExoPlayerLib/2.12.0",
                "accept-encoding": "gzip",
                "host": "wvproxy.unext.jp",
                "connection": "Keep-Alive"
            }
            return mpd_response, mpd_link+f"&play_token={play_token}", {"widevine": widevine_url, "playready": playready_url}, license_header 
        
    def decrypt_done(self):
        self.close_session(media_code=url_info["code"], play_token=play_token)    
    
    def close_session(self, media_code, play_token):
        signal_result = self.session.get(f"https://beacon.unext.jp/beacon/stop/{media_code}/0/?play_token={play_token}&last_viewing_flg=0")
        
        if signal_result.status_code == 200:
            return True
        else:
            return False
        
    
    
    ### SPECIAL LOGIC HERE(LIVE)
    def special_logic(self, url_input):
        self.logger.info("Live Content Detect")
        
        liv_id = re.search(r"(LIV\d+)", url_input).group(1)
        
        get_data = self.get_live_info(liv_id)
        self.logger.info("Live Name: "+get_data["live_name"])
        
        template_url, public_key = self.check_config()
        template_url = template_url.format(titleId=liv_id)
        
        self.logger.info("Checking available watch")
        available_watch, data_info = self.get_playlist(template_url)
        self.logger.info(" + "+str(available_watch))
        if available_watch == False:
            return
        
        playlist_info = self.get_playlist_api(liv_id)
        
        if data_info["result_status"] == 200:
            dash_profile = data_info["endpoint_urls"][0]["playables"].get("dash")
            mpd_link = dash_profile["playlist_url"]
            if dash_profile.get("license_url_list"):
                widevine_url = dash_profile.get("license_url_list").get("widevine")+f"?play_token={play_token}"
                playready_url = dash_profile.get("license_url_list").get("playready")+f"?play_token={play_token}"
    
                ### migrate token
                payload = {
                    "client_id": "unextAndroidApp",
                    "scope": [
                        "offline",
                        "unext"
                    ],
                    "portal_user_info": {
                        "securityToken": self.default_payload["common"]["userInfo"]["securityToken"]
                    }
                }
                response = self.session.post("https://oauth.unext.jp/oauth2/migration", json=payload)
                
                ### get token
                payload = {
                    "client_id": "unextAndroidApp",
                    "client_secret": "unextAndroidApp",
                    "grant_type": "authorization_code",
                    "code": response.json()["auth_code"],
                    "redirect_uri": response.json()["redirect_uri"]
                }
                response = self.session.post("https://oauth.unext.jp/oauth2/token", data=payload, headers={"content-type": "application/x-www-form-urlencoded; charset=utf-8"})
                
                response = response.json()
                
                ### create live content play_token
                payload = {
                    "_at": response["access_token"]
                }
                response = self.session.post("https://stunt-right.ca.unext.jp/PROD/llp", json=payload)
                
                play_token = response.json()["long_lived_playtoken"]
                
                
                ### get isem
                payload = {
                    "long_lived_playtoken": play_token,
                    "device_id": self.default_payload["common"]["deviceInfo"]["deviceUuid"]
                }
                response = self.session.post("https://stunt-right.ca.unext.jp/PROD/isem", json=payload).json()
                isem_token = response["isem_token"]
                
                ### activation isem
                headers = {
                    "u-isem-token": isem_token
                }
                response = self.session.post(f"https://wabit-isem.ca.unext.jp/activate_token?device_id={self.default_payload["common"]["deviceInfo"]["deviceUuid"]}&overwrite=1").json()
                activate_isem_token = response["token"]
                
                #### 五分経ったら新しいの取得
                # time.sleep(300)
                headers = {
                    "u-isem-token": activate_isem_token
                }
                response = self.session.post(f"https://wabit-isem.ca.unext.jp/refresh_token?device_id={self.default_payload["common"]["deviceInfo"]["deviceUuid"]}&overwrite=0").json()
                activate_isem_token = response["token"]
                
                ### revoke isem
                querystring = { "device_id": self.default_payload["common"]["deviceInfo"]["deviceUuid"] }
                
                headers = {
                    "u-isem-token": isem_token,
                }
                self.session.post("https://wabit-isem.ca.unext.jp/discard_token", headers=headers, params=querystring)
                
    
    def get_live_info(self, liv_id):
        payload = self.default_payload.copy()
        payload["data"] = {
            "live_code": liv_id
        }
        
        response = self.session.post("https://napi.unext.jp/1/lcms/live", json=payload)
        if response.json()["common"]["result"]["errorCode"] == "":
            return response.json()["data"]
        else:
            return None
        
    def check_config(self):
        config_response = self.session.get("https://rconf.unext.jp/unext/common/config.json").json()
        template_url = config_response["live_llp"]["static_playlist_url_template"]
        public_key = config_response["live_llp"]["public_key"]
        return template_url, public_key
    
    def get_playlist(self, template_url):
        config_response = self.session.get(template_url)
        if config_response.status_code == 403:
            return False, None
        else:
            return True, config_response.json()["data"]
        
    def get_playlist_api(self, liv_id):
        payload = self.default_payload.copy()
        payload["data"] = {
            "live_code": liv_id,
            "validation_flg": False
        }
        
        response = self.session.post("https://napi.unext.jp/3/lcms/live_playlisturl", json=payload)
        if response.json()["common"]["result"]["errorCode"] == "":
            return response.json()["data"]
        else:
            return None