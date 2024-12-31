#The following code is partially modified code from DRMLAB-VT1.0.zip distributed within the DRMLab Project and PlayReady-Amazon-Tool-works.zip distributed by mcmasterhit.
#
#Most of the code is copied.

import os
import re
import time
import math
import html
import json
import hashlib
import requests
import logging
import jsonpickle
from enum import Enum
from pathlib import Path
from langcodes import Language
from tldextract import tldextract
from collections import defaultdict
from urllib.parse import urlencode, quote
from http.cookiejar import MozillaCookieJar
from langcodes import Language, closest_match

class Types(Enum):
    CHROME = 1
    ANDROID = 2
    PLAYREADY = 3

class Amazon_downloader:
    def __init__(self, session, pv_status):
        self.session = session
        self.service = "Amazon"
        self.cdn = None
        self.vcodec = None
        self.orig_bitrate = None
        self.vquality = None
        self.vrange = None
        self.profile = None
        self.domain_region = None
        self.device_id = None
        self.device_token = None
        self.chapters_only = None
        self.client_id = "f22dbddb-ef2c-48c5-8876-bed0d47594fd"  # browser client id
        self.VIDEO_RANGE_MAP = {
            "SDR": "None",
            "HDR10": "Hdr10",
            "DV": "DolbyVision",
        }
        self.pv = pv_status # if url is primevideo
        self.region = {
            "us": {
              "base": "www.amazon.com",
              "base_api": "api.amazon.com",
              "base_manifest": "atv-ps.amazon.com",
              "marketplace_id": "ATVPDKIKX0DER"
            },
            "gb": {
              "base": "www.amazon.co.uk",
              "base_api": "api.amazon.co.uk",
              "base_manifest": "atv-ps-eu.amazon.co.uk",
              "marketplace_id": "A2IR4J4NTCP2M5"
            },
            "it": {
              "base": "www.amazon.it",
              "base_api": "api.amazon.it",
              "base_manifest": "atv-ps-eu.primevideo.com",
              "marketplace_id": "A3K6Y4MI8GDYMT"
            },
            "de": {
              "base": "www.amazon.de",
              "base_api": "api.amazon.de",
              "base_manifest": "atv-ps-eu.amazon.de",
              "marketplace_id": "A1PA6795UKMFR9"
            },
            "au": {
              "base": "www.amazon.com.au",
              "base_api": "api.amazon.com.au",
              "base_manifest": "atv-ps-fe.amazon.com.au",
              "marketplace_id": "A3K6Y4MI8GDYMT"
            },
            "jp": {
              "base": "www.amazon.co.jp",
              "base_api": "api.amazon.co.jp",
              "base_manifest": "atv-ps-fe.amazon.co.jp",
              "marketplace_id": "A1VC38T7YXB528"
            },
            "pl": {
              "base": "www.amazon.com",
              "base_api": "api.amazon.com",
              "base_manifest": "atv-ps-eu.primevideo.com",
              "marketplace_id": "A3K6Y4MI8GDYMT"
            }
          }
        self.endpoints = {
          "browse": "/cdp/catalog/Browse",
          "details": "/gp/video/api/getDetailPage",
          "playback": "/cdp/catalog/GetPlaybackResources",
          "licence": "/cdp/catalog/GetPlaybackResources",
          "xray": "/swift/page/xray",
          "ontv": "/gp/video/ontv/code",
          "devicelink": "/gp/video/api/codeBasedLinking",
          "codepair": "/auth/create/codepair",
          "register": "/auth/register",
          "token": "/auth/token"
        }
        self.device = {
          "default": {
            "domain": "Device",
            "app_name": "AIV",
            "app_version": '3.12.0',
            "device_model": 'SHIELD Android TV',
            "os_version": '28',
            "device_type": "A1KAXIG6VXSG8Y",
            "device_serial": '13f5b56b4a17de5d136f0e4c28236109',  # `os.urandom(8).hex()`
            "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Shield TV",
            "software_version": '248'
          }
        }
        
    def update_variable(self, variable_name, value):
        """
        Updates the value of the specified instance variable if it exists.

        Args:
            variable_name (str): The name of the instance variable to update.
            value: The new value to assign to the variable.

        Raises:
            AttributeError: If the variable does not exist.
        """
        if hasattr(self, variable_name):
            setattr(self, variable_name, value)
        else:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{variable_name}'")

    def get_cache(self, key):
        """
        Get path object for an item from service Cache. The path object can then be
        used to read or write to the cache under the item's key.

        Parameters:
            key: A string similar to a relative path to an item.
        """
        return os.path.join("cache", "AMZN", key)
    def parse_cookie(self, profile):
        """Get the profile's cookies if available."""
        cookie_file = os.path.join("cookies", self.service.lower(), f"{profile}.txt")
        if not os.path.isfile(cookie_file):
            cookie_file = os.path.join("cookies", self.service, f"{profile}.txt")
        if os.path.isfile(cookie_file):
            cookie_jar = MozillaCookieJar(cookie_file)
            with open(cookie_file, "r+", encoding="utf-8") as fd:
                unescaped = html.unescape(fd.read())
                fd.seek(0)
                fd.truncate()
                fd.write(unescaped)
            cookie_jar.load(ignore_discard=True, ignore_expires=True)
            self.cookies = cookie_jar
            return cookie_jar
        return None
    def get_domain_region(self):
        """Get the region of the cookies from the domain."""
        tlds = [tldextract.extract(x.domain) for x in self.cookies if x.domain_specified]
        tld = next((x.suffix for x in tlds if x.domain.lower() in ("amazon", "primevideo")), None)
        if tld:
            tld = tld.split(".")[-1]
        return {"com": "us", "uk": "gb"}.get(tld, tld)
    def get_region(self) -> dict:
        domain_region = self.get_domain_region()
        if not domain_region:
            return {}, "Region Not Found"

        region = self.region.get(domain_region)
        if not region:
            #raise self.log.exit(f" - There's no region configuration data for the region: {domain_region}")
            return {}, f"There's no region configuration data for the region: {domain_region}" 

        region["code"] = domain_region

        if self.pv:
            res = self.session.get("https://www.primevideo.com").text
            match = re.search(r'ue_furl *= *([\'"])fls-(na|eu|fe)\.amazon\.[a-z.]+\1', res)
            if match:
                pv_region = match.group(2).lower()
            else:
                #raise self.log.exit(" - Failed to get PrimeVideo region")
                return {}, "Not Match Primevideo region" 
            pv_region = {"na": "atv-ps"}.get(pv_region, f"atv-ps-{pv_region}")
            region["base_manifest"] = f"{pv_region}.primevideo.com"
            region["base"] = "www.primevideo.com"
            
        self.domain_region = domain_region
        
        return region, None, self.cookies
    def prepare_endpoint(self, name: str, uri: str, region: dict) -> str:
        if name in ("browse", "playback", "licence", "xray"):
            return f"https://{(region['base_manifest'])}{uri}"
        if name in ("ontv", "devicelink", "details"):
            if self.pv:
                host = "www.primevideo.com"
            else:
                host = region["base"]
            return f"https://{host}{uri}"
        if name in ("codepair", "register", "token"):
            return f"https://{self.region['us']['base_api']}{uri}"
        raise ValueError(f"Unknown endpoint: {name}")

    def prepare_endpoints(self, region: dict) -> dict:
        return {k: self.prepare_endpoint(k, v, region) for k, v in self.endpoints.items()}
    def get_device(self, profile, endpoints):
        self.endpoints = endpoints
        self.profile = profile
        return (self.device or {}).get(profile, {})

    def register_device(self, session, profile, logger):
        self.register_v_device = (self.device or {}).get(profile, {})
        device_cache_path = self.get_cache("device_tokens_{profile}_{hash}.json".format(
            profile=profile,
            hash=hashlib.md5(json.dumps(self.register_v_device).encode()).hexdigest()[0:6]
        ))
        self.session = session
        self.device_token = self.DeviceRegistration(
            device=self.register_v_device,
            endpoints=self.endpoints,
            log=logger,
            cache_path=device_cache_path,
            session=self.session
        ).bearer
        self.device_id = self.register_v_device.get("device_serial")
        if not self.device_id:
            raise logger.error(f" - A device serial is required in the config, perhaps use: {os.urandom(8).hex()}", extra={"service_name": "Amazon"})
        return self.device_id, self.device_token

    def choose_manifest(self, manifest: dict, cdn=None):
        """Get manifest URL for the title based on CDN weight (or specified CDN)."""
        if cdn:
            cdn = cdn.lower()
            manifest = next((x for x in manifest["audioVideoUrls"]["avCdnUrlSets"] if x["cdn"].lower() == cdn), {})
            if not manifest:
                raise print(f" - There isn't any DASH manifests available on the CDN \"{cdn}\" for this title")
        else:
            manifest = next((x for x in sorted([x for x in manifest["audioVideoUrls"]["avCdnUrlSets"]], key=lambda x: int(x["cdnWeightsRank"]))), {})

        return manifest
    def clean_mpd_url(self, mpd_url, optimise=False):
        """Clean up an Amazon MPD manifest url."""
        if optimise:
            return mpd_url.replace("~", "") + "?encoding=segmentBase"
        if match := re.match(r"(https?://.*/)d.?/.*~/(.*)", mpd_url):
            mpd_url = "".join(match.groups())
        else:
            try:
                mpd_url = "".join(
                    re.split(r"(?i)(/)", mpd_url)[:5] + re.split(r"(?i)(/)", mpd_url)[9:]
                )
            except IndexError:
                print("Unable to parse MPD URL")

        return mpd_url
    
    def remove_duplicates_and_count(tracks):
        # 重複の検出用辞書
        unique_tracks = {}
        duplicates_count = 0
    
        for track in tracks:
            #print(track["content_type"])
            # ハッシュ可能なタプル化（重要な識別可能なフィールドをキーとする）
            try:
                if track["content_type"] == "video":
                    track_key = (
                        track.get("height"),
                        track.get("widthge"),
                        track.get("bitrate"),
                    )
                elif track["content_type"] == "audio":
                    track_key = (
                        track.get("codec"),
                        track.get("channels"),
                        track.get("bitrate"),
                    )
                elif track["content_type"] == "text":
                    track_key = (
                        track.get("codec"),
                        track.get("language"),
                    )
                else:
                    print("wtf", str(track))
        
                if track_key in unique_tracks:
                    duplicates_count += 1  # 重複カウント
                else:
                    unique_tracks[track_key] = track
            except:
                print("wtf", str(track))
    
        # 重複のないリストを生成
        unique_track_list = list(unique_tracks.values())
    
        #print(f"- Found and skipped {duplicates_count} duplicate tracks")
        return unique_track_list
    def select_print_tracks(self, data):
        result = {"video_track": [], "audio_track": [], "text_track": []}
    
        # Select the best video track
        if "video_track" in data:
            best_video = max(
                data["video_track"],
                key=lambda x: (int(x["bitrate"]), x["width"], x["height"]),
                default=None
            )
            result["video_track"].append(best_video)
    
        # Select the best audio track
        if "audio_track" in data:
            best_audio = max(
                data["audio_track"],
                key=lambda x: int(x["bitrate"]),
                default=None
            )
            result["audio_track"].append(best_audio)
    
        # Select the first text track
        if "text_track" in data:
            best_text = data["text_track"][0] if data["text_track"] else None
            result["text_track"].append(best_text)
    
        return result

    def free_license_widevine(self, id, pssh, device_type):
        from pywidevine.cdm import Cdm
        from pywidevine.device import Device
        from pywidevine.pssh import PSSH
        device = Device.load(
            "./l3.wvd"
        )
        cdm = Cdm.from_device(device)
        print(self.region["jp"])
        print(self.device_token)
        lic = self.session.post(
            url=self.endpoints["licence"],
            params={
                "asin": id,
                "consumptionType": "Streaming",
                "desiredResources": "Widevine2License",
                "deviceTypeID": device_type,
                "deviceID": self.device_id,
                "firmware": 1,
                "gascEnabled": str(self.pv).lower(),
                "marketplaceID": self.region["jp"]["marketplace_id"],
                "resourceUsage": "ImmediateConsumption",
                "videoMaterialType": "Feature",
                "operatingSystemName": "Linux" if self.vquality == "SD" else "Windows",
                "operatingSystemVersion": "unknown" if self.vquality == "SD" else "10.0",
                "customerID": self.customer_id,
                "deviceDrmOverride": "CENC",
                "deviceStreamingTechnologyOverride": "DASH",
                "deviceVideoQualityOverride": self.vquality,
                "deviceHdrFormatsOverride": self.VIDEO_RANGE_MAP.get(self.vrange, "None"),
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {self.device_token}"
            },
            data={
                "widevine2Challenge": bytes(cdm.get_license_challenge(cdm.open(), PSSH(pssh))),  # expects base64
                "includeHdcpTestKeyInLicense": "true"
            }
        ).json()
        print(lic)

    # ここでいろいろゲッチュ
    def get_original_language(self, manifest):
        """Get a title's original language from manifest data."""
        try:
            return next(
                x["language"].replace("_", "-")
                for x in manifest["catalogMetadata"]["playback"]["audioTracks"]
                if x["isOriginalLanguage"]
            )
        except (KeyError, StopIteration):
            pass

        if "defaultAudioTrackId" in manifest.get("playbackUrls", {}):
            try:
                return manifest["playbackUrls"]["defaultAudioTrackId"].split("_")[0]
            except IndexError:
                pass

        try:
            return sorted(
                manifest["audioVideoUrls"]["audioTrackMetadata"],
                key=lambda x: x["index"]
            )[0]["languageCode"]
        except (KeyError, IndexError):
            pass

        return None
    def get_titles(self, session, title_id, single, vcodec, bitrate, vquality):
        self.real_value_titles = [vcodec, bitrate, vquality]
        self.session = session
        self.title = title_id
        self.single = single
        res = self.session.get(
            url=self.endpoints["details"],
            params={
                "titleID": self.title,
                "isElcano": "1",
                "sections": ["Atf", "Btf"]
            },
            headers={
                "Accept": "application/json"
            }
        )

        if not res.ok:
            raise print(f"Unable to get title: {res.text} [{res.status_code}]")

        data = res.json()["widgets"]
        product_details = data.get("productDetails", {}).get("detail")

        if not product_details:
            error = res.json()["degradations"][0]
            raise print(f"Unable to get title: {error['message']} [{error['code']}]")

        titles = []

        if data["pageContext"]["subPageType"] == "Movie":
            card = data["productDetails"]["detail"]

            temp_json = {}
            temp_json["id"] = card["catalogId"]
            temp_json["type"] = "Movie"
            temp_json["name"] = product_details["title"]
            temp_json["year"] = card.get("releaseYear", "")
            titles.append(temp_json)
        else:
            if not data["titleContent"]:
                episodes = data["episodeList"]["episodes"]
                for episode in episodes:
                    details = episode["detail"]
                    temp_json = {}
                    temp_json["id"] = details["catalogId"]
                    temp_json["type"] = "TV"
                    temp_json["name"] = product_details["title"]
                    temp_json["season"] = data["productDetails"]["detail"]["seasonNumber"]
                    temp_json["episode"] = episode["self"]["sequenceNumber"]
                    temp_json["episode_name"] = details["title"]                    
                    temp_json["year"] = details["releaseYear"]
                    temp_json["deny_download"] = not episode["action"].get("downloadActions")
                    if (
                        (action := episode.get("action"))
                        and (download_actions := action.get("downloadActions"))
                        and (main := download_actions.get("main"))
                        and (children := main.get("children"))
                        and isinstance(children, list)
                        and len(children) > 0
                        and "entitlementType" in children[0]
                    ):
                        temp_json["free"] = children[0]["entitlementType"] == "FREE"
                    else:
                        temp_json["free"] = False
                    #if (
                    #    (action := episode.get("action"))
                    #    and (playback_actions := action.get("playbackActions"))
                    #    and (main := playback_actions.get("main"))
                    #    and (children := main.get("children"))
                    #    and isinstance(children, list)
                    #    and len(children) > 0
                    #    and "entitlementType" in children[0]
                    #):
                    #    temp_json["free_id"] = children[0]["playbackID"]
                    #else:
                    #    temp_json["free_id"] = None
                    titles.append(temp_json)
                if len(titles) == 25:
                    page_count = 1
                    pagination_data = data.get('episodeList', {}).get('actions', {}).get('pagination', [])
                    token = next((quote(item.get('token')) for item in pagination_data if item.get('tokenType') == 'NextPage'), None)
                    while True:
                        page_count += 1
                        res = self.session.get(
                            url=self.endpoints["getDetailWidgets"],
                            params={
                                "titleID": self.title,
                                "isTvodOnRow": "1",
                                "widgets": f'[{{"widgetType":"EpisodeList","widgetToken":"{token}"}}]'
                            },
                            headers={
                                "Accept": "application/json"
                            }
                        ).json()
                        episodeList = res['widgets'].get('episodeList', {})
                        for item in episodeList.get('episodes', []):
                            episode = int(item.get('self', {}).get('sequenceNumber', {}))
                            temp_json = {}
                            temp_json["id"] = item["detail"]["catalogId"]
                            temp_json["type"] = "TV"
                            temp_json["name"] = product_details["parentTitle"]
                            temp_json["season"] = product_details["seasonNumber"]
                            temp_json["episode"] = episode
                            temp_json["episode_name"] = item["detail"]["title"]
                            temp_json["year"] = item["detail"]["releaseYear"]
                            temp_json["deny_download"] = not item["detail"]["action"].get("downloadActions")
                            if (
                                (detail := item.get("detail"))
                                and (action := detail.get("action"))
                                and (download_actions := action.get("downloadActions"))
                                and (main := download_actions.get("main"))
                                and (children := main.get("children"))
                                and isinstance(children, list)
                                and len(children) > 0
                                and "entitlementType" in children[0]
                            ):
                                temp_json["free"] = children[0]["entitlementType"] == "FREE"
                            else:
                                temp_json["free"] = False
                            #if (
                            #    (detail := item.get("detail"))
                            #    and (action := detail.get("action"))
                            #    and (playback_actions := action.get("playbackActions"))
                            #    and (main := playback_actions.get("main"))
                            #    and (children := main.get("children"))
                            #    and isinstance(children, list)
                            #    and len(children) > 0
                            #    and "entitlementType" in children[0]
                            #):
                            #    temp_json["free_id"] = children[0]["playbackID"]
                            #else:
                            #    temp_json["free_id"] = None
                            titles.append(temp_json)
                        pagination_data = res['widgets'].get('episodeList', {}).get('actions', {}).get('pagination', [])
                        token = next((quote(item.get('token')) for item in pagination_data if item.get('tokenType') == 'NextPage'), None)
                        if not token:
                            break
            else:
                cards = [
                    x["detail"]
                    for x in data["titleContent"][0]["cards"]
                        if not self.single or
                           (self.single and self.title in data["self"]["asins"]) or (self.single and self.title in data["self"]["compactGTI"]) or
                           (self.single and self.title in x["self"]["asins"]) or (self.single and self.title == x["detail"]["catalogId"])
                ]
                for card in cards:
                    episode_number = card.get("episodeNumber", 0)
                    if episode_number != 0:
                        temp_json = {}
                        temp_json["id"] = card["catalogId"]
                        temp_json["type"] = "TV"
                        temp_json["name"] = product_details["parentTitle"]
                        temp_json["season"] = product_details["seasonNumber"]
                        temp_json["episode"] = episode_number
                        temp_json["episode_name"] = card["title"]                    
                        temp_json["year"] = card.get("releaseYear", "")
                        titles.append(temp_json)
            
            if not self.single:
                temp_title = self.title
                temp_single = self.single
            
                self.single = True
                for season in data.get('seasonSelector', []):
                    season_link = season["seasonLink"]
                    match = re.search(r'/([a-zA-Z0-9]+)\/ref=', season_link)    #extract other season id using re 
                    if match:
                        extracted_value = match.group(1)
                        if data["self"]["compactGTI"] == extracted_value:   #skip entered asin season data and grab rest id's
                            continue
                        
                        self.title = extracted_value
                        for title in self.get_titles(self.session, self.title, self.single, vcodec, bitrate, vquality):
                            titles.append(title)
            
                self.title = temp_title
                self.single = temp_single
                
        if titles:
            # TODO: Needs playback permission on first title, title needs to be available
            manifest_temp = self.get_manifest(
                next((x for x in titles if x["type"] == "Movie" or x["episode"] > 0), titles[0]),
                video_codec=vcodec,
                bitrate_mode=bitrate,
                quality=vquality,
                ignore_errors=True
            )
            original_lang = self.get_original_language(manifest_temp)
            if original_lang:
                for title in titles:
                    title["original_lang"] = Language.get(original_lang)
            else:
                #self.log.warning(" - Unable to obtain the title's original language, setting 'en' default...")
                for title in titles:
                    title["original_lang"] = Language.get("en")
        filtered_titles = []
        season_episode_count = defaultdict(int)
        for title in titles:
            key = (title["season"], title["episode"]) 
            if season_episode_count[key] < 1:
                filtered_titles.append(title)
                season_episode_count[key] += 1

        titles = filtered_titles
        
        self.real_titles = titles
        
        return titles
    def get_manifest(
        self, title: json, video_codec: str, bitrate_mode: str, quality: str, hdr=None,
            ignore_errors: bool = False
    ) -> dict:
        res = self.session.get(
            url=self.endpoints["playback"],
            params={
                "asin": title["id"],
                "consumptionType": "Streaming",
                "desiredResources": ",".join([
                    "PlaybackUrls",
                    "AudioVideoUrls",
                    "CatalogMetadata",
                    "ForcedNarratives",
                    "SubtitlePresets",
                    "SubtitleUrls",
                    "TransitionTimecodes",
                    "TrickplayUrls",
                    "CuepointPlaylist",
                    "XRayMetadata",
                    "PlaybackSettings",
                ]),
                "deviceID": self.device_id,
                "deviceTypeID": self.device[self.profile]["device_type"],
                "firmware": 1,
                "gascEnabled": str(self.pv).lower(),
                "marketplaceID": self.region[self.domain_region]["marketplace_id"],
                "resourceUsage": "CacheResources",
                "videoMaterialType": "Feature",
                "playerType": "html5",
                "clientId": self.client_id,
                **({
                    "operatingSystemName": "Linux" if quality == "SD" else "Windows",
                    "operatingSystemVersion": "unknown" if quality == "SD" else "10.0",
                } if not self.device_token else {}),
                "deviceDrmOverride": "CENC",
                "deviceStreamingTechnologyOverride": "DASH",
                "deviceProtocolOverride": "Https",
                "deviceVideoCodecOverride": video_codec,
                "deviceBitrateAdaptationsOverride": bitrate_mode.replace("+", ","),
                "deviceVideoQualityOverride": quality,
                "deviceHdrFormatsOverride": self.VIDEO_RANGE_MAP.get(hdr, "None"),
                "supportedDRMKeyScheme": "DUAL_KEY",  # ?
                "liveManifestType": "live,accumulating",  # ?
                "titleDecorationScheme": "primary-content",
                "subtitleFormat": "TTMLv2",
                "languageFeature": "MLFv2",  # ?
                "uxLocale": "en_US",
                "xrayDeviceClass": "normal",
                "xrayPlaybackMode": "playback",
                "xrayToken": "XRAY_WEB_2020_V1",
                "playbackSettingsFormatVersion": "1.0.0",
                "playerAttributes": json.dumps({"frameRate": "HFR"}),
                # possibly old/unused/does nothing:
                "audioTrackId": "all",
            },
            headers={
                "Authorization": f"Bearer {self.device_token}" if self.device_token else None,
            },
        )
        try:
            manifest = res.json()
        except json.JSONDecodeError:
            if ignore_errors:
                return {}

            raise print(" - Amazon didn't return JSON data when obtaining the Playback Manifest.")

        if "error" in manifest:
            if ignore_errors:
                return {}
            raise print(" - Amazon reported an error when obtaining the Playback Manifest.")

        # Commented out as we move the rights exception check elsewhere
        # if "rightsException" in manifest["returnedTitleRendition"]["selectedEntitlement"]:
        #     if ignore_errors:
        #         return {}
        #     raise print(" - The profile used does not have the rights to this title.")

        # Below checks ignore NoRights errors

        if (
          manifest.get("errorsByResource", {}).get("PlaybackUrls") and
          manifest["errorsByResource"]["PlaybackUrls"].get("errorCode") != "PRS.NoRights.NotOwned"
        ):
            if ignore_errors:
                return {}
            error = manifest["errorsByResource"]["PlaybackUrls"]
            raise print(f" - Amazon had an error with the Playback Urls: {error['message']} [{error['errorCode']}]")

        if (
          manifest.get("errorsByResource", {}).get("AudioVideoUrls") and
          manifest["errorsByResource"]["AudioVideoUrls"].get("errorCode") != "PRS.NoRights.NotOwned"
        ):
            if ignore_errors:
                return {}
            error = manifest["errorsByResource"]["AudioVideoUrls"]
            raise print(f" - Amazon had an error with the A/V Urls: {error['message']} [{error['errorCode']}]")

        return manifest
    def get_tracks(self, title, device):
        self.device[self.profile]["device_type"] = device["device_type"]
        #tracks = Tracks()
        #if self.chapters_only:
        #    return []
#
        #manifest, chosen_manifest, tracks = self.get_best_quality(title)
#
        manifest = self.get_manifest(
            title,
            video_codec=self.vcodec,
            bitrate_mode=self.orig_bitrate,
            quality=self.vquality,
            hdr=self.vrange,
            ignore_errors=False
            
        )
        #
        ## Move rightsException termination here so that script can attempt continuing
        #if "rightsException" in manifest["returnedTitleRendition"]["selectedEntitlement"]:
        #    self.log.error(" - The profile used does not have the rights to this title.")
        #    return
#
        self.customer_id = manifest["returnedTitleRendition"]["selectedEntitlement"]["grantedByCustomerId"]
#
        #default_url_set = manifest["playbackUrls"]["urlSets"][manifest["playbackUrls"]["defaultUrlSetId"]]
        #encoding_version = default_url_set["urls"]["manifest"]["encodingVersion"]
        #self.log.info(f" + Detected encodingVersion={encoding_version}")
#
        chosen_manifest = self.choose_manifest(manifest, self.cdn)

        if not chosen_manifest:
            raise print(f"No manifests available")
#
        manifest_url = self.clean_mpd_url(chosen_manifest["avUrlInfoList"][0]["url"], False)
        print(manifest_url)
        print(chosen_manifest)
        print(" + Downloading Manifest")
        
        # ALIASES = ["AMZN", "amazon"]
        #v_a_tracks = {"video_track": [], "audio_track": []}        

        if chosen_manifest["streamingTechnology"] == "DASH":
            print("ここでmpdをparseする。")
            #tracks = Tracks([
            #    x for x in iter(Tracks.from_mpd(
            #        url=manifest_url,
            #        session=self.session,
            #        source=self.ALIASES[0],
            #    ))
            #])
            tracks = Amazon_downloader.Mpd_parse.get_mpd_content(
                url=manifest_url,
                session=self.session,
                source="AMZN"
            )
           #print(tracks)

        elif chosen_manifest["streamingTechnology"] == "SmoothStreaming":
            print("ok unsupported")
            #tracks = Tracks([
            #    x for x in iter(Tracks.c(
            #        url=manifest_url,
            #        session=self.session,
            #        source=self.ALIASES[0],
            #    ))
            #])
        else:
            raise print(f"Unsupported manifest type: {chosen_manifest['streamingTechnology']}")
        
#
        #need_separate_audio = ((self.aquality or self.vquality) != self.vquality
        #                       or self.amanifest == "CVBR" and (self.vcodec, self.bitrate) != ("H264", "CVBR")
        #                       or self.amanifest == "CBR" and (self.vcodec, self.bitrate) != ("H264", "CBR")
        #                       or self.amanifest == "H265" and self.vcodec != "H265"
        #                       or self.amanifest != "H265" and self.vcodec == "H265")
#
        #if not need_separate_audio:
        #    audios = defaultdict(list)
        #    for audio in tracks.audios:
        #        audios[audio.language].append(audio)
#
        #    for lang in audios:
        #        if not any((x.bitrate or 0) >= 640000 for x in audios[lang]):
        #            need_separate_audio = True
        #            break
#
        #if need_separate_audio and not self.atmos:
        #    manifest_type = self.amanifest or "H265"
        #    self.log.info(f"Getting audio from {manifest_type} manifest for potential higher bitrate or better codec")
        #    audio_manifest = self.get_manifest(
        #        title=title,
        #        video_codec="H265" if manifest_type == "H265" else "H264",
        #        bitrate_mode="CVBR" if manifest_type != "CBR" else "CBR",
        #        quality=self.aquality or self.vquality,
        #        hdr=None,
        #        ignore_errors=True
        #    )
        #    if not audio_manifest:
        #        self.log.warning(f" - Unable to get {manifest_type} audio manifests, skipping")
        #    elif not (chosen_audio_manifest := self.choose_manifest(audio_manifest, self.cdn)):
        #        self.log.warning(f" - No {manifest_type} audio manifests available, skipping")
        #    else:
        #        audio_mpd_url = self.clean_mpd_url(chosen_audio_manifest["avUrlInfoList"][0]["url"], optimise=False)
        #        self.log.debug(audio_mpd_url)
        #        self.log.info(" + Downloading HEVC manifest")
#
        #        try:
        #            audio_mpd = Tracks([
        #                x for x in iter(Tracks.from_mpd(
        #                    url=audio_mpd_url,
        #                    session=self.session,
        #                    source=self.ALIASES[0],
        #                ))
        #            ])
        #        except KeyError:
        #            self.log.warning(f" - Title has no {self.amanifest} stream, cannot get higher quality audio")
        #        else:
        #            tracks.add(audio_mpd.audios, warn_only=True)  # expecting possible dupes, ignore
#
        #need_uhd_audio = self.atmos
#
        #if not self.amanifest and ((self.aquality == "UHD" and self.vquality != "UHD") or not self.aquality):
        #    audios = defaultdict(list)
        #    for audio in tracks.audios:
        #        audios[audio.language].append(audio)
        #    for lang in audios:
        #        if not any((x.bitrate or 0) >= 640000 for x in audios[lang]):
        #            need_uhd_audio = True
        #            break
#
        #if need_uhd_audio and (self.config.get("device") or {}).get(self.profile, None):
        #    self.log.info("Getting audio from UHD manifest for potential higher bitrate or better codec")
        #    temp_device = self.device
        #    temp_device_token = self.device_token
        #    temp_device_id = self.device_id
        #    uhd_audio_manifest = None
#
        #    try:
        #        if self.cdm.device.type == Types.CHROME and self.quality < 2160:
        #            self.log.info(f" + Switching to device to get UHD manifest")
        #            self.register_device()
#
        #        uhd_audio_manifest = self.get_manifest(
        #            title=title,
        #            video_codec="H265",
        #            bitrate_mode="CVBR+CBR",
        #            quality="UHD",
        #            hdr="DV",  # Needed for 576kbps Atmos sometimes
        #            ignore_errors=True
        #        )
        #    except:
        #        pass
#
        #    self.device = temp_device
        #    self.device_token = temp_device_token
        #    self.device_id = temp_device_id
#
        #    if not uhd_audio_manifest:
        #        self.log.warning(f" - Unable to get UHD manifests, skipping")
        #    elif not (chosen_uhd_audio_manifest := self.choose_manifest(uhd_audio_manifest, self.cdn)):
        #        self.log.warning(f" - No UHD manifests available, skipping")
        #    else:
        #        uhd_audio_mpd_url = self.clean_mpd_url(chosen_uhd_audio_manifest["avUrlInfoList"][0]["url"], optimise=False)
        #        self.log.debug(uhd_audio_mpd_url)
        #        self.log.info(" + Downloading UHD manifest")
#
        #        try:
        #            uhd_audio_mpd = Tracks([
        #                x for x in iter(Tracks.from_mpd(
        #                    url=uhd_audio_mpd_url,
        #                    session=self.session,
        #                    source=self.ALIASES[0],
        #                ))
        #            ])
        #        except KeyError:
        #            self.log.warning(f" - Title has no UHD stream, cannot get higher quality audio")
        #        else:
        #            # replace the audio tracks with DV manifest version if atmos is present
        #            if any(x for x in uhd_audio_mpd.audios if x.atmos):
        #                tracks.audios = uhd_audio_mpd.audios
#
        for video in tracks["video_track"]:
            video["hdr10"] = chosen_manifest["hdrFormat"] == "Hdr10"
            video["dv"] = chosen_manifest["hdrFormat"] == "DolbyVision"

        for audio in tracks["audio_track"]:
            audio["descriptive"] = audio["extra"][1].get("audioTrackSubtype") == "descriptive"
            # Amazon @lang is just the lang code, no dialect, @audioTrackId has it.
            audio_track_id = audio["extra"][1].get("audioTrackId")
            if audio_track_id:
                audio["language"] = Language.get(audio_track_id.split("_")[0])  # e.g. es-419_ec3_blabla
                
        #return tracks
#
        for sub in manifest.get("subtitleUrls", []) + manifest.get("forcedNarratives", []):
            tracks["text_track"].append({
                "content_type": "text",
                "id_":sub.get(
                    "timedTextTrackId",
                    f"{sub['languageCode']}_{sub['type']}_{sub['subtype']}_{sub['index']}"
                ),
                "source":"AMZN",
                "url":os.path.splitext(sub["url"])[0] + ".srt",  # DFXP -> SRT forcefully seems to work fine
                # metadata
                "codec":"srt",  # sub["format"].lower(),
                "language":sub["languageCode"],
                #is_original_lang:title.original_lang and is_close_match(sub["languageCode"], [title.original_lang]),
                "forced":"forced" in sub["displayName"],
                "sdh":sub["type"].lower() == "sdh"  # TODO: what other sub types? cc? forced?
              })  # expecting possible dupes, ignore
                
        tracks["text_track"] = Amazon_downloader.remove_duplicates_and_count(
            tracks["text_track"]
        )
        return tracks, chosen_manifest, manifest
    def get_track_name(self, track):
        TERRITORY_MAP = {
            "001": "",
            "150": "European",
            "419": "Latin American",
            "AU": "Australian",
            "BE": "Flemish",
            "BR": "Brazilian",
            "CA": "Canadian",
            "CZ": "",
            "DK": "",
            "EG": "Egyptian",
            "ES": "European",
            "FR": "European",
            "GB": "British",
            "GR": "",
            "HK": "Hong Kong",
            "IL": "",
            "IN": "",
            "JP": "",
            "KR": "",
            "MY": "",
            "NO": "",
            "PH": "",
            "PS": "Palestinian",
            "PT": "European",
            "SE": "",
            "SY": "Syrian",
            "US": "American",
        }
        self.language = Language.get(track["language"] or "en")
        """Return the base track name. This may be enhanced in subclasses."""
        if self.language is None:
            self.language = Language.get("en")
        if ((self.language.language or "").lower() == (self.language.territory or "").lower()
                and self.language.territory not in TERRITORY_MAP):
            self.language.territory = None  # e.g. de-DE
        if self.language.territory == "US":
            self.language.territory = None
        language = self.language.simplify_script()
        extra_parts = []
        if language.script is not None:
            extra_parts.append(language.script_name())
        if language.territory is not None:
            territory = language.territory_name()
            extra_parts.append(TERRITORY_MAP.get(language.territory, territory))
        return ", ".join(extra_parts) or None
    def get_print_track(self, track):
        text_temp = ""  
        total_duplicates = {"video_track": 0, "audio_track": 0, "text_track": 0}
    
        for track_type in ["video_track", "audio_track", "text_track"]:
            if track_type in track:
                # 重複を削除
                unique_tracks = []
                seen = set()
                for item in track[track_type]:
                    if isinstance(item, dict):
                        # アイテム全体をユニーク化するために内容をタプル化
                        item_tuple = tuple((key, item[key]) for key in sorted(item.keys()))
                    else:
                        # 辞書以外の要素をそのまま比較
                        item_tuple = item
    
                    if item_tuple not in seen:
                        seen.add(item_tuple)
                        unique_tracks.append(item)
                    else:
                        total_duplicates[track_type] += 1
    
                track[track_type] = unique_tracks
    
        # 重複スキップログ
        for track_type, duplicates in total_duplicates.items():
            if duplicates > 0:
                print(f"- Found and skipped {duplicates} duplicate tracks in {track_type}")


        CODEC_MAP = {
            # Video
            "avc1": "H.264",
            "avc3": "H.264",
            "hev1": "H.265",
            "hvc1": "H.265",
            "dvh1": "H.265",
            "dvhe": "H.265",
            # Audio
            "aac": "AAC",
            "mp4a": "AAC",
            "stereo": "AAC",
            "HE": "HE-AAC",
            "ac3": "AC3",
            "ac-3": "AC3",
            "eac": "E-AC3",
            "eac-3": "E-AC3",
            "ec-3": "E-AC3",
            "atmos": "E-AC3",
            # Subtitles
            "srt": "SRT",
            "vtt": "VTT",
            "wvtt": "VTT",
            "dfxp": "TTML",
            "stpp": "TTML",
            "ttml": "TTML",
            "tt": "TTML",
        }
        
        text_temp += f"{len(track['video_track']) - total_duplicates['video_track']} Video Tracks:\n"
        for index, video in enumerate(track["video_track"]):
            vencode = 'HDR10' if video["hdr10"] else 'HLG' if video["hlg"] else 'DV' if video["dv"] else 'SDR'
            quality = f"{video['width']}x{video['height']}"
            bitrate = f"{str(int(video['bitrate']) // 1000) if video['bitrate'] else '?'}"
            if "/" in str(video["fps"]):
                num, den = video["fps"].split("/")
                video["fps"] = int(num) / int(den)
            elif video["fps"]:
                video["fps"] = float(video["fps"])
            else:
                video["fps"] = None
            encode_fps = f"{video['fps']:.3f}" if video["fps"] else "Unknown"
            text_temp += "├─ VID | [{vcodec}, {vencode}] | {quality} @ {bitrate} kb/s, {fps} FPS".format(
                vcodec=CODEC_MAP[video["codec"]], 
                vencode=vencode, 
                quality=quality, 
                bitrate=bitrate, 
                fps=encode_fps
            )
            if index < len(track["video_track"]) - 1:  # 最後の行以外に改行を追加
                text_temp += "\n"
        
        text_temp += f"\n{len(track["audio_track"]) - total_duplicates["audio_track"]} Audio Tracks:\n"
        def parse_channels(channels):
            """
            Converts a string to a float-like string which represents audio channels.
            E.g. "2" -> "2.0", "6" -> "5.1".
            """
            # TODO: Support all possible DASH channel configurations (https://datatracker.ietf.org/doc/html/rfc8216)
            if channels == "A000":
                return "2.0"
            if channels == "F801":
                return "5.1"
    
            try:
                channels = str(float(channels))
            except ValueError:
                channels = str(channels)
    
            if channels == "6.0":
                return "5.1"
    
            return channels
        def is_close_match(language, languages):
            LANGUAGE_MAX_DISTANCE = 5
            if not (language and languages and all(languages)):
                return False
            languages = list(map(str, [x for x in languages if x]))
            return closest_match(language, languages)[1] <= LANGUAGE_MAX_DISTANCE
        for index, audio in enumerate(track["audio_track"]):
            original_lang = self.get_original_language(self.get_manifest(
                next((x for x in self.real_titles if x["type"] == "Movie" or x["episode"] > 0), self.real_titles[0]),
                video_codec=self.real_value_titles[0],
                bitrate_mode=self.real_value_titles[1],
                quality=self.real_value_titles[2],
                ignore_errors=True
            ))
            is_original_lang = is_close_match(audio["language"], [original_lang])
            option = "".join([self.get_track_name(audio) or "", "| [Original]" if is_original_lang else ""])
            text_temp += "├─ AUD | [{acodec}] | [{atmos}] | {channel} | {bitrate} kb/s | {language} {option}".format(
                acodec=CODEC_MAP[audio["codec"]],
                atmos=audio["codec"],
                channel=parse_channels(audio["channels"]),
                bitrate=str(int(math.ceil(float(audio["bitrate"]))) // 1000 if audio["bitrate"] else "?"),
                language=Language.get(audio["language"] or "en"),
                option=option
            )
            if index < len(track["audio_track"]) - 1:
                text_temp += "\n"

        # Text Tracks
        text_temp += f"\n{len(track['text_track']) - total_duplicates['text_track']} Text Tracks:\n"
        for index, text in enumerate(track["text_track"]):
            track_name = ""
            flag = text["sdh"] and "SDH" or text["forced"] and "Forced"
            if flag:
                if track_name:
                    flag = f" ({flag})"
                track_name += flag
            original_lang = self.get_original_language(self.get_manifest(
                next((x for x in self.real_titles if x["type"] == "Movie" or x["episode"] > 0), self.real_titles[0]),
                video_codec=self.real_value_titles[0],
                bitrate_mode=self.real_value_titles[1],
                quality=self.real_value_titles[2],
                ignore_errors=True
            ))
            is_original_lang = is_close_match(text["language"], [original_lang])
            option = "".join(["| [Original]" if is_original_lang else ""])
            text_temp += "├─ SUB | [{codec}] | {language} | {track_name} {option}".format(
                codec=CODEC_MAP[text["codec"]],
                language=text["language"],
                track_name=track_name,
                option=option
            )
            if index < len(track["text_track"]) - 1:
                text_temp += "\n"
        
        return text_temp
    class Mpd_parse:
        class Descriptor(Enum):
            URL = 1  # Direct URL, nothing fancy
            M3U = 2  # https://en.wikipedia.org/wiki/M3U (and M3U8)
            MPD = 3  # https://en.wikipedia.org/wiki/Dynamic_Adaptive_Streaming_over_HTTP
        def load_xml(xml):
            from lxml import etree
            if not isinstance(xml, bytes):
                xml = xml.encode("utf-8")
            root = etree.fromstring(xml)
            for elem in root.getiterator():
                if not hasattr(elem.tag, "find"):
                    # e.g. comment elements
                    continue
                elem.tag = etree.QName(elem).localname
            etree.cleanup_namespaces(root)
            return root
        def pt_to_sec(d):
            if isinstance(d, float):
                return d
            if d[0:2] == "P0":
                d = d.replace("P0Y0M0DT", "PT")
            if d[0:2] != "PT":
                raise ValueError("Input data is not a valid time string.")
            d = d[2:].upper()  # skip `PT`
            m = re.findall(r"([\d.]+.)", d)
            return sum(
                float(x[0:-1]) * {"H": 60 * 60, "M": 60, "S": 1}[x[-1].upper()]
                for x in m
            )
        def get_mpd_content(*, url=None, data=None, source, session=None, downloader=None):
            v_a_tracks = {"video_track": [], "audio_track": [], "text_track": []}
            import uuid
            import math
            import base64
            import urllib.parse
            from copy import copy
            from hashlib import md5
            from langcodes import Language
            from langcodes.tag_parser import LanguageTagError
            tracks = []
            if not data:
                if not url:
                    raise ValueError("Neither a URL nor a document was provided to Tracks.from_mpd")
                base_url = url.rsplit('/', 1)[0] + '/'
                if downloader is None:
                    data = (session or requests).get(url).text
                else:
                    raise ValueError(f"Unsupported downloader: {downloader}")
        
            root = Amazon_downloader.Mpd_parse.load_xml(data)  
            if root.tag != "MPD":
                raise ValueError("Non-MPD document provided to Tracks.from_mpd")
            for period in root.findall("Period"):
                if source == "HULU" and next(iter(period.xpath("SegmentType/@value")), "content") != "content":
                    continue
        
                period_base_url = period.findtext("BaseURL") or root.findtext("BaseURL")
                if url and not period_base_url or not re.match("^https?://", period_base_url.lower()):
                    period_base_url = urllib.parse.urljoin(url, period_base_url)
                    period_base_url = period_base_url.replace('manifests.api.hbo.com', 'cmaf.cf.eu.hbomaxcdn.com')
        
                for adaptation_set in period.findall("AdaptationSet"):
                    if any(x.get("schemeIdUri") == "http://dashif.org/guidelines/trickmode"
                           for x in adaptation_set.findall("EssentialProperty")
                           + adaptation_set.findall("SupplementalProperty")):
                        # Skip trick mode streams (used for fast forward/rewind)
                        continue
        
                    for rep in adaptation_set.findall("Representation"):
                        # content type
                        try:
                            content_type = next(x for x in [
                                rep.get("contentType"),
                                rep.get("mimeType"),
                                adaptation_set.get("contentType"),
                                adaptation_set.get("mimeType")
                            ] if bool(x))
                        except StopIteration:
                            raise ValueError("No content type value could be found")
                        else:
                            content_type = content_type.split("/")[0]
                        if content_type.startswith("image"):
                            continue  # most likely seek thumbnails
                        # codec
                        codecs = rep.get("codecs") or adaptation_set.get("codecs")
                        if content_type == "text":
                            mime = adaptation_set.get("mimeType")
                            if mime and not mime.endswith("/mp4"):
                                codecs = mime.split("/")[1]
                        # language
                        track_lang = None
                        for lang in [rep.get("lang"), adaptation_set.get("lang")]:
                            lang = (lang or "").strip()
                            if not lang:
                                continue
                            try:
                                t = Language.get(lang.split("-")[0])
                                if t == Language.get("und") or not t.is_valid():
                                    raise LanguageTagError()
                            except LanguageTagError:
                                continue
                            else:
                                track_lang = Language.get(lang)
                                break
        
                        # content protection
                        protections = rep.findall("ContentProtection") + adaptation_set.findall("ContentProtection")
                        encrypted = bool(protections)
                        playready_pssh = None
                        widevine_pssh = None
                        kid = None
                        for protection in protections:
                            # For HMAX, the PSSH has multiple keys but the PlayReady ContentProtection tag
                            # contains the correct KID
                            kid = protection.get("default_KID")
                            if kid:
                                kid = uuid.UUID(kid).hex
                            else:
                                kid = protection.get("kid")
                                if kid:
                                    kid = uuid.UUID(bytes_le=base64.b64decode(kid)).hex
                            if (protection.get("schemeIdUri") or "").lower() == "urn:uuid:9a04f079-9840-4286-ab92-e65be0885f95": # playready
                                playready_pssh = protection.findtext("pssh")
                            if (protection.get("schemeIdUri") or "").lower() == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed": # widevine
                                widevine_pssh = protection.findtext("pssh")
                            else:
                                continue
                        
                        rep_base_url = rep.findtext("BaseURL")
                        if rep_base_url and source not in ["DSCP", "DSNY"]:  # TODO: Don't hardcode services
                            # this mpd allows us to download the entire file in one go, no segmentation necessary!
                            if not re.match("^https?://", rep_base_url.lower()):
                                rep_base_url = urllib.parse.urljoin(period_base_url, rep_base_url)
                            query = urllib.parse.urlparse(url).query
                            if query and not urllib.parse.urlparse(rep_base_url).query:
                                rep_base_url += "?" + query
                            track_url = rep_base_url
        
                        else:
                            # this mpd provides no way to download the entire file in one go :(
                            segment_template = rep.find("SegmentTemplate")
                            if segment_template is None:
                                segment_template = adaptation_set.find("SegmentTemplate")
                            if segment_template is None:
                                raise ValueError("Couldn't find a SegmentTemplate for a Representation.")
                            segment_template = copy(segment_template)
        
                            # join value with base url
                            for item in ("initialization", "media"):
                                if not segment_template.get(item):
                                    continue
                                segment_template.set(
                                    item, segment_template.get(item).replace("$RepresentationID$", rep.get("id"))
                                )
                                query = urllib.parse.urlparse(url).query
                                if query and not urllib.parse.urlparse(segment_template.get(item)).query:
                                    segment_template.set(item, segment_template.get(item) + "?" + query)
                                if not re.match("^https?://", segment_template.get(item).lower()):
                                    segment_template.set(item, urllib.parse.urljoin(
                                        period_base_url if not rep_base_url else rep_base_url, segment_template.get(item)
                                    ))
        
                            period_duration = period.get("duration")
                            if period_duration:
                                period_duration = Amazon_downloader.Mpd_parse.pt_to_sec(period_duration)
                            mpd_duration = root.get("mediaPresentationDuration")
                            if mpd_duration:
                                mpd_duration = Amazon_downloader.Mpd_parse.pt_to_sec(mpd_duration)
        
                            track_url = []
        
                            def replace_fields(url, **kwargs):
                                for field, value in kwargs.items():
                                    url = url.replace(f"${field}$", str(value))
                                    m = re.search(fr"\${re.escape(field)}%([a-z0-9]+)\$", url, flags=re.I)
                                    if m:
                                        url = url.replace(m.group(), f"{value:{m.group(1)}}")
                                return url
        
                            initialization = segment_template.get("initialization")
                            if initialization:
                                # header/init segment
                                track_url.append(replace_fields(
                                    initialization,
                                    Bandwidth=rep.get("bandwidth"),
                                    RepresentationID=rep.get("id")
                                ))
        
                            start_number = int(segment_template.get("startNumber") or 1)
        
                            segment_timeline = segment_template.find("SegmentTimeline")
                            if segment_timeline is not None:
                                seg_time_list = []
                                current_time = 0
                                for s in segment_timeline.findall("S"):
                                    if s.get("t"):
                                        current_time = int(s.get("t"))
                                    for _ in range(1 + (int(s.get("r") or 0))):
                                        seg_time_list.append(current_time)
                                        current_time += int(s.get("d"))
                                seg_num_list = list(range(start_number, len(seg_time_list) + start_number))
                                track_url += [
                                    replace_fields(
                                        segment_template.get("media"),
                                        Bandwidth=rep.get("bandwidth"),
                                        Number=n,
                                        RepresentationID=rep.get("id"),
                                        Time=t
                                    )
                                    for t, n in zip(seg_time_list, seg_num_list)
                                ]
                            else:
                                period_duration = period_duration or mpd_duration
                                segment_duration = (
                                    float(segment_template.get("duration")) / float(segment_template.get("timescale") or 1)
                                )
                                total_segments = math.ceil(period_duration / segment_duration)
                                track_url += [
                                    replace_fields(
                                        segment_template.get("media"),
                                        Bandwidth=rep.get("bandwidth"),
                                        Number=s,
                                        RepresentationID=rep.get("id"),
                                        Time=s
                                    )
                                    for s in range(start_number, start_number + total_segments)
                                ]
        
                        # for some reason it's incredibly common for services to not provide
                        # a good and actually unique track ID, sometimes because of the lang
                        # dialect not being represented in the id, or the bitrate, or such.
                        # this combines all of them as one and hashes it to keep it small(ish).
                        track_id = "{codec}-{lang}-{bitrate}-{extra}".format(
                            codec=codecs,
                            lang=track_lang,
                            bitrate=rep.get("bandwidth") or 0,  # subs may not state bandwidth
                            extra=(adaptation_set.get("audioTrackId") or "") + (rep.get("id") or ""),
                        )
                        track_id = md5(track_id.encode()).hexdigest()
        
                        if content_type == "video":
                            temp_json = {
                                "note": None,
                                "size": None,
                                "content_type": "video",
                                "id_": track_id,
                                "source": source,
                                "url": track_url,
                                # metadata
                                "codec": (codecs or "").split(".")[0],
                                "language": track_lang,
                                "bitrate": rep.get("bandwidth"),
                                "width": int(rep.get("width") or 0) or adaptation_set.get("width"),
                                "height": int(rep.get("height") or 0) or adaptation_set.get("height"),
                                "fps": rep.get("frameRate") or adaptation_set.get("frameRate"),
                                "hdr10": any(
                                    x.get("schemeIdUri") == "urn:mpeg:mpegB:cicp:TransferCharacteristics"
                                    and x.get("value") == "16"  # PQ
                                    for x in adaptation_set.findall("SupplementalProperty")
                                ) or any(
                                    x.get("schemeIdUri") == "http://dashif.org/metadata/hdr"
                                    and x.get("value") == "SMPTE2094-40"  # HDR10+
                                    for x in adaptation_set.findall("SupplementalProperty")
                                ),
                                "hlg": any(
                                    x.get("schemeIdUri") == "urn:mpeg:mpegB:cicp:TransferCharacteristics"
                                    and x.get("value") == "18"  # HLG
                                    for x in adaptation_set.findall("SupplementalProperty")
                                ),
                                "dv": codecs and codecs.startswith(("dvhe", "dvh1")),
                                # switches/options
                                "descriptor": 3,
                                # decryption
                                "encrypted": encrypted,
                                "playready_pssh": playready_pssh,
                                "widevine_pssh": widevine_pssh,
                                "kid": kid,
                                # extra
                                "extra": (rep, adaptation_set)
                            }
                            
                            v_a_tracks["video_track"].append(temp_json)
        
                        elif content_type == "audio":
                            temp_json = {
                                "note": None,
                                "size": None,
                                "content_type": "audio",
                                "id_": track_id,
                                "source": source,
                                "url": track_url,
                                # metadata
                                "codec": (codecs or "").split(".")[0],
                                "language": track_lang,
                                "bitrate": rep.get("bandwidth"),
                                "channels": next(iter(
                                    rep.xpath("AudioChannelConfiguration/@value")
                                    or adaptation_set.xpath("AudioChannelConfiguration/@value")
                                ), None),
                                "descriptive": any(
                                    x.get("schemeIdUri") == "urn:mpeg:dash:role:2011" and x.get("value") == "description"
                                    for x in adaptation_set.findall("Accessibility")
                                ),
                                # switches/options
                                "descriptor": 3,
                                # decryption
                                "encrypted": encrypted,
                                "playready_pssh": playready_pssh,
                                "widevine_pssh": widevine_pssh,
                                "kid": kid,
                                # extra
                                "extra": (rep, adaptation_set)
                            }
                            
                            v_a_tracks["audio_track"].append(temp_json)
                        elif content_type == "text":
                            print("text cxomeGetting auto")
                            if source == 'HMAX':
                                # HMAX SUBS
                                segment_template = rep.find("SegmentTemplate")
        
                                sub_path_url = rep.findtext("BaseURL")
                                if not sub_path_url:
                                    sub_path_url = segment_template.get('media')
                               
                                try:
                                    path = re.search(r'(t\/.+?\/)t', sub_path_url).group(1)
                                except AttributeError:
                                    path = 't/sub/'
                                
                                is_normal = any(x.get("value") == "subtitle" for x in adaptation_set.findall("Role"))
                                is_sdh = any(x.get("value") == "caption" for x in adaptation_set.findall("Role"))
                                is_forced = any(x.get("value") == "forced-subtitle" for x in adaptation_set.findall("Role"))
        
                                if is_normal:
                                    track_url = [base_url + path + adaptation_set.get('lang') + '_sub.vtt']
                                elif is_sdh:
                                    track_url = [base_url + path + adaptation_set.get('lang') + '_sdh.vtt']
                                elif is_forced:
                                    track_url = [base_url + path + adaptation_set.get('lang') + '_forced.vtt']
        
                                temp_json = {
                                    "content_type": "text",
                                    "id_": track_id,
                                    "source": source,
                                    "url": track_url,
                                    # metadata
                                    "codec": (codecs or "").split(".")[0],
                                    "language": track_lang,
                                    "forced": is_forced if 'is_forced' in locals() else None,  # 'is_forced' が存在すれば設定
                                    "sdh": is_sdh if 'is_sdh' in locals() else None,  # 'is_sdh' が存在すれば設定
                                    "cc": False,
                                    # switches/options
                                    "descriptor": Amazon_downloader.Mpd_parse.Descriptor.MPD,
                                    # extra
                                    "extra": (rep, adaptation_set)
                                }
                                
                                v_a_tracks["text_track"].append(temp_json)
                            else:
                                temp_json = {
                                    "content_type": "text",
                                    "id_": track_id,
                                    "source": source,
                                    "url": track_url,
                                    # metadata
                                    "codec": (codecs or "").split(".")[0],
                                    "language": track_lang,
                                    "sdh": is_sdh if 'is_sdh' in locals() else None,
                                    "cc": False,
                                    # switches/options
                                    "descriptor": Amazon_downloader.Mpd_parse.Descriptor.MPD,
                                    # extra
                                    "extra": (rep, adaptation_set)
                                }
                                
                                v_a_tracks["text_track"].append(temp_json)
        
            # Add tracks, but warn only. Assume any duplicate track cannot be handled.
            # Since the custom track id above uses all kinds of data, there realistically would
            # be no other workaround.
            # ここfor分
            #tracks_obj = Tracks()
            #print(tracks)
            #tracks_obj.add(tracks, warn_only=True)
        
            #print("Video tracks:", v_a_tracks["video_track"])
            #print("Audio tracks:", v_a_tracks["audio_track"])
            #print("Text tracks:", v_a_tracks["text_track"])
            v_a_tracks["video_track"] = Amazon_downloader.remove_duplicates_and_count(
                v_a_tracks["video_track"]
            )
            v_a_tracks["audio_track"] = Amazon_downloader.remove_duplicates_and_count(
                v_a_tracks["audio_track"]
            )
            v_a_tracks["text_track"] = Amazon_downloader.remove_duplicates_and_count(
                v_a_tracks["text_track"]
            )
            return v_a_tracks

    class DeviceRegistration:

        def __init__(self, device: dict, endpoints: dict, cache_path: Path, session: requests.Session, log: logging.Logger):
            self.session = session
            self.device = device
            self.endpoints = endpoints
            self.cache_path = cache_path
            self.log = log

            self.device = {k: str(v) if not isinstance(v, str) else v for k, v in self.device.items()}

            self.bearer = None
            if os.path.isfile(self.cache_path):
                with open(self.cache_path, encoding="utf-8") as fd:
                    cache = jsonpickle.decode(fd.read())
                #self.device["device_serial"] = cache["device_serial"]
                if cache.get("expires_in", 0) > int(time.time()):
                    # not expired, lets use
                    self.log.info(" + Using cached device bearer", extra={"service_name": "Amazon"})
                    self.bearer = cache["access_token"]
                else:
                    # expired, refresh
                    self.log.info("Cached device bearer expired, refreshing...", extra={"service_name": "Amazon"})
                    refreshed_tokens = self.refresh(self.device, cache["refresh_token"])
                    refreshed_tokens["refresh_token"] = cache["refresh_token"]
                    # expires_in seems to be in minutes, create a unix timestamp and add the minutes in seconds
                    refreshed_tokens["expires_in"] = int(time.time()) + int(refreshed_tokens["expires_in"])
                    with open(self.cache_path, "w", encoding="utf-8") as fd:
                        fd.write(jsonpickle.encode(refreshed_tokens))
                    self.bearer = refreshed_tokens["access_token"]
            else:
                self.log.info(" + Registering new device bearer", extra={"service_name": "Amazon"})
                self.bearer = self.register(self.device)

        def register(self, device: dict) -> dict:
            """
            Register device to the account
            :param device: Device data to register
            :return: Device bearer tokens
            """
            # OnTV csrf
            csrf_token = self.get_csrf_token()

            # Code pair
            code_pair = self.get_code_pair(device)

            # Device link
            response = self.session.post(
                url=self.endpoints["devicelink"],
                headers={
                    "Accept": "*/*",
                    "Accept-Language": "en-US,en;q=0.9,es-US;q=0.8,es;q=0.7",  # needed?
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": self.endpoints["ontv"]
                },
                params=urlencode({
                    # any reason it urlencodes here? requests can take a param dict...
                    "ref_": "atv_set_rd_reg",
                    "publicCode": code_pair["public_code"],  # public code pair
                    "token": csrf_token  # csrf token
                })
            )
            if response.status_code != 200:
                raise self.log.error(f"Unexpected response with the codeBasedLinking request: {response.text} [{response.status_code}]", extra={"service_name": "Amazon"})

            # Register
            response = self.session.post(
                url=self.endpoints["register"],
                headers={
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US"
                },
                json={
                    "auth_data": {
                        "code_pair": code_pair
                    },
                    "registration_data": device,
                    "requested_token_type": ["bearer"],
                    "requested_extensions": ["device_info", "customer_info"]
                },
                cookies=None  # for some reason, may fail if cookies are present. Odd.
            )
            if response.status_code != 200:
                self.log.error(f"Unable to register: {response.text} [{response.status_code}]", extra={"service_name": "Amazon"})
                self.log.error("Please Update Cookie File", extra={"service_name": "Amazon"})
                raise
            bearer = response.json()["response"]["success"]["tokens"]["bearer"]
            bearer["expires_in"] = int(time.time()) + int(bearer["expires_in"])

            # Cache bearer
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as fd:
                fd.write(jsonpickle.encode(bearer))

            return bearer["access_token"]

        def refresh(self, device: dict, refresh_token: str) -> dict:
            response = self.session.post(
                url=self.endpoints["token"],
                json={
                    "app_name": device["app_name"],
                    "app_version": device["app_version"],
                    "source_token_type": "refresh_token",
                    "source_token": refresh_token,
                    "requested_token_type": "access_token"
                }
            ).json()
            if "error" in response:
                #cache_path = Path(self.cache_path) if isinstance(self.cache_path, str) else self.cache_path
                self.cache_path.unlink(missing_ok=True)  # Remove the cached device as its tokens have expired
                raise self.log.error(
                    f"Failed to refresh device token: {response['error_description']} [{response['error']}]"
                , extra={"service_name": "Amazon"})
            if response["token_type"] != "bearer":
                raise self.log.error("Unexpected returned refreshed token type", extra={"service_name": "Amazon"})
            return response

        def get_csrf_token(self) -> str:
            """
            On the amazon website, you need a token that is in the html page,
            this token is used to register the device
            :return: OnTV Page's CSRF Token
            """
            res = self.session.get(self.endpoints["ontv"])
            response = res.text
            if 'input type="hidden" name="appAction" value="SIGNIN"' in response:
                raise self.log.error(
                    "Cookies are signed out, cannot get ontv CSRF token. "
                    f"Expecting profile to have cookies for: {self.endpoints['ontv']}"
                , extra={"service_name": "Amazon"})
            for match in re.finditer(r"<script type=\"text/template\">(.+)</script>", response):
                prop = json.loads(match.group(1))
                prop = prop.get("props", {}).get("codeEntry", {}).get("token")
                if prop:
                    return prop
            #print(response)
            raise self.log.error("Unable to get ontv CSRF token", extra={"service_name": "Amazon"})  ## OK FUCKING ERROR;        ... why not match..??? Fucking Amazon

        def get_code_pair(self, device: dict) -> dict:
            """
            Getting code pairs based on the device that you are using
            :return: public and private code pairs
            """
            res = self.session.post(
                url=self.endpoints["codepair"],
                headers={
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US"
                },
                json={"code_data": device}
            ).json()
            if "error" in res:
                raise self.log.error(f"Unable to get code pair: {res['error_description']} [{res['error']}]", extra={"service_name": "Amazon"})
            return res