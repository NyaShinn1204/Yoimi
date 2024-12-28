import os
import re
import time
import html
import json
import hashlib
import requests
import logging
import jsonpickle
from pathlib import Path
from tldextract import tldextract
from urllib.parse import urlencode
from http.cookiejar import MozillaCookieJar


class Amazon_downloader:
    def __init__(self, session, pv_status):
        self.session = session
        self.service = "Amazon"
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
            "app_name": "com.amazon.amazonvideo.livingroom",
            "app_version": "1.1",
            "device_model": "Hisense",
            "os_version": "6.0.1",
            "device_type": "A3REWRVYBYPKUM",
            "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Hisense",
            "device_serial": "3cc61028646759e273"
          },
          "snowman8585": {
            "domain": "Device",
            "app_name": "com.amazon.amazonvideo.livingroom",
            "app_version": "1.1",
            "device_model": "Hisense",
            "os_version": "6.0.1",
            "device_type": "A3REWRVYBYPKUM",
            "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Hisense",
            "device_serial": "12a95b33987e83ae51"
          },
          "snowmanuk": {
            "domain": "Device",
            "app_name": "com.amazon.amazonvideo.livingroom",
            "app_version": "1.1",
            "device_model": "Hisense",
            "os_version": "6.0.1",
            "device_type": "A3REWRVYBYPKUM",
            "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Hisense",
            "device_serial": "12a95b33989e83ae51"
          },
          "us": {
            "domain": "Device",
            "app_name": "com.amazon.amazonvideo.livingroom",
            "app_version": "1.1",
            "device_model": "Hisense",
            "os_version": "6.0.1",
            "device_type": "A3REWRVYBYPKUM",
            "device_name": "%FIRST_NAME%'s%DUPE_STRATEGY_1ST% Hisense",
            "device_serial": "12a95b3312fb2013d9"
          }
        }

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

        return region, None
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
        return (self.device or {}).get(profile, {})

    def register_device(self, session, profile, logger):
        self.register_v_device = (self.device or {}).get(profile, {})
        device_cache_path = self.get_cache("device_tokens_{profile}_{hash}.json".format(
            profile=profile,
            hash=hashlib.md5(json.dumps(self.register_v_device).encode()).hexdigest()[0:6]
        ))
        self.device_token = self.DeviceRegistration(
            device=self.register_v_device,
            endpoints=self.endpoints,
            log=logger,
            cache_path=device_cache_path,
            session=session
        ).bearer
        self.device_id = self.device.get("device_serial")
        if not self.device_id:
            raise self.log.error(f" - A device serial is required in the config, perhaps use: {os.urandom(8).hex()}")
        return self.device_id, self.device_token
    
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
                raise self.log.error(f"Unable to register: {response.text} [{response.status_code}]", extra={"service_name": "Amazon"})
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