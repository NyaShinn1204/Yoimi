import os
import re
import html
from tldextract import tldextract
from http.cookiejar import MozillaCookieJar


class Amazon_downloader:
    def __init__(self, session):
        self.session = session
        self.service = "Amazon"
        self.pv = True # if url is primevideo
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
    def get_device(self, profile):
        return (self.device or {}).get(profile, {})