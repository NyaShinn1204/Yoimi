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