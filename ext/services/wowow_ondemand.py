"""
SERVICE INFO


name: WOWOW-Ondemand
require_account: Yes
enable_refresh: No
support_normal: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url:
   WIP
"""

import re
import time
from urllib.parse import urlparse

__service_config__ = {
    "service_name": "WOWOW-Ondemand",
    "require_account": True,
    "enable_refresh": True,
    "support_normal": False,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        
        self.user_id = None
        self.wip_access_token = None
        self.wip_refresh_token = None
        
        self.default_headers = {
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.179 Mobile Safari/537.36 jp.ne.wowow.vod.androidtv/3.8.3",
            "accept-language": "ja",
            "content-type": "application/json; charset=utf-8",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip"
        }
        self.session.headers.update(self.default_headers)