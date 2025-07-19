"""
SERVICE INFO


name: Hulu-jp
require_account: Yes
enable_refresh: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://www.hulu.jp/xxx
   https://www.hulu.jp/watch/xxx
   https://www.hulu.jp/store/watch/xxx
"""

__user_agent__ = "jp.happyon.android/3.24.0 (Linux; Android 8.0.0; BRAVIA 4K GB Build/OPR2.170623.027.S32) AndroidTV"

__service_config__ = {
    "service_name": "Hulu-jp",
    "require_account": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session):
        self.session = session
    
    def authorize(self, email, password):
        pass
    def refresh_token(self, refresh_token, session_data):
        pass
    def get_userinfo(self):
        pass