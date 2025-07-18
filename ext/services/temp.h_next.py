"""
SERVICE INFO


name: H-Next
require_account: Yes
cache_session: Yes
support_url: 
   https://video.hnext.jp/title/xxx
   https://video.hnext.jp/play/xxx/xxx
"""

__user_agent__ = "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 japanview/1.0.6"

__service_config__ = {
    "service_name": "H-Next",
    "require_account": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session):
        self.session = session