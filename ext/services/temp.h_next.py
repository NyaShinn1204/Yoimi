"""
SERVICE INFO


name: H-Next
require_account: Yes
enable_refresh: No
support_qr: Yes
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url: 
   https://video.hnext.jp/title/xxx
   https://video.hnext.jp/play/xxx/xxx
"""

__service_config__ = {
    "service_name": "H-Next",
    "require_account": True,
    "support_qr": True,
    "is_drm": True,
    "cache_session": True,
    "cache_session": True,
    "enable_refresh": False,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        
        self.use_cahce = True
        
        self.default_headers = {
            "connection": "keep-alive",
            "pragma": "no-cache",
            "cache-control": "no-cache",
            "sec-ch-ua-platform": "\"Android\"",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/138.0.7204.169 Mobile Safari/537.36 japanview/1.0.6",
            "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Android WebView\";v=\"138\"",
            "sec-ch-ua-mobile": "?1",
            "baggage": "sentry-environment=prod,sentry-release=v105.0-2-gca2628b65,sentry-public_key=d46f18dd0cfb4b0cb210f8e67c535fe1,sentry-trace_id=7027522fb22847e6a57671c198a8ab7e,sentry-sample_rate=0.0001,sentry-sampled=false",
            "accept": "*/*",
            "x-requested-with": "com.japan_view",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
        }
        
        self.session.headers.update(self.default_headers)