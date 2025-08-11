"""
SERVICE INFO


name: RakutenTV-JP
require_account: No
enable_refresh: No
support_qr: No
is_drm: Yes
cache_session: Yes
use_tlsclient: No
support_url:
   WIP
"""

__service_config__ = {
    "service_name": "RakutenTV-JP",
    "require_account": False,
    "enable_refresh": False,
    "support_qr": False,
    "is_drm": True,
    "cache_session": True,
    "use_tls": False,
}

class downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger

        self.default_headers = {
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; A7S Build/QP1A.190711.020) Rakuten TV AndroidTV/2.2.5-edce7eacd6-P (Linux;Android 10) AndroidXMedia3/1.4.1",
            "host": "api.tv.rakuten.co.jp",
            "connection": "Keep-Alive",
            "accept-encoding": "gzip",
        }
        self.session.headers.update(self.default_headers)

        self.device_list = {
            "Windows XP": "1",         # DASH        1280x720
            "Windows Vista": "2",      # DASH        1280x720
            "Xbox 360": "3",           # API ERROR
            "Windows 7": "4",          # DASH        1280x720
            "Windows RT": "5",         # API ERROR
            "Windows 8": "6",          # DASH        1280x720
            "Windows Other": "7",      # API ERROR
            "Windows Phone": "8",      # API ERROR
            "iPad": "9",               # HLS         1280x720
            "iPhone,iPod touch": "10", # HLS         960x540
            "Intel Mac": "11",         # HLS & DASH  1280x720
            "Mac Other": "12",         # API ERROR
            "Android mobile": "13",    # DASH        960x540
            "Android tablet": "14",    # DASH        1280x720
            "Android Other": "15",     # API ERROR
            "Chromecast": "16",        # DASH        1920x1080
            "VIERA HLS": "17",         # HLS         SERVER DOWN (Status: 500)
            "VIERA": "18",             # DASH        1920x1080
            "BRAVIA": "19",            # DASH        1920x1080
            "Wii U": "20",             # DASH        1920x1080
            "Xbox One": "21",          # DASH        1920x1080
            "Windows 10": "22",        # DASH        1280x720
            "PS4": "23",               # DASH        1920x1080
            "UNKNOWN DEVICE": "24",    # DASH        1920x1080
            "Android TV": "25",        # DASH        1920x1080
            "Apple TV": "26",          # HLS         1920x1080
            "REGZA": "27",             # DASH        1920x1080
            "Fire TV": "28",           # DASH        1920x1080
        }
        
        self.device_id = self.device_list["Android TV"]