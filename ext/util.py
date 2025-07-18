import re
import os
import logging
import requests
import tls_client

from typing import Iterator
from importlib import import_module
from urllib.parse import urlparse, parse_qs


from ext.utils.session_util import session_logic


def path_check(input_path):
    invalid_chars = r'[<>:"|?*]'
    if re.search(invalid_chars, input_path):
        return False

    if not input_path.strip():
        return False

    has_extension = bool(os.path.splitext(input_path)[1])
    looks_like_path = '/' in input_path or '\\' in input_path

    return has_extension or looks_like_path

def check_dmm_content_type(season_id):
    try:
        res = requests.post("https://api.tv.dmm.com/graphql", json={
            "operationName": "FetchVideoContent",
            "variables": {
                "id": season_id,
                "playDevice": "BROWSER",
                "isLoggedIn": False
            },
            "query": "query FetchVideoContent($id: ID!, $playDevice: PlayDevice!, $isLoggedIn: Boolean!) {\n  videoContent(id: $id) {\n    contentType\n  }\n}"
        })
        if res.status_code == 200:
            return res.json()["data"]["videoContent"]["contentType"]
    except Exception:
        return None

def get_parser(url):
    patterns = [
        # パターン, 条件, モジュール名, ラベル名
        (re.compile(r'^https?://abema\.tv/.+'), lambda u: "-v1" in u, 'ext.services.abematv', 'abemav1'),
        (re.compile(r'^https?://abema\.tv/.+'), None, 'ext.services.abematv_v2', 'abema'),
        (re.compile(r'^https?://gyao\.yahoo\.co\.jp/.+'), None, 'ext.services.gyao', 'gyao'),
        (re.compile(r'^https?://(?:www\.)?aniplus-asia\.com/episode/.+'), None, 'ext.services.aniplus', 'aniplus'),
        (re.compile(r'^https?://(?:video|video-share)\.unext\.jp/.+(SID\d+|ED\d+)'), None, 'ext.services.unext_v2', 'unext'),
        (re.compile(r'^https?://video\.hnext\.jp/(?:play|title)/.+(AID\d+|AED\d+)'), None, 'ext.services.hnext', 'H-Next'),
        (re.compile(r'^https?://tv\.dmm\.com/.+season=([^&]+).*(content=([^&]+))?'), lambda u: check_dmm_content_type(parse_qs(urlparse(u).query).get("season", [None])[0]) == "VOD_VR", 'ext.services.fanza', 'Fanza-VR'),
        (re.compile(r'^https?://tv\.dmm\.com/.+season=([^&]+)'), None, 'ext.services.dmm_tv', 'dmm_tv'),
        (re.compile(r'^https?://www\.brainshark\.com/.+pi=([^&]+)'), None, 'ext.services.brainshark', 'brainshark'),
        (re.compile(r'^https?://fod\.fujitv\.co\.jp/title/[0-9a-z]+'), None, 'ext.services.fod_v2', 'fod'),
        (re.compile(r'^https?://anime3rb\.com/.+'), None, 'ext.services.anime3rb', 'anime3rb'),
        (re.compile(r'^https?://www\.crunchyroll\.com/(series|watch)/.+'), None, 'ext.services.crunchyroll', 'Crunchyroll'),
        (re.compile(r'^https?://www\.b-ch\.com/titles/\d+'), None, 'ext.services.bandai_ch', 'Bandai-Ch'),
        (re.compile(r'^https?://(?:www\.)?telasa\.jp/.+'), None, 'ext.services.telasa', 'Telasa'),
        (re.compile(r'^https?://(?:www\.)?videomarket\.jp/.+'), None, 'ext.services.videomarket', 'VideoMarket'),
        (re.compile(r'^https?://(?:www\.)?hulu\.jp/.+'), None, 'ext.services.hulu_jp', 'Hulu-jp'),
        (re.compile(r'^https?://www\.dmm\.(?:com|co\.jp)/digital/-/player/=/.+'), None, 'ext.services.fanza', 'Fanza'),
        (re.compile(r'^https?://tv\.dmm\.com/vod/restrict/.+season=([^&]+)'), lambda u: check_dmm_content_type(re.match(r'.*season=([^&]+)', u).group(1)) == "VOD_VR", 'ext.services.fanza', 'Fanza-VR'),
        (re.compile(r'^https?://tv\.dmm\.com/vod/restrict/.+season=([^&]+)'), lambda u: check_dmm_content_type(re.match(r'.*season=([^&]+)', u).group(1)) == "VOD_2D", 'ext.services.fanza', 'Fanza'),
        (re.compile(r'^https?://(?:www\.)?hiyahtv\.com/.+'), None, 'ext.services.hiyahtv', 'Hi-YAH!'),
        (re.compile(r'^https?://lemino\.docomo\.ne\.jp/.+'), None, 'ext.services.lemino', 'Lemino'),
    ]

    for pattern, condition, module_name, label in patterns:
        if pattern.match(url):
            if condition is None or condition(url):
                module = import_module(module_name)
                return module, label

    if "plus.nhk.jp" in url:
        from ext import nhk_plus
        return nhk_plus, "NHK+"
    elif "jff.jpf.go.jp" in url:
        from ext import jff_theater
        return jff_theater, "Jff Theater"
    elif "wod.wowow.co.jp" in url:
        from ext import wowow
        return wowow, "WOD-WOWOW"
    elif "dmmvrplayerstreaming" in url or "vr-sample-player" in url:
        from ext import fanza
        return fanza.Fanza_VR, "Fanza-VR"

    return None, None

class Logger:
    COLOR_GREEN = "\033[92m"
    COLOR_GRAY = "\033[90m"
    COLOR_RESET = "\033[0m"
    COLOR_BLUE = "\033[94m"
    class CustomFormatter(logging.Formatter):
        def format(self, record):
            service_name = getattr(record, "service_name", "")
            levelname = record.levelname
            record.color_service_name = f"{Logger.COLOR_BLUE}{service_name}{Logger.COLOR_RESET}" if service_name else ""
            record.color_levelname = f"{Logger.COLOR_GRAY}{levelname}{Logger.COLOR_RESET}"
            
            if not hasattr(record, "asctime"):
                record.asctime = self.formatTime(record, self.datefmt)
            record.color_asctime = f"{Logger.COLOR_GREEN}{record.asctime}{Logger.COLOR_RESET}"
    
            self._style._fmt = (
                "%(color_asctime)s [%(color_levelname)s] %(color_service_name)s : %(message)s"
            )
            return super().format(record)
    
    class ServiceLoggerAdapter(logging.LoggerAdapter):
        def process(self, msg, kwargs):
            kwargs.setdefault('extra', {})
            kwargs['extra'].setdefault('service_name', self.extra['service_name'])
            return msg, kwargs
    
    def create_logger(service_name: str, LOG_LEVEL: bool):
        base_logger = logging.getLogger('YoimiLogger')
        if LOG_LEVEL == "DEBUG":
            base_logger.setLevel(logging.DEBUG)
        else:
            base_logger.setLevel(logging.INFO)
    
        formatter = Logger.CustomFormatter(
            '%(asctime)s [%(levelname)s] %(service_name)s : %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
    
        if not base_logger.handlers:
            base_logger.addHandler(console_handler)
        
        logger = Logger.ServiceLoggerAdapter(base_logger, {'service_name': service_name})
        return logger

def download_command(input: str, command_list: Iterator):
    module_service, module_label = get_parser(input)
    service_config = module_service.__service_config__
    service_label = service_config["service_name"]
    service_logger = Logger.create_logger(service_label, LOG_LEVEL=command_list["verbose"])
    
    email, password = command_list["email"], command_list["password"]
    
    if (not email or not password) and service_config["require_account"]:
        service_logger.error(f"{service_label} is require account login.")
        exit(1)
    
    ### define, init service
    if service_config["use_tls"]:
        session = tls_client.Session(client_identifier="chrome139",random_tls_extension_order=True)
    else:
        session = requests.Session()
    service_downloader = module_service.downloader(session=session)
    
    ### check session
    if service_config["require_account"]:
        session_manager = session_logic(logger=service_logger, service_name=service_label, service_util=service_downloader)
        
        session_status = session_manager.check_session(service_label)