import re
import os
import time
import logging
import requests
import threading
import subprocess
from tqdm import tqdm
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_RESET = "\033[0m"
COLOR_BLUE = "\033[94m"


class aria2c_downloader:
    """aria2cを使用してファイルをダウンロードし、進捗を表示するクラス"""
    def _parse_progress_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        aria2cの進捗行を正規表現でパースする。
        例: "[#a3f5a1 1.0GiB/2.3GiB(44%) CN:16 DL:23MiB ETA:58s]"
        """
        progress_pattern = re.compile(
            r"\[#.{6}\s+"
            r"([\d.]+)(KiB|MiB|GiB)"
            r"/"
            r"([\d.]+)(KiB|MiB|GiB)"
            r"\((\d+)%\)"
        )
        match = progress_pattern.search(line)
        if not match:
            return None

        downloaded_val, downloaded_unit, total_val, total_unit, percentage = match.groups()

        return {
            "downloaded": self._to_mib(float(downloaded_val), downloaded_unit),
            "total": self._to_mib(float(total_val), total_unit),
            "percentage": int(percentage),
        }

    def _to_mib(self, value: float, unit: str) -> float:
        """指定された単位をMiBに変換する。"""
        if unit == "GiB":
            return value * 1024
        if unit == "KiB":
            return value / 1024
        return value

    def _format_size_info(self, downloaded_mib: float, total_mib: float) -> str:
        """ダウンロードサイズ情報を見やすい文字列にフォーマットする。"""
        if total_mib >= 1024:
            return f"{downloaded_mib / 1024:.2f}/{total_mib / 1024:.2f} GiB"
        return f"{downloaded_mib:.1f}/{total_mib:.1f} MiB"

    def _format_log_message(self, service_name: str, message: str) -> str:
        """タイムスタンプや色を含む標準的なログメッセージを生成する。"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return (
            f"{COLOR_GREEN}{timestamp}{COLOR_RESET} "
            f"[{COLOR_GRAY}INFO{COLOR_RESET}] "
            f"{COLOR_BLUE}{service_name}{COLOR_RESET} : {message}"
        )
    
    def _handle_progress_output(self, process: subprocess.Popen, service_name: str, stdout_lines: List[str]):
        """
        サブプロセスの出力をリアルタイムで処理し、プログレスバーを更新する。
        """
        last_progress_data = None

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            stdout_lines.append(line + '\n')

            progress_data = self._parse_progress_line(line)
            if progress_data:
                last_progress_data = progress_data
                percentage = progress_data["percentage"]
                
                percentage_str = str(percentage).rjust(3)
                progress_bar_fill = '#' * (percentage // 10)
                progress_bar_empty = '-' * (10 - (percentage // 10))
                
                bar_and_size = f"{percentage_str}%|{progress_bar_fill}{progress_bar_empty}| {self._format_size_info(progress_data['downloaded'], progress_data['total'])}"
                
                log_message = self._format_log_message(service_name, bar_and_size)
                print(f"\r{log_message}", end="", flush=True)

        if last_progress_data:
            total_mib = last_progress_data["total"]
            final_bar_and_size = f"100%|{'#' * 10}| {self._format_size_info(total_mib, total_mib)}"
            final_message = self._format_log_message(service_name, final_bar_and_size)
            print(f"\r{final_message}", flush=True)
            print()


    def _get_executable_path(self, config: Dict[str, Any]) -> str:
        """OSに応じてaria2cの実行可能ファイルパスを取得する。"""
        if os.name == 'nt':
            path = os.path.join(config["directories"]["Binaries"], "aria2c.exe")
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise FileNotFoundError(f"aria2c binary not found or not executable: {path}")
            return path
        return "aria2c"

    
    def download(self, url: str, output_file_name: str, config: Dict[str, Any], unixtime: str, service_name: str = "") -> Tuple[bool, str]:
        """
        指定されたURLからファイルをダウンロードする。

        Args:
            url (str): ダウンロードするファイルのURL。
            output_file_name (str): 保存するファイル名。
            config (Dict): ディレクトリ設定などを含む辞書。
            unixtime (str): 一時ディレクトリ名として使用するunixtime。
            service_name (str): ログに表示するサービス名。

        Returns:
            Tuple[bool, str]: (成功フラグ, 成功時はファイルパス / 失敗時はエラーメッセージ)
        """
        try:
            aria2c_path = self._get_executable_path(config)
        except FileNotFoundError as e:
            return False, str(e)
            
        output_temp_directory = os.path.join(config["directories"]["Temp"], "content", unixtime)
        os.makedirs(output_temp_directory, exist_ok=True)

        aria2c_command = [
            aria2c_path,
            url,
            "-d", output_temp_directory,
            "-o", output_file_name,
            "-j", "16",
            "-s", "16",
            "-x", "16",
            "-U", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "--allow-overwrite=false",
            "--async-dns=false",
            "--auto-file-renaming=false",
            "--console-log-level=warn",
            "--retry-wait=5",
            "--summary-interval=1",
        ]

        process = subprocess.Popen(
            aria2c_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        stdout_lines: List[str] = []
        self._handle_progress_output(process, service_name, stdout_lines)

        stderr_output = process.communicate()[1]
        
        if process.returncode != 0:
            error_message = f"aria2c exited with code {process.returncode}.\n"
            error_message += "--- STDOUT ---\n" + "".join(stdout_lines)
            error_message += "\n--- STDERR ---\n" + stderr_output
            return False, error_message

        return True, os.path.join(output_temp_directory, output_file_name)

class segment_downloader:
    def __init__(self, logger):
        self.logger = logger
    
    def verify_download(self, segment_links, output_temp_directory, fetch_and_save):
        self.logger.info(" + Starting file integrity verification...")
        for i, url in enumerate(segment_links):
            temp_path = os.path.join(output_temp_directory, f"{i:05d}.ts")
            if not os.path.exists(temp_path):
                fetch_and_save((i, url))
                self.logger.info(f" + Successfully downloaded segment {i}: {url}")
                time.sleep(2)
        self.logger.info(" + Completed file integrity verification.")
    def download(self, segment_links: list, output_file_name: str, config: Dict[str, Any], unixtime: str, service_name: str = "") -> Tuple[bool]:
        """
        セグメントのURLリストから並列でダウンロードを行い、結合して1つのファイルに出力する。

        Args:
            segment_links (list): ダウンロード対象の.tsセグメントのURLリスト。
            output_file_name (str): 出力ファイル名（結合後のファイル名）。
            config (Dict): 各種ディレクトリ設定などを含む辞書。
            unixtime (str): 一時作業用ディレクトリ名として使用するUnixタイム。
            service_name (str): ログ表示用のサービス名。

        Returns:
            Tuple[bool]: 正常終了時はTrue、失敗または割り込み時は例外を送出。
        """
        
        output_temp_directory = os.path.join(config["directories"]["Temp"], "content", unixtime)
        os.makedirs(output_temp_directory, exist_ok=True)
        
        stop_flag = threading.Event()

        def fetch_and_save(index_url):
            """
            セグメントを1つずつダウンロードして一時ファイルとして保存する内部関数。

            Args:
                index_url (tuple): (インデックス, URL) のタプル。

            Returns:
                int: 成功時はインデックスを返す。

            Raises:
                Exception: 3回のリトライでも失敗した場合に例外を送出。
            """
            index, url = index_url
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    response = requests.get(url.strip(), timeout=10)
                    response.raise_for_status()
                    temp_path = os.path.join(output_temp_directory, f"{index:05d}.ts")
                    with open(temp_path, 'wb') as f:
                        f.write(response.content)
                    return index
                except requests.exceptions.RequestException:
                    retry += 1
                    time.sleep(2)

            if not stop_flag.is_set():
                raise Exception(f"Failed to download segment {index}: {url}")

        futures = []
        try:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(fetch_and_save, (i, url)) for i, url in enumerate(segment_links)]
                
                with tqdm(
                    total=len(segment_links),
                    desc=f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : ",
                    unit="file"
                ) as pbar:
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            print(f"Error: {e}")
                        pbar.update(1)
            
            self.verify_download(segment_links, output_temp_directory, fetch_and_save)
            
            output_path = os.path.join(output_temp_directory, output_file_name)
            with open(output_path, 'wb') as out_file:
                for i in range(len(segment_links)):
                    temp_path = os.path.join(output_temp_directory, f"{i:05d}.ts")
                    with open(temp_path, 'rb') as f:
                        out_file.write(f.read())
                    os.remove(temp_path)
                    
            return True, output_path
        
        except KeyboardInterrupt:
            stop_flag.set()
            for future in futures:
                future.cancel()

            for i in range(len(segment_links)):
                temp_path = os.path.join(output_temp_directory, f"{i:05d}.ts")
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
            return False, "Download interrupted by user."
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
 
class live_downloader:       
    """ライブコンテンツのダウンロード"""
    def __init__(self, logger):
        self.logger = logger
    def download(self, url: str, res_info: Dict[str, Any], config: Dict[str, Any], unixtime: str, service_name: str = "") -> Tuple[bool]:
        try:
            output_temp_directory = os.path.join(config["directories"]["Temp"], "content", unixtime)
            os.makedirs(output_temp_directory, exist_ok=True)
            
            while True:
                ### define output 
                output_video = os.path.join(output_temp_directory, "download_encrypt_video.mp4")
                output_audio = os.path.join(output_temp_directory, "download_encrypt_audio.mp4")
                
                ### check mpd content
                mpd_content = self.fetch_mpd_and_segment_info(url)
                if not mpd_content:
                    time.sleep(5)
                    continue
        
                mup = self.parse_minimum_update_period(mpd_content)
                self.download_and_merge_segments(res_info, mpd_content)
        
                print(f"Sleeping for {mup} seconds before refreshing MPD...")
                time.sleep(mup)
        except KeyboardInterrupt:
            return True
        except:
            return False
########## TEST SCRIPT HERE ##########

if __name__ == '__main__':
    
    if os.name == 'nt':
        os.system('') ## Bypass Fucking Idiot Windows Color Issue
    
    dummy_config = {
        "directories": {
            "Temp": "temp_dir",
            "Binaries": "."
        }
    }
    dummy_unixtime = str(int(datetime.now().timestamp()))
    
    test_url = "https://ash-speed.hetzner.com/1GB.bin"
    test_filename = "test_1gb.bin"

    downloader = aria2c_downloader()

    print("Download starting...")
    success, result = downloader.download(
        url=test_url,
        output_file_name=test_filename,
        config=dummy_config,
        unixtime=dummy_unixtime,
        service_name="Yoimi-Test"
    )

    if success:
        print(f"\nDownload successful! File saved at: {result}")
    else:
        print(f"\nDownload failed:\n{result}")
        
if __name__ == '__main__':
    
    if os.name == 'nt':
        os.system('') ## Bypass Fucking Idiot Windows Color Issue
    
    dummy_config = {
        "directories": {
            "Temp": "temp_dir",
            "Binaries": "."
        }
    }
    dummy_unixtime = str(int(datetime.now().timestamp()))
    
    test_segments = [
      "https://test-streams.mux.dev/x36xhzz/url_8/url_590/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_591/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_592/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_593/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_594/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_595/193039199_mp4_h264_aac_fhd_7.ts",
      "https://test-streams.mux.dev/x36xhzz/url_8/url_596/193039199_mp4_h264_aac_fhd_7.ts",
    ]
    test_filename = "sample_m3u8.mp4"

    downloader = segment_downloader(logging.Logger())

    print("Download starting...")
    success, result = downloader.download(
        segment_links=test_segments,
        output_file_name=test_filename,
        config=dummy_config,
        unixtime=dummy_unixtime,
        service_name="Yoimi-Test"
    )

    if success:
        print(f"\nDownload successful! File saved at: {test_filename}")
    else:
        print(f"\nDownload failed:\n{success}")

if __name__ == '__main__':
    
    if os.name == 'nt':
        os.system('') ## Bypass Fucking Idiot Windows Color Issue
    
    dummy_config = {
        "directories": {
            "Temp": "temp_dir",
            "Binaries": "."
        }
    }
    dummy_unixtime = str(int(datetime.now().timestamp()))
    
    test_url = "https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/manifest.mpd"
    test_info = {
        'video': {
            'url': 'segment_ua2anvupo_ctvideo_cfm4s_ridp0va0br2808000_cinit_mpd.m4s',
            'url_base': '',
            'url_segment_base': 'segment_ua2anvupo_ctvideo_cfm4s_ridp0va0br2808000_cs$Time$_mpd.m4s',
            'seg_duration': '540000',
            'seg_timescale': '90000',
            'segment_count': 15,
            'id': 'p0va0br2808000',
            'bitrate': '2808',
            'codec': 'avc1.64001f',
            'type': 'video',
            'resolution': '1280x720'
        },
        'audio': {
            'url': 'segment_ua2anvupo_ctaudio_cfm4s_ridp0aa0br445189_cinit_mpd.m4s',
            'url_base': '',
            'url_segment_base': 'segment_ua2anvupo_ctaudio_cfm4s_ridp0aa0br445189_cs$Time$_mpd.m4s',
            'seg_duration': '287712',
            'seg_timescale': '48000',
            'segment_count': 15,
            'id': 'p0aa0br445189',
            'bitrate': '445',
            'codec': 'mp4a.40.2',
            'type': 'audio',
            'language': 'eng'
        }
    }
    test_info["video"]["url_base"] = "https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/"
    test_info["audio"]["url_base"] = "https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/"
    downloader = live_downloader()

    print("Download starting...")
    success = downloader.download(
        url=test_url,
        res_info=test_info,
        config=dummy_config,
        unixtime=dummy_unixtime,
        service_name="Yoimi-Test"
    )

    if success:
        print(f"\nDownload successful! File saved at: {result}")
    else:
        print(f"\nDownload failed:\n{result}")
        