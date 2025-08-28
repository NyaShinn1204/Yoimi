import re
import os
import sys
import time
import logging
import requests
import threading
import subprocess
import xml.etree.ElementTree as ET
from tqdm import tqdm
from datetime import datetime
from urllib.parse import urljoin
from typing import Optional, Tuple, List, Dict, Any
from tqdm.contrib.logging import logging_redirect_tqdm
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
                try:
                    result = fetch_and_save((i, url))
                    if result is not None:
                        self.logger.info(f" + Successfully downloaded segment {i}: {url}")
                except Exception as e:
                    # 404は無視
                    if "404" in str(e):
                        self.logger.warning(f" + Segment {i} not found (404), skipping.")
                        continue
                    else:
                        raise
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
            index, url = index_url
            retry = 0
            while retry < 3 and not stop_flag.is_set():
                try:
                    response = requests.get(url.strip(), timeout=10)
                    if response.status_code == 404:
                        # 404は無視して終了
                        self.logger.warning(f" + Segment {index} not found (404), skipping: {url}")
                        return None
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
                    if os.path.exists(temp_path):
                        with open(temp_path, 'rb') as f:
                            out_file.write(f.read())
                        os.remove(temp_path)
                    else:
                        self.logger.warning(f" + Segment {i:05d}.ts missing, skipping.")
                    
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
        self.downloaded_segments = {
            "video": set(),
            "audio": set()
        }
    def _download_segment(self, url, output_path):
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(output_path, 'ab') as f:
                f.write(response.content)
            self.logger.info(f" + Downloaded: {url}")
        else:
            self.logger.error(f"Failed to download {url}: {response.status_code}")
    def _extract_segment_times(self, mpd_content, media_type):
        times = []
        try:
            ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
            root = ET.fromstring(mpd_content)
            period = root.find('mpd:Period', ns)
            adaptation_sets = period.findall('mpd:AdaptationSet', ns)
    
            for aset in adaptation_sets:
                if media_type in aset.attrib.get("mimeType", ""):
                    seg_template = aset.find('mpd:SegmentTemplate', ns)
                    seg_timeline = seg_template.find('mpd:SegmentTimeline', ns)
                    s_elements = seg_timeline.findall('mpd:S', ns)
                    current_time = 0
                    for s in s_elements:
                        d = int(s.attrib['d'])
                        if 't' in s.attrib:
                            current_time = int(s.attrib['t'])
                        times.append(current_time)
                        current_time += d
                    break
        except Exception as e:
            self.logger.error(f"Error extracting segment times for {media_type}: {e}")
        return times
    def _fill_template(self, template: str, values: dict) -> str:
        # よく使う置換トークンに対応（足りない場合は随時追加）
        out = template
        for k, v in values.items():
            out = out.replace(f"${k}$", str(v))
        return out
    
    def _extract_segment_plan(self, mpd_content: str, media_type: str):
        """
        MPD からダウンロード計画を抽出して返す
        return:
          {
            "media": "<media template>",
            "init": "<initialization template or None>",
            "uses_time": bool,
            "uses_number": bool,
            "start_number": int|None,
            "timescale": int,
            "timeline": [{"t":int,"d":int}],  # r 展開後
            "rep": { "id":str|None, "bandwidth":int|None, ... }  # Representation属性
          }
        """
        try:
            ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
            root = ET.fromstring(mpd_content)
            period = root.find('mpd:Period', ns)
            if period is None:
                return None
    
            for aset in period.findall('mpd:AdaptationSet', ns):
                if media_type not in aset.attrib.get("mimeType", ""):
                    continue
    
                reps = aset.findall('mpd:Representation', ns)
                if not reps:
                    continue
    
                # 帯域が最大の Representation を採用（任意の選び方でOK）
                def bw(x): return int(x.attrib.get("bandwidth", "0"))
                rep = max(reps, key=bw)
    
                seg_template = rep.find('mpd:SegmentTemplate', ns)
                if seg_template is None:
                    seg_template = aset.find('mpd:SegmentTemplate', ns)  # 保険
    
                if seg_template is None:
                    continue
    
                media = seg_template.attrib.get('media')
                init  = seg_template.attrib.get('initialization')
                timescale = int(seg_template.attrib.get('timescale', '1'))
                start_number = seg_template.attrib.get('startNumber')
                start_number = int(start_number) if start_number is not None else None
    
                uses_time = ('$Time$' in (media or '')) or ('$Time$' in (init or ''))
                uses_number = ('$Number$' in (media or '')) or ('$Number$' in (init or ''))
    
                # SegmentTimeline 展開
                timeline = []
                st = seg_template.find('mpd:SegmentTimeline', ns)
                if st is not None:
                    current_time = None
                    for s in st.findall('mpd:S', ns):
                        d = int(s.attrib['d'])
                        r = int(s.attrib.get('r', '0'))
                        if 't' in s.attrib:
                            current_time = int(s.attrib['t'])
                        if current_time is None:
                            current_time = 0
                        for _ in range(r + 1):
                            timeline.append({"t": current_time, "d": d})
                            current_time += d
    
                # Representation 属性を値埋め込み用に保持
                rep_info = {
                    "RepresentationID": rep.attrib.get("id"),
                    "Bandwidth": rep.attrib.get("bandwidth")
                }
    
                return {
                    "media": media,
                    "init": init,
                    "uses_time": uses_time,
                    "uses_number": uses_number,
                    "start_number": start_number,
                    "timescale": timescale,
                    "timeline": timeline,
                    "rep": rep_info,
                }
        except Exception as e:
            self.logger.error(f"Error extracting plan for {media_type}: {e}")
        return None
    def _download_and_merge_segments(self, seg_info, mpd_content, video_output, audio_output):
        for media_type in ["video", "audio"]:
            info = seg_info[media_type]
    
            plan = self._extract_segment_plan(mpd_content, media_type)
            if not plan:
                self.logger.error(f"No segment plan found in MPD for {media_type}")
                continue
    
            # === 初期化セグメント ===
            init_filename = video_output if media_type == "video" else audio_output
            if plan["init"]:
                init_path = self._fill_template(plan["init"], plan["rep"])
                init_url = urljoin(info["url_base"], init_path)
                if not os.path.exists(init_filename):
                    self._download_segment(init_url, init_filename)
    
            # === 本編セグメント ===
            media_tpl = plan["media"]
            if not media_tpl:
                self.logger.error("media template missing.")
                continue
    
            if plan["uses_time"]:
                for item in plan["timeline"]:
                    t = item["t"]
                    if t in self.downloaded_segments[media_type]:
                        continue
                    seg_path = self._fill_template(media_tpl, {**plan["rep"], "Time": t})
                    seg_url = urljoin(info["url_base"], seg_path)
                    self._download_segment(seg_url, init_filename)
                    self.downloaded_segments[media_type].add(t)
    
            elif plan["uses_number"]:
                if plan["start_number"] is None:
                    self.logger.error("startNumber is missing for $Number$ addressing.")
                    continue
                count = len(plan["timeline"]) if plan["timeline"] else 0
                # SegmentTimeline が無い $Number$ の場合はライブでは「増える」ので、
                # 既に落とした最大番号+1 から順に試すなどの戦略が必要。ここでは TL 長に合わせる簡易版。
                for i in range(count):
                    n = plan["start_number"] + i
                    if n in self.downloaded_segments[media_type]:
                        continue
                    seg_path = self._fill_template(media_tpl, {**plan["rep"], "Number": n})
                    seg_url = urljoin(info["url_base"], seg_path)
                    self._download_segment(seg_url, init_filename)
                    self.downloaded_segments[media_type].add(n)
    
            else:
                self.logger.error("Unknown addressing mode (neither $Time$ nor $Number$).")
    def _parse_minimum_update_period(self, mpd_content):
        try:
            root = ET.fromstring(mpd_content)
            mup_str = root.attrib.get("minimumUpdatePeriod", "PT5S")
            if mup_str.startswith("PT") and mup_str.endswith("S"):
                return float(mup_str[2:-1])
        except Exception as e:
            self.logger.error(f"Error parsing minimumUpdatePeriod: {e}")
        return 5.0  # nothing found/ return 5.0
    def _fetch_mpd_segment_info(self, mpd_url: str):
        response = requests.get(mpd_url)
        if response.status_code == 200:
            return response.text
        else:
            self.logger.error(f"Failed to fetch MPD: {response.status_code}")
            return None
    def download(self, url: str, res_info: Dict[str, Any], config: Dict[str, Any], unixtime: str, service_name: str = "") -> Tuple[bool]:
        try:
            output_temp_directory = os.path.join(config["directories"]["Temp"], "content", unixtime)
            os.makedirs(output_temp_directory, exist_ok=True)
            
            while True:
                ### define output 
                output_video = os.path.join(output_temp_directory, "download_encrypt_video.mp4")
                output_audio = os.path.join(output_temp_directory, "download_encrypt_audio.mp4")
                
                ### check mpd content
                not_found_mpd = 0
                mpd_content = self._fetch_mpd_segment_info(url)
                if not_found_mpd == 5:
                    self.logger.info("Live Stream Ended")
                    return True
                if not mpd_content:
                    not_found_mpd = not_found_mpd + 1
                    time.sleep(5)
                    continue
        
                mup = self._parse_minimum_update_period(mpd_content)
                self._download_and_merge_segments(res_info, mpd_content, output_video, output_audio)
        
                self.logger.info(f"Sleeping for {mup} seconds before refreshing MPD...")
                time.sleep(mup)
        except KeyboardInterrupt:
            return True
        except Exception:
            return True # ライブ終了時の判別ができていないので仮

class n_m3u8dl_downloader:
    def __init__(self, enable_debug):
        self.debug = enable_debug
    def _get_executable_path(self, config: Dict[str, Any]) -> str:
        """OSに応じてaria2cの実行可能ファイルパスを取得する。"""
        if os.name == 'nt':
            path = os.path.join(config["directories"]["Binaries"], "N_m3u8DL-RE.exe")
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise FileNotFoundError(f"N-m3u8DL-RE binary not found or not executable: {path}")
            return path
        else:
            path = os.path.join(config["directories"]["Binaries"], "N_m3u8DL-RE")
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise FileNotFoundError(f"N-m3u8DL-RE binary not found or not executable: {path}")
            return path
    def _log_line(self, service_name: str, line: str):
        """指定フォーマットで1行出力する（進捗以外）。"""
        prefix = (
            f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} "
            f"[{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "
        )
        # tqdmと共存するため tqdm.write を使用
        tqdm.write(prefix + line)

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
            n_m3u8dl_re_path = self._get_executable_path(config)
        except FileNotFoundError as e:
            return False, str(e)
            
        output_temp_directory = os.path.join(config["directories"]["Temp"], "content", unixtime)
        os.makedirs(output_temp_directory, exist_ok=True)

        downlaoder_command = [
            n_m3u8dl_re_path,
            url,
            "--tmp-dir", output_temp_directory,
            "--save-name", output_file_name,
            "--download-retry-count", "4",
            "--binary-merge",
            #"--skip-merge",
            "--http-request-timeout", "30",
            "-H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
            "--disable-update-check",
            "-M", "format=mp4"
        ]

        #if self.debug:
        #    downlaoder_command.extend(["-M", "keep=true"])
#
        #print(downlaoder_command)


        ratio_re = re.compile(r"(?P<cur>\d+)\s*/\s*(?P<tot>\d+)")
        segs_re = re.compile(r"Segments\s*\|\s*(?P<tot>\d+)")
        progress_line_hint = re.compile(r"Vid\s+Kbps.*\d+/\d+")

        pbar = None
        last_n = 0
        total_from_segments = None
        done_flag = False

        try:
            process = subprocess.Popen(
                downlaoder_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
                encoding='utf-8',
                errors='replace',
                cwd=output_temp_directory
            )
        except Exception as e:
            return False, f"Failed to start process: {e}"
        
        output_desc = f"{COLOR_GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{COLOR_RESET} [{COLOR_GRAY}INFO{COLOR_RESET}] {COLOR_BLUE}{service_name}{COLOR_RESET} : "

        try:
            assert process.stdout is not None
            for raw_line in iter(process.stdout.readline, ""):
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue

                # total 推定 (Segments行)
                if total_from_segments is None:
                    sm = segs_re.search(line)
                    if sm:
                        try:
                            total_from_segments = int(sm.group("tot"))
                            if pbar is None:
                                pbar = tqdm(
                                    total=total_from_segments,
                                    desc=output_desc,
                                    leave=True,
                                    dynamic_ncols=True,
                                    mininterval=0.3,
                                    disable=not sys.stderr.isatty(),
                                )
                        except ValueError:
                            pass

                # 進捗更新 (65/75 のような行)
                m = ratio_re.search(line)
                if m:
                    cur = int(m.group("cur"))
                    tot = int(m.group("tot"))
                    if pbar is None:
                        pbar = tqdm(
                            total=tot,
                            desc=output_desc,
                            leave=True,
                            dynamic_ncols=True,
                            mininterval=0.3,
                            disable=not sys.stderr.isatty(),
                        )
                    elif pbar.total != tot:
                        pbar.total = tot

                    if cur >= last_n:
                        pbar.n = cur
                        pbar.refresh()
                        last_n = cur

                # Done検出
                if "Done" in line:
                    done_flag = True
                    if pbar is not None:
                        pbar.n = pbar.total
                        pbar.refresh()


                # 進捗行以外だけ自前ログに流す
                if not progress_line_hint.search(line):
                    self._log_line(service_name, line)
            process.wait()
        finally:
            if pbar is not None:
                pbar.close()

        if process.returncode != 0:
            return False, f"Downloader exited with code {process.returncode}"

        if done_flag:
            return True, output_temp_directory
        else:
            return False, "Download did not complete (no 'Done' detected)."                

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
        