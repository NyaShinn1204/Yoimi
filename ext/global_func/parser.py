# -*- coding: utf-8 -*-
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin # BaseURL結合のため
import math # for math.ceil

class global_parser:

    def _resolve_base_url(self, element, current_base_url, ns):
        """
        要素とその親からBaseURLを解決する。
        要素内にBaseURLがあれば、それを current_base_url と結合する。
        なければ current_base_url をそのまま返す。
        """
        new_base_url = current_base_url
        base_url_elem = element.find("mpd:BaseURL", ns)
        if base_url_elem is not None and base_url_elem.text:
            resolved = urljoin(current_base_url, base_url_elem.text.strip())
            new_base_url = resolved
        return new_base_url

    def _extract_track_info_from_representation(self, representation, adaptation_set, current_period_base_url, ns, debug=False):
        """
        Representation要素からトラック情報を抽出するヘルパー関数。
        SegmentTemplate (AdaptationSetレベルも考慮), SegmentBase (range含む) に対応。
        BaseURLの解決、$RepresentationID$の置換も行う。
        """
        rep_id = representation.attrib.get("id")
        if not rep_id:
             if debug: print("  Skipping Representation without ID.")
             return None
        if debug: print(f"Processing Representation ID: {rep_id}")

        # --- BaseURL解決 (Period -> AdaptationSet -> Representation) ---
        adapt_base_url = self._resolve_base_url(adaptation_set, current_period_base_url, ns)
        rep_base_url = self._resolve_base_url(representation, adapt_base_url, ns)
        effective_base_url = rep_base_url
        if debug: print(f"  Effective BaseURL for Rep ID {rep_id}: {effective_base_url}")

        # --- セグメント情報抽出 ---
        segment_template = representation.find("mpd:SegmentTemplate", ns)
        segment_base_elem = representation.find("mpd:SegmentBase", ns)
        source_element_for_template = representation

        if segment_template is None and segment_base_elem is None:
            segment_template = adaptation_set.find("mpd:SegmentTemplate", ns)
            if segment_template is not None:
                source_element_for_template = adaptation_set
                if debug: print(f"  Using SegmentTemplate from AdaptationSet for Rep ID {rep_id}")

        track_info = None

        # --- Case 1: SegmentTemplate ---
        if segment_template is not None:
            if debug: print(f"  Found SegmentTemplate (source: {source_element_for_template.tag.split('}')[-1]}) for Rep ID {rep_id}")

            init_template = segment_template.attrib.get("initialization")
            media_template = segment_template.attrib.get("media")
            segment_duration = segment_template.attrib.get("duration", "N/A")
            timescale = segment_template.attrib.get("timescale", "N/A")
            start_number_str = segment_template.attrib.get("startNumber", "1") # 元のコードに合わせてデフォルト"1"

            if not init_template or not media_template:
                if debug: print(f"    SegmentTemplate found but missing 'initialization' or 'media' attribute for Rep ID {rep_id}")
                return None

            # --- Replace $RepresentationID$ ---
            init_path = init_template.replace('$RepresentationID$', rep_id)
            media_path_template = media_template.replace('$RepresentationID$', rep_id)

            # --- Resolve URL ---
            init_url = urljoin(effective_base_url, init_path)
            url_base = "/".join(init_url.split("/")[:-1]) + "/" if "/" in init_url else ""

            # --- Calculate url_segment_base ---
            # 元のロジックに近い形で再実装
            # media属性からファイル名部分 ($Number$, $Time$ などを含む) を特定し、それより前の部分を取得
            segment_base_url_part = ""
            media_parts = media_path_template.split('$')
            if len(media_parts) > 1: # $識別子$ が含まれる場合
                # 最初の $ より前の部分を取得
                segment_base_url_part = media_parts[0]
            else: # $識別子$ が含まれない場合 (固定ファイル名？)
                 # 元のコードの re.sub に近い挙動 (ただし$置換後)
                 segment_base_url_part = re.sub(r'^(audio|video)/[0-9a-f-]+/', '', media_path_template)

            # 元のコードでは segment_base は以下のように算出していたのでそれに合わせる
            # segment_base = re.sub(r'^(audio|video)/[0-9a-f-]+/', '', segment_template.attrib.get("media", ""))
            # 今回は $RepresentationID$ を置換した後の media_path_template を使う
            # また、元のコードの url_segment_base の定義と合わせる
            segment_base = re.sub(r'^(audio|video)/[0-9a-f-]+/', '', media_path_template)


            if debug: print(f"    SegmentTemplate Info: init='{init_path}', media_template='{media_path_template}', duration='{segment_duration}', timescale='{timescale}'")
            if debug: print(f"    Resolved init URL: {init_url}")
            if debug: print(f"    Calculated segment_base (original logic): {segment_base}")

            track_info = {
                "url": init_url,                  # Initialization URL
                "url_base": url_base,             # Base path for init URL
                "url_segment_base": segment_base, # Segment base name (original logic)
                "seg_duration": segment_duration,
                "seg_timescale": timescale,
                # "initialization_range": None, # Add if needed later
                # "segment_index_range": None,  # Add if needed later
                "id": rep_id
            }

        # --- Case 2: SegmentBase ---
        elif segment_base_elem is not None:
            if debug: print(f"  Found SegmentBase for Rep ID {rep_id}")
            initialization_elem = segment_base_elem.find("mpd:Initialization", ns)
            init_range = None
            if initialization_elem is not None:
                init_range = initialization_elem.attrib.get("range") # Just get the range
                if debug: print(f"    Initialization range: {init_range}")
            # segment_range = segment_base_elem.attrib.get("indexRange") # Not used in original track_info

            if not effective_base_url:
                 if debug: print(f"    SegmentBase found but no BaseURL resolved for Rep ID {rep_id}. Using Rep ID as placeholder URL.")
                 effective_base_url = rep_id

            url_base = "/".join(effective_base_url.split("/")[:-1]) + "/" if "/" in effective_base_url else ""
            segment_base_url_part = "" # Not applicable in original logic

            track_info = {
                "url": effective_base_url,          # Media file URL
                "url_base": url_base,
                "url_segment_base": segment_base_url_part, # N/A
                "seg_duration": "N/A",            # N/A in original
                "seg_timescale": "N/A",           # N/A in original
                # "initialization_range": init_range, # Add if needed later
                # "segment_index_range": segment_range, # Add if needed later
                "id": rep_id
            }

        else:
            if debug: print(f"  SegmentTemplate and SegmentBase not found for Rep ID {rep_id}")
            return None

        if not track_info:
            return None

        # --- Extract common media properties (as in original code) ---
        mime_type = representation.attrib.get("mimeType")
        if not mime_type: mime_type = adaptation_set.attrib.get("mimeType", "")

        # Check contentType as fallback (useful for some MPDs)
        if not mime_type:
             content_type = adaptation_set.attrib.get("contentType")
             if not content_type: content_type = representation.attrib.get("contentType")
             if content_type == "video": mime_type = "video/mp4"
             elif content_type == "audio": mime_type = "audio/mp4"
             elif debug: print(f"  MimeType/contentType not found for Rep ID {rep_id}.")
             # Allow proceeding without mimeType if needed, type-specific info will be missing

        bandwidth_str = representation.attrib.get("bandwidth", "0")
        codec = representation.attrib.get("codecs", "")

        try:
            bitrate_kbps = int(bandwidth_str or 0) / 1000
            track_info["bitrate"] = str(int(bitrate_kbps)) # Store as integer string
            track_info["codec"] = codec
        except ValueError as e:
            print(f"ValueError: Invalid bandwidth value: '{bandwidth_str}' for Rep ID {rep_id} - {e}")
            return None # Treat as fatal error

        # --- Extract type-specific properties (as in original code) ---
        if "video" in mime_type:
            track_info["type"] = "video" # Mark type for categorization
            width = representation.attrib.get("width")
            height = representation.attrib.get("height")
            track_info["resolution"] = f"{width}x{height}" if width and height else "N/A"
            if debug: print(f"  Extracted Video Track Info: {track_info}")
            return track_info

        elif "audio" in mime_type:
            track_info["type"] = "audio" # Mark type for categorization
            # Original code didn't extract language or channels here, add if needed
            lang = adaptation_set.attrib.get("lang", "und")
            track_info["language"] = lang # Add language as it's often useful
            if debug: print(f"  Extracted Audio Track Info: {track_info}")
            return track_info
        else:
            if debug: print(f"  Unknown or unsupported mimeType '{mime_type}' for Rep ID {rep_id}")
            # Return the basic track info even if type is unknown, or return None
            # Let's return the info, downstream code can filter later if needed
            track_info["type"] = "unknown"
            return track_info


    def mpd_parser(self, mpd_content, mpd_url="", debug=False):
        """MPDコンテンツを解析し、トラック情報やPSSHなどを抽出する (元の形式に近いPSSHリスト)"""
        try:
            if mpd_content.startswith('\ufeff'): mpd_content = mpd_content[1:]
            root = ET.fromstring(mpd_content.strip())
        except ET.ParseError as e:
            print(f"Error parsing MPD XML: {e}")
            try:
                line, column = e.position; lines = mpd_content.splitlines()
                if 0 < line <= len(lines):
                     print(f"Error near line {line}:\n{lines[line-1]}\n{' ' * (column-1)}^")
            except Exception: pass
            return None

        ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011',
              'cenc': 'urn:mpeg:cenc:2013',
              'mspr': 'urn:microsoft:playready', # Kept namespace for potential future use
              'xsi': 'http://www.w3.org/2001/XMLSchema-instance'}

        # --- Resolve MPD level BaseURL ---
        mpd_base_url = mpd_url
        base_url_elem = root.find('mpd:BaseURL', ns)
        if base_url_elem is not None and base_url_elem.text:
             mpd_base_url = urljoin(mpd_url, base_url_elem.text.strip())
        if debug: print(f"BaseURL (MPD level, resolved from '{mpd_url}'): {mpd_base_url}")

        # --- PSSH情報の取得 (元の形式) ---
        pssh_list = {}
        # Find all ContentProtection elements anywhere in the document
        for content_protection in root.findall(".//mpd:ContentProtection", ns):
            scheme_id_uri = content_protection.attrib.get("schemeIdUri", "").lower()
            # Find the cenc:pssh element within this ContentProtection
            pssh_elem = content_protection.find("cenc:pssh", ns)

            if pssh_elem is not None and pssh_elem.text:
                pssh_text = pssh_elem.text.replace('\n', '').strip()
                drm_system = None
                if "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" in scheme_id_uri: drm_system = "widevine"
                elif "9a04f079-9840-4286-ab92-e65be0885f95" in scheme_id_uri: drm_system = "playready"
                elif "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b" in scheme_id_uri: drm_system = "w3c_cenc" # As in original

                # Store the first PSSH found for each system
                if drm_system and drm_system not in pssh_list:
                    pssh_list[drm_system] = pssh_text
                    if debug: print(f"Found {drm_system.upper()} PSSH.")
            # Stop searching if all desired systems are found (optional optimization)
            # if "widevine" in pssh_list and "playready" in pssh_list and "w3c_cenc" in pssh_list:
            #     break

        if debug: print(f"PSSH List: {pssh_list}")


        # --- トラック情報の抽出 ---
        video_tracks = []
        audio_tracks = []
        # text_tracks = [] # Original didn't handle text tracks
        periods = root.findall('mpd:Period', ns)
        if not periods and root.tag == '{' + ns['mpd'] + '}MPD': periods = [root]

        for period in periods:
            period_id = period.attrib.get('id', 'N/A')
            if debug: print(f"Processing Period (ID: {period_id})")
            current_period_base_url = self._resolve_base_url(period, mpd_base_url, ns)
            if debug: print(f"  BaseURL (Period level): {current_period_base_url}")

            for adaptation_set in period.findall('mpd:AdaptationSet', ns):
                adapt_id = adaptation_set.attrib.get('id', 'N/A')
                mime_type_adapt = adaptation_set.attrib.get('mimeType', 'N/A')
                content_type_adapt = adaptation_set.attrib.get('contentType', 'N/A')
                if debug: print(f"  Processing AdaptationSet (ID: {adapt_id}, mimeType: {mime_type_adapt}, contentType: {content_type_adapt})")

                for representation in adaptation_set.findall("mpd:Representation", ns):
                    track_info = self._extract_track_info_from_representation(
                        representation, adaptation_set, current_period_base_url, ns, debug=debug
                    )

                    if track_info:
                        track_type = track_info.get("type")
                        if track_type == "video": video_tracks.append(track_info)
                        elif track_type == "audio": audio_tracks.append(track_info)
                        # elif track_type == "text": text_tracks.append(track_info)

        # --- MPDルート要素の属性を取得 ---
        more_info = self.extract_mpd_attributes(mpd_content) # Kept this method

        # --- 結果を返す ---
        return {
            "info": more_info,
            "pssh_list": pssh_list,
            "video_track": video_tracks,
            "audio_track": audio_tracks
            # "text_track": text_tracks # Keep commented out as per original
        }

    def calculate_video_duration(self, duration_str):
        """ISO 8601 duration (PnYnMnDTnHnMnS) を秒単位に変換"""
        if not duration_str or not isinstance(duration_str, str) or not duration_str.startswith('P'):
            return 0
        try:
            # 正規表現で全フィールドをキャプチャ
            pattern = (
                r'P' 
                r'(?:(?P<years>\d+(?:\.\d+)?)Y)?'
                r'(?:(?P<months>\d+(?:\.\d+)?)M)?'
                r'(?:(?P<days>\d+(?:\.\d+)?)D)?'
                r'(?:T'
                    r'(?:(?P<hours>\d+(?:\.\d+)?)H)?'
                    r'(?:(?P<minutes>\d+(?:\.\d+)?)M)?'
                    r'(?:(?P<seconds>\d+(?:\.\d+)?)S)?'
                r')?'
            )
            match = re.match(pattern, duration_str)
            if not match:
                return 0
            parts = match.groupdict()
            duration_sec = 0.0
            if parts['years']: duration_sec += float(parts['years']) * 31536000  # 365日換算
            if parts['months']: duration_sec += float(parts['months']) * 2592000  # 30日換算
            if parts['days']: duration_sec += float(parts['days']) * 86400
            if parts['hours']: duration_sec += float(parts['hours']) * 3600
            if parts['minutes']: duration_sec += float(parts['minutes']) * 60
            if parts['seconds']: duration_sec += float(parts['seconds'])
            return duration_sec
        except Exception:
            return 0

    def calculate_segments(self, media_duration, segment_duration, timescale):
        """セグメント数を計算"""
        segment_seconds = segment_duration / timescale
        return round(media_duration / segment_seconds)  


    def extract_mpd_attributes(self, mpd_content):
        """
        MPD文字列からルート要素の属性を抽出します。
        (元のコードには無かったが、便利なので残しておく)
        xmlnsとxsi:schemaLocationを除外します。
        """
        # (Implementation from previous step - kept as is)
        try:
            if mpd_content.startswith('\ufeff'): mpd_content = mpd_content[1:]
            root = ET.fromstring(mpd_content.strip())
            attributes = {}; ns_xsi = '{http://www.w3.org/2001/XMLSchema-instance}'; ns_xmlns = '{http://www.w3.org/2000/xmlns/}'
            for key, value in root.attrib.items():
                 if key.startswith(ns_xmlns) or key == ns_xsi + 'schemaLocation': continue
                 local_name = key.split('}', 1)[-1]
                 attributes[local_name] = value
            return attributes
        except ET.ParseError: return {}


    def print_tracks(self, tracks_json):
        """解析結果を元のシンプルな形式で表示する文字列を生成"""
        # --- Reverted to the original print_tracks code ---
        if not tracks_json or not isinstance(tracks_json, dict):
            return "Invalid tracks data provided."

        output = ""
        # Video tracks
        video_tracks = tracks_json.get('video_track', [])
        output += f"{len(video_tracks)} Video Tracks:\n"
        if video_tracks:
             # Determine prefix for each line
             prefixes = ["├─"] * (len(video_tracks) - 1) + ["└─"] if len(video_tracks) > 0 else []
             for i, video in enumerate(video_tracks):
                 prefix = prefixes[i]
                 codec = video.get('codec', 'N/A')
                 resolution = video.get('resolution', 'N/A')
                 bitrate = video.get('bitrate', 'N/A')
                 output += f"{prefix} VID | [{codec}] [{resolution}] | {bitrate} kbps\n" # Original format
        else:
             output += "  No video tracks found.\n" # Indentation for consistency if needed

        # Audio tracks
        audio_tracks = tracks_json.get('audio_track', [])
        output += f"\n{len(audio_tracks)} Audio Tracks:\n"
        if audio_tracks:
             prefixes = ["├─"] * (len(audio_tracks) - 1) + ["└─"] if len(audio_tracks) > 0 else []
             for i, audio in enumerate(audio_tracks):
                 prefix = prefixes[i]
                 codec = audio.get('codec', 'N/A')
                 bitrate = audio.get('bitrate', 'N/A')
                 # Original format didn't explicitly show language, but it's useful. Keeping it simple.
                 # lang = audio.get('language', 'und')
                 # output += f"{prefix} AUD | [{codec}] [{lang}] | {bitrate} kbps\n"
                 output += f"{prefix} AUD | [{codec}] | {bitrate} kbps\n" # Reverted to original format
        else:
             output += "  No audio tracks found.\n"

        # Text tracks (Keep commented out as original)
        # text_tracks = tracks_json.get('text_track', [])
        # output += f"\n{len(text_tracks)} Text Tracks:\n"
        # ...

        return output.strip()


    def select_best_tracks(self, tracks_json):
        """利用可能なトラックの中から最もビットレートが高いものを選択"""
        # (Implementation from previous step - kept as is, robust version)
        if not tracks_json or not isinstance(tracks_json, dict): return {"video": None, "audio": None}
        highest_video, highest_audio = None, None
        video_tracks = tracks_json.get("video_track", [])
        if video_tracks:
            try:
                valid_videos = [v for v in video_tracks if str(v.get("bitrate", "")).isdigit()]
                if valid_videos: highest_video = max(valid_videos, key=lambda x: int(x["bitrate"]))
                else: highest_video = video_tracks[0] if video_tracks else None
            except (ValueError, TypeError, IndexError): highest_video = video_tracks[0] if video_tracks else None
        audio_tracks = tracks_json.get("audio_track", [])
        if audio_tracks:
             try:
                 valid_audios = [a for a in audio_tracks if str(a.get("bitrate", "")).isdigit()]
                 if valid_audios: highest_audio = max(valid_audios, key=lambda x: int(x["bitrate"]))
                 else: highest_audio = audio_tracks[0] if audio_tracks else None
             except (ValueError, TypeError, IndexError): highest_audio = audio_tracks[0] if audio_tracks else None
        return {"video": highest_video, "audio": highest_audio}