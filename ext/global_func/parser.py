import re
import xml.etree.ElementTree as ET

class global_parser:
    def mpd_parser(self, mpd_content, debug=False):
        root = ET.fromstring(mpd_content)
        ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013', 'mspr': 'urn:microsoft:playready'}
    
        # BaseURLの取得（存在しない場合は None）
        base_url_elem = root.find('mpd:BaseURL', ns)
        base_url = base_url_elem.text if base_url_elem is not None else ""
        if debug:
            print(f"BaseURL: {base_url}")
    
        # PSSH情報を取得
        pssh_list = {}
        for content_protection in root.findall(".//mpd:ContentProtection", ns):
            scheme_id_uri = content_protection.attrib.get("schemeIdUri", "")
            pssh = content_protection.find("cenc:pssh", ns)
            if pssh is not None and pssh.text:
                pssh_text = pssh.text.replace('\n', '').strip()
                if "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" in scheme_id_uri.lower(): # Widevine
                    pssh_list["widevine"] = pssh_text
                elif "9a04f079-9840-4286-ab92-e65be0885f95" in scheme_id_uri.lower(): # PlayReady
                    pssh_list["playready"] = pssh_text
                elif "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b" in scheme_id_uri.lower(): # W3C Cenc
                    pssh_list["w3c_cenc"] = pssh_text
        if debug:
            print(f"PSSH List: {pssh_list}")
    
        # トラック情報
        video_tracks = []
        audio_tracks = []
        for adaptation_set in root.findall(".//mpd:AdaptationSet", ns):
            if debug:
                print("Found AdaptationSet")
            mime_type = adaptation_set.attrib.get("mimeType", "")
            if debug:
                print(f"AdaptationSet MIME Type: {mime_type}")
            segment_template_adaptation_set = adaptation_set.find("mpd:SegmentTemplate", ns)
            if segment_template_adaptation_set is not None and debug:
                print("Found AdaptationSet SegmentTemplate")
    
            # AdaptationSetにmimeTypeが指定されている場合の処理
            if "video/mp4" in mime_type or "audio/mp4" in mime_type:
                for representation in adaptation_set.findall("mpd:Representation", ns):
                    if debug:
                        print("Found Representation")
                    rep_id = representation.attrib.get("id")  # IDを取得
                    if debug:
                        print(f"Representation ID: {rep_id}")
                    segment_template = representation.find("mpd:SegmentTemplate", ns)
                    if segment_template is None:
                        segment_template = segment_template_adaptation_set
    
                    if segment_template is not None:
                        if debug:
                            print("Found SegmentTemplate")
                        init = segment_template.attrib.get("initialization", "")
                        url = f"{base_url}{init}" if base_url else init
                        url_base = "/".join(url.split("/")[:-1]) + "/" if url.split("/")[:-1] else ""
                        segment_base = re.sub(r'^(audio|video)/[0-9a-f-]+/', '', segment_template.attrib.get("media", ""))
    
                        segment_duration = segment_template.attrib.get("duration", "404_notfound")
                        timescale = segment_template.attrib.get("timescale", "404_notfound")
    
                        track_info = {
                            "seg_duration": segment_duration,
                            "seg_timescale": timescale,
                            "url": url,
                            "url_base": url_base,
                            "url_segment_base": segment_base
                        }
                        if rep_id:
                            track_info["id"] = rep_id  # IDがある場合に追加
    
                        if "video/mp4" in mime_type:
                            width = representation.attrib.get("width")
                            height = representation.attrib.get("height")
                            bitrate_str = representation.attrib.get("bandwidth", "0")
                            codec = representation.attrib.get("codecs", "")
                            try:
                                bitrate = int(bitrate_str) / 1000
                                if debug:
                                    print(f"Video Bitrate: {bitrate}")
                            except ValueError as e:
                                print(f"ValueError: Invalid bandwidth value: {bitrate_str} - {e}")
                                continue
    
                            track_info["resolution"] = f"{width}x{height}"
                            track_info["bitrate"] = str(int(bitrate))
                            track_info["codec"] = codec
    
                            video_tracks.append(track_info)
                            if debug:
                                print(f"Added Video Track: {track_info}")
                        elif "audio/mp4" in mime_type:
                            bandwidth_str = representation.attrib.get("bandwidth", "0")
                            codec = representation.attrib.get("codecs", "")
                            try:
                                bandwidth = int(bandwidth_str) / 1000
                                if debug:
                                    print(f"Audio Bandwidth: {bandwidth}")
                            except ValueError as e:
                                print(f"ValueError: Invalid bandwidth value: {bandwidth_str} - {e}")
                                continue
    
                            track_info["bitrate"] = str(int(bandwidth))
                            track_info["codec"] = codec
    
                            audio_tracks.append(track_info)
                            if debug:
                                print(f"Added Audio Track: {track_info}")
                    else:
                        if debug:
                            print("SegmentTemplate not found")
            else:  # AdaptationSetにmimeTypeが指定されていない場合の処理
                for representation in adaptation_set.findall("mpd:Representation", ns):
                    if debug:
                        print("Found Representation")
                    representation_mime_type = representation.attrib.get("mimeType", "")
                    if debug:
                        print(f"Representation MIME Type: {representation_mime_type}")
                    rep_id = representation.attrib.get("id")  # IDを取得
                    if debug:
                        print(f"Representation ID: {rep_id}")
                    segment_template = representation.find("mpd:SegmentTemplate", ns)
                    if segment_template is None:
                        segment_template = segment_template_adaptation_set

                    if segment_template is not None:
                        if debug:
                            print("Found SegmentTemplate")
                        init = segment_template.attrib.get("initialization", "")
                        url = f"{base_url}{init}" if base_url else init
                        url_base = "/".join(url.split("/")[:-1]) + "/" if url.split("/")[:-1] else ""
                        segment_base = re.sub(r'^(audio|video)/[0-9a-f-]+/', '', segment_template.attrib.get("media", ""))

                        segment_duration = segment_template.attrib.get("duration", "404_notfound")
                        timescale = segment_template.attrib.get("timescale", "404_notfound")

                        track_info = {
                            "seg_duration": segment_duration,
                            "seg_timescale": timescale,
                            "url": url,
                            "url_base": url_base,
                            "url_segment_base": segment_base
                        }
                        if rep_id:
                            track_info["id"] = rep_id  # IDがある場合に追加

                        if "video/mp4" in representation_mime_type:
                            width = representation.attrib.get("width")
                            height = representation.attrib.get("height")
                            bitrate_str = representation.attrib.get("bandwidth", "0")
                            codec = representation.attrib.get("codecs", "")
                            try:
                                bitrate = int(bitrate_str) / 1000
                                if debug:
                                    print(f"Video Bitrate: {bitrate}")
                            except ValueError as e:
                                print(f"ValueError: Invalid bandwidth value: {bitrate_str} - {e}")
                                continue

                            track_info["resolution"] = f"{width}x{height}"
                            track_info["bitrate"] = str(int(bitrate))
                            track_info["codec"] = codec

                            video_tracks.append(track_info)
                            if debug:
                                print(f"Added Video Track: {track_info}")
                        elif "audio/mp4" in representation_mime_type:
                            bandwidth_str = representation.attrib.get("bandwidth", "0")
                            codec = representation.attrib.get("codecs", "")
                            try:
                                bandwidth = int(bandwidth_str) / 1000
                                if debug:
                                    print(f"Audio Bandwidth: {bandwidth}")
                            except ValueError as e:
                                print(f"ValueError: Invalid bandwidth value: {bandwidth_str} - {e}")
                                continue

                            track_info["bitrate"] = str(int(bandwidth))
                            track_info["codec"] = codec

                            audio_tracks.append(track_info)
                            if debug:
                                print(f"Added Audio Track: {track_info}")
                    else:
                        if debug:
                            print("SegmentTemplate not found")
    
        more_info = self.extract_mpd_attributes(mpd_content)
    
        return {
            "info": more_info,
            "pssh_list": pssh_list,
            "video_track": video_tracks,
            "audio_track": audio_tracks
        }
    
    def calculate_video_duration(self, duration_str):
        """ISO 8601 duration (PT format) を秒単位に変換"""
        match = re.match(r'P(?:\d+Y)?(?:\d+M)?(?:\d+D)?T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?', duration_str)
        if not match:
            raise ValueError("Invalid duration format")
        hours = float(match.group(1) or 0)
        minutes = float(match.group(2) or 0)
        seconds = float(match.group(3) or 0)
        
        return hours * 3600 + minutes * 60 + seconds
    def calculate_segments(self, media_duration, segment_duration, timescale):
        """セグメント数を計算"""
        segment_seconds = segment_duration / timescale
        return round(media_duration / segment_seconds)    
    def extract_mpd_attributes(self, mpd_content):
        """
        MPD文字列からxmlnsとxmlns:ns2を除いた属性を抽出します。
    
        Args:
            mpd_string: MPDのXML文字列
    
        Returns:
            属性を格納した辞書(例: {"info": {"id": "05a2c312-074f-4684-a26c-31c3ca8fb0b8", "type": "static", ...}})
        """
    
        try:
            root = ET.fromstring(mpd_content)
            attributes = root.attrib.copy()  # 属性をコピーして変更に備える
    
            # 名前空間の属性を削除
            attributes.pop('xmlns', None)
            attributes.pop('xmlns:ns2', None)
    
            return attributes
        except ET.ParseError as e:
            #print(f"XMLパースエラー: {e}")
            return {}  # エラー発生時は空の辞書を返す
    
    def print_tracks(self, tracks_json):
        output = ""
        # Video tracks まぁvideoやな
        output += f"{len(tracks_json['video_track'])} Video Tracks:\n"
        for i, video in enumerate(tracks_json["video_track"]):
            output += f"├─ VID | [{video['codec']}] [{video["resolution"]}] | {video['bitrate']} kbps\n"
        
        # Audio tracks まぁaudioやな
        output += f"\n{len(tracks_json['audio_track'])} Audio Tracks:\n"
        for i, audio in enumerate(tracks_json["audio_track"]):
            output += f"├─ AUD | [{audio['codec']}] | {audio['bitrate']} kbps\n"
    
        # Text tracks まぁsubやな
        # output += f"\n{len(tracks_json['text_track'])} Text Tracks:\n"
        # for i, text in enumerate(tracks_json["text_track"]):
            # output += f"├─ SUB | [VTT] | {text['language']} | {text['name']}\n"
        
        #print(output)
        return output
    def select_best_tracks(self, tracks_json):
        # ここでビットレートが一番高いやつを盗んでreturnで殴る
        highest_bitrate_video = max(tracks_json["video_track"], key=lambda x: int(x["bitrate"]))
    
        # ここでビットレートが一番高いやつを盗んでreturnで殴る
        highest_bitrate_audio = max(tracks_json["audio_track"], key=lambda x: int(x["bitrate"]))
    
        return {
            "video": highest_bitrate_video,
            "audio": highest_bitrate_audio
        }