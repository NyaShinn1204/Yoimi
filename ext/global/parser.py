import xml.etree.ElementTree as ET

class global_parser:
    def mpd_parser(self, mpd_content):
        root = ET.fromstring(mpd_content)
        ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011', 'cenc': 'urn:mpeg:cenc:2013'}
    
        # BaseURLの取得
        base_url = root.find('mpd:BaseURL', ns).text
    
        # PSSH情報を取得
        pssh_list = {}
        for content_protection in root.findall(".//mpd:ContentProtection", ns):
            scheme_id_uri = content_protection.attrib.get("schemeIdUri", "")
            pssh = content_protection.find("cenc:pssh", ns)
            if pssh is not None and pssh.text:
                if "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed" in scheme_id_uri:  # Widevine
                    pssh_list["widevine"] = pssh.text
                elif "9a04f079-9840-4286-ab92-e65be0885f95" in scheme_id_uri:  # PlayReady
                    pssh_list["playready"] = pssh.text
    
        # ビデオトラック情報
        video_tracks = []
        for adaptation_set in root.findall(".//mpd:AdaptationSet[@mimeType='video/mp4']", ns):
            for representation in adaptation_set.findall("mpd:Representation", ns):
                width = representation.attrib.get("width")
                height = representation.attrib.get("height")
                bitrate = int(representation.attrib.get("bandwidth", 0))
                codec = representation.attrib.get("codecs", "")
                
                segment_template = representation.find("mpd:SegmentTemplate", ns)
                if segment_template is not None:
                    init = segment_template.attrib.get("initialization")
                    url = f"{base_url}{init}"
                    url_base = "/".join(url.split("/")[:-1]) + "/"
    
                    video_tracks.append({
                        "resolution": f"{width}x{height}",
                        "bitrate": bitrate,
                        "codec": codec,
                        "url": url,
                        "url_base": url_base
                    })
    
        # オーディオトラック情報
        audio_tracks = []
        for adaptation_set in root.findall(".//mpd:AdaptationSet[@mimeType='audio/mp4']", ns):
            for representation in adaptation_set.findall("mpd:Representation", ns):
                bandwidth = representation.attrib.get("bandwidth", "0")
                codecs = representation.attrib.get("codecs", "")
    
                segment_template = representation.find("mpd:SegmentTemplate", ns)
                if segment_template is not None:
                    init = segment_template.attrib.get("initialization")
                    url = f"{base_url}{init}"
                    url_base = "/".join(url.split("/")[:-1]) + "/"
    
                    audio_tracks.append({
                        "bandwidth": bandwidth,
                        "codecs": codecs,
                        "url": url,
                        "url_base": url_base
                    })
    
        return {
            "pssh_list": pssh_list,
            "video_track": video_tracks,
            "audio_track": audio_tracks
        }
    