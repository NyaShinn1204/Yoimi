import requests
import time
import os
import xml.etree.ElementTree as ET
from urllib.parse import urljoin


# Track downloaded segments
downloaded_segments = {
    "video": set(),
    "audio": set()
}

def download_segment(url, output_path):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(output_path, 'ab') as f:
            f.write(response.content)
        print(f"Downloaded: {url}")
    else:
        print(f"Failed to download {url}: {response.status_code}")


def extract_segment_times(mpd_content, media_type):
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
        print(f"Error extracting segment times for {media_type}: {e}")
    return times


def download_and_merge_segments(seg_info, mpd_content):
    for media_type in ["video", "audio"]:
        info = seg_info[media_type]

        # Initialization segment
        init_url = urljoin(info["url_base"], info["url"])
        init_filename = f"encrypt_{media_type}.mp4"
        if not os.path.exists(init_filename):
            download_segment(init_url, init_filename)

        # Segment timeline from MPD
        seg_times = extract_segment_times(mpd_content, media_type)

        for t in seg_times:
            if t in downloaded_segments[media_type]:
                continue  # skip already downloaded segment

            seg_url = urljoin(info["url_base"], info["url_segment_base"].replace("$Time$", str(t)))
            download_segment(seg_url, init_filename)
            downloaded_segments[media_type].add(t)


def parse_minimum_update_period(mpd_content):
    try:
        ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}
        root = ET.fromstring(mpd_content)
        mup_str = root.attrib.get("minimumUpdatePeriod", "PT5S")
        if mup_str.startswith("PT") and mup_str.endswith("S"):
            return float(mup_str[2:-1])
    except Exception as e:
        print(f"Error parsing minimumUpdatePeriod: {e}")
    return 5.0  # fallback


def fetch_mpd_and_segment_info(mpd_url):
    response = requests.get(mpd_url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to fetch MPD: {response.status_code}")
        return None


def main_loop(mpd_url, seg_info):
    while True:
        mpd_content = fetch_mpd_and_segment_info(mpd_url)
        if not mpd_content:
            time.sleep(5)
            continue

        mup = parse_minimum_update_period(mpd_content)
        download_and_merge_segments(seg_info, mpd_content)

        print(f"Sleeping for {mup} seconds before refreshing MPD...")
        time.sleep(mup)


if __name__ == "__main__":
    
    ### THIS CONTENT KEY IS
    ### 29177ff84df84408b7f185ad7905bc56:4859dec234b09f48e59dc5cc2c3f1715
    mpd_url = "https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/manifest.mpd"

    seg_info = {
        'video': {
            'url': 'segment_ua2anvupo_ctvideo_cfm4s_ridp0va0br2808000_cinit_mpd.m4s',
            'url_base': 'https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/',
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
            'url_base': 'https://streaml01cf.nxtv.jp/p-checkch01-uni88978us/index2.ism/',
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

    main_loop(mpd_url, seg_info)
