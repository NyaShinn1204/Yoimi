# 入力データ（例）
data = {
    'video': {
        'url': 'init-0-0-video_$Bandwidth$.m4s(encryption=cenc)',
        'url_base': 'https://rtv01e-mvod-ds.akamaized.net/de81a035-1fd8-4ed8-8b06-2f2b74992804/eCm57F_tab_hd.ism/',
        'url_segment_base': 'media-0-0-video_$Bandwidth$-$Time$.m4s(encryption=cenc)',
        'seg_duration': '25025000',
        'seg_timescale': '10000000',
        'segment_count': 300,
        'id': 'video_5967770',
        'bitrate': '997633',
    },
    'audio': {
        'url': 'init-0-0-audio_127901.m4s(encryption=cenc)',
        'url_base': 'https://rtv01e-mvod-ds.akamaized.net/de81a035-1fd8-4ed8-8b06-2f2b74992804/eCm57F_tab_hd.ism/',
        'url_segment_base': 'media-0-0-audio_127901-$Time$.m4s(encryption=cenc)',
        'seg_duration': '20053333',
        'seg_timescale': '10000000',
        'segment_count': 374,
        'id': 'audio_127901',
        'bitrate': '127901',
    }
}

# セグメントタイムリスト（例: 実際はMPDから取得したリスト）
segment_times = {
    'video': [i * 25025000 for i in range(data['video']['segment_count'])],
    'audio': [i * 20053333 for i in range(data['audio']['segment_count'])],
}

def build_segment_links(track):
    """映像または音声の完全なセグメントURLリストを作る"""
    base = data[track]['url_base']
    init_url = data[track]['url'].replace('$Bandwidth$', data[track]['bitrate'])
    segment_base = data[track]['url_segment_base'].replace('$Bandwidth$', data[track]['bitrate'])
    
    links = []
    # init セグメント
    links.append(base + init_url)
    
    # 各メディアセグメント
    for t in segment_times[track]:
        seg_url = segment_base.replace('$Time$', str(t))
        links.append(base + seg_url)
    
    return links

# 実行例
video_links = build_segment_links('video')
audio_links = build_segment_links('audio')

print(len(video_links))
print(len(audio_links))