# util/abema/utils/analyze.py
import re
import m3u8
import requests

def get_video_episode_meta(episode_id):
    import data.setting as setting
    meta_json = {
        "division": 0,
        "include": "tvod"
    }
    config_downloader_end = setting.get_json()["downloader_setting"]["abema"] 
    response = requests.post(setting.abema_url_list()["runtimeConfig"]["VIDEO_API"]+"/programs/"+episode_id, params=meta_json, headers={"authorization": setting.abema_auth["email"]["token"]})
    return response.json()

def resolutions(m3u8_uri):
    import data.setting as setting
    session = requests.Session()
    config_downloader_end = setting.get_json()["downloader_setting"]["abema"] 
    
    if config_downloader_end["login_method"] == "email":
        session.headers.update({'Authorization': setting.unext_auth["email"]["token"]})
    else:
        session.headers.update({'Authorization': config_downloader_end["token"]})
    
    print('Requesting data to API')
    
    m3u8_ = m3u8_uri[:m3u8_uri.rfind('/')]
    base_url = m3u8_[:m3u8_.rfind('/')] + '/'
    m3u8_1080 = m3u8_[:m3u8_.rfind('/')] + '/1080/playlist.m3u8'
    m3u8_720 = m3u8_[:m3u8_.rfind('/')] + '/720/playlist.m3u8'
    m3u8_480 = m3u8_[:m3u8_.rfind('/')] + '/480/playlist.m3u8'
    m3u8_360 = m3u8_[:m3u8_.rfind('/')] + '/360/playlist.m3u8'
    m3u8_240 = m3u8_[:m3u8_.rfind('/')] + '/240/playlist.m3u8'
    m3u8_180 = m3u8_[:m3u8_.rfind('/')] + '/180/playlist.m3u8'
    
    rr_all = session.get(base_url + 'playlist.m3u8')
    
    if 'timeshift forbidden' in rr_all.text:
        return None, 'This video can\'t be downloaded for now.', None
    
    r_all = m3u8.loads(rr_all.text)
    
    play_res = []
    for r_p in r_all.playlists:
        temp = []
        temp.append(r_p.stream_info.resolution)
        temp.append(base_url + r_p.uri)
        play_res.append(temp)
        
    resgex = re.compile(r'(\d*)(?:\/\w+.ts)')
    
    ava_reso = []
    for resdata in play_res:
        reswh, m3u8_uri = resdata
        resw, resh = reswh
        #print('Validating {}p resolution'.format(resh))
        rres = m3u8.loads(session.get(m3u8_uri).text)
        m3f = rres.files[1:]
        if not m3f:
            return None, 'This video can\'t be downloaded for now.', None
        #print('Sample link: ' + m3f[5])
        if 'tsda' in rres.files[5]:
            # Assume DRMed
            return None, 'This video has a different DRM method and cannot be decrypted by yuu for now', None
        if str(resh) in re.findall(resgex, m3f[5]):
            ava_reso.append(
                [
                    '{h}p'.format(h=resh),
                    '{w}x{h}'.format(w=resw, h=resh)
                ]
            )
            
    if ava_reso:
        reso = [r[0] for r in ava_reso]
        #print('Resolution list: {}'.format(', '.join(reso)))
        
    return ava_reso, 'Success'

is_m3u8 = False
resolution = None
resolution_o = None
_PROGRAMAPI = 'https://api.abema.io/v1/video/programs/'
_CHANNELAPI = 'https://api.abema.io/v1/media/slots/'
_SERIESAPI = "https://api.abema.io/v1/video/series/"
_GROUPSAPI = "https://api.p-c3-e.abema-tv.com/v1/contentlist/episodeGroups/"

resolution_data = {
    "1080p": ["4000kb/s", "AAC 192kb/s 2ch"],
    "720p": ["2000kb/s", "AAC 160kb/s 2ch"],
    "480p": ["900kb/s", "AAC 128kb/s 2ch"],
    "360p": ["550kb/s", "AAC 128kb/s 2ch"],
    "240p": ["240kb/s", "AAC 64kb/s 1ch"],
    "180p": ["120kb/s", "AAC 64kb/s 1ch"]
}

def convert_kanji_to_int(string):
    """
    Return "漢数字" to "算用数字"
    """
    result = string.translate(str.maketrans("零〇一壱二弐三参四五六七八九拾", "00112233456789十", ""))
    convert_table = {"十": "0", "百": "00", "千": "000"}
    unit_list = "|".join(convert_table.keys())
    while re.search(unit_list, result):
        for unit in convert_table.keys():
            zeros = convert_table[unit]
            for numbers in re.findall(rf"(\d+){unit}(\d+)", result):
                result = result.replace(numbers[0] + unit + numbers[1], numbers[0] + zeros[len(numbers[1]):len(zeros)] + numbers[1])
            for number in re.findall(rf"(\d+){unit}", result):
                result = result.replace(number + unit, number + zeros)
            for number in re.findall(rf"{unit}(\d+)", result):
                result = result.replace(unit + number, "1" + zeros[len(number):len(zeros)] + number)
            result = result.replace(unit, "1" + zeros)
    return result

def is_channel(url):
    url = re.findall('(slot)', url)
    if url:
        return True
    return False

def parse(resolution=None, check_only=False, url=None):
    is_m3u8 = False
    
    import data.setting as setting
    session = requests.Session()    
    session.headers.update({'Authorization': setting.abema_auth["email"]["token"]})
    """
    Function to parse abema url
    """
    res_list = [
        '180p', '240p', '360p', '480p', '720p', '1080p', 'best', 'worst'
    ]
    if resolution not in res_list:
        if not check_only:
            return None, 'Unknown resolution: {}. (Check it with `-R`)'.format(resolution), None
    if resolution == 'best':
        resolution = '1080p'
        resolution_o = 'best'
    if resolution == 'worst':
        resolution = '180p'
    # https://abema.tv/video/title/26-55 (series/playlists)
    # https://api.abema.io/v1/video/series/26-55
    # https://api.abema.io/v1/video/series/26-55/programs?seriesVersion=1577436473958778090&seasonId=26-55_s1&offset=0&order=seq&limit=40
    
    print("URL LOL: "+url)    
    
    series = re.search(r"(?P<series>title)/(?P<video_id>.*[^-_])", url)
    if series:
        video_id = series.group(2)
        
        if not url.__contains__("_s"):
            season_real = video_id+"_s1"
        else:
            season_real = video_id+re.compile(r"_s\d+").search(url).group()
            
        print('Series url format detected, fetching all links...')
        #print('Requesting data to Abema API.')
        req = session.get(_SERIESAPI + video_id)
        if req.status_code != 200:
            print(40, 'Abema Response: ' + req.text)
            return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code), None
        print('Data requested')
        print('Parsing json results...')
        m3u8_url_list = []
        output_list = []
        jsdata = req.json()
        #to_be_requested = "{api}{vid}/programs?seriesVersion={sv}&seasonId={si}&offset=0&order={od}&limit=100"
        to_be_requested = "{api}{vid}_eg0/contents?seasonId={sv}&limit=100&offset=0&orderType=asc&includes=liveEvent,slot"
        season_data = jsdata['seasons']
        if not season_data:
            season_data = [{'id': ''}] # Assume film or some shit
        #version = jsdata['version']
        #prog_order = jsdata['programOrder']
        for ns, season in enumerate(season_data, 1):
            print('Processing season ' + str(ns))
            #print('Requesting data to Abema API.')
            #req_season = session.get(to_be_requested.format(api=_SERIESAPI, vid=video_id, sv=version, si=season['id'], od=prog_order))
            req_season = session.get(to_be_requested.format(api=_GROUPSAPI, vid=video_id, sv=season_real))
            if req_season.status_code != 200:
                print(40, 'Abema Response: ' + req_season.text)
                return None, 'Error occured when communicating with Abema (Response: {})'.format(req_season.status_code), None
            print('Data requested')
            print('Parsing json results...')
            season_jsdata = req_season.json()
            print(to_be_requested.format(api=_GROUPSAPI, vid=video_id, sv=season_real))
            print('Processing total of {ep} episode for season {se}'.format(ep=len(season_jsdata['episodeGroupContents']), se=ns))
            
            # ここ
            for nep, episode in enumerate(season_jsdata['episodeGroupContents'], 1):
                free_episode = False
                if 'label' in episode:
                    if 'free' in episode['label']:
                        free_episode = True
                elif 'freeEndAt' in episode:
                    free_episode = True
                if 'episode' in episode:
                    try:
                        episode_name = episode['episode']['title']
                        if not episode_name:
                            episode_name = episode_name['title']['number']
                    except KeyError:
                        episode_name = episode_name['title']['number']
                else:
                    episode_name = nep
                if not free_episode and setting.unext_auth["email"]["token"]:
                    print('Skipping episode {} (Not authorized and premium video)'.format(episode_name))
                    continue
                print('Processing episode {}'.format(episode_name))
                req_ep = session.get(_PROGRAMAPI + episode['id'])
                if req_ep.status_code != 200:
                    print(40, 'Abema Response: ' + req_ep.text)
                    return None, 'Error occured when communicating with Abema (Response: {})'.format(req_ep.status_code), None
                print('Data requested')
                print('Parsing json API')
                ep_json = req_ep.json()
                title = ep_json['series']['title']
                epnumber = episode["episode"]["title"]
                epnum = episode["episode"]["number"]
                epnumber_tmp = convert_kanji_to_int(epnumber)
                if re.match(r'第\d+話\s*(.+)', epnumber_tmp):
                    eptle = re.match(r'第\d+話\s*(.+)', epnumber_tmp).group(1)
                elif re.search(r'#\d+', epnumber_tmp):
                    eptle = re.match(r'#\d+\s*(.+)', epnumber_tmp).group(1)
                else:
                    before_space = epnumber_tmp.split(" ")[0]
                    after_space = " ".join(epnumber_tmp.split(" ")[1:])
                    if any(char.isdigit() for char in before_space):
                        eptle = after_space
                    else:
                        eptle = None
                hls = ep_json['playback']['hls']
                output_name = title + "_" + epnumber
                m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
                print('M3U8 Link: {}'.format(m3u8_url))
                print('Video title: {}'.format(title))
                m3u8_url_list.append(m3u8_url)
                output_list.append(output_name)
        resolution = resolution
        m3u8_url = m3u8_url_list
        if not output_list:
            err_msg = "All video are for premium only, please provide login details."
        else:
            err_msg = "Success"
        return output_list, err_msg, m3u8_url
    if '.m3u8' in url[-5:]:
        reg = re.compile(r'(program|slot)\/[\w+-]+')
        url = re.search(reg, m3u8)[0]
        is_m3u8 = True
    ep_link = url[url.rfind('/')+1:]
    if is_channel(url):
        req = session.get(_CHANNELAPI + ep_link)
        if req.status_code != 200:
            print(40, 'Abema Response: ' + req.text)
            return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code), None
        print('Data requested')
        print('Parsing json API')
        jsdata = req.json()
        output_name = jsdata['slot']['title']
        if 'playback' in jsdata['slot']:
            hls = jsdata['slot']['playback']['hls']
        else:
            hls = jsdata['slot']['chasePlayback']['hls']  # Compat
        m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
        if is_m3u8:
            m3u8_url = url
        print('M3U8 Link: {}'.format(m3u8_url))
        print('Title: {}'.format(output_name))
    else:
        req = session.get(_PROGRAMAPI + ep_link)
        if req.status_code != 200:
            print(40, 'Abema Response: ' + req.text)
            return None, 'Error occured when communicating with Abema (Response: {})'.format(req.status_code), None
        print('Data requested')
        print('Parsing json API')
        jsdata = req.json()
        if jsdata['mediaStatus']:
            if 'drm' in jsdata['mediaStatus']:
                if jsdata['mediaStatus']['drm']:
                    return None, 'This video has a different DRM method and cannot be decrypted by yuu for now', None
        title = jsdata['series']['title']
        epnumber = jsdata['episode']['title']
        if "ライブ" in epnumber.lower() or "live" in epnumber.lower():
            print('Live Content: True')
        else:
            print('Live Content: False')
        epnum = jsdata['episode']['number']
        epnumber_tmp = convert_kanji_to_int(epnumber)
        if re.match(r'第\d+話\s*(.+)', epnumber_tmp):
            eptle = re.match(r'第\d+話\s*(.+)', epnumber_tmp).group(1)
        elif re.search(r'#\d+', epnumber_tmp):
            eptle = re.match(r'#\d+\s*(.+)', epnumber_tmp).group(1)
        else:
            before_space = epnumber_tmp.split(" ")[0]
            after_space = " ".join(epnumber_tmp.split(" ")[1:])
            if any(char.isdigit() for char in before_space):
                eptle = after_space
            else:
                eptle = None
        hls = jsdata['playback']['hls']
        output_name = title + "_" + epnumber
        m3u8_url = '{x}/{r}/playlist.m3u8'.format(x=hls[:hls.rfind('/')], r=resolution[:-1])
        if is_m3u8:
            m3u8_url = url
        print('M3U8 Link: {}'.format(m3u8_url))
        print('Video title: {}'.format(title))
        print('Episode number: {}'.format(epnumber))
        print('Episode num: {}'.format(epnum))
        print('Episode title: {}'.format(eptle))
    resolution = resolution
    m3u8_url = m3u8_url
    return output_name, 'Success', m3u8_url

def get_video_resoltion(url, root, all_num):
    import data.setting as setting
    print('Checking available resolution...')
    res = "best"
    resR = True
    outputs, reason, m3u8_url = parse(res, resR, url)
    if not outputs:
        print('{}'.format(reason))
        exit(1)
    if isinstance(m3u8_url, list):
        m3u8_list = m3u8_url
    else:
        m3u8_list = [m3u8_url]
    print(m3u8_list)
    if resR:
        i = 1
        for m3u8_uri in m3u8_list:
            avares, reason = resolutions(m3u8_uri)
            if not avares:
                print('{}'.format(reason))
            #print('Available resolution:')
            #print(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
            #print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format("   Key", "Resolution", "Video Quality", "Audio Quality", width=16))
            #print(setting.unext_video_meta[index-1]) # [['704x396', 'avc1.4d401e', 'video/mp4'], ['1280x720', 'avc1.4d401f', 'video/mp4'], ['1920x1080', 'avc1.4d4028', 'video/mp4']]
            #print(setting.unext_audio_meta[index-1]) # [['48000', 'mp4a.40.2', 'audio/mp4']]
            #print(avares)
            video_resolution = [["best"]]
            audio_resolution = [["best"]]
            setting.abema_video_meta.append([[["best"]]])
            setting.abema_audio_meta.append([[["best"]]])
            for res in avares:
                r_c, wxh = res
                vidq, audq = resolution_data[r_c]
                #print(r_c)
                #print(0, '{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))
                #print('{0: <{width}}{1: <{width}}{2: <{width}}{3: <{width}}'.format('>> ' + r_c, wxh, vidq, audq, width=16))
                video_temp = [r_c,vidq]
                audio_temp = [audq]
                video_resolution.append(video_temp)
                audio_resolution.append(audio_temp)
                setting.abema_video_meta.append(video_resolution)
                setting.abema_audio_meta.append(audio_resolution)
            root.title(setting.title+f"解像度の取得中 -> {i}/{all_num}")
            i = i + 1
                
        #print(video_resolution)
        #print(audio_resolution)
        
        print("all done")
        
    return video_resolution, audio_resolution, m3u8_list, outputs