import requests

session = requests.Session()

base_url = "https://edge.api.brightcove.com/playback/v1/accounts/6415533679001/videos/6370524822112?ad_config_id=49858721-b38a-4e71-86bc-13f5ec8ca505"

response = session.get(base_url).json()

print(response["duration"])

for single in response["sources"]:
    print(single["codecs"])
    
    
# hehe sample
response = {
    "poster": "https://house-fastly-signed-us-east-1-prod.brightcovecdn.com/image/v1/static/6415533679001/0c27a452-039c-4bec-a0f8-87f32ffa2761/fcf9defe-8088-4df9-91f6-738e7dbab96d/3840x2160/match/image.jpg?fastly_token=NjdmZmIzZGFfZjAzZjVkOTgzZDA2NTUyZmQyNjllZDhmOWViMzYyMjFjZmUwNTBiMjNhYThlMGU0ZjU0ODk5MDAzYzQxNzAyZV9odHRwczovL2hvdXNlLWZhc3RseS1zaWduZWQtdXMtZWFzdC0xLXByb2QuYnJpZ2h0Y292ZWNkbi5jb20vaW1hZ2UvdjEvc3RhdGljLzY0MTU1MzM2NzkwMDEvMGMyN2E0NTItMDM5Yy00YmVjLWEwZjgtODdmMzJmZmEyNzYxL2ZjZjlkZWZlLTgwODgtNGRmOS05MWY2LTczOGU3ZGJhYjk2ZC8zODQweDIxNjAvbWF0Y2gvaW1hZ2UuanBn",
    "thumbnail": "https://house-fastly-signed-us-east-1-prod.brightcovecdn.com/image/v1/static/6415533679001/0c27a452-039c-4bec-a0f8-87f32ffa2761/84cbe81c-6581-4615-b520-59e907000d6b/800x450/match/image.jpg?fastly_token=NjdmZmIzZGFfNjI4MDRlZjkwODhjMGU3YjcxNGYyOTg4NjU4ZDdmMmJjNWUwYjJiNzkxNzQ4ZDIyMTE5NmY1ZDZlOTBlYzdjM19odHRwczovL2hvdXNlLWZhc3RseS1zaWduZWQtdXMtZWFzdC0xLXByb2QuYnJpZ2h0Y292ZWNkbi5jb20vaW1hZ2UvdjEvc3RhdGljLzY0MTU1MzM2NzkwMDEvMGMyN2E0NTItMDM5Yy00YmVjLWEwZjgtODdmMzJmZmEyNzYxLzg0Y2JlODFjLTY1ODEtNDYxNS1iNTIwLTU5ZTkwNzAwMGQ2Yi84MDB4NDUwL21hdGNoL2ltYWdlLmpwZw%3D%3D",
    "poster_sources": [
        {
            "src": "https://house-fastly-signed-us-east-1-prod.brightcovecdn.com/image/v1/static/6415533679001/0c27a452-039c-4bec-a0f8-87f32ffa2761/fcf9defe-8088-4df9-91f6-738e7dbab96d/3840x2160/match/image.jpg?fastly_token=NjdmZmIzZGFfZjAzZjVkOTgzZDA2NTUyZmQyNjllZDhmOWViMzYyMjFjZmUwNTBiMjNhYThlMGU0ZjU0ODk5MDAzYzQxNzAyZV9odHRwczovL2hvdXNlLWZhc3RseS1zaWduZWQtdXMtZWFzdC0xLXByb2QuYnJpZ2h0Y292ZWNkbi5jb20vaW1hZ2UvdjEvc3RhdGljLzY0MTU1MzM2NzkwMDEvMGMyN2E0NTItMDM5Yy00YmVjLWEwZjgtODdmMzJmZmEyNzYxL2ZjZjlkZWZlLTgwODgtNGRmOS05MWY2LTczOGU3ZGJhYjk2ZC8zODQweDIxNjAvbWF0Y2gvaW1hZ2UuanBn"
        }
    ],
    "thumbnail_sources": [
        {
            "src": "https://house-fastly-signed-us-east-1-prod.brightcovecdn.com/image/v1/static/6415533679001/0c27a452-039c-4bec-a0f8-87f32ffa2761/84cbe81c-6581-4615-b520-59e907000d6b/800x450/match/image.jpg?fastly_token=NjdmZmIzZGFfNjI4MDRlZjkwODhjMGU3YjcxNGYyOTg4NjU4ZDdmMmJjNWUwYjJiNzkxNzQ4ZDIyMTE5NmY1ZDZlOTBlYzdjM19odHRwczovL2hvdXNlLWZhc3RseS1zaWduZWQtdXMtZWFzdC0xLXByb2QuYnJpZ2h0Y292ZWNkbi5jb20vaW1hZ2UvdjEvc3RhdGljLzY0MTU1MzM2NzkwMDEvMGMyN2E0NTItMDM5Yy00YmVjLWEwZjgtODdmMzJmZmEyNzYxLzg0Y2JlODFjLTY1ODEtNDYxNS1iNTIwLTU5ZTkwNzAwMGQ2Yi84MDB4NDUwL21hdGNoL2ltYWdlLmpwZw%3D%3D"
        }
    ],
    "description": "Part | 2025 | Full HD",
    "tags": [
        "rassvet",
        "austyn gillette",
        "part",
        "short",
        "brand",
        "2025",
        "full hd",
        "memo",
        "los angeles",
        "la",
        "california",
        "paris",
        "france",
        "europe",
        "trevor dare",
        "max kushewski",
        "thomas vigoureux"
    ],
    "cue_points": [
        {
            "id": "5798042643131",
            "name": "pre-roll",
            "type": "AD",
            "time": 0,
            "metadata": "",
            "force_stop": True
        }
    ],
    "custom_fields": {
        "beacon_cast_actor": "Austyn Gillette",
        "beacon_cast_composer": "Trevor Dare",
        "beacon_cast_director": "Rassvet",
        "beacon_cast_songwriter": "Trevor Dare",
        "beacon_cast_writer": "Max Kushewski,Thomas Vigoureux",
        "beacon_genre": "Rassvet",
        "beacon_rights_1_devices": "iOS,Android,web,Roku,STV,Firetv,LGTV,Samsung,appletv,androidtv,panasonic",
        "beacon_rights_1_enddate": "2045-03-25 15:09:51",
        "beacon_rights_1_locationspermit": "world",
        "beacon_rights_1_packagename": "Am - Monthly Free Trial,Pro Plan— Monthly,Am — Yearly Free Trial,Pro Plan — Yearly,Pro Plan— Yearly (Amazon),Pro Plan— Monthly (Amazon),Am — Yearly Free Trial (Amazon),Am - Monthly Free Trial (Amazon),AuthVOD - Free",
        "beacon_rights_1_startdate": "2025-03-25 14:09:51",
        "beacon_rights_1_type": "SVOD",
        "beacon_video_type": "movie"
    },
    "account_id": "6415533679001",
    "sources": [
        {
            "codecs": "avc1,mp4a",
            "ext_x_version": "4",
            "src": "http://ssaimanifest.prod.boltdns.net/playback/once/v1/hls/v4/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/master.m3u8?bc_token=NjdmZjY5MGFfYWYyZjA5NzYzYWI2YzkyOTc0ZDFiYzIyZThmMjgwMjM3NjU3YzJmZTc5ZWEyMzM5MTdiN2RiZjAyNGE0N2U4ZQ%3D%3D",
            "type": "application/x-mpegURL",
            "vmap": "http://ssaimanifest.prod.boltdns.net/playback/once/v1/vmap/hls/v4/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/content.vmap?bc_token=NjdmZjY5MGFfYmUyNWQ4ZTJiZDRmMmE3NTBjOTAzZDJkNTBkNDQ4ZjdjZDgwNGI1Yjk0YTFhYTM2NWVmZDcxYjQ4YWQ5NjRjYg%3D%3D"
        },
        {
            "codecs": "avc1,mp4a",
            "ext_x_version": "4",
            "src": "https://ssaimanifest.prod.boltdns.net/playback/once/v1/hls/v4/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/master.m3u8?bc_token=NjdmZjY5MGFfYWYyZjA5NzYzYWI2YzkyOTc0ZDFiYzIyZThmMjgwMjM3NjU3YzJmZTc5ZWEyMzM5MTdiN2RiZjAyNGE0N2U4ZQ%3D%3D",
            "type": "application/x-mpegURL",
            "vmap": "https://ssaimanifest.prod.boltdns.net/playback/once/v1/vmap/hls/v4/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/content.vmap?bc_token=NjdmZjY5MGFfYmUyNWQ4ZTJiZDRmMmE3NTBjOTAzZDJkNTBkNDQ4ZjdjZDgwNGI1Yjk0YTFhYTM2NWVmZDcxYjQ4YWQ5NjRjYg%3D%3D"
        },
        {
            "codecs": "avc1,mp4a",
            "profiles": "urn:mpeg:dash:profile:isoff-live:2011",
            "src": "http://ssaimanifest.prod.boltdns.net/playback/once/v1/dash/live-timeline/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/manifest.mpd?bc_token=NjdmZjY5MGFfNDFiZjM1NTllOWVmMzA4NDY2ODVhOTYwYjc0NWJmZmNmNTkyODk0NWEzZmNiYTFhMGI2OWIyYzY3NTRhMjI5ZQ%3D%3D",
            "type": "application/dash+xml",
            "vmap": "http://ssaimanifest.prod.boltdns.net/playback/once/v1/vmap/dash/live-timeline/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/content.vmap?bc_token=NjdmZjY5MGFfZThlMDcyNGIzYjVkZmNjZmY0NTViODY2ZDQ2MDIwOWJhMWU5MzM5NzAzNmFmNzk5MDIxZTg5YzE4OGQxYjZkMw%3D%3D"
        },
        {
            "codecs": "avc1,mp4a",
            "profiles": "urn:mpeg:dash:profile:isoff-live:2011",
            "src": "https://ssaimanifest.prod.boltdns.net/playback/once/v1/dash/live-timeline/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/manifest.mpd?bc_token=NjdmZjY5MGFfNDFiZjM1NTllOWVmMzA4NDY2ODVhOTYwYjc0NWJmZmNmNTkyODk0NWEzZmNiYTFhMGI2OWIyYzY3NTRhMjI5ZQ%3D%3D",
            "type": "application/dash+xml",
            "vmap": "https://ssaimanifest.prod.boltdns.net/playback/once/v1/vmap/dash/live-timeline/clear/6415533679001/49858721-b38a-4e71-86bc-13f5ec8ca505/0c27a452-039c-4bec-a0f8-87f32ffa2761/content.vmap?bc_token=NjdmZjY5MGFfZThlMDcyNGIzYjVkZmNjZmY0NTViODY2ZDQ2MDIwOWJhMWU5MzM5NzAzNmFmNzk5MDIxZTg5YzE4OGQxYjZkMw%3D%3D"
        }
    ],
    "name": "RASSVET — AUSTYN GILLETTE - MEMO",
    "reference_id": None,
    "long_description": "Get full credentials, skater details, and video soundtracks from our friends at skatevideosite.com",
    "duration": 231619,
    "economics": "AD_SUPPORTED",
    "text_tracks": [],
    "published_at": "2025-03-25T15:07:44.843Z",
    "created_at": "2025-03-25T15:07:44.843Z",
    "updated_at": "2025-03-31T20:51:00.592Z",
    "offline_enabled": True,
    "link": None,
    "id": "6370524822112",
    "ad_keys": None,
    "manifest_url_ttl": 3600
}