import requests
import uuid
session = requests.Session()
session.headers.update({"X-Device-Id": str(uuid.uuid4())})
episode_html = session.get("https://www.telasa.jp/videos/245264?related=episodes")


payload = {"video_ids":["245264"]}
get_video_info = session.post("https://api-videopass-anon.kddi-video.com/v3/batch/query", json=payload).json()
#print(get_video_info["status"]["type"])

episode_data = get_video_info["data"]["items"][0]["data"]
button_data = get_video_info["data"]["items"][0]["video_button_status"]

title_name = episode_data

if "freemium" in button_data:
    for i in button_data:
        if i["license"] == "freemium":
            free_end = i["info"]["public_end_at"]
            episode_type = "FREE"
else:
    episode_type = "PREMIUM"

print(f"+ {title_name["name"]} [ID:{episode_data["id"]}]")

print("Getting playback token...")
payload = {"query":"{ playbackToken( item_id: "+str(episode_data["id"])+", item_type: Mezzanine ) { token expires_at license_id } }"}
playback_token = session.post("https://playback.kddi-video.com/graphql", json=payload).json()["data"]["playbackToken"]["token"]
print(playback_token)
print("Getting Streaming Link...")
payload = {"query":"{ manifests( item_id: \""+str(episode_data["id"])+"\", item_type: Mezzanine, playback_token: \""+playback_token+"\" ) { protocol items { name url } } subtitles( id: \""+str(episode_data["id"])+"\", playback_token: \""+playback_token+"\" ) { language url } mezzanine( id: \""+str(episode_data["id"])+"\" ) { id title time { last_played duration endStart }, recommend { previous { id title images { url } } next { id title images { url } } }, video { id } } thumbnailSeekings( id: \"245264\", playback_token: \""+playback_token+"\" ) { quality url } }"}
#print(payload)
streaming_list = session.post("https://playback.kddi-video.com/graphql", json=payload).json()
print(streaming_list)

print("Ez dumped. lol")