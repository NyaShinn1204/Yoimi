widevine license server:
https://cenc.webstream.ne.jp/drmapi/wv/fujitv?custom_data=TOKEN_HERE

TOKEN_HERE:
episode_id = "70v8110012"
unixtime = "int(time.time() * 1000)"
uuid_here = response.cookies.get["uuid"]
https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={episode_id}&qa=auto&uuid={uuid_here}&starttime=0&is_pt=false&dt=&_={unixtime}

response.json()["ticket"]