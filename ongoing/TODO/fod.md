widevine license server:
https://cenc.webstream.ne.jp/drmapi/wv/fujitv?custom_data=TOKEN_HERE

TOKEN_HERE:
episode_id = "70v8110012"
unixtime = "int(time.time() * 1000)"
uuid_here = response.cookies.get["uuid"]
https://fod.fujitv.co.jp/apps/api/1/auth/contents/web?site_id=fodapp&ep_id={episode_id}&qa=auto&uuid={uuid_here}&starttime=0&is_pt=false&dt=&_={unixtime}

response.json()["ticket"]

shaka-packager.exe input=video_encrypted.mp4,stream=video,output=vid.mp4 input=audio_encrypted.mp4,stream=audio,output=aud.mp4 --enable_raw_key_decryption --keys key_id=e248e04ab8544554a98aaa4eba2c3732:key=9d330096c4ff91d0e2cbf8f21aa16e43cd F:\Yoimi\temp\content\1734860412

shaka-packeger.exe from c:\dvdfab\streamrfab\ (But it looks like it might have a virus in it, so I'll use the built one.)'