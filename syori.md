GET https://playlist.unext.jp/playlist/v00001/dash/get/MEZ0000959882.mpd/?file_code=MEZ0000959882&play_token=$play_token
↓
Get Video_URL, Audio_URL, License_Key
↓
POST https://wvproxy.unext.jp/proxy?play_token=$play_token (Get License_Key)
↓
Downlaod Video, Audio
↓
Decrypt Video, Audio
↓
https://beacon.unext.jp/beacon/interruption/MEZ0000959882/2/?play_token=$play_token
https://beacon.unext.jp/beacon/stop/MEZ0000959882/2/?play_token=$play_token&last_viewing_flg=0
(Pause, Stop Play Video)