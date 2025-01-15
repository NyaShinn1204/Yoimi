cosmo_getVideoTitleをpost
- idとtitleNameとcatchphraseとattractionsとstoryを取得
- thumbnailのstandardを取得

cosmo_getVideoTitleEpisodesをpost
- episodes[] (各エピソード)からepisodeNameとthumbnailのstandardを取得dl
- あとintoroductionも保存

ここから各エピソードの解像度などを取得
cosmo_getPlaylistUrlをpost
- playTokenとurlInfoのcodeを取得
- https://playlist.unext.jp/playlist/v00001/dash/get/{code}.mpd/?file_code={code}&play_token={playToken}にgetを送り解像度をparse

エピソードの再生停止処理
メモ: ここでの1とは経過時間のことである。0でもok
- https://beacon.unext.jp/beacon/interruption/{code}/1/?play_token={playToken} #ここで再生停止
- https://beacon.unext.jp/beacon/stop/{code}/1/?play_token={playToken}&last_viewing_flg=0 #ここで再生終了

ここで解像度取得終了
新しいplaytokenを返す。

新しいplaytokenを使い
- https://wvproxy.unext.jp/proxy?play_token={playtoken}
でライセンスの解読

動画のdlは別にplaytoken要らないのでこれで終了



























v2:
cosmo_getVideoTitleをpost
- idとtitleNameとcatchphraseとattractionsとstoryを取得
- thumbnailのstandardを取得

cosmo_getVideoTitleEpisodesをpost
- episodes[] (各エピソード)からepisodeNameとthumbnailのstandardを取得dl
- あとintoroductionも保存

ここから各エピソードの解像度などを取得
cosmo_getPlaylistUrlをpost
- playTokenとurlInfoのcodeを取得
- https://playlist.unext.jp/playlist/v00001/dash/get/{code}.mpd/?file_code={code}&play_token={playToken}にgetを送り解像度をparse

エピソードの再生停止処理
メモ: ここでの1とは経過時間のことである。0でもok
- https://beacon.unext.jp/beacon/interruption/{code}/1/?play_token={playToken} #ここで再生停止
- https://beacon.unext.jp/beacon/stop/{code}/1/?play_token={playToken}&last_viewing_flg=0 #ここで再生終了

ここで解像度取得終了
playtokenを使い
- https://wvproxy.unext.jp/proxy?play_token={playtoken}
でライセンスの解読

動画のdlは別にplaytoken要らないのでこれで終了