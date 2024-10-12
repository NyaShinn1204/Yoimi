<p align="center">
    <h3 align="center">Yoimi</h3>
    <p align="center">
        AbemaやU-Nextでの動画ダウンロードツール<br />
    </p>
</p>

## インストール

**※ Pythonのバージョン3.10以上が必要。**

Yoimi」を使うには、以下のコマンドを実行する： .

> [!TIP]
> こちらは開發バージョン！注目

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

#### ✨ 「最弱テイマー、ゴミ拾いの旅に出る" from Abema. 第1話ダウンロードはこちらから（オリジナルファイル）

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1"
```

#### ✨ 「最弱テイマー、ゴミ拾いの旅に出る" from Abema. から1話ダウンロード（mp4に変換しています）

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1" --mux
```

#### ✨ U-nextから"ロシア語で出れる隣のアーリャさん"の一話をダウンロードする

```python
python3 yoimi.py download "https://video.unext.jp/play/SID0104147/ED00570917" --username ここにemail --password ここにパスワード
```


## 免責事項

Yoimiは、[Yuu]（https://github.com/noaione/yuu）と呼ばれるパケットの約90％をコピーして圧縮するための改良されたメカニズムである。
