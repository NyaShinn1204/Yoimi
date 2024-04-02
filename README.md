<p align="center">
    <h3 align="center">Yoimi</h3>
    <p align="center">
        Abemaでの動画ダウンロードツール<br />
    </p>
</p>

## Installation

**※ Python 3.10 以上のバージョンが必要です。**

「Yoimi」を使うには、以下のコマンドを実行します:

> [!TIP]
> 開発バージョンです! 注意をしてください

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

#### ✨ Abemaから"最弱テイマーはゴミ拾いの旅を始めました。"の一話をダウンロードする (オリジナルファイル)

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1"
```

#### ✨ Abemaから"最弱テイマーはゴミ拾いの旅を始めました。"の一話をダウンロードする (mp4コンバートファイル)

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1" --mux
```


## 免責事項

Yoimiは、[Yuu]("https://github.com/noaione/yuu")というパッケージから、9割程度コピーし圧縮するための機構を修正したものです