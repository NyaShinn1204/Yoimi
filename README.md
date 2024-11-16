![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=Abema%E3%82%84U-Next%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%89%E3%83%84%E3%83%BC%E3%83%AB%0AA%20Simple%20Abema%20TV%2C%20U-Next%20Downloader&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&stargazers=1&theme=Light)

[![jp](https://img.shields.io/badge/README-jp-red.svg)](README.md)
[![en](https://img.shields.io/badge/README-en-red.svg)](README.en-us.md)

## インストール

**※ Pythonのバージョン3.10以上が必要です**

「Yoimi」を使うには、以下のコマンドを実行してください

> [!TIP]
> これは開発バージョンです！

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

#### ✨ 「最弱テイマー、ゴミ拾いの旅に出る」をAbemaから第1話をダウンロード（オリジナルファイル）

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1"
```

#### ✨ 「最弱テイマー、ゴミ拾いの旅に出る」をAbemaから1話をダウンロード（mp4に変換）

```python
python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1" --mux
```

#### ✨ 「ロシア語で出れる隣のアーリャさん」をUnextから一話をダウンロードする

```python
python3 yoimi.py download "https://video.unext.jp/play/SID0104147/ED00570917" --username ここにemail --password ここにパスワード
```

#### ✨ 「ロシア語で出れる隣のアーリャさん」をUnextからワンシーズンすべてをダウンロードする

```python
python3 yoimi.py download "https://video.unext.jp/play/SID0104147" --username ここにemail --password ここにパスワード
```

> [!CAUTION]
> Yoimiは、[Yuu](https://github.com/noaione/yuu) と呼ばれるパッケージの約95％をコピーして圧縮するコードを改良されたものです。