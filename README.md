![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=%E8%A4%87%E6%95%B0%E3%81%AE%E3%82%B5%E3%82%A4%E3%83%88%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%80%E3%83%BC%0AA%20Simple%20Encrypt%20Content%20Downloader&font=Raleway&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&pattern=Solid&theme=Light)

[![jp](https://img.shields.io/badge/README-jp-red.svg)](README.md)
[![en](https://img.shields.io/badge/README-en-red.svg)](README.en-us.md)

## インストール

**※ Pythonのバージョン3.12以上が必要です**

「Yoimi」を使うには、以下のコマンドを実行してください

> [!TIP]
> これは開発バージョンです！

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

## 使い方
```
>> python yoimi.py download -h
Usage: yoimi.py download [OPTIONS] <URL site>

  Main command to access downloader

  Check supported streams from yuu with `yuu streams`

Options:
  -U, --username TEXT        Use username/password to download premium video
  -P, --password TEXT        Use username/password to download premium video
  -p, --proxy <ip:port/url>  Use http(s)/socks5 proxies (please add
                             `socks5://` if you use socks5)
  -r, --resolution TEXT      Resolution to be downloaded (Default: best)
  -R, --resolutions          Show available resolutions
  -m, --mux                  Mux .ts to .mkv (Need ffmpeg or mkvmerge)
  -mf, --muxfile TEXT        Mux .ts to opticial file
  -keep, --keep-fragments    Keep downloaded fragment and combined fragment
                             (If muxing) (Default: no)
  -o, --output TEXT          Output filename
  -v, --verbose              Enable verbosity
  -h, --help                 Show this message and exit.
```

- **`--username/-U`**: ユーザー名またはメールアドレス
- **`--password/-P`**: パスワード
- **`--proxies/-p`**: プロキシ
    - 例: `127.0.0.1:1080`, `http://127.0.0.1:1080`, `http://user:pass@127.0.0.1:1080`, `socks5://127.0.0.1:1080`
- **`--verbose/-v`**: デバッグモードを利用する

**プロキシはまだ完全にはテストされていません**

### Example command: 
Abemaからのダウンロード
1. **オリジナルファイルでダウンロード**  
   ```bash
   python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1"
   ```
   ✨ 「最弱テイマー、ゴミ拾いの旅に出る」第1話をオリジナル形式でダウンロードします。

2. **MP4形式に変換してダウンロード**  
   ```bash
   python3 yoimi.py download "https://abema.tv/video/episode/248-17_s1_p1" --mux
   ```
   ✨ 「最弱テイマー、ゴミ拾いの旅に出る」第1話をMP4形式でダウンロードします。

- - -

U-NEXTからのダウンロード
1. **特定エピソードをダウンロード**  
   ```bash
   python3 yoimi.py download "https://video.unext.jp/play/SID0104147/ED00570917" --username あなたのメールアドレス --password あなたのパスワード
   ```
   ✨ 「ロシア語で出れる隣のアーリャさん」第1話をダウンロードします。

   **サンプルビデオ**: [こちらをクリック](https://github.com/user-attachments/assets/c98fe42c-ab27-498d-b2e5-b0ba897e2d81)

2. **シーズン全体をダウンロード**  
   ```bash
   python3 yoimi.py download "https://video.unext.jp/play/SID0104147" --username あなたのメールアドレス --password あなたのパスワード
   ```
   ✨ 「ロシア語で出れる隣のアーリャさん」のシーズン全エピソードをダウンロードします。

   **サンプルビデオ**: [こちらをクリック](https://youtu.be/09vmBKzQMQE)

- - -

Dmm-TVからのダウンロード
1. **特定エピソードをダウンロード**  
   ```bash
   python3 yoimi.py download "https://tv.dmm.com/vod/playback/?season=i4ub9mtfsaqk6zyvgw7wz17yb&content=4sqn17vutgo79wc8jugmupy3f" --username あなたのメールアドレス --password あなたのパスワード
   ```
   ✨ 「ダンダダン」第1話をダウンロードします。

   **サンプルビデオ**: [こちらをクリック](https://youtu.be/rOpmUqHd5MM)

2. **シーズン全体をダウンロード**  
   ```bash
   python3 yoimi.py download "https://tv.dmm.com/vod/playback/?season=i4ub9mtfsaqk6zyvgw7wz17yb" --username あなたのメールアドレス --password あなたのパスワード
   ```
   ✨ 「ダンダダン」のシーズン全エピソードをダウンロードします。

   **サンプルビデオ**: [こちらをクリック](https://youtu.be/hVpCYZ2bV88)

- - -

### サポートリスト

現在サポートされているリストです

- [x] [Abema](https://abema.tv)
- [x] [U-Next](https://video.unext.jp)
- [x] [Dmm-TV](https://tv.dmm.com/vod)

&nbsp;
- - -
&nbsp;  

##### 把握している問題:
 * 時々ライセンス取得に失敗し、プログラムが停止してしまう問題がある

##### サポート
- discord: nyanyakko005

> [!WARNING]
> Yoimiは、[Yuu](https://github.com/noaione/yuu) と呼ばれるパッケージの約95％をコピーして圧縮するコードを改良されたものです。
