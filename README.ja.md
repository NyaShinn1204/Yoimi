![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=%E8%A4%87%E6%95%B0%E3%81%AE%E3%82%B5%E3%82%A4%E3%83%88%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%80%E3%83%BC%0AA%20Simple%20Encrypt%20Content%20Downloader&font=Raleway&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&pattern=Solid&theme=Light)

[English](./README.md) | [日本語](./README.ja.md)

シンプルな暗号化コンテンツダウンローダーです。

現在以下のデバイスでの動作を確認しています。

- Linux (aarch64, arm64)
- Windows (10&11)
- Nintendo Switch(L4T noble)

# 目次

- [インストール](#インストール方法)
    - [Git Cloneでのダウンロード](#git-cloneでのダウンロード)
    - [リリースからのダウンロード](#リリースからのダウンロード)
- [使い方](#使い方)
    - [コマンド](#基本的なコマンド)
    - [基本的なダウンロード](#基本的なダウンロード)
    - [サポートされているサイト](#サポートされているサイト)
- [既存の問題](#既存の問題)


## インストール方法

### Git cloneでのダウンロード

    git clone https://github.com/nyashinn1204/yoimi

注意: gitからのダウンロードの場合layer3のwidevine cdmが必要となります。(l3.wvd)

もし用意できるのであればできる限りこのオプションを利用してください


### リリースからのダウンロード

[こちら](https://github.com/NyaShinn1204/Yoimi/releases/latest) から最新版のYoimiをダウンロードしてください。

このzipにはl3.wvdなどが含まれています。用意がめんどくさいときはこちらを使ってください。

また、たまにですがYoimi-hot-fix-〇.zipという風に修正がされている場合があります。

その際にはできるだけ更新を行ってください。

## 使い方

### 基本的なコマンド

```
>> python yoimi.py download -h
Usage: yoimi.py download [OPTIONS] <URL site>

  Main command to access downloader

  Check supported streams from yuu with `yuu streams`

Options:
  -U, --username TEXT            Use username/password to download premium
                                 video
  -P, --password TEXT            Use username/password to download premium
                                 video
  -p, --proxy <ip:port/url>      Use http(s)/socks5 proxies (please add
                                 `socks5://` if you use socks5)
  -r, --resolution TEXT          Resolution to be downloaded (Default: best)
  -R, --resolutions              Show available resolutions
  -m, --mux                      Mux .ts to .mkv (Need ffmpeg or mkvmerge)
  -mf, --muxfile TEXT            Mux .ts to opticial file
  -keep, --keep-fragments        Keep downloaded fragment and combined
                                 fragment (If muxing) (Default: no)
  -o, --output TEXT              Output filename
  -v, --verbose                  Enable verbosity
  -rd, --random-directory        Make temp a random directory
  -gnc, --get-niconico-comment   Get Niconico Commment for Title # Unsupported
                                 Anime3rb
  -odc, --only-download-comment  Only Download Niconico Commment # Unsupported
                                 Anime3rb
  -h, --help                     Show this message and exit.
```

- **`--username/-U`**: ユーザー名またはメールアドレス
- **`--password/-P`**: パスワード
- **`--proxies/-p`**: プロキシ
    - 例: `127.0.0.1:1080`, `http://127.0.0.1:1080`, `http://user:pass@127.0.0.1:1080`, `socks5://127.0.0.1:1080`
- **`--verbose/-v`**: デバッグモードを利用する
- **`--random-directory/-rd`**: tempフォルダをランダム文字にする [※1](#中国語環境で暗号化解除が失敗する)
- **`--get-niconico-comment`**: ニコニコのコメントをダウンロードする
- **`--only-download-comment`**: ニコニコのコメントのみダウンロードする

### 基本的なダウンロード

基本的には

    python yoimi.py download ここに動画のurl

のようにすると、動作します。アカウントが必要な場合には

    python yoimi.py download ここに動画のurl --username ここにメールアドレス --password ここにパスワード

のようにすると、アカウントが使われます。一部クッキーが必要なものも出てくるかもしれません。

### サポートされているサイト

現在以下のサイトにサポート、または取り組んでいます。

完了: ✅   |   作成中: 🔄️   |   キャンセル: ❌

|                      | Premium  | Free  | 
| -------------------- | -------- | ----- |
| Abema                | ✅      | ✅   |
| U-Next               | ✅      | ｘ    |
| Dmm-TV               | ✅      | 🔄️   |
| Dアニメ              | 🔄️      | 🔄️   |
| FOD                  | ✅      | ｘ    |
| NHK+                 | 🔄️      |  🔄️  |
| Anime3rb             |  X       |  ✅  |
| Crunchyroll          | 🔄️      |  ✅  |

Abemaで問題が発生したら、urlの最後に"-v1"をつけてみてください。v1のモードでダウンローダーが動きます。

## 既存の問題

#### 中国語環境で暗号化解除が失敗する

この場合は-rdオプション、または--random-directoryオプションを利用してください。

#### その他

時々ライセンス取得に失敗し、プログラムが停止してしまう問題


## 問題を発見しましたか？

discord: nyanyakko005
または
telegmra: skidnyarara

に連絡をしてください

> [!WARNING]
> Yoimiは、[Yuu](https://github.com/noaione/yuu) と呼ばれるパッケージのベース部分をもとに開発されています。コードが似ている部分が多くあります
> またYoimiは、教育目的のみの使用を推奨しています。