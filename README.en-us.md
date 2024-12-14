![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=Abema%E3%82%84U-Next%E3%80%81Dmm-TV%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%80%E3%83%BC%0AA%20Simple%20Abema%20TV%2C%20U-Next%2C%20Dmm-TV%2C%20Dmm-TV%20Downloader&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&stargazers=1&theme=Light)

[![jp](https://img.shields.io/badge/README-jp-red.svg)](README.md)
[![en](https://img.shields.io/badge/README-en-red.svg)](README.en-us.md)

## Installation

**※ Python version 3.12 or higher is required**

To use 「Yoimi」, execute the following command

> [!TIP]
> This is the development version!

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

## Usage
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

- **`--username/-U`**: Username or email
- **`--password/-P`**: Password
- **`--proxies/-p`**: Proxie
    - 例: `127.0.0.1:1080`, `http://127.0.0.1:1080`, `http://user:pass@127.0.0.1:1080`, `socks5://127.0.0.1:1080`
- **`--verbose/-v`**: Enable debug mode

**Proxy has not yet been fully tested**

### Example command: 
Download from Abema
1. **Download original file**  
   ```bash
   python3 yoimi.py download "https://abema.tv/video/episode/19-171_s1_p1"
   ```
   ✨ Download the first episode of「Frieren: Beyond Journey's End」from Abema（.ts file）

2. **Download convert mp4 file**  
   ```bash
   python3 yoimi.py download "https://abema.tv/video/episode/19-171_s1_p1" --mux
   ```
   ✨ Download the first episode of「Frieren: Beyond Journey's End」from Abema（Conver to mp4）

- - -

Download from U-Next
1. **Download specific episodes**  
   ```bash
   python3 yoimi.py download "https://video.unext.jp/play/SID0104147/ED00570917" --username EMAIL_HERE --password PASSWORD_HERE
   ```
   ✨ Download an episode of「Alya Sometimes Hides Her Feelings in Russian」from Unext

   **Sample Video**: [Click Here](https://github.com/user-attachments/assets/c98fe42c-ab27-498d-b2e5-b0ba897e2d81)

2. **Download one season**  
   ```bash
   python3 yoimi.py download "https://video.unext.jp/play/SID0104147" --username EMAIL_HERE --password PASSWORD_HERE
   ```
   ✨ Download the entire one season of「Alya Sometimes Hides Her Feelings in Russian」from Unext

   **Sample Video**: [Click Here](https://youtu.be/09vmBKzQMQE)


&nbsp;
- - -
&nbsp;  

##### Known issues:
 * Sometimes licensing fails and the program stops.

##### Contact us:
- discord: nyanyakko005

> [!WARNING]
> Yoimi is an improved version of a code that copies and compresses about 95% of a package called [Yuu](https://github.com/noaione/yuu)
