![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=%E8%A4%87%E6%95%B0%E3%81%AE%E3%82%B5%E3%82%A4%E3%83%88%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%80%E3%83%BC%0AA%20Simple%20Encrypt%20Content%20Downloader&font=Raleway&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&pattern=Solid&theme=Light)

日本語: [![jp](https://img.shields.io/badge/README-jp-red.svg)](README.md)

English: [![en](https://img.shields.io/badge/README-en-red.svg)](README.en-us.md)

A simple encrypted content downloader.

Currently, we have confirmed operation with the following devices

- Linux (aarch64, arm64)
- Windows (10&11)
- Nintendo Switch(L4T Ubuntu noble)

# Table of contents

- [Installation](#how-to-install)
    - [Download with Git Clone](#download-with-git-clone)
    - [Downlaod with Release](#download-with-release)
- [How to use](#how-to-use)
    - [Commands](#basic-commands)
    - [Download](#basic-download)
    - [Supported Sites](#supported-sites)
- [Existing Issues](#exsiting-issues)


## How to Install

### Download with Git Clone

    git clone https://github.com/nyashinn1204/yoimi

Note: you will need layer3 widevine cdm if downloading from git. (l3.wvd)

If you are able to prepare it, please use this option if at all possible!


### Downlaod with Release

Download the latest version of Yoimi from [here](https://github.com/NyaShinn1204/Yoimi/releases/latest).

This zip contains l3.wvd and other files. If you are having trouble preparing it, use this one.

Also, sometimes there are modifications to the Yoimi-hot-fix-0.zip.

In that case, please update the file as much as possible.

## How to use

### Basic Commands

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
  -rd, --random-directory    Make temp a random directory
  -h, --help                 Show this message and exit.
```

- **`--username/-U`**: Username or Email
- **`--password/-P`**: Password
- **`--proxies/-p`**: Proxy
    - Example: `127.0.0.1:1080`, `http://127.0.0.1:1080`, `http://user:pass@127.0.0.1:1080`, `socks5://127.0.0.1:1080`
- **`--verbose/-v`**: Use debug mode
- **`--random-directory/-rd`**: Temp folder to random characters [※1](#decryption-fails-in-chinese-environment)

### Basic Download

Basically

    python yoimi.py download Here is the url of the video

and it will work. If you need an account

    python yoimi.py download here url of video --username here email address --password here password

If you want to use your account, you can use your account as follows. Some cookies may be required.

### Supported Sites

We currently support or are working on the following sites

Completed: ✅ | Under construction: 🔄️

|                      | Premium  | Free  | 
| -------------------- | -------- | ----- |
| Abema                | ✅      | ✅   |
| U-Next               | ✅      | ｘ    |
| Dmm-TV               | ✅      | 🔄️   |
| Danime               | 🔄️      | 🔄️   |
| FOD                  | ✅      | ｘ    |
| NHK+                 | 🔄️      | 🔄️   |

## Existing Issues

#### Decryption fails in Chinese environment

In this case, use the -rd option or the --randaom-directory option.

#### Other

Problem with occasional licensing failures and program stoppage


## Have you found a problem?

discord: nyanyakko005
or
telegmra: skidnyarara

Please contact us at

> [!WARNING]
> Yoimi is developed from the base part of a package called [Yuu](https://github.com/noaione/yuu). There are many similarities in the code
> Yoimi also recommends that it be used for educational purposes only.