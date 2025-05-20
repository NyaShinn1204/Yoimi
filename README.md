![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=%E8%A4%87%E6%95%B0%E3%81%AE%E3%82%B5%E3%82%A4%E3%83%88%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%80%E3%83%BC%0AA%20Simple%20Encrypt%20Content%20Downloader&font=Raleway&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&pattern=Solid&theme=Light)

[English](./README.md) | [日本語](./README.ja.md)

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
- [Credits](#credits)


## How to Install

### Download with Git Clone

    git clone https://github.com/nyashinn1204/yoimi

Note: you will need layer3 widevine cdm if downloading from git. 

If you are able to prepare it, please use this option if at all possible!


### Downlaod with Release

Download the latest version of Yoimi from [here](https://github.com/NyaShinn1204/Yoimi/releases/latest).

~~This zip contains l3.wvd and other files. If you are having trouble preparing it, use this one.~~

l3.wvd will not be provided in the future, get it from drmlab or somewhere else.

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
  -U, --username TEXT            Use username/password to download premium
                                 video
  -P, --password TEXT            Use username/password to download premium
                                 video
  -p, --proxy <ip:port/url>      Use http(s)/socks5 proxies (please add
                                 `socks5://` if you use socks5)
   THIS OPTION IS NO LONGER AVAILABLE.
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

- **`--username/-U`**: Username or Email
- **`--password/-P`**: Password
- **`--proxies/-p`**: Proxy
    - Example: `127.0.0.1:1080`, `http://127.0.0.1:1080`, `http://user:pass@127.0.0.1:1080`, `socks5://127.0.0.1:1080`
- **`--verbose/-v`**: Use debug mode
- **`--random-directory/-rd`**: Temp folder to random characters [※1](#decryption-fails-in-chinese-environment)
- **`--get-niconico-comment`**: download niconico comment
- **`--only-download-comment`**: download only niconico comment

### Basic Download

Basically

    python yoimi.py download Here is the url of the video

and it will work. If you need an account

    python yoimi.py download here url of video --username here email address --password here password

If you want to use your account, you can use your account as follows. Some cookies may be required.

### Supported Sites

We currently support or are working on the following sites

Completed: ✅ | In Progress: 🔄️ | Cancelled: ❌ | Not Available: N/A

| Service            | Premium | Free  | Subtitles                   |
|--------------------|---------|-------|---------------------------- |
| Abema              | ✅      | ✅    | ✅ (Around 10~20 titles)  |
| U-Next             | ✅      | N/A   | N/A                         |
| DMM TV             | ✅      | ✅    | ✅                        |
| Danime             | 🔄️      | 🔄️    | N/A                        |
| FOD                | ✅      | ✅    | N/A                        |
| NHK+               | ✅      | ✅    | ✅                        |
| Anime3rb           | N/A     | ✅    | N/A                         |
| Crunchyroll        | 🔄️      | ✅    | 🔄️                        |
| JFF Theater        | N/A     | ✅    | N/A                         |
| WOWOW              | 🔄️(under adjustment)      | N/A   | N/A                         |
| Bandai Channel     | ✅      | ✅    | N/A                        |
| Fanza VR           | 🔄️      | N/A    | N/A                        |

If you have problems with Abema, try adding “-v1” to the end of the url, and the downloader will work in v1 mode.

## Existing Issues

#### Decryption fails in Chinese environment

In this case, use the -rd option or the --random-directory option.
(This setting was automatically enabled in v1.2.0)

#### Other

Problem with occasional licensing failures and program stoppage

## Credits

Credits is [here](./CREDITS.md)!


## Have you found a problem?

discord: nyanyakko005 (https://discord.gg/KvGuzNh5UP) Recently made. :)
or
telegmra: skidnyarara

Please contact us at

> [!WARNING]
> Yoimi is developed from the base part of a package called [Yuu](https://github.com/noaione/yuu). There are many similarities in the code
> Yoimi also recommends that it be used for educational purposes only.

<!-- https://discord.gg/ReZT8E2F2j -->