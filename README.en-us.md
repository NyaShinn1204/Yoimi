![Yoimi](https://socialify.git.ci/NyaShinn1204/Yoimi/image?description=1&descriptionEditable=Abema%E3%82%84U-Next%E3%81%AE%E5%8B%95%E7%94%BB%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%89%E3%83%84%E3%83%BC%E3%83%AB%0AA%20Simple%20Abema%20TV%2C%20U-Next%20Downloader&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Ffiles.catbox.moe%2Fue535j.png&name=1&stargazers=1&theme=Light)

[![jp](https://img.shields.io/badge/README-jp-red.svg)](README.md)
[![en](https://img.shields.io/badge/README-en-red.svg)](README.en-us.md)

## Installation

**※ Python version 3.10 or higher is required**

To use 「Yoimi」, execute the following command

> [!TIP]
> This is the development version!

```bash
git clone https://github.com/NyaShinn1204/Yoimi

cd Yoimi

python3 yoimi.py -h
```

#### ✨ Download the first episode of「Frieren: Beyond Journey's End」from Abema（.ts file）

```python
python3 yoimi.py download "https://abema.tv/video/episode/19-171_s1_p1"
```

#### ✨ Download the first episode of「Frieren: Beyond Journey's End」from Abema（Conver to mp4）

```python
python3 yoimi.py download "https://abema.tv/video/episode/19-171_s1_p1" --mux
```

#### ✨ Download an episode of「Alya Sometimes Hides Her Feelings in Russian」from Unext

```python
python3 yoimi.py download "https://video.unext.jp/play/SID0104147/ED00570917" --username EMAIL_HERE --password PASSWORD_HERE
```

#### ✨ Download the entire one season of「Alya Sometimes Hides Her Feelings in Russian」from Unext

```python
python3 yoimi.py download "https://video.unext.jp/play/SID0104147" --username EMAIL_HERE --password PASSWORD_HERE
```

#### ✨ Sample video to download an episode of “Arya next door who can answer in Russian” from Unext

https://github.com/user-attachments/assets/c98fe42c-ab27-498d-b2e5-b0ba897e2d81

#### ✨ Sample video to download the entire one season of “Arya-san next door who can answer in Russian” from Unext.

[Click here](https://youtu.be/09vmBKzQMQE)


&nbsp;
- - -
&nbsp;  

##### Known issues:
 * Sometimes licensing fails and the program stops.

> [!WARNING]
> Yoimi is an improved version of a code that copies and compresses about 95% of a package called [Yuu](https://github.com/noaione/yuu)