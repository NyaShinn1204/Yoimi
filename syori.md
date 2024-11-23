# U-NEXT API Flow

## Overview
A step-by-step guide to interacting with the U-NEXT API for video playback, including fetching playlists, downloading media, and handling playback interruptions.

## Step-by-Step Process

### 1. Request Playlist
Send a GET request to retrieve the playlist information.
```http
GET https://playlist.unext.jp/playlist/v00001/dash/get/MEZ0000959882.mpd/?file_code=MEZ0000959882&play_token=$play_token
```

### 2. Retrieve Required Information
Extract the following details from the response:
- **Video_URL**
- **Audio_URL**
- **License_Key**

### 3. Obtain License Key
Send a POST request to retrieve the license key.
```http
POST https://wvproxy.unext.jp/proxy?play_token=$play_token
```

### 4. Download Media Files
Download the video and audio files using the extracted URLs:
- **Video**
- **Audio**

### 5. Decrypt Media Files
Decrypt the downloaded media files:
- **Video**
- **Audio**

### 6. Beacon Calls
Handle beacon calls to monitor playback events.
#### Pause or Stop Video Playback
- **Pause**:
```http
https://beacon.unext.jp/beacon/interruption/MEZ0000959882/2/?play_token=$play_token
```
- **Stop**:
```http
https://beacon.unext.jp/beacon/stop/MEZ0000959882/2/?play_token=$play_token&last_viewing_flg=0
```

