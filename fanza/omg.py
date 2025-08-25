import requests


def create_session(token: str, user_id: str) -> requests.Session:
    """
    認証付きセッションを作成し、Cookie を更新して返す
    """
    session = requests.Session()

    # 初期ヘッダー
    session.headers.update({
        "authorization": f"Bearer {token}",
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 10; A7S Build/QP1A.190711.020)",
        "host": "gw.dmmapis.com",
        "connection": "Keep-Alive",
        "accept-encoding": "gzip"
    })

    # セッション発行
    payload = {"user_id": user_id}
    resp = session.post("https://gw.dmmapis.com/connect/v1/issueSessionId", json=payload).json()

    # Cookie 更新
    session.cookies.update({
        "secid": resp["body"]["secure_id"],
        "dmm_app_uid": resp["body"]["unique_id"]
    })

    return session


def request_with_headers(session: requests.Session, url: str, headers: dict) -> requests.Response:
    """
    任意のヘッダーを付けて GET リクエストを行う
    """
    return session.get(url, allow_redirects=False, headers=headers)


def main():
    # 固定パラメータ プロヂューサー...leakしたら死ぬね...ふふ by 広
    TOKEN = ""
    USER_ID = ""
    TARGET_URL = "https://api.webstream.ne.jp/rights/urn:uuid:XXXXXXXXXXXXXXXXXXXX"

    # セッション作成。これで君もあなるの仲間入りだ
    session = create_session(TOKEN, USER_ID)

    # WebStream API を呼び出して8kのlicense keyをraid
    webstream_headers = {
        "host": "api.webstream.ne.jp",
        "user-agent": "Mozilla/5.0 (Linux; Android 10; A7S Build/QP1A.190711.020; wv) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
                      "Chrome/139.0.7258.95 Mobile Safari/537.36 "
                      "AndroidToaster/com.dmm.app.player.vr/2.0.5 "
                      "(app/a45c1b62-1cd9-479c-a8f2-137bf5fb7520; ) "
                      "WebStream DRM ({46bc2e5f-19a2-45b1-9b7e-13bf40633269})",
        "x-requested-with": "com.dmm.app.player.vr",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8,"
                  "application/signed-exchange;v=b3;q=0.7",
        "accept-language": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    response = request_with_headers(session, TARGET_URL, webstream_headers)

    # DMMのリダイレクト用アナルバイブヘッダーを挿入
    dmm_headers = {
        "host": "www.dmm.com",
        "user-agent": webstream_headers["user-agent"],
        "x-requested-with": "com.dmm.app.player.vr",
        "accept": webstream_headers["accept"],
        "accept-language": webstream_headers["accept-language"],
    }

    # リダイレクトをやりまくって、ヤリ中毒
    for _ in range(4):
        next_url = response.headers.get("Location")
        if not next_url:
            break
        response = request_with_headers(session, next_url, dmm_headers)

    print(response.text)


if __name__ == "__main__":
    main()
