import json
import pprint

def _recursive_search(genre_list, target_id):
    """
    ジャンルのリストを再帰的に探索し、指定されたIDのジャンルオブジェクトを返す。（内部ヘルパー関数）
    """
    # リスト内の各ジャンルをチェック
    for genre in genre_list:
        # genre_idが一致したら、そのオブジェクトを返す
        if genre.get('genre_id') == target_id:
            return genre

        # サブジャンルのキーがあれば、その中を再帰的に探索する
        # このJSONファイルでサブジャンルリストを持つ可能性のあるキーを列挙
        sub_genre_keys = ['sub', 'ttb_top_genre', 'ttb_top_sub_genre']
        for key in sub_genre_keys:
            if key in genre and isinstance(genre.get(key), list):
                # 再帰呼び出しでサブジャンルを探索
                found_genre = _recursive_search(genre[key], target_id)
                # 見つかった場合は、その結果を上に伝播させて処理を終了する
                if found_genre:
                    return found_genre
    
    # リストの最後まで探しても見つからなければNoneを返す
    return None

def find_genre_by_id(genre_data, target_id):
    """
    JSONデータ全体から指定されたgenre_idを持つジャンル情報を検索する。

    Args:
        genre_data (dict): genre_search.jsonを読み込んだ辞書データ。
        target_id (str): 検索したいgenre_id。

    Returns:
        dict or None: 見つかったジャンルオブジェクト。見つからない場合はNone。
    """
    # 探索の開始地点となる 'genre_master' -> 'VOD' のリストを取得
    vod_genres = genre_data.get('genre_master', {}).get('VOD', [])
    if not vod_genres:
        print("エラー: 'genre_master' -> 'VOD' の構造が見つかりません。")
        return None
    
    # 再帰探索を開始
    return _recursive_search(vod_genres, target_id)

# --- メインの実行部分 ---
if __name__ == "__main__":
    import requests
    file_path = requests.get("https://conf.lemino.docomo.ne.jp/genre/genre_search.json").json()

    try:
        #with open(file_path, 'r', encoding='utf-8') as f:
        data = file_path
    except FileNotFoundError:
        print(f"エラー: ファイル '{file_path}' が見つかりません。スクリプトと同じ場所に配置してください。")
        exit()
    except json.JSONDecodeError:
        print(f"エラー: ファイル '{file_path}' のJSON形式が正しくありません。")
        exit()

    # --- 検索の実行例 ---
    
    # 検索したいgenre_idのリスト（サンプル）
    search_ids = [
        "2.1.101",          # トップレベルのジャンル（アニメ）
        "2.1.105.4",        # サブジャンル（邦画 -> アクション）
        "2.1.113.7.1.2",    # 深い階層のサブジャンル（... -> ドラマ -> コメディ）
        "2.1.150.10.3",     # Leminoチャンネル内のジャンル (... -> FANYチャンネル -> ロケ番組)
        "9.9.999",           # 存在しないID,
        "2.1.107.2"
    ]

    for genre_id in search_ids:
        print(f"--- 検索ID: {genre_id} ---")
        result = find_genre_by_id(data, genre_id)

        if result:
            print("ジャンルが見つかりました:")
            # pprintを使うと整形されて見やすく表示できる
            print(result)
            pprint.pprint(result)
        else:
            print("指定されたIDのジャンルは見つかりませんでした。")
        print("-" * 25 + "\n")