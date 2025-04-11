import os
import parser as parser
import re # 正規表現モジュールを追加 (より柔軟な数値抽出のため)
# もしくは、自然順ソートライブラリを使う場合は import natsort

# --- オプション1: 手動で数値ソートキーを定義 ---
def get_numeric_part(filename):
    """ファイル名から数値部分を抽出して整数で返す。見つからない場合は非常に大きな数を返す"""
    # ファイル名から拡張子を除去
    basename = os.path.splitext(filename)[0]
    # basename が数字だけで構成されているか確認
    if basename.isdigit():
        return int(basename)
    else:
        # 数字以外が含まれる場合、ソート順を最後にするか、
        # もしくはエラー処理をするなど、仕様に応じて変更してください。
        # ここでは、数字でないものは最後に回すために大きな数を返します。
        # または、正規表現で先頭の数字列を抽出するなども考えられます。
        match = re.match(r'^(\d+)', basename)
        if match:
            return int(match.group(1))
        return float('inf') # 数値でないものを最後にソート

# --- オプション2: natsortライブラリを使用 (推奨、要インストール: pip install natsort) ---
# import natsort # ファイル冒頭で import

# --- 以下は共通コード ---
parser_for_mpd = parser.global_parser() # parser がユーザー定義モジュール/変数と仮定

mpd_directory = "./mpd_text"

# 1. 全ファイル名を取得
all_files = os.listdir(mpd_directory)

# 2. .mpd ファイルのみをフィルタリング
mpd_files = [f for f in all_files if f.endswith(".mpd")]

# 3. ファイル名を数値的にソート
# --- オプション1: 手動ソートキーを使用 ---
sorted_mpd_files = sorted(mpd_files, key=get_numeric_part)

# --- オプション2: natsortを使用 ---
# try:
#     import natsort
#     sorted_mpd_files = natsort.natsorted(mpd_files)
# except ImportError:
#     print("natsortライブラリが見つかりません。手動ソートを使用します。")
#     print("pip install natsort を実行すると、より自然なソートが可能です。")
#     # natsortがない場合のフォールバックとして手動ソート
#     sorted_mpd_files = sorted(mpd_files, key=get_numeric_part)


print(f"処理対象ファイル (ソート後): {sorted_mpd_files}") # 確認用

# 4. ソートされたファイルリストでループ処理
for filename in sorted_mpd_files:
    file_path = os.path.join(mpd_directory, filename)
    print(f"--- Processing: {filename} ---") #どのファイルを処理中か表示
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            mpd_text = file.read()
            # 注意: 以前のコードでは mpd_text に追記していましたが、
            #       ループ内で毎回パーサーを呼んでいるため、
            #       各ファイルの内容は独立して処理されるべきです。
            #       もし全ファイルの結合が必要ならループの外で結合します。

        # パーサーを実行 (各ファイルごとに)
        parsed_data = parser_for_mpd.mpd_parser(mpd_text)
        #print(str(parsed_data) + "\n\n")

        track_data = parser_for_mpd.print_tracks(parsed_data)
        
        print(track_data + "\n\n")
    except FileNotFoundError:
        print(f"エラー: ファイルが見つかりません - {file_path}")
    except Exception as e:
        print(f"エラー: {filename} の処理中に問題が発生しました - {e}")