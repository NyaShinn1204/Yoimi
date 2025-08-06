import re
import os
import unicodedata
from collections import defaultdict

def safe_format(format_string, raw_values):
    keys_in_format = set(re.findall(r"{(\w+)}", format_string))
    values = {k: raw_values.get(k, "") for k in keys_in_format if raw_values.get(k)}
    
    for k in keys_in_format:
        if not raw_values.get(k):
            format_string = re.sub(rf"_?{{{k}}}", "", format_string)
 
    return format_string.format_map(defaultdict(str, values))

class titlename_logic:
    def __init__(self, config):
        self.config = config
    def create_titlename_logger(self, content_type, episode_count, title_name, episode_num, episode_name):
        
        # Sample
        # content_type = "anime", episode_count = 3, title_name = "サイレント・ウィッチ 沈黙の魔女の隠しごと", episode_num = "第一話", episode_name = "同期が来りて無茶を言う"
        # content_type = "movie", episode_count = 1, title_name = "劇場版 ソードアート・オンライン –オーディナル・スケール-", episode_num = None, episode_name = None
        # content_type = "movie", episode_count = 2, title_name = "劇場版 魔法少女まどか☆マギカ", episode_num = "［前編］ 始まりの物語", episode_name = None
        # content_type = "movie", episode_count = 2, title_name = "劇場版 魔法少女まどか☆マギカ", episode_num = "［後編］ 永遠の物語", episode_name = None
        
        raw_values = {
            "seriesname": title_name,
            "titlename": episode_num,
            "episodename": episode_name
        }
    
        if content_type in ("anime", "drama", "アニメ", "ドラマ"):
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values)
        elif content_type in ("movie", "洋画", "邦画"):
            if episode_count == 1:
                title_name_logger = title_name
            else:
                format_string = self.config["format"]["movie"]
                title_name_logger = safe_format(format_string, raw_values)
        else:
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values) 
        return title_name_logger
    def create_output_filename(self, video_info, command_list, season_title, output_titlename):
        ### Setting output filename
        ## define name
        sanitize_logic = filename_logic(delete_only=False)
        title_name = video_info["title_name"]
        extension_name = "." + command_list["output_extension"]
        
        output_dir = command_list.get("output_directory")
        output_filename = command_list.get("output_filename")
        
        content_type = video_info["content_type"] 
        
        ## Build output path :skull:
        if output_dir or output_filename:
            if content_type in ("movie", "洋画", "邦画"):
                if output_dir and not output_filename:
                    output_path = os.path.join(output_dir, season_title, sanitize_logic.sanitize_filename(output_titlename) + extension_name)
                elif output_dir and output_filename:
                    output_path = os.path.join(output_dir, output_filename)
        else:
            output_dir = self.config["directories"]["Downloads"]
            if content_type in ("movie", "洋画", "邦画"):
                output_path = os.path.join(output_dir, sanitize_logic.sanitize_filename(output_titlename) + extension_name)
            else:
                output_path = os.path.join(output_dir, sanitize_logic.sanitize_filename(title_name), season_title, sanitize_logic.sanitize_filename(output_titlename) + extension_name)
        
        
        return output_filename, output_path
    
class filename_logic:
    def __init__(self, delete_only: bool = False):
        self.delete_only = delete_only
    def sanitize_filename(self, filename: str) -> str:
        """
        Fucking idiot Windows filename convert to JP string
        
        例:
            delete_only = False
            filename:
            いずれ最強の錬金術師? -> いずれ最強の錬金術師？
            
            delete_only = True
            filename:
            いずれ最強の錬金術師? -> いずれ最強の錬金術師
        """
        if self.delete_only:
            filename = unicodedata.normalize('NFKD', filename).encode('ascii', 'ignore').decode('ascii')
            filename = re.sub(r'[^\w\s-]', '', filename.lower())
            return re.sub(r'[-\s]+', '-', filename).strip('-_')
        replacements = {
            '<': '＜',
            '>': '＞',
            ':': '：',
            '"': '”',
            '/': '／',
            '\\': '＼',
            '|': '｜',
            '?': '？',
            '*': '＊'
        }
        for bad_char, safe_char in replacements.items():
            filename = filename.replace(bad_char, safe_char)
        return filename