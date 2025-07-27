import re
from collections import defaultdict

def safe_format(format_string, raw_values):
    keys_in_format = set(re.findall(r"{(\w+)}", format_string))
    values = {k: raw_values.get(k, "") for k in keys_in_format if raw_values.get(k)}
    
    for k in keys_in_format:
        if not raw_values.get(k):
            format_string = re.sub(rf"_?{{{k}}}", "", format_string)
 
    return format_string.format_map(defaultdict(str, values))

class titlename_logic:
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
    
        if content_type in ("anime", "drama"):
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values)
        elif content_type in ("movie"):
            if episode_count == 1:
                title_name_logger = title_name
            else:
                format_string = self.config["format"]["movie"]
                title_name_logger = safe_format(format_string, raw_values)
        else:
            format_string = self.config["format"]["anime"]
            title_name_logger = safe_format(format_string, raw_values) 
        return title_name_logger