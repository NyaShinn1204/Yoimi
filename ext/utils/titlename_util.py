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