import re
import unicodedata

def sanitize_filename(filename: str, delete_only: bool = False) -> str:
    """
    Fucking idiot Windows filename convert to JP string 
    """
    if delete_only:
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