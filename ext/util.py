import re
import os

from typing import Iterator


def path_check(input_path):
    invalid_chars = r'[<>:"|?*]'
    if re.search(invalid_chars, input_path):
        return False

    if not input_path.strip():
        return False

    has_extension = bool(os.path.splitext(input_path)[1])
    looks_like_path = '/' in input_path or '\\' in input_path

    return has_extension or looks_like_path

def download_command(input: str, command_list: Iterator):
    pass