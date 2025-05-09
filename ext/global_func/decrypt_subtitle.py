from typing import Union

def data_view_to_string(data: Union[bytes, bytearray, memoryview], encoding: str = "utf-8") -> str:
    if encoding == "utf-8":
        return data.decode("utf-8")
    else:
        return "".join(chr(byte) for byte in data)
def parse_binary_content(content):
    return data_view_to_string(content, "utf-8")