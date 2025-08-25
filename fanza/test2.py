import base64
import struct
from pathlib import Path
class Tracks:
    def find_moov_box(mp4_data):
        """MP4バイナリデータからmoovボックスをうあーする"""
        f = mp4_data
        i = 0
        while i < len(f):
            box_size, box_type = struct.unpack('>I4s', f[i:i+8])
            i += 8
    
            if box_type == b'moov':
                return f[i:i+box_size-8]
    
            i += box_size - 8
    
        return None
    
    def parse_box(data, index=0):
        """指定されたデータからボックスをうあーして返す"""
        boxes = []
        while index < len(data):
            box_size, box_type = struct.unpack('>I4s', data[index:index+8])
            index += 8
    
            box = {
                'size': box_size,
                'type': box_type.decode('utf-8'),
                'data': data[index:index+box_size-8]
            }
    
            boxes.append(box)
    
            index += box_size - 8
        return boxes

def to_pssh(content: bytes) -> str:
            moov_box = Tracks.find_moov_box(content)
            
            pssh_box = ""
            count = 0
            if moov_box:
                sub_boxes = Tracks.parse_box(moov_box)
                for box in sub_boxes:
                    if box["type"] == "pssh":
                        if count == 0:
                            pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            pssh_box = pssh_temp.replace("==", "")
                            #pssh_box = pssh_temp // なぜかこれでもdecryptできる。謎
                        else:
                            pssh_temp = "AAAA"+str(base64.b64encode(b"<pssh"+box["data"]), encoding='utf-8', errors='replace')
                            pssh_box = pssh_box + pssh_temp.replace("==", "====")
                        count += 1
            return pssh_box
            

def from_file(file_path: str) -> str:
    print('Extracting PSSH from init file:', file_path)
    return to_pssh(Path(file_path).read_bytes())

print(from_file("h_1558csdx000062d_v1_drm_a_4k.dcv"))