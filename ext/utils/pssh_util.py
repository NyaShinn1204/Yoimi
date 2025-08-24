# src from pssh-extractor

import base64
from typing import List, Dict, Callable

DRM_TYPES: Dict[str, str] = {
    "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed": "Widevine",
    "9a04f079-9840-4286-ab92-e65be0885f95": "PlayReady",
    "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b": "WC3 Common",
    "3ea8778f-7742-4bf9-b18b-e834b2acbd47": "Clear Key AES-128",
    "be58615b-19c4-4684-88b3-c8c57e99e957": "Clear Key SAMPLE-AES",
    "e2719d58-a985-b3c9-781a-b030af78d30e": "Clear Key DASH-IF",
    "5e629af5-38da-4063-8977-97ffbd9902d4": "Marlin",
    "9a27dd82-fde2-4725-8cbc-4234aa06ec09": "Verimatrix VCAS",
    "b4413586-c58c-ffb0-94a5-d4896c1af6c3": "Viaccess-Orca DRM",
    "793b7956-9f94-4946-a942-23e7ef7e44b4": "VisionCrypt",
    "80a6be7e-1448-4c37-9e70-d5aebe04c8d2": "Irdeto Content Protection",
    "94ce86fb-07ff-4f43-adb8-93d2fa968ca2": "FairPlay",
    "f239e769-efa3-4850-9c16-a903c6932efb": "Adobe Primetime",
    "adb41c24-2dbf-4a6d-958b-4457c0d27b95": "Nagra MediaAccess PRM 3.0",
    "3d5e6d35-9b9a-41e8-b843-dd3c6e72c42c": "ChinaDRM",
}

PsshArray = List[Dict[str, str]]


def handle_error(msg: str, callback: Callable[[str], None] = None):
    print(f"Error: {msg}")
    if callback:
        callback(msg)


def array_buffer_to_base64(buffer: bytes) -> str:
    return base64.b64encode(buffer).decode("ascii")


def extract_pssh_array(buffer: bytes) -> PsshArray:
    if not buffer:
        raise ValueError("It looks like your file is empty.")

    view = bytearray(buffer)
    text = buffer.decode("latin-1", errors="ignore")
    pssh_offsets = []
    pssh_array: PsshArray = []

    index_of_occurrence = text.find("pssh")
    while index_of_occurrence >= 0:
        pssh_offsets.append(index_of_occurrence)
        index_of_occurrence = text.find("pssh", index_of_occurrence + 1)

    if not pssh_offsets:
        raise ValueError("Failed to extract PSSH from your file.")

    for offset in pssh_offsets:
        offset_start = offset - 4
        offset_end = view[offset - 2] * 256 + view[offset - 1]
        arr_we_need = view[offset_start:offset_start + offset_end]

        pssh_b64 = array_buffer_to_base64(arr_we_need)

        uuid_bytes = arr_we_need[12:28]
        uuid = "".join(f"{b:02x}" for b in uuid_bytes)
        uuid = f"{uuid[0:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:32]}"

        drm_type = DRM_TYPES.get(uuid, "Unknown")

        pssh_array.append({"type": drm_type, "data": pssh_b64})

    return pssh_array
