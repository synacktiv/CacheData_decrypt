import binascii
import struct
import hashlib
import os
import dpapick3.eater as eater
from enum import IntEnum
from typing import List

class CacheNodeType(IntEnum):
    PASSWORD = 1
    UNKNOW_TWO = 2
    UNKNOW_THREE = 3
    UNKNOW_FOUR = 4
    PIN = 5

class CacheDataNodeHeader(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwNodeType = data.eat("L")
        self.dwCryptoBlobSize = data.eat("L")
        self.dwField8 = data.eat("L")
        self.dwEncryptedPRTSize = data.eat("L")
        self.dwField10 = data.eat("L")


class CacheDataNode:
    def __init__(self, header : CacheDataNodeHeader):
        self._header : CacheDataNodeHeader = header
        self._cryptoBlob : bytes = None
        self._encryptedPrtBlob : bytes = None

    @property
    def cryptoBlob(self):
        return self._cryptoBlob

    @cryptoBlob.setter
    def cryptoBlob(self, value):
        self._cryptoBlob = value

    @property
    def encryptedPRTBlob(self):
        return self._encryptedPrtBlob

    @encryptedPRTBlob.setter
    def encryptedPRTBlob(self, value):
        self._encryptedPrtBlob = value

    def is_node_type_password(self) -> bool:
        return self._header.dwNodeType == CacheNodeType.PASSWORD

    def is_node_type_pin(self) -> bool:
        return self._header.dwNodeType == CacheNodeType.PIN

def parse_cache_data(file_path) -> List[CacheDataNode]:
    cache_data_node_list = list()
    print(f'[+] Parsing CacheData file {file_path}')
    with open(file_path, "rb") as f:
        file_size = f.seek(0, os.SEEK_END)
        f.seek(0, os.SEEK_SET)
        # First 4 byte is a version number
        (version,) = struct.unpack("<I", f.read(4))
        print(f"[+] CacheData file version is 0x{version:x}")
        # 32 following bytes is the sha256 expected checksum
        sha256_checksum = f.read(32)
        # Compute checksum to check if matching
        payload = f.read(file_size - f.tell())
        # Read raw file
        f.seek(0, os.SEEK_SET)
        raw_payload = f.read(file_size)

    m = hashlib.sha256()
    m.update(payload)
    print(f"[+] CacheData expected sha256: {str(binascii.hexlify(sha256_checksum), 'ascii')}")
    print(f"[+] CacheData computed sha256: {m.hexdigest()}")
    assert version == 0x02
    assert sha256_checksum == m.digest()

    cache_data_node_count, = struct.unpack("<I", raw_payload[0x50:0x54])
    offset = 0x54

    print(f"[+] Parsing Cache node headers")
    for i in range (0, cache_data_node_count):
        cache_data_node_header = CacheDataNodeHeader(raw_payload[offset:offset+0x14])
        print(f"[+]\tFound CacheNode of type 0x{cache_data_node_header.dwNodeType:x}, CryptoBlobSize = 0x{cache_data_node_header.dwCryptoBlobSize:x}, EncryptedPRTSize = 0x{cache_data_node_header.dwEncryptedPRTSize:x}")
        cache_data_node_list.append(CacheDataNode(cache_data_node_header))
        offset += 0x14

    print(f"[+] Parsing raw blob")
    i = 0
    while offset < len(raw_payload):
        blob_size, = struct.unpack("<I", raw_payload[offset:offset+4])
        offset += 4
        if blob_size == 0:
            continue
        print(f'[+]\tFound blob of size 0x{blob_size:x} (offset = 0x{offset:x}/0x{len(raw_payload):x})')
        blob = raw_payload[offset:offset+blob_size]
        offset += blob_size
        if offset % 4 != 0:
            offset += (4 - (offset % 4))
        index_cache_data_node_list = i // 2
        # For each cache node, there is one cryptoBlob and one encryptedPRTBlob
        if i % 2 == 0:
            cache_data_node_list[index_cache_data_node_list].cryptoBlob = blob
        else:
            cache_data_node_list[index_cache_data_node_list].encryptedPRTBlob = blob
        i += 1

    return cache_data_node_list
