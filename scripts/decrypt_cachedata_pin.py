#!/usr/bin/env python3
import struct
import os
import hashlib
import binascii
import json
import hexdump
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import dpapick3.eater as eater


class BcryptRsaKeyBlob(eater.DataStruct):
    """
    // https://learn.microsoft.com/fr-fr/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    typedef struct _BCRYPT_RSAKEY_BLOB {
      ULONG Magic;
      ULONG BitLength;
      ULONG cbPublicExp;
      ULONG cbModulus;
      ULONG cbPrime1;
      ULONG cbPrime2;
    } BCRYPT_RSAKEY_BLOB;

    BCRYPT_RSAKEY_BLOB
    PublicExponent[cbPublicExp] // Big-endian.
    Modulus[cbModulus] // Big-endian.
    """

    # From bcrypt.h -> #define BCRYPT_RSAPRIVATE_MAGIC     0x32415352
    BCRYPT_RSAPRIVATE_MAGIC = 0x32415352  # 'RSA2'
    # From bcrypt.h -> #define 	BCRYPT_RSAPUBLIC_MAGIC   0x31415352
    BCRYPT_RSAPUBLIC_MAGIC = 0x31415352   # 'RSA1'

    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)
    
    def parse(self, data):
        self.Magic = data.eat("L")
        self.BitLength = data.eat("L")
        self.cbPublicExp = data.eat("L")
        self.cbModulus = data.eat("L")
        self.cbPrime1 = data.eat("L")
        self.cbPrime2 = data.eat("L")
        self.PublicExp = int.from_bytes(data.eat_string(self.cbPublicExp), "big")
        self.Modulus = int.from_bytes(data.eat_string(self.cbModulus), "big")
        if self.Magic == BcryptRsaKeyBlob.BCRYPT_RSAPUBLIC_MAGIC:
            assert self.cbPrime1 == 0 and self.cbPrime2 == 0
        elif self.Magic == BcryptRsaKeyBlob.BCRYPT_RSAPRIVATE_MAGIC:
            assert self.cbPrime1 != 0 and self.cbPrime2 != 0
            self.Prime1 = int.from_bytes(data.eat_string(self.cbPrime1), "big")
            self.Prime2 = int.from_bytes(data.eat_string(self.cbPrime1), "big")
        assert data.ofs == data.end, "Invalid BcryptRsaKeyBlob size"
    
    def get_rsa_public_key(self) -> rsa.RSAPublicKey:
        rsa_pub_num = rsa.RSAPublicNumbers(self.PublicExp, self.Modulus)
        return rsa_pub_num.public_key()

    def get_rsa_private_key(self) -> rsa.RSAPrivateKey:
        assert self.Magic == 0x32415352
        # Compute n = p * q
        n = self.Prime1 * self.Prime2
        rsa_pub_num = rsa.RSAPublicNumbers(self.PublicExp, n)
        # Compute the RSA private exponent (d)
        d = rsa._modinv(self.PublicExp, (self.Prime1 - 1) * (self.Prime2 - 1))
        # Computes the dmp1 parameter from the RSA private exponent (d) and prime p
        dmp1 = rsa.rsa_crt_dmp1(d, self.Prime1)
        # Computes the dmq1 parameter from the RSA private exponent (d) and prime q
        dmq1 = rsa.rsa_crt_dmq1(d, self.Prime2)
        # Computes the iqmp (also known as qInv) parameter from the RSA primes p and q
        iqmp = rsa.rsa_crt_iqmp(self.Prime1, self.Prime2)
        rsa_priv_num = rsa.RSAPrivateNumbers(
            self.Prime1, self.Prime2, d, dmp1, dmq1, iqmp, rsa_pub_num
        )
        rsa_priv_key: rsa.RSAPrivateKey = rsa_priv_num.private_key()
        assert rsa_priv_key.key_size == self.BitLength
        return rsa_priv_key


class NgcAsymetricKeyEncryptedBlob(eater.DataStruct):
    """
    Undocumented _NGC_ASYMMETRIC_KEY_ENCRYPTED_BLOB structure.
    - 3rd arg of cryptngc!NgcDecryptWithUserIdKeySilent
    - 5th arg of cryptngc!DecryptWithUserIdKey
    00000000 dwVersion
    00000004 dwEncryptedAESKey1Length
    00000008 dwIVLength
    0000000C dwEncryptedAESKey2Length
    00000010 dwEncryptedTPMKeyLength
    ...
    """
    def __init__(self, raw=None):
        eater.DataStruct.__init__(self, raw)
    
    def parse(self, data):
        self.dwVersion = data.eat("L")
        self.dwEncryptedAESKey1Length = data.eat("L")
        self.dwIVLength = data.eat("L")
        self.dwEncryptedAESKey2Length = data.eat("L")
        self.dwEncryptedTPMKeyLength = data.eat("L")
        self.encryptedAESKey1 = data.eat_string(self.dwEncryptedAESKey1Length)
        self.IV = data.eat_string(self.dwIVLength)
        self.encryptedAESKey2 = data.eat_string(self.dwEncryptedAESKey2Length)
        self.encryptedTPMKey = data.eat_string(self.dwEncryptedTPMKeyLength)
        assert data.ofs == data.end, "Invalid NgcAsymetricKeyEncryptedBlob size"


class ScardCacheDataBlob(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwScardversion = data.eat("L")
        self.dwScardBlobSize = data.eat("L")
        self.dwScardCertOffset = data.eat("L")
        self.dwScardCertSize = data.eat("L")
        self.dwScardIVOffset = data.eat("L")
        self.dwScardIVSize = data.eat("L")
        self.dwScardEncKeyOffset = data.eat("L")
        self.dwScardEncKeySize = data.eat("L")
        self.dwScardCredKeyOffset = data.eat("L")
        self.dwScardCredKeySize = data.eat("L")
        assert data.ofs == self.dwScardCertOffset
        self.ScardCert = data.eat_string(self.dwScardCertSize)
        assert data.ofs == self.dwScardIVOffset
        self.ScardIV = data.eat_string(self.dwScardIVSize)
        assert data.ofs == self.dwScardEncKeyOffset
        self.ScardEncKey = data.eat_string(self.dwScardEncKeySize)
        assert data.ofs == self.dwScardCredKeyOffset
        self.ScardCredKey = data.eat_string(self.dwScardCredKeySize)
        assert self.dwScardBlobSize == (
            self.dwScardCertSize +
            self.dwScardIVSize +
            self.dwScardEncKeySize +
            self.dwScardCredKeySize + 
            0x28
        )


class DPAPICredKeyBlob(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwBlobSize = data.eat("L")
        self.dwField4 = data.eat("L")
        self.dwCredKeyOffset = data.eat("L")
        self.dwCredKeySize = data.eat("L")
        self.Guid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")
        assert data.ofs == self.dwCredKeyOffset
        self.CredKey = data.eat_string(self.dwCredKeySize)


def decrypt_encrypted_AESKey2(
    aes_key_encrypted_2, aes_key_decrypted_1, IVKey1
) -> bytes:
    """
    Implement cryptngc!DecryptNgcData()
    Take as the AES key, the output of decrypt_encrypted_key1().
    Take as the IV, the IV specified in the EncKey blob
    Take as the input, the 0x30 EncryptedHeaderBlob.
    """
    return aes_decrypt(aes_key_encrypted_2, aes_key_decrypted_1, IVKey1)


def aes_decrypt(encrypted_data, key, iv) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data


def rsa_decrypt(
    bcrypt_rsa_key_obj: BcryptRsaKeyBlob, rsa_pub_key_cache: rsa.RSAPublicKey, ciphertext: bytes
) -> bytes:
    rsa_pub_key = bcrypt_rsa_key_obj.get_rsa_public_key()
    rsa_priv_key = bcrypt_rsa_key_obj.get_rsa_private_key()
    assert (
        len(ciphertext) == rsa_priv_key.key_size / 8
    ), "Ciphertext size does not match key size for RSA decrypt operation"

    # Check that the RSA public specified in the CacheData file matched
    # the one from Microsoft Software Key Storage Provider
    assert (
        rsa_pub_key_cache.public_numbers() == rsa_pub_key.public_numbers()
    ), "Public key found in CacheData does not match with provided private key"

    return rsa_priv_key.decrypt(ciphertext, padding.PKCS1v15())


def parse_cache_data(file_path) -> bytes:
    print(f'[+] Parsing CacheData file {file_path}')
    with open(file_path, "rb") as f:
        size_file = f.seek(0, os.SEEK_END)
        f.seek(0, os.SEEK_SET)
        # First 4 byte is a version number
        (version,) = struct.unpack("<I", f.read(4))
        print(f"[+] CacheData file version is 0x{version:x}")
        # 32 following bytes is the sha256 expected checksum
        sha256_checksum = f.read(32)
        # Compute checksum to check if matching
        payload = f.read(size_file - f.tell())
    m = hashlib.sha256()
    m.update(payload)
    print(f"[+] CacheData expected sha256: {binascii.hexlify(sha256_checksum)}")
    print(f"[+] CacheData computed sha256: {m.hexdigest()}")
    assert version == 0x02
    assert sha256_checksum == m.digest()
    return payload


def decrypt_cachedata_with_private_key(cache_data_file_path, rsa_priv_key_blob):
    payload = parse_cache_data(cache_data_file_path)
    
    if not rsa_priv_key_blob.startswith(b"RSA2"):
        raise Exception("Bad private key format")
    rsa_priv_key_obj = BcryptRsaKeyBlob(rsa_priv_key_blob)

    # From bcrypt.h -> #define 	BCRYPT_RSAPUBLIC_MAGIC   0x31415352
    rsa_public_magic_offset = payload.find(b"RSA1")
    if rsa_public_magic_offset == -1:
        raise Exception("Unable to find BCRYPT_RSAPUBLIC_MAGIC in CacheData file.")
    if rsa_public_magic_offset < 0x28:
        raise Exception("Unable to read SCardCacheData header in CacheData file.")
    
   
    keys_cache_node_offset = rsa_public_magic_offset - 0x28
    scard_blob = ScardCacheDataBlob(payload[keys_cache_node_offset:])

    rsa_pub_key = BcryptRsaKeyBlob(scard_blob.ScardCert).get_rsa_public_key()
    ngc_asym_key_blob = NgcAsymetricKeyEncryptedBlob(scard_blob.ScardEncKey)

    # The rsa_priv_key_obj (encrypted version) come from the file Crypto/Keys/1c7c0d0195a393b00297fb4a1bc6efc2_c2e570f7-a2b1-4483-b686-ab4ab03d6a70
    # Which as the key {1EB9AF77-CC62-4C28-A173-19267DD63045}
    # [+] Name     : //CA00CFA8-EB0F-42BA-A707-A3A43CDA5BD9
    # [+] Provider : Microsoft Software Key Storage Provider
    # [+] Key Name : {1EB9AF77-CC62-4C28-A173-19267DD63045}

    # RSA Decrypt #1
    print("[+] RSA decrypt encrypted AES key 1")
    decryptedAESKey1 = rsa_decrypt(rsa_priv_key_obj, rsa_pub_key, ngc_asym_key_blob.encryptedAESKey1)
    
    # AES Decrypt #1
    print("[+] AES decrypt encrypted AES key 2")
    decryptedAESkey2 = decrypt_encrypted_AESKey2(
        ngc_asym_key_blob.encryptedAESKey2, decryptedAESKey1, ngc_asym_key_blob.IV
    )
    # AES-256 bit key size
    decryptedAESkey2 = decryptedAESkey2[:0x20]  # skip padding

    encrypted_blob_offset = scard_blob.dwScardBlobSize + keys_cache_node_offset
    # Weird, one null byte between the scard blob and start of encrypted prt file
    # Try to a align on a dword boudnary...
    if encrypted_blob_offset % 4 != 0:
        encrypted_blob_offset = encrypted_blob_offset + (4 - (encrypted_blob_offset % 4))

    encrypted_blob_size = int.from_bytes(
        payload[encrypted_blob_offset : encrypted_blob_offset + 4], "little"
    )
    encrypted_blob_offset += 4  # skip size
    encrypted_blob = payload[
        encrypted_blob_offset : encrypted_blob_offset + encrypted_blob_size
    ]
    print(f"[+] AES decrypt encrypted blob of size 0x{encrypted_blob_size:x} (DPAPI CredKey + PRT)")
    # AES Decrypt #2
    decrypted_blob = aes_decrypt(encrypted_blob, decryptedAESkey2, scard_blob.ScardIV)
    # From cloudAP!UnlockCloudAPCacheNodeData
    version, flags, dword3, raw_dpapi_cred_key_size = struct.unpack("<IIII", decrypted_blob[0:0x10])
    assert version == 0x00
    dpapi_cred_key_blob = decrypted_blob[0x10:0x10+raw_dpapi_cred_key_size]
    dpapi_cred_key_blob_obj = DPAPICredKeyBlob(dpapi_cred_key_blob)
    
    print(f'[+] Dumping raw DPAPI Cred key, with GUID {dpapi_cred_key_blob_obj.Guid} (0x40 bytes):')
    hexdump.hexdump(dpapi_cred_key_blob_obj.CredKey)
    decrypted_prt = decrypted_blob[0x10+raw_dpapi_cred_key_size:]

    print("[+] Dumping decrypted PRT file:")
    prt_dict = json.loads(decrypted_prt)
    print(json.dumps(prt_dict, indent=4))
    print("\n")
