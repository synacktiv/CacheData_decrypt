from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from scripts.parse_cachedata import parse_cache_data
from scripts.decrypt_cachedata_pin import NgcAsymetricKeyEncryptedBlob, ScardCacheDataBlob, parse_pin_crypto_blob, parse_scard_crypto_blob
import hexdump

def dump_cache_data(file_path):
    cache_data_node_list = parse_cache_data(file_path)
    print('[+] Dumping entries from CacheData')
    for entry in cache_data_node_list:
        try:
            if entry.is_node_type_password():
                print('[+] CacheData node of type password (0x1) has been found')
                print('Dumping cryptoBlob')
                hexdump.hexdump(entry.cryptoBlob)
                print('\n')
            elif entry.is_node_type_pin():
                print('[+] CacheData node of type PIN (0x5) has been found')
                scard_blob : ScardCacheDataBlob = None
                rsa_pub_key: rsa.RSAPublicKey = None
                ngc_asym_key_blob : NgcAsymetricKeyEncryptedBlob = None
                scard_blob, rsa_pub_key, ngc_asym_key_blob = parse_pin_crypto_blob(entry.cryptoBlob)
                print('[+] Dumping ScardCacheDataBlob from cryptoBlob')
                print(scard_blob)
                print('[+] Dumping NgcAsymetricKeyEncryptedBlob')
                print(ngc_asym_key_blob)
                print('\n')
            elif entry.is_node_type_scard():
                print('[+] CacheData node of type Scard (0x4) has been found')
                scard_blob : ScardCacheDataBlob = None
                x509_cert : x509.Certificate = None
                scard_enc_key : bytes = None
                scard_blob, x509_cert, scard_enc_key  = parse_scard_crypto_blob(entry.cryptoBlob)
                print('[+] Dumping ScardCacheDataBlob from cryptoBlob')
                print(scard_blob)
                cert_val = x509_cert.public_bytes(serialization.Encoding.PEM)
                print('[+] Dumping x509 cert (Microsoft Smartcard Login)')
                print(str(cert_val, 'us-ascii'))
                print('\n')
                # TODO: dump scard_enc_key once format is supported
            else:
                print(f'[+] CacheData node of type (0x{entry.get_node_type():x}) is not supported\n')
        except Exception as e:
            print('[-] Error when trying to parse entry: ' + str(e))
