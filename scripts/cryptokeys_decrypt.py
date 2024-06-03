import os, hashlib
from dpapick3 import blob, masterkey, registry
#from dpapick3.probes.certificate import PrivateKeyBlob, BcryptPrivateKeyBlob
from scripts import parser_data

def cryptokeys_decrypt(arguments, protector, bf) -> bytes:
    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(arguments.security, arguments.system)
    dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(arguments.masterkeydir)
    mkp.addSystemCredential(dpapi_system)
    #decrn = mkp.try_credential_hash(None, None)
    mkp.try_credential_hash(None, None)
    
    for root, _, files in os.walk(arguments.keys):
        for sFile in files:
            filepath = os.path.join(root, sFile)
            with open(filepath, 'rb') as f:
                file_data = f.read()
                sInfo, arrFieldData = parser_data.parseFile(file_data)
                blobPrivateKeyProperties = arrFieldData[1]
                pkpBlob = blob.DPAPIBlob(blobPrivateKeyProperties)
                mks = mkp.getMasterKeys(pkpBlob.mkguid.encode())
                for mk in mks:
                    if mk.decrypted:
                        pkpBlob.decrypt(mk.get_key(), entropy = b'6jnkd5J3ZdQDtrsu\x00')
                        if pkpBlob.decrypted:
                            arrPrivateKeyProperties = parser_data.parsePrivateKeyProperties(pkpBlob.cleartext.hex())
                
                blobPrivateKey = arrFieldData[2]
                pkBlob = blob.DPAPIBlob(blobPrivateKey)
                mks = mkp.getMasterKeys(pkBlob.mkguid.encode())
                for mk in mks:
                    if sInfo == protector:
                        if mk.decrypted:
                            pkBlob.decrypt(mk.get_key(), entropy = b'xT5rZW5qVVbrvpuA\x00', strongPassword=None)
                            if pkBlob.decrypted:
                                print('[+] Private Key decrypted : ')
                                print('    ' + pkBlob.cleartext.hex())
                            else:
                                for sProperty in arrPrivateKeyProperties:
                                    if sProperty['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Salt': sSalt = sProperty['Value'].hex()
                                    elif sProperty['Name'].decode('UTF-16LE',errors='ignore') == 'NgcSoftwareKeyPbkdf2Round': iRounds = int(parser_data.reverseByte(sProperty['Value']).hex(),16)
                                (pkResult, sPIN) = brutePIN(arguments, mk, pkBlob, sSalt, iRounds, bf)
                                if pkResult and pkResult.decrypted:
                                    if arguments.verbose:
                                        print('[+] Private Key decrypted: ' + pkBlob.cleartext.hex())
                                    return pkBlob.cleartext
                                else:
                                    if sPIN:
                                        print('[-] Decryption with PIN tried but failed')
                                    else:
                                        print('[-] Entropy unknown for ' + pkBlob.description.decode())
                                    return None

def decryptWithPIN(mk, pkBlob, sSalt, iRounds, sPIN) -> bytes:
        sHexPIN = ''
        if not len(sPIN) == 64:
            sHexPIN = sPIN.encode().hex().upper().encode('UTF-16LE').hex()
        else:
            sHexPIN = sPIN.upper().encode('UTF-16LE').hex()
        bPIN = hashlib.pbkdf2_hmac('sha256', bytes.fromhex(sHexPIN), bytes.fromhex(sSalt), iRounds).hex().upper().encode('UTF-16LE')
        bPIN = hashlib.sha512(bPIN).digest()
        pkBlob.decrypt(mk.get_key(), entropy = b'xT5rZW5qVVbrvpuA\x00', smartCardSecret = bPIN)
        return pkBlob

                                
def brutePIN(arguments, mk, pkBlob, sSalt, iRounds, bf):
    for PIN in arguments.pins:
        if arguments.verbose:
            print("Trying: " + PIN + "\n")
        pkResult = decryptWithPIN(mk, pkBlob, sSalt, iRounds, PIN)
        if pkResult.decrypted:
            if bf:
                print('\n[+] Found PIN: ' + PIN)
            return (pkResult, PIN)
    return (pkBlob, '')
