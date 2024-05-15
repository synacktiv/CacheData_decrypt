# CacheData_decrypt
A simple Toolkit to BF and decrypt Windows EntraId CacheData

usage: decrypt_cachedata.py [-h] {pin,password} ...

CacheData bruteforcer. On a live windows host, to copy the folders with all subfolders and
files: xcopy <folder> <destination> /H /E /G /C as SYSTEM. The script will automatically
iterates on each Entra ID user who has logged in on the device. If you want to bruteforce the
PIN for only one user, use the --sid parameter.

positional arguments:
  {pin,password}  Available subparser (pin or password)
    pin           BF pin.
    password      BF password.

options:
  -h, --help      show this help message and exit
