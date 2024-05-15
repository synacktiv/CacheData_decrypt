import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5



def fileToList(fileName):
   lineList = []
   try:
      fileParser = open(fileName, 'r')

   except IOError:
      print(" Error opening file : " + fileName)

   except:
      print(" Error accessing file : " + fileName)


   for line in fileParser.readlines():
      newLine = line.replace('\n', '')
      lineList.append(newLine)

   return lineList

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseProtectors(sPath, verbose):
    arrProtectors = []
    for protector in os.listdir(sPath):
        arrProtector = []
        arrProtector.append(protector)
        with open(os.path.join(sPath, protector, '1.dat'), 'rb') as f: 
            arrProtector.append(f.read().decode('utf16').strip('\x00'))
        try:
            with open(os.path.join(sPath, protector, '2.dat'), 'rb') as f: 
                arrProtector.append(f.read().decode('utf16').strip('\x00'))
        except:
            arrProtector.append('')
            print('[-] Protector is being stored in the TPM chip.')
        arrProtectors.append(arrProtector)
        with open(os.path.join(sPath, protector, '15.dat'), 'rb') as f: arrProtector.append(f.read())

        if verbose:
            print('[+] Provider  : ' + arrProtector[1])
            print('[+] Key Name  : ' + arrProtector[2])
    return arrProtectors

def parseItems(sPath, verbose):
    arrHeadItems = []
    for sFolder in os.listdir(sPath):
        if not sFolder.startswith('{'): continue
        if len(os.listdir(os.path.join(sPath, sFolder))) <= 1: continue
        arrHeadItems.append(sFolder)
        if verbose: print('= ' + sFolder + ' =')
        for sSubFolder in os.listdir(os.path.join(sPath, sFolder)):
            if sSubFolder.startswith('{'): continue
            ## filename, name, provider, keyname
            arrSubItems = []
            arrSubItems.append(sSubFolder)
            with open(os.path.join(sPath, sFolder, sSubFolder, '1.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '2.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '3.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            arrHeadItems.append(arrSubItems)
            if verbose:
                print('* ' + arrSubItems[0])
                print('[+] Name     : ' + arrSubItems[1])
                print('[+] Provider : ' + arrSubItems[2])
                print('[+] Key Name : ' + arrSubItems[3])
                print('')
    return arrHeadItems


def extract_NGC_data(arguments):
    try:
        GUIDs = os.listdir(arguments.NGC)
    except:
        print('Failed. On a live system, are you running as SYSTEM? To extract the NGC folder: xcopy C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\\ C:\\Users\\Public /H /E /G /C')
        exit(1)

    for GUID in GUIDs:
        with open(os.path.join(arguments.NGC, GUID, '1.dat'), 'rb') as f: 
            sUserSID = f.read().decode('utf16').strip('\x00')
        if arguments.sid and arguments.sid != sUserSID:
            continue
        if arguments.verbose:
            print('\n[+] NGC GUID      : ' + GUID)
            with open(os.path.join(arguments.NGC, GUID, '1.dat'), 'rb') as f: 
                sUserSID = f.read().decode('utf16')
            print('[+] User SID      : ' + sUserSID)
        with open(os.path.join(arguments.NGC, GUID, '7.dat'), 'rb') as f: 
            sMainProvider = f.read().decode('utf16')

        if arguments.verbose:
            print('\n[+] Main Provider : ' + sMainProvider)
        arrProtectors = parseProtectors(os.path.join(arguments.NGC, GUID, 'Protectors'), arguments.verbose)
        arrItems = parseItems(os.path.join(arguments.NGC, GUID), arguments.verbose)
        return arrProtectors, arrItems

def parseFile(bData, boolVerbose = False):
    iType = int(reverseByte(bData[:4]).hex(), 16) ## followed by 4 bytes unknown
    iDescrLen = int(reverseByte(bData[8:12]).hex(), 16) ## followed by 2 bytes unknown
    iNumberOfFields = int(reverseByte(bData[14:16]).hex(), 16) ## followed by 2 bytes unknown
    sDescription = bData[44:44+iDescrLen].decode('UTF-16LE',errors='ignore')
    if boolVerbose: print('[+] File Descriptor : ' + sDescription)
    bRemainder = bData[44+iDescrLen:] ## Start of the data fields
    arrFieldData = []
    for i in range(0,iNumberOfFields):
        iFieldLen = int(reverseByte(bData[16+(4*i):16+(4*i)+4]).hex(), 16)
        bField = bRemainder[:iFieldLen]
        arrFieldData.append(bField)
        bRemainder = bRemainder[iFieldLen:]
    return (sDescription, arrFieldData)


def parsePrivateKeyProperties(hPKP, boolVerbose = False):
    def parseProperty(bProperty, boolVerbose = False):
        bStructLen = bProperty[:4]
        iType = int(reverseByte(bProperty[4:8]).hex(), 16)
        bUnk = bProperty[8:12]
        iNameLength = int(reverseByte(bProperty[12:16]).hex(), 16)
        iPropLength = int(reverseByte(bProperty[16:20]).hex(), 16)
        bName = bProperty[20:(20+iNameLength)]
        bProperty = bProperty[(20+iNameLength):(20+iNameLength+iPropLength)]
        if boolVerbose:
            print('Name  : ' + bName.decode('UTF-16LE',errors='ignore'))
            print('Value : ' + bProperty.hex())
        return {'Name':bName, 'Value':bProperty}
        
    bRest = bytes.fromhex(hPKP)
    arrProperties = []
    while not bRest == b'':
        iSize = int(reverseByte(bRest[:4]).hex(), 16)
        bProperty = bRest[:iSize]
        bRest = bRest[iSize:]
        arrProperties.append(parseProperty(bProperty))
    return arrProperties

def constructRSAKEY(sDATA, verbose):
    def calcPrivateKey(e,p,q):
        def recurseFunction(a,b):
            if b==0:return (1,0)
            (q,r) = (a//b,a%b)
            (s,t) = recurseFunction(b,r)
            return (t, s-(q*t))
        t = (p-1)*(q-1) ## Euler's totient
        inv = recurseFunction(e,t)[0]
        if inv < 1: inv += t
        return inv

## Parsing based on: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
    bDATA = bytes.fromhex(sDATA)
    if not bDATA[:4] == b'RSA2': exit('[-] Error: not an RSA key!')
    iBitlen = int(reverseByte(bDATA[4:8]).hex().encode(),16)
    iPubExpLen = int(reverseByte(bDATA[8:12]).hex().encode(),16)
    iModulusLen = int(reverseByte(bDATA[12:16]).hex().encode(),16)
    iPLen = int(reverseByte(bDATA[16:20]).hex().encode(),16)
    iQLen = int(reverseByte(bDATA[20:24]).hex().encode(),16)
    iOffset = 24
    iPubExp = int(reverseByte(bDATA[iOffset:iOffset+iPubExpLen]).hex().encode(),16)
    iOffset += iPubExpLen
    iModulus = int(bDATA[iOffset:iOffset+iModulusLen].hex().encode(),16)
    iOffset += iModulusLen
    iP = int(bDATA[iOffset:iOffset+iPLen].hex().encode(),16)
    iOffset += iPLen
    iQ = int(bDATA[iOffset:iOffset+iQLen].hex().encode(),16)
    if verbose:
        print('[!] BitLength      : ' + str(iBitlen) + ' bit')
        print('[!] Modulus Length : ' + str(iModulusLen) + ' bytes')
        print('[!] Prime Lengths  : ' + str(iPLen) + ' bytes')
    if not iModulus == iP*iQ: exit('[-] Prime numbers do not currespond to the public key')
    iPrivateKey = calcPrivateKey(iPubExp, iP, iQ)
    try: oRSAKEY = RSA.construct((iModulus,iPubExp,iPrivateKey,iP,iQ)) ## oRSAKEY = RSA.construct((n,e,d,p,q))
    except: exit('[-] Error constructing RSA Key')
    return oRSAKEY


def parseDecryptPin(bData, verbose):
    if len(bData)<(32*3): exit('[-] Decrypted data not long enough')
    bUnkPin = bData[-(32*3):-(32*2)]
    bDecryptPin = bData[-(32*2):-32]
    bSignPin = bData[-32:]
    if verbose:
        print('Unknown PIN : ' + bUnkPin.hex())
        print('Decrypt PIN : ' + bDecryptPin.hex())
        print('Sign PIN    : ' + bSignPin.hex())
    return bDecryptPin


def extract_decryptPin(key, bInputData, verbose):
    oRSAKEY = constructRSAKEY(key.hex(), verbose)
    oCipher = PKCS1_v1_5.new(oRSAKEY)
    try: bClearText = oCipher.decrypt(bInputData, b'')
    except: exit('[-] Error decrypting the inputdata')
    bDecryptPin = parseDecryptPin(bClearText, verbose)
    if verbose:
        print('[+] Got DecryptPIN : ' + bDecryptPin.hex().upper())
    return bDecryptPin