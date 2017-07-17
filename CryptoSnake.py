#!/usr/bin/env python
# -*- coding: utf-8 -*-


###
# This script uses PyCrypto, a module developed by Dwayne C. Litzenberger
# The module is released under the Public Domain license
# You can find the homepage here: http://www.pycrypto.org/
###

###
# This script uses a python implementation of PBKDF2, a module developed by Dwayne C. Litzenberger
# This module does not include a license
# You can find the homepage here: http://www.dlitz.net/software/python-pbkdf2/
###

###
# This script uses a base64 module, developed by the Python Foundation as a standard library
# You can find the homepage here: https://docs.python.org/2/library/base64.html
###

###
# THOUGHTS:
# add file manipulation (read from, print to, encrypt)
# give user the option to not use IV (specify in new_cipher object)
# with an invalid key, binary is outputted
###

###
# INFORMATION:
# This script takes the primitives supplied by pycrypto to perform cryptographic functions
# The script uses AES (Rijndael) operating ins CBC mode with key sizes of 128, 192 (AES Specification), and 256
#
# This script has the following exit codes:
# 0 = Script exited without error
# 1 = Script exited with ImportError, is pycrypto installed?
# 2 = Script was passed an invalid mode, there are only two options [y/n]
# 3 = Script exited with TypeError, was a valid randomly generated base64 key supplied?
# 4 = Script exited with TypeError, was a valid base64 Initialization Vector supplied?
# 5 = Script was passed an invalid mode, did you misspell "Encrypt" or "Decrypt" ?
# 
###



# This has to be initialized, even if the user has all of the modules
insecOK = False


try:

    # import Rijndael
    from Crypto.Cipher import *
   
    # import SHA256
    from Crypto.Hash import SHA256
    
    # import CSPRNG for optional keygen
    from Crypto.Random import get_random_bytes
   
    # import base64
    import base64
    
    from sys import exit
    
    import time

except ImportError:
    
    #if the user doesn't have pycrypto
    print "You do not have PyCrypto"
    print "Run \"$ pip install pycrypto\" to install it"
    
    exit(1)
    
try:

    #import Password Based Key Derivation Function
    from pbkdf2 import PBKDF2

except ImportError:

    # make the abscence of PBKDF2 run the script in SHA256 mode (!less secure!)

    print "You do not have PKDF2 required for secure password derivation\nUse less secure SHA256 derivation mode?\n"

    insecOK = raw_input(">>>")
    insecOK = insecOK.upper()

    if insecOK[0] == "Y":
        insecOK = True

    else: insecOK = False

    if not insecOK: print "You will not be able to use a user-supplied passphrase"

verboseBool = False
securityBool = False
debugBool = False

def verbose(message):
    if verboseBool:
        time.sleep(.1)
        print '\033[92m' + "\n[VERBOSE] " +'\033[0m' + message
        print ""
        time.sleep(.1)
    
def security(message):
    if securityBool:
        time.sleep(.1)
        print '\033[95m' +"\n[SECURITY] " +'\033[0m' + message
        print ""
        time.sleep(.1)

def debug(message):
    if debugBool:
        time.sleep(.1)
        print '\033[93m' +"\n[DEBUG] " +'\033[0m' + message
        print ""
        time.sleep(.1)
    
def rollCall():
    verbose("Enabled")
    security("Enabled")
    debug("Enabled")

# get this out of the way...
salt = get_random_bytes(8)

class Encryption(object):
    def key(self):

        global SHA256
        global key
        global keyLen
        
        verbose("asking for a key")
        print("You will now be prompted to enter a key")
        print("To use a random key, type '128', '192', or  '256', specifying key length")
        security("A longer key is more secure, and random keys are more secure than user-supplied keys, but harder to remember")
        key = raw_input(">>>")
        keyLen = len(key)
        key = str.encode(key)
        if keyLen > 0 and key != "128" and key != "192" and key != "256":
        
        
            if insecOK:
                security("insecure mode (SHA256) is enabled)")
                # we'll use the user supplied key, Hashed
                SHA256 = SHA256.new()
                SHA256.update(key)
                key = SHA256.digest()

            else:
            
                security("using PKDF2")
                key = PBKDF2(key, salt).read(32)

        elif key == "128":
            # we're working with bytes for random generation
            debug("generating 16 random bytes")
            key = get_random_bytes(16)

        elif key == "192":
            # we're working with bytes for random generation
            debug("generating 24 random bytes")
            key = get_random_bytes(24)

        elif key == "256":
            # we're working with bytes for random generation
            byteConverted = 256 / 8
            debug("generating 32 random bytes")
            key = get_random_bytes(32)

    def encrypt(self):

        global encryptedMessage
        global initVector

        print("You will now be prompted to enter a message to encrypt")
        message = raw_input(">>>")
       
        # pad the message to multiple of 16 for AES
        isMod16=False
        messageLen = 1

        while not isMod16:

            if messageLen%16==0:
     
                isMod16=True
                debug("done")
            else:
                message = message.rjust(messageLen+1," ")
                messageLen=len(message)
                debug("rjusting")
        message = str.encode(message)
        verbose("Getting random bytes")
        initVector = get_random_bytes(16)
        new_cipher = AES.new(key, AES.MODE_CBC, initVector)

        # actually encrypt
        verbose("Encrypting")
        encryptedMessage = str(new_cipher.encrypt(message))

        return encryptedMessage
        return initVector

    def printCiphertext(self):

        # print AES enciphered string
        # maybe give the user the option to avoid base64?
        encryptedB64 = base64.b64encode(encryptedMessage)

        print "Ciphertext:", encryptedB64

        keyB64 = base64.b64encode(key)
        print "Key: ", keyB64

        initVectorB64 = base64.b64encode(initVector)
        print "IV: ", initVectorB64
        
        saltB64 = base64.b64encode(salt)
        if keyLen > 0 and key != "128" and key != "192" and key != "256" and not insecOK:
            print "PBKDF2 Salt: ",saltB64


class Decryption(object):
    def keyIntake(self):

        try:
            global key

            print "Was a randomly generated key used?"
            keyUsed = raw_input(">>>")
            keyUsedUpper = keyUsed.upper()

            if keyUsedUpper[0] == "Y":

                print "Enter the base64 key given:"
                base64key = raw_input(">>>")
                key = base64.b64decode(base64key)

            elif keyUsedUpper[0] == "N":

                print "Enter the key used:"
                key = raw_input(">>>")
                
                print "Enter the PBKDF2 Salt:"
                SaltHash= raw_input(">>>")
                
                salt = base64.b64decode(SaltHash)
                
                key = PBKDF2(key, salt).read(32)
                

            else:
                    print "Invalid option"

                    exit(2)
        except TypeError:

            print "Invalid key"
            raise TypeError("Invalid Base64")
            exit(3)

    def initVectorIntake(self):

        try:

            global initVector

            print "Input the Initialization Vector (IV):"
            initVector = raw_input(">>>")
            
            verbose("Decoding base64")
            initVector = base64.b64decode(initVector)

        except TypeError:

                print("Invalid Base64 input, this is not an IV")
                exit(4)

    def decrypt(self):

        global plaintext

        print "Enter the ciphertext"
        ciphertext = raw_input(">>>")
        # if this doesn't decode, the user supplied the wrong key
        
        verbose("decoding base64 ciphertext")
        ciphertext = base64.b64decode(ciphertext)
        
        new_cipher = AES.new(key, AES.MODE_CBC, initVector)

        plaintext = new_cipher.decrypt(ciphertext)

    def printPlaintext(self):

        print plaintext

print "Running with any parameters [verbose / security / debug]?"

parameters = raw_input(">>>")
parametersUpper = parameters.upper()

for i in parametersUpper:

    if i == "V" : 
        verboseBool = True
    if i == "Y": 
        securityBool = True
    if i == "D": 
        debugBool = True   

rollCall()

print("Are you encrypting or decrypting?")
encOrDec = raw_input(">>>")
encOrDecUpper = encOrDec.upper()

try:

    if encOrDecUpper[0] == "E":

    
        encObj = Encryption()

        encObj.key()
        encObj.encrypt()
        encObj.printCiphertext()

    elif encOrDecUpper[0] == "D":
    
    
        decObj = Decryption()

        decObj.keyIntake()
        decObj.initVectorIntake()
        decObj.decrypt()
        decObj.printPlaintext()
    else:
        print "Invalid option"
        exit(5)
except IndexError:
    print "Invalid input\nexiting..."
    exit(5)
