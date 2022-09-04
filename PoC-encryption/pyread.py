#!/usr/bin/env python3

'''
This is just a proof of concept to read a file encrypted by openssl aes-256-cbc
from the bash command line.

The reason for this is that the file needs to be decrypted, edited and re-encrypted
in bash. The file is then decrypted and used python script.

The code here came from one of the answers on this Stack Overflow page:
    https://stackoverflow.com/questions/16761458/how-to-decrypt-openssl-aes-encrypted-files-in-python
'''

import binascii
import base64
import hashlib
from getpass import getpass
from Crypto.Cipher import AES

infile = "./encrypted"
password = getpass()
pbkdf2iterations=10000

passwordbytes = password.encode('utf-8')

with open(infile, 'rb') as f:
    openssloutputbytes = f.read()

salt = openssloutputbytes[8:16]

derivedkey = hashlib.pbkdf2_hmac('sha256', passwordbytes, salt, pbkdf2iterations, 48)

key = derivedkey[0:32]
iv = derivedkey[32:48]

ciphertext = openssloutputbytes[16:]

decryptor = AES.new(key, AES.MODE_CBC, iv)
plaintext = decryptor.decrypt(ciphertext)

plaintext = plaintext[:-plaintext[-1]]
print(plaintext.decode())
