#!/usr/bin/env python3

"""
This is just a proof of concept to read a file encrypted by openssl aes-256-cbc
from the bash command line.

The reason for this is that the file needs to be decrypted, edited and re-encrypted
in bash. The file is then decrypted and used python script.

The code below can decrypt a file encrypted with the command:
    openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in /path/to/unencrypted/source/file -out /path/to/encrypted/output/file

The code here came from one of the answers on this Stack Overflow page:
    https://stackoverflow.com/questions/16761458/how-to-decrypt-openssl-aes-encrypted-files-in-python
"""

import hashlib
from getpass import getpass
from Crypto.Cipher import AES

infile = "./encrypted"
password = getpass()
PBKDF2_ITERATIONS = 10000

with open(infile, "rb") as f:
    openssloutputbytes = f.read()

# The first 16 bytes of the file are the string 'Salted__XXXXXXXX'
# where 'XXXXXXXX' are the actual salt bytes
salt = openssloutputbytes[8:16]

derivedkey = hashlib.pbkdf2_hmac(
    "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, 48
)

key = derivedkey[0:32]
iv = derivedkey[32:48]

# the cipher text is the bytes after 'Salted__XXXXXXXX'
ciphertext = openssloutputbytes[16:]

decryptor = AES.new(key, AES.MODE_CBC, iv)
plaintext = decryptor.decrypt(ciphertext)

# the number of padding bytes is in the last byte of the decrypted ciphertext
num_pad_bytes = plaintext[-1]
plaintext = plaintext[:-num_pad_bytes]
print(plaintext.decode())
