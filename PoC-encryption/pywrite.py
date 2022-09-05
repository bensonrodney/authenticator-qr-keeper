#!/usr/bin/env python3
'''
This PoC will write out data to a file that can be decrypted with openssl from the cli
like so:

    openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in /path/to/encrypted/file

'''

import hashlib
from Crypto.Cipher import AES
from Crypto import Random

password = 'some password'
plaintext = "some \nrandom plaintext\ndata\n"

iterations = 10000
bs = AES.block_size


def _pad(s):
    '''
    The length of the data to be encrypted needs to be a multiple of AES.block_size.

    NOTE: the padding bytes are each set to the actual number of pad bytes.
    I think the requirement is that only the last byte needs to be set to that
    but it's easier to set them all to that.
    '''
    pad_len = bs - (len(s) % bs)
    return s + ((pad_len) * chr(pad_len))


salt = Random.new().read(AES.block_size - len('Salted__'))
derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, 48)
key = derived_key[0:32]
iv = derived_key[32:48]


plaintext_bytes = _pad(plaintext).encode()
encryptor = AES.new(key, AES.MODE_CBC, iv)

ciphertext = encryptor.encrypt(plaintext_bytes)

with open("./pyencrypted", 'wb') as f:
    f.write('Salted__'.encode() + salt)
    f.write(ciphertext)