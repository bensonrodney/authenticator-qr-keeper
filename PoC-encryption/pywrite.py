#!/usr/bin/env python3
"""
This PoC will write out data to a file that can be decrypted with openssl from the cli
like so:

    openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in /path/to/encrypted/file

"""

import hashlib
from Crypto.Cipher import AES
from Crypto import Random

PBKDF2_ITERATIONS = 10000
bs = AES.block_size


def _pad(s: bytes) -> bytes:
    """
    The length of the data to be encrypted needs to be a multiple of AES.block_size.

    NOTE: the padding bytes are each set to the actual number of pad bytes.
    The requirement is that only the last byte needs to be set to that
    but it's easier to just write them all with the same value.
    """
    # pad_len can never be 0 as the number of padding bytes always needs to be written.
    # The calculation of pad_len below always produces a result from '1 to bs' inclusive
    pad_len = bs - (len(s) % bs)
    return s + (pad_len.to_bytes(1, byteorder="big") * pad_len)


def _unpad(s: bytes) -> bytes:
    """NOTE: not used but put here as a demonstration of how to do this"""
    pad_bytes_count = s[-1]
    return s[:-pad_bytes_count]


def encrypt(plaintext_bytes: bytes, password: str) -> bytes:
    """
    Returns bytes that look like:
        Salted__XXXXXXXXDDDDDDDD...P

    where:
        XXXXXXXX = salt
        DDDDDDDD... = encrypted data
        P = number of padding bytes
    """
    salt = Random.new().read(AES.block_size - len("Salted__"))
    derived_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS, 48
    )
    key = derived_key[0:32]
    iv = derived_key[32:48]

    plaintext_bytes = _pad(plaintext_bytes)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = encryptor.encrypt(plaintext_bytes)
    return "Salted__".encode() + salt + ciphertext


password = "some password"
plaintext = "0123456789abcdef0"

ciphertext = encrypt(plaintext.encode(), password)
with open("./pyencrypted", "wb") as f:
    f.write(ciphertext)

test_string = "some string"
assert _unpad(_pad(test_string.encode())).decode() == test_string
