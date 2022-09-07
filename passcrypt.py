#!/usr/bin/env python3

'''
The purpose of this module is to provide python encryption and decryption functions
that are compatible with the openssl commands below:

encryption by openssl:
    openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in /path/to/unencrypted/input/file -out /path/to/encrypted/output/file

decryption by openssl:
    openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in /path/to/encrypted/input/file -out /path/to/decrypted/output/file
'''

import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from typing import (
    Optional,
    Tuple,
)
# test imports
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess

BS = AES.block_size
PBKDF2_ITERATIONS = 10000
# This is the string found right at the start of an openssl encrypted file
SALTED = 'Salted__'


def _pad(s: bytes) -> bytes:
    '''
    The length of the data to be encrypted needs to be a multiple of AES.block_size.

    NOTE: the padding bytes are each set to the actual number of pad bytes.
    The requirement is that only the last byte needs to be set to that
    but it's easier to just write them all with the same value.
    '''
    # pad_bytes_count can never be 0 as the number of padding bytes always needs to be written.
    # The calculation of pad_len below always produces a result from 1 to BS inclusive
    pad_bytes_count = BS - (len(s) % BS)
    return s + (pad_bytes_count.to_bytes(1, byteorder='big') * pad_bytes_count)


def _unpad(s: bytes) -> bytes:
    pad_bytes_count = s[-1]
    return s[:-pad_bytes_count]


def get_key_iv(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
    # if decrypting you should have provided the 'salt' parameter
    if not salt:
        salt = Random.new().read(BS - len(SALTED))

    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, 48)
    key = derived_key[0:32]
    iv = derived_key[32:48]
    return key, iv, salt


def encrypt_file_bytes(plaintext: bytes, password: str, salt: Optional[bytes] = None) -> bytes:
    plaintext = _pad(plaintext)
    key, iv, salt = get_key_iv(password, salt)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = encryptor.encrypt(plaintext)

    # Return the bytes that the openssl command would write to a file
    return SALTED.encode('utf-8') + salt + ciphertext


def decrypt_file_bytes(ciphertext: bytes, password: str) -> bytes:
    # Decode/decrypt the bytes as if they came from a file encrypted with the openssl command
    salt = ciphertext[len(SALTED):16]
    ciphertext = ciphertext[16:]

    key, iv, _ = get_key_iv(password, salt)
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(ciphertext)
    return _unpad(plaintext)


def save_data_to_encrypted_file(output_file: str, plaintext: bytes, password: str, salt: Optional[bytes] = None) -> None:
    '''
    Saves a set of unencrypted bytes to an encrypted file.
    '''
    encrypted_data = encrypt_file_bytes(plaintext, password, salt)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)


def load_data_from_encrypted_file(input_file: str, password: str) -> bytes:
    '''
    Loads a set of decrypted bytes from an encrypted file.
    '''
    with open(input_file, 'rb') as f:
        ciphertext_data = f.read()
    return decrypt_file_bytes(ciphertext_data, password)


if __name__ == '__main__':
    # TODO: moves tests to run in pytest under a 'tests' directory
    plaintext = "some awesome string that we CAN TEST"
    password = "bobloblaw"

    encrypted_bytes = encrypt_file_bytes(plaintext.encode(), password)
    decrypted_bytes = decrypt_file_bytes(encrypted_bytes, password)
    assert decrypted_bytes.decode() == plaintext

    # Test python can decrypt python encrypted file
    # Test openssl can decrypt python encrypted file
    # Test python can decrypt openssl encrypted file
    with TemporaryDirectory(prefix="passcrypt_") as tmpdir:
        # write encrypted data to a file
        plaintext_file = Path(tmpdir) / 'plaintext_file'
        with open(str(plaintext_file), 'w') as f:
            f.write(plaintext)

        python_encrypted_file = Path(tmpdir) / 'python_encrypted_file'
        save_data_to_encrypted_file(str(python_encrypted_file), plaintext.encode(), password)

        # confirm openssl can decrypt the file
        result1 = subprocess.run(
            f'echo "{password}" | openssl aes-256-cbc -d -pass stdin -pbkdf2 -iter 10000 -in {str(python_encrypted_file)}',
            shell=True, check=False, stdout=subprocess.PIPE,
        )

        # decrypt our encrypted file using the helper function
        python_decrypted_file_bytes = load_data_from_encrypted_file(str(python_encrypted_file), password)

        # create encrypted file using openssl and decrypt in python
        openssl_encrypted_file = Path(tmpdir) / 'openssl_encrypted_file'
        result2 = subprocess.run(
            f'echo "{password}" | openssl aes-256-cbc -pass stdin -pbkdf2 -iter 10000 -salt -in {str(plaintext_file)} -out {str(openssl_encrypted_file)}',
            shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        assert result2.returncode == 0
        python_decrypted_file_bytes2 = load_data_from_encrypted_file(str(openssl_encrypted_file), password)

    # make assertions about the decrypted data
    assert python_decrypted_file_bytes.decode() == plaintext
    assert result1.returncode == 0
    assert result1.stdout.decode() == plaintext
    assert python_decrypted_file_bytes2.decode() == plaintext