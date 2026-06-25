"""
Python encryption/decryption functions compatible with openssl aes-256-cbc:

    encryption: openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in <infile> -out <outfile>
    decryption: openssl aes-256-cbc -d -pbkdf2 -iter 10000 -in <infile> -out <outfile>
"""

import hashlib
from typing import Optional, Tuple

from Crypto import Random
from Crypto.Cipher import AES

BS = AES.block_size
PBKDF2_ITERATIONS = 10000
SALTED = "Salted__"


def _pad(s: bytes) -> bytes:
    # pad_bytes_count is always 1..BS so there is always at least one padding byte
    pad_bytes_count = BS - (len(s) % BS)
    return s + (pad_bytes_count.to_bytes(1, byteorder="big") * pad_bytes_count)


def _unpad(s: bytes) -> bytes:
    pad_bytes_count = s[-1]
    return s[:-pad_bytes_count]


def get_key_iv(
    password: str, salt: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    if not salt:
        salt = Random.new().read(BS - len(SALTED))
    derived_key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PBKDF2_ITERATIONS, 48
    )
    key = derived_key[0:32]
    iv = derived_key[32:48]
    return key, iv, salt


def encrypt_file_bytes(
    plaintext: bytes, password: str, salt: Optional[bytes] = None
) -> bytes:
    plaintext = _pad(plaintext)
    key, iv, salt = get_key_iv(password, salt)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = encryptor.encrypt(plaintext)
    return SALTED.encode("utf-8") + salt + ciphertext


def decrypt_file_bytes(ciphertext: bytes, password: str) -> bytes:
    salt = ciphertext[len(SALTED):16]
    ciphertext = ciphertext[16:]
    key, iv, _ = get_key_iv(password, salt)
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    plaintext = decryptor.decrypt(ciphertext)
    return _unpad(plaintext)


def save_data_to_encrypted_file(
    output_file: str, plaintext: bytes, password: str, salt: Optional[bytes] = None
) -> None:
    encrypted_data = encrypt_file_bytes(plaintext, password, salt)
    with open(output_file, "wb") as f:
        f.write(encrypted_data)


def load_data_from_encrypted_file(input_file: str, password: str) -> bytes:
    with open(input_file, "rb") as f:
        ciphertext_data = f.read()
    return decrypt_file_bytes(ciphertext_data, password)
