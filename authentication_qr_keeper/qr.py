#!/usr/bin/env python3

"""
The purpose of this script is to reproduce Google Authenticator QR codes
from a list of accounts defined in a file '/home/$USER/.qrcodes`

A list of accounts is displayed and you select which code you want to view.

"""

import copy
import getpass
import hashlib
import io
import re
import shlex
import sys
from argparse import ArgumentParser
from datetime import datetime
from pathlib import Path
from shutil import copyfile
from subprocess import PIPE, Popen
from typing import Union
from urllib.parse import parse_qs, quote, unquote, urlparse

from Crypto import Random
from Crypto.Cipher import AES
from cv2 import QRCodeDetector, imread
from qrcode import QRCode

TYPE_TOTP = 'totp'
TYPE_HOTP = 'hotp'

# iterations when hashing the password
PBKDF2_ITERATIONS = 10000
bs = AES.block_size

src_file = Path("/home/{}/.qrcodes".format(getpass.getuser()))
leading_slashes = re.compile('^[/]{1,}')


def _pad(s: bytes) -> bytes:
    '''
    The length of the data to be encrypted needs to be a multiple of AES.block_size.

    NOTE: the padding bytes are each set to the actual number of pad bytes.
    The requirement is that only the last byte needs to be set to that
    but it's easier to just write them all with the same value.
    '''
    # pad_len can never be 0 as the number of padding bytes always needs to be written.
    # The calculation of pad_len below always produces a result from '1 to bs' inclusive
    pad_len = bs - (len(s) % bs)
    return s + (pad_len.to_bytes(1, byteorder='big') * pad_len)


def _unpad(s: bytes) -> bytes:
    ''' NOTE: not used but put here as a demonstration of how to do this
    '''
    pad_bytes_count = s[-1]
    return s[:-pad_bytes_count]


def encrypt(plaintext_bytes: bytes, password: str) -> bytes:
    '''
    Returns bytes that look like:
        Salted__XXXXXXXXDDDDDDDD...P

    where:
        XXXXXXXX = salt
        DDDDDDDD... = encrypted data
        P = number of padding bytes
    '''
    salt = Random.new().read(AES.block_size - len('Salted__'))
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS, 48)
    key = derived_key[0:32]
    iv = derived_key[32:48]


    padded_plaintext_bytes = _pad(plaintext_bytes)
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = encryptor.encrypt(padded_plaintext_bytes)
    return 'Salted__'.encode() + salt + ciphertext


def decrypt(encrypted_bytes: bytes, password: str) -> bytes:
    salt = encrypted_bytes[8:16]

    derivedkey = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS, 48)

    key = derivedkey[0:32]
    iv = derivedkey[32:48]
    ciphertext = encrypted_bytes[16:]
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = decryptor.decrypt(ciphertext)

    plaintext = _unpad(padded_plaintext)
    return plaintext


def read_and_decrypt_file(file, password):
    '''
    Returns a file-like stream object (in memory) which contains the decrypted
    file data.
    The file will have been encrypted in bash using the command below:

	echo "${password}" | openssl aes-256-cbc -pbkdf2 -iter 10000 -salt -in ${infile} -out ${outfile} -pass stdin

    '''

    with open(file, 'rb') as f:
        openssloutputbytes = f.read()

    plaintext = decrypt(openssloutputbytes, password)

    try:
        plaintext = plaintext.decode()
        return io.StringIO(plaintext)
    except UnicodeDecodeError:
        return None


def read_qr_code(image_file):
    '''
    Reads the value from a QR code image and returns the string or None if the image can't be decoded.
    '''
    try:
        img = imread(image_file)
        detector = QRCodeDetector()
        value, points, straight_qrcode = detector.detectAndDecode(img)
        return value
    except Exception as exc:
        msg = str(exc)
        print(msg)
        return None


class Code(object):
    def __init__(self, url):
        self._raw = url.strip()
        self._url = urlparse(self._raw)
        self._name = None

    def _get_name(self):
        if not self._name:
            self._name = leading_slashes.sub("", unquote(self._url.path))
        return copy.copy(self._name)
    name = property(_get_name)

    def __str__(self):
        return copy.copy(self._raw)

    def show_qr(self):
        code = QRCode()
        code.add_data(str(self))
        code.print_ascii()


def parse_file(src, password):
    '''
    Handy notes:
    With a full URL, you can do the following:
        url = urllib.parse.urlparse("otpauth://totp/Code%20Name?secret=123456789&issuer=Some%20Company")
        print(urllib.parse.unquote(url.path)[1:])
        print(urllib.parse.parse_qs(url.query))

    Produces:
        Code Name
        {'secret': ['123456789'], 'issuer': ['Some Company']}
    '''
    codes = []
    try:
        data_stream = read_and_decrypt_file(src, password)
        if not data_stream:
            return []
        lines = [l.strip() for l in data_stream.readlines()]
        codes = [Code(l) for l in lines if (len(l) > 0) and (l[0] != "#")]
        return codes
    except FileNotFoundError:
        return None


def select_and_print_code(codes):
    sel = None
    codes.sort(key=Code._get_name)
    while sel is None:
        print("\n\nSelect a code to view:\n\n")
        for i, c in enumerate(codes):
            print("    {:>2}) {}".format(i+1, c.name))
        try:
            try:
                selection = input("\n\nEnter selection: ")
            except KeyboardInterrupt:
                return 1

            sel = int(selection)
            if sel < 1 or sel > len(codes):
                print("Selection invalid!\n\n")
                sel = None
        except ValueError:
            print("Selection invalid!")
            sel = None
        except KeyboardInterrupt:
            print("\nAborted!\n\n")
            return 1
    print(codes[sel-1].name)
    codes[sel-1].show_qr()
    return 0


def do_show_codes() -> int:
    if not src_file.is_file():
        print('ERROR: source file not found. Exiting.')
        return 1

    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print()
        return 0

    codes = parse_file(str(src_file), password)
    if codes is None:
        print('ERROR! Couldn\'t parse source file.')
        return 1

    if len(codes) < 1:
        print('ERROR: No codes found in source file or the password is incorrect.')
        return 1

    choice_regex = re.compile(r'^([yY]|[yY][eE][sS]|)$')
    while True:
        try:
            if select_and_print_code(codes) != 0:
                print()
                break
            choice = input("Display another code? [Yn]: ")
            if not choice_regex.search(choice):
                break
        except KeyboardInterrupt:
            print()
            break

    return 0


def add_code_to_file(src, password, code):
    data_stream = read_and_decrypt_file(src, password)
    if not data_stream:
        raise RuntimeError('Failed to read source file')

    lines = [l.strip() for l in data_stream.readlines()]
    lines.append(code.strip())
    lines.append("")

    data = '\n'.join(lines)
    encrypted_data = encrypt(data.encode('utf-8'), password)

    # backup the original file before overwriting it
    now = datetime.now().strftime("%Y%m%d-%H%M%S")
    copyfile(src, f"{src}.backup.{now}")

    with open(src, 'wb') as outfile:
        outfile.write(encrypted_data)


def do_add_code(image_file_path: Union[str, Path]) -> int:
    if not isinstance(image_file_path, Path):
        image_file_path = Path(image_file_path)

    if not image_file_path.is_file():
        print(f"ERROR: file not found - '{image_file_path}'")
        return 1

    data = read_qr_code(str(image_file_path))
    if not data:
        print(f"ERROR: error reading QR code or no data within the QR code.")
        return 1

    print(f"#### {data}")

    if not src_file.is_file():
        print('ERROR: source file not found. Exiting.')
        return 1

    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print()
        return 0

    try:
        add_code_to_file(str(src_file), password, data)
    except:
        print("ERROR: failed to add code to file")
        return 1

    return 0


def main():
    parser = ArgumentParser()
    parser.add_argument('-a', '--add', metavar="IMAGE_FILE_PATH", default=None,
        help='Add new qrcode from a qrcode image.')
    args = parser.parse_args()

    if args.add:
        return do_add_code(args.add)

    return do_show_codes()


if __name__ == '__main__':
    sys.exit(main())

