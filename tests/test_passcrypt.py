import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from authentication_qr_keeper.passcrypt import (
    SALTED,
    decrypt_file_bytes,
    encrypt_file_bytes,
    load_data_from_encrypted_file,
    save_data_to_encrypted_file,
)

PLAINTEXT = "some awesome string that we CAN TEST"
PASSWORD = "bobloblaw"


def test_encrypt_decrypt_roundtrip():
    encrypted = encrypt_file_bytes(PLAINTEXT.encode(), PASSWORD)
    decrypted = decrypt_file_bytes(encrypted, PASSWORD)
    assert decrypted.decode() == PLAINTEXT


def test_empty_plaintext_roundtrip():
    encrypted = encrypt_file_bytes(b"", PASSWORD)
    decrypted = decrypt_file_bytes(encrypted, PASSWORD)
    assert decrypted == b""


def test_binary_data_roundtrip():
    data = bytes(range(256))
    encrypted = encrypt_file_bytes(data, PASSWORD)
    decrypted = decrypt_file_bytes(encrypted, PASSWORD)
    assert decrypted == data


def test_encrypted_output_starts_with_salted_header():
    encrypted = encrypt_file_bytes(PLAINTEXT.encode(), PASSWORD)
    assert encrypted[: len(SALTED)] == SALTED.encode()


def test_two_encryptions_produce_different_ciphertext():
    # Each call generates a fresh random salt so output must differ
    enc1 = encrypt_file_bytes(PLAINTEXT.encode(), PASSWORD)
    enc2 = encrypt_file_bytes(PLAINTEXT.encode(), PASSWORD)
    assert enc1 != enc2


def test_wrong_password_does_not_recover_plaintext():
    encrypted = encrypt_file_bytes(PLAINTEXT.encode(), PASSWORD)
    decrypted = decrypt_file_bytes(encrypted, "wrong-password")
    assert decrypted != PLAINTEXT.encode()


def test_python_can_decrypt_python_encrypted_file():
    with TemporaryDirectory(prefix="passcrypt_") as tmpdir:
        encrypted_file = Path(tmpdir) / "encrypted"
        save_data_to_encrypted_file(str(encrypted_file), PLAINTEXT.encode(), PASSWORD)
        result = load_data_from_encrypted_file(str(encrypted_file), PASSWORD)
        assert result.decode() == PLAINTEXT


def test_openssl_can_decrypt_python_encrypted_file():
    with TemporaryDirectory(prefix="passcrypt_") as tmpdir:
        encrypted_file = Path(tmpdir) / "encrypted"
        save_data_to_encrypted_file(str(encrypted_file), PLAINTEXT.encode(), PASSWORD)
        result = subprocess.run(
            f'echo "{PASSWORD}" | openssl aes-256-cbc -d -pass stdin -pbkdf2 -iter 10000 -in {encrypted_file}',
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
        )
        assert result.returncode == 0
        assert result.stdout.decode() == PLAINTEXT


def test_python_can_decrypt_openssl_encrypted_file():
    with TemporaryDirectory(prefix="passcrypt_") as tmpdir:
        plaintext_file = Path(tmpdir) / "plaintext"
        plaintext_file.write_text(PLAINTEXT)

        encrypted_file = Path(tmpdir) / "encrypted"
        result = subprocess.run(
            f'echo "{PASSWORD}" | openssl aes-256-cbc -pass stdin -pbkdf2 -iter 10000 -salt -in {plaintext_file} -out {encrypted_file}',
            shell=True,
            check=False,
            capture_output=True,
        )
        assert result.returncode == 0

        decrypted = load_data_from_encrypted_file(str(encrypted_file), PASSWORD)
        assert decrypted.decode() == PLAINTEXT
