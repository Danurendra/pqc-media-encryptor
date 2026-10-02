import hashlib
import os

from app.crypto.aes_baseline import (
    encrypt_file_aes,
    decrypt_file_aes,
)


def sha256_file(path):

    digest = hashlib.sha256()

    with open(path, "rb") as f:

        while True:

            data = f.read(
                1024 * 1024
            )

            if not data:
                break

            digest.update(data)

    return digest.hexdigest()


def main():

    input_path = (
        "data/test_1mb.bin"
    )

    encrypted_path = (
        "data/test_1mb_aes.pqcm"
    )

    recovered_path = (
        "data/test_1mb_aes_recovered.bin"
    )

    key = bytes(
        range(32)
    )

    chunk_size = (
        64 * 1024
    )

    print(
        "Testing AES-256-GCM baseline..."
    )

    encrypt_file_aes(
        input_path,
        encrypted_path,
        key,
        chunk_size,
    )

    decrypt_file_aes(
        encrypted_path,
        recovered_path,
        key,
    )

    original_hash = sha256_file(
        input_path
    )

    recovered_hash = sha256_file(
        recovered_path
    )

    print(
        f"Original SHA-256  : "
        f"{original_hash}"
    )

    print(
        f"Recovered SHA-256 : "
        f"{recovered_hash}"
    )

    print(
        f"Integrity         : "
        f"{original_hash == recovered_hash}"
    )

    assert (
        original_hash
        == recovered_hash
    )

    assert (
        os.path.getsize(input_path)
        == os.path.getsize(recovered_path)
    )

    print(
        "\nAES BASELINE TEST: PASS"
    )


if __name__ == "__main__":
    main()
