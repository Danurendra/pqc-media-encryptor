import hashlib
import os

from app.crypto.stream_cipher import (
    decrypt_file_streaming,
)


def sha256_file(path: str) -> str:

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

    encrypted_path = (
        "data/test_1mb_stream.pqcm"
    )

    recovered_path = (
        "data/test_1mb_stream_recovered.bin"
    )

    original_path = (
        "data/test_1mb.bin"
    )

    seed = bytes(
        range(64)
    )

    print(
        "Testing streaming decryption..."
    )

    decrypt_file_streaming(
        input_path=encrypted_path,
        output_path=recovered_path,
        seed=seed,
    )

    original_hash = sha256_file(
        original_path
    )

    recovered_hash = sha256_file(
        recovered_path
    )

    original_size = os.path.getsize(
        original_path
    )

    recovered_size = os.path.getsize(
        recovered_path
    )

    print(
        f"Original size     : "
        f"{original_size} bytes"
    )

    print(
        f"Recovered size    : "
        f"{recovered_size} bytes"
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
        original_size
        == recovered_size
    )

    assert (
        original_hash
        == recovered_hash
    )

    print(
        "\nSTREAM DECRYPTION TEST: PASS"
    )


if __name__ == "__main__":
    main()
