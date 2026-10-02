import os
import hashlib

from app.crypto.file_cipher import (
    encrypt_file,
    decrypt_file,
)


ORIGINAL = "data/test_1mb.bin"
ENCRYPTED = "data/test_1mb.bin.pqcm"
RECOVERED = "data/test_1mb.recovered.bin"


def sha256_file(path):
    sha = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            block = f.read(1024 * 1024)

            if not block:
                break

            sha.update(block)

    return sha.hexdigest()


def main():
    print("=" * 60)
    print("Hybrid File Encryption Test")
    print("=" * 60)

    seed = os.urandom(64)

    print("\nEncrypting file...")

    encrypt_file(
        ORIGINAL,
        ENCRYPTED,
        seed,
    )

    print("Encryption: PASS")

    print("\nDecrypting file...")

    decrypt_file(
        ENCRYPTED,
        RECOVERED,
        seed,
    )

    print("Decryption: PASS")

    original_hash = sha256_file(
        ORIGINAL
    )

    recovered_hash = sha256_file(
        RECOVERED
    )

    print()
    print(f"Original SHA-256 : {original_hash}")
    print(f"Recovered SHA-256: {recovered_hash}")

    assert original_hash == recovered_hash

    print("Integrity         : MATCH")

    print()
    print(f"Original size     : {os.path.getsize(ORIGINAL)} bytes")
    print(f"Encrypted size    : {os.path.getsize(ENCRYPTED)} bytes")
    print(f"Recovered size    : {os.path.getsize(RECOVERED)} bytes")

    print()
    print("=" * 60)
    print("REAL FILE ENCRYPTION TEST: PASS")
    print("=" * 60)


if __name__ == "__main__":
    main()
