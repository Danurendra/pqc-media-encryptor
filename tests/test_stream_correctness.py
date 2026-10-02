import hashlib
import os
import time

from app.crypto.stream_cipher import (
    encrypt_file_streaming,
    decrypt_file_streaming,
)


DATA_DIR = "data/correctness"

SEED = bytes(range(64))

FILE_SIZES = [
    1 * 1024 * 1024,      # 1 MiB
    10 * 1024 * 1024,     # 10 MiB
    50 * 1024 * 1024,     # 50 MiB
    100 * 1024 * 1024,    # 100 MiB
]

CHUNK_SIZES = [
    4 * 1024,             # 4 KiB
    64 * 1024,            # 64 KiB
    256 * 1024,           # 256 KiB
    1024 * 1024,          # 1 MiB
]


def create_test_file(
    path: str,
    size: int,
):
    """
    Create a deterministic binary test file.

    The content pattern is repeated so that
    we do not depend on random data.
    """

    pattern = bytes(
        range(256)
    )

    with open(
        path,
        "wb",
    ) as f:

        remaining = size

        while remaining > 0:

            block_size = min(
                len(pattern),
                remaining,
            )

            f.write(
                pattern[:block_size]
            )

            remaining -= block_size


def sha256_file(
    path: str,
) -> str:

    digest = hashlib.sha256()

    with open(
        path,
        "rb",
    ) as f:

        while True:

            data = f.read(
                1024 * 1024
            )

            if not data:
                break

            digest.update(data)

    return digest.hexdigest()


def format_size(
    size: int,
) -> str:

    if size >= 1024 * 1024:
        return (
            f"{size / (1024 * 1024):.0f} MiB"
        )

    return (
        f"{size / 1024:.0f} KiB"
    )


def main():

    os.makedirs(
        DATA_DIR,
        exist_ok=True,
    )

    total_tests = (
        len(FILE_SIZES)
        * len(CHUNK_SIZES)
    )

    passed = 0

    print(
        "========================================"
    )

    print(
        "Streaming Correctness Test"
    )

    print(
        f"Configurations : {total_tests}"
    )

    print(
        "========================================"
    )

    for file_size in FILE_SIZES:

        input_path = os.path.join(
            DATA_DIR,
            f"test_{file_size}.bin",
        )

        print(
            f"\nPreparing "
            f"{format_size(file_size)}..."
        )

        create_test_file(
            input_path,
            file_size,
        )

        original_hash = sha256_file(
            input_path
        )

        for chunk_size in CHUNK_SIZES:

            encrypted_path = os.path.join(
                DATA_DIR,
                (
                    f"test_{file_size}_"
                    f"{chunk_size}.pqcm"
                ),
            )

            recovered_path = os.path.join(
                DATA_DIR,
                (
                    f"test_{file_size}_"
                    f"{chunk_size}_recovered.bin"
                ),
            )

            print(
                f"\n[{format_size(file_size)}]"
                f" + "
                f"[{format_size(chunk_size)}]"
            )

            start = time.perf_counter()

            encrypt_file_streaming(
                input_path=input_path,
                output_path=encrypted_path,
                seed=SEED,
                chunk_size=chunk_size,
            )

            encryption_time = (
                time.perf_counter()
                - start
            )

            start = time.perf_counter()

            decrypt_file_streaming(
                input_path=encrypted_path,
                output_path=recovered_path,
                seed=SEED,
            )

            decryption_time = (
                time.perf_counter()
                - start
            )

            recovered_hash = sha256_file(
                recovered_path
            )

            original_size = os.path.getsize(
                input_path
            )

            recovered_size = os.path.getsize(
                recovered_path
            )

            integrity = (
                original_hash
                == recovered_hash
            )

            size_match = (
                original_size
                == recovered_size
            )

            print(
                f"Encryption time : "
                f"{encryption_time:.3f} s"
            )

            print(
                f"Decryption time : "
                f"{decryption_time:.3f} s"
            )

            print(
                f"Size match      : "
                f"{size_match}"
            )

            print(
                f"SHA-256 match   : "
                f"{integrity}"
            )

            assert size_match

            assert integrity

            passed += 1

    print(
        "\n========================================"
    )

    print(
        f"Correctness: "
        f"{passed}/{total_tests} PASS"
    )

    print(
        "========================================"
    )

    assert passed == total_tests

    print(
        "\nSTREAM CORRECTNESS TEST: PASS"
    )


if __name__ == "__main__":
    main()
