import os
import shutil

from app.crypto.stream_cipher import (
    decrypt_file_streaming,
)


SOURCE = "data/test_1mb_stream.pqcm"
TEMP = "data/tampered.pqcm"
OUTPUT = "data/tampered_recovered.bin"

SEED = bytes(range(64))


def expect_rejection(
    description: str,
    encrypted_path: str,
):
    print(f"\nTesting: {description}")

    try:
        decrypt_file_streaming(
            input_path=encrypted_path,
            output_path=OUTPUT,
            seed=SEED,
        )

    except Exception as exc:
        print(
            f"REJECTED: {type(exc).__name__}"
        )
        print(
            f"Reason   : {exc}"
        )
        return True

    print("ERROR: tampered file was accepted")
    return False


def flip_byte(
    source: str,
    destination: str,
    offset: int,
):
    shutil.copyfile(
        source,
        destination,
    )

    with open(
        destination,
        "r+b",
    ) as f:

        f.seek(offset)

        original = f.read(1)

        if len(original) != 1:
            raise ValueError(
                "Offset outside file"
            )

        f.seek(offset)

        f.write(
            bytes(
                [original[0] ^ 0x01]
            )
        )


def truncate_file(
    source: str,
    destination: str,
    remove_bytes: int,
):
    shutil.copyfile(
        source,
        destination,
    )

    size = os.path.getsize(
        destination
    )

    if remove_bytes >= size:
        raise ValueError(
            "Cannot remove entire file"
        )

    with open(
        destination,
        "r+b",
    ) as f:

        f.truncate(
            size - remove_bytes
        )


def main():

    print(
        "========================================"
    )
    print(
        "Streaming Integrity Test"
    )
    print(
        "========================================"
    )

    encrypted_size = os.path.getsize(
        SOURCE
    )

    print(
        f"Encrypted file size : "
        f"{encrypted_size} bytes"
    )

    passed = 0
    total = 0

    # -------------------------------------
    # Test 1: ciphertext modification
    # -------------------------------------

    # Header = 1122 bytes.
    # The first chunk length field begins
    # immediately after the header.
    #
    # Skip:
    #   header
    #   4-byte chunk length
    #
    # Then modify first ciphertext byte.

    first_ciphertext_offset = (
        1122 + 4
    )

    flip_byte(
        SOURCE,
        TEMP,
        first_ciphertext_offset,
    )

    total += 1

    if expect_rejection(
        "Modified ciphertext",
        TEMP,
    ):
        passed += 1

    # -------------------------------------
    # Test 2: wrong seed
    # -------------------------------------

    print(
        "\nTesting: Wrong ML-KEM seed"
    )

    wrong_seed = bytes(
        [x ^ 0xFF for x in SEED]
    )

    try:

        decrypt_file_streaming(
            input_path=SOURCE,
            output_path=OUTPUT,
            seed=wrong_seed,
        )

    except Exception as exc:

        print(
            f"REJECTED: {type(exc).__name__}"
        )

        print(
            f"Reason   : {exc}"
        )

        passed += 1

    else:

        print(
            "ERROR: wrong seed was accepted"
        )

    total += 1

    # -------------------------------------
    # Test 3: truncation
    # -------------------------------------

    truncate_file(
        SOURCE,
        TEMP,
        remove_bytes=10,
    )

    total += 1

    if expect_rejection(
        "Truncated ciphertext",
        TEMP,
    ):
        passed += 1

    # -------------------------------------
    # Test 4: modified chunk metadata
    # -------------------------------------

    # Chunk 0 plaintext length is stored
    # at offset 1122.
    #
    # Change one byte of this length.

    flip_byte(
        SOURCE,
        TEMP,
        1122,
    )

    total += 1

    if expect_rejection(
        "Modified chunk length metadata",
        TEMP,
    ):
        passed += 1

    # -------------------------------------
    # Final result
    # -------------------------------------

    print(
        "\n========================================"
    )

    print(
        f"Integrity tests: "
        f"{passed}/{total} PASS"
    )

    print(
        "========================================"
    )

    assert passed == total

    print(
        "\nSTREAM INTEGRITY TEST: PASS"
    )


if __name__ == "__main__":
    main()
