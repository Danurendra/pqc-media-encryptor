import os

from app.crypto.file_format import (
    HEADER_STRUCT,
    build_header,
    parse_header,
    calculate_chunk_count,
    derive_chunk_nonce,
    build_chunk_aad,
)


def main():

    print(
        "Testing streaming file format..."
    )

    chunk_size = 64 * 1024

    original_size = 1024 * 1024

    kem_ciphertext = os.urandom(1088)

    nonce_prefix = os.urandom(8)

    header = build_header(
        chunk_size=chunk_size,
        original_size=original_size,
        kem_ciphertext=kem_ciphertext,
        nonce_prefix=nonce_prefix,
    )

    parsed = parse_header(
        header
    )

    expected_chunks = (
        calculate_chunk_count(
            original_size,
            chunk_size,
        )
    )

    print(
        f"Fixed header     : "
        f"{HEADER_STRUCT.size} bytes"
    )

    print(
        f"Complete header  : "
        f"{len(header)} bytes"
    )

    print(
        f"Chunk size       : "
        f"{parsed['chunk_size']} bytes"
    )

    print(
        f"Original size    : "
        f"{parsed['original_size']} bytes"
    )

    print(
        f"Chunk count      : "
        f"{parsed['chunk_count']}"
    )

    print(
        f"KEM ciphertext   : "
        f"{len(parsed['kem_ciphertext'])} bytes"
    )

    print(
        f"Nonce prefix     : "
        f"{len(parsed['nonce_prefix'])} bytes"
    )

    assert (
        parsed["chunk_count"]
        == expected_chunks
    )

    nonce0 = derive_chunk_nonce(
        nonce_prefix,
        0,
    )

    nonce1 = derive_chunk_nonce(
        nonce_prefix,
        1,
    )

    print(
        f"Nonce 0          : "
        f"{nonce0.hex()}"
    )

    print(
        f"Nonce 1          : "
        f"{nonce1.hex()}"
    )

    assert len(nonce0) == 12
    assert len(nonce1) == 12

    assert nonce0 != nonce1

    aad0 = build_chunk_aad(
        header,
        chunk_index=0,
        plaintext_length=chunk_size,
    )

    aad1 = build_chunk_aad(
        header,
        chunk_index=1,
        plaintext_length=chunk_size,
    )

    assert aad0 != aad1

    print(
        "\nSTREAM FORMAT TEST: PASS"
    )


if __name__ == "__main__":
    main()
