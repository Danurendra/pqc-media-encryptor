import os

from app.crypto.file_format import (
    HEADER_STRUCT,
    parse_header,
)

from app.crypto.stream_cipher import (
    encrypt_file_streaming,
)


def main():

    input_path = (
        "data/test_1mb.bin"
    )

    output_path = (
        "data/test_1mb_stream.pqcm"
    )

    chunk_size = (
        64 * 1024
    )

    seed = bytes(
        range(64)
    )

    print(
        "Testing streaming encryption..."
    )

    encrypt_file_streaming(
        input_path=input_path,
        output_path=output_path,
        seed=seed,
        chunk_size=chunk_size,
    )

    original_size = os.path.getsize(
        input_path
    )

    encrypted_size = os.path.getsize(
        output_path
    )

    with open(
        output_path,
        "rb",
    ) as f:

        fixed_header = f.read(
            HEADER_STRUCT.size
        )

        (
            magic,
            version,
            algorithm_id,
            stored_chunk_size,
            stored_original_size,
            chunk_count,
            kem_ct_len,
            nonce_prefix,
        ) = HEADER_STRUCT.unpack(
            fixed_header
        )

        kem_ciphertext = f.read(
            kem_ct_len
        )

        full_header = (
            fixed_header
            + kem_ciphertext
        )

    parsed = parse_header(
        full_header
    )

    print(
        f"Original size     : "
        f"{original_size} bytes"
    )

    print(
        f"Encrypted size    : "
        f"{encrypted_size} bytes"
    )

    print(
        f"Chunk size        : "
        f"{parsed['chunk_size']} bytes"
    )

    print(
        f"Chunk count       : "
        f"{parsed['chunk_count']}"
    )

    print(
        f"Original in header: "
        f"{parsed['original_size']} bytes"
    )

    assert (
        parsed["original_size"]
        == original_size
    )

    assert (
        parsed["chunk_size"]
        == chunk_size
    )

    assert (
        parsed["chunk_count"]
        == 16
    )

    assert encrypted_size > original_size

    print(
        "\nSTREAM ENCRYPTION TEST: PASS"
    )


if __name__ == "__main__":
    main()
