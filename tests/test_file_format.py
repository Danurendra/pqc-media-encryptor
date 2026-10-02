from app.crypto.file_format import (
    build_header,
    parse_header,
)


def main():
    chunk_size = 64 * 1024

    kem_ciphertext = bytes(range(256)) * 4

    header = build_header(
        chunk_size,
        kem_ciphertext,
    )

    print("Header created")
    print(f"Header size      : {len(header)} bytes")

    parsed = parse_header(header)

    print(f"Version           : {parsed['version']}")
    print(f"Algorithm ID      : {parsed['algorithm_id']}")
    print(f"Chunk size        : {parsed['chunk_size']} bytes")
    print(
        f"KEM ciphertext    : "
        f"{len(parsed['kem_ciphertext'])} bytes"
    )

    assert parsed["version"] == 1
    assert parsed["algorithm_id"] == 1
    assert parsed["chunk_size"] == chunk_size
    assert parsed["kem_ciphertext"] == kem_ciphertext

    print()
    print("=" * 40)
    print("FILE FORMAT TEST: PASS")
    print("=" * 40)


if __name__ == "__main__":
    main()
