import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_PREFIX_SIZE = 8
GCM_TAG_SIZE = 16

CHUNK_LENGTH_STRUCT = struct.Struct(">I")


def derive_nonce(
    nonce_prefix: bytes,
    chunk_index: int,
) -> bytes:

    if len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError(
            "Invalid nonce prefix"
        )

    if not 0 <= chunk_index < 2**32:
        raise ValueError(
            "Invalid chunk index"
        )

    return (
        nonce_prefix
        + chunk_index.to_bytes(
            4,
            "big",
        )
    )


def build_aad(
    chunk_index: int,
    plaintext_length: int,
) -> bytes:

    return struct.pack(
        ">II",
        chunk_index,
        plaintext_length,
    )


def encrypt_file_aes(
    input_path: str,
    output_path: str,
    key: bytes,
    chunk_size: int,
):
    """
    AES-256-GCM streaming baseline.

    This intentionally excludes ML-KEM and HKDF.
    """

    if len(key) != 32:
        raise ValueError(
            "AES-256 key must be 32 bytes"
        )

    original_size = os.path.getsize(
        input_path
    )

    nonce_prefix = os.urandom(
        NONCE_PREFIX_SIZE
    )

    # Simple baseline header:
    #
    # magic       4 bytes
    # version     1 byte
    # chunk size  4 bytes
    # file size   8 bytes
    # nonce       8 bytes
    #
    header = struct.pack(
        ">4sBIQ8s",
        b"ABAS",
        1,
        chunk_size,
        original_size,
        nonce_prefix,
    )

    aesgcm = AESGCM(key)

    with open(
        input_path,
        "rb",
    ) as input_file, open(
        output_path,
        "wb",
    ) as output_file:

        output_file.write(header)

        chunk_index = 0

        while True:

            plaintext = input_file.read(
                chunk_size
            )

            if not plaintext:
                break

            plaintext_length = len(
                plaintext
            )

            nonce = derive_nonce(
                nonce_prefix,
                chunk_index,
            )

            aad = build_aad(
                chunk_index,
                plaintext_length,
            )

            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext,
                aad,
            )

            output_file.write(
                CHUNK_LENGTH_STRUCT.pack(
                    plaintext_length
                )
            )

            output_file.write(
                ciphertext
            )

            chunk_index += 1

        # Empty-file support
        if original_size == 0:

            nonce = derive_nonce(
                nonce_prefix,
                0,
            )

            aad = build_aad(
                0,
                0,
            )

            ciphertext = aesgcm.encrypt(
                nonce,
                b"",
                aad,
            )

            output_file.write(
                CHUNK_LENGTH_STRUCT.pack(
                    0
                )
            )

            output_file.write(
                ciphertext
            )


def decrypt_file_aes(
    input_path: str,
    output_path: str,
    key: bytes,
):
    """
    Decrypt AES-256-GCM baseline.
    """

    if len(key) != 32:
        raise ValueError(
            "AES-256 key must be 32 bytes"
        )

    header_struct = struct.Struct(
        ">4sBIQ8s"
    )

    with open(
        input_path,
        "rb",
    ) as input_file, open(
        output_path,
        "wb",
    ) as output_file:

        header = input_file.read(
            header_struct.size
        )

        if len(header) != (
            header_struct.size
        ):
            raise ValueError(
                "Invalid AES baseline header"
            )

        (
            magic,
            version,
            chunk_size,
            original_size,
            nonce_prefix,
        ) = header_struct.unpack(
            header
        )

        if magic != b"ABAS":
            raise ValueError(
                "Invalid AES baseline magic"
            )

        if version != 1:
            raise ValueError(
                "Unsupported AES baseline version"
            )

        aesgcm = AESGCM(key)

        total_plaintext = 0
        chunk_index = 0

        while total_plaintext < original_size:

            length_data = input_file.read(
                CHUNK_LENGTH_STRUCT.size
            )

            if len(length_data) != (
                CHUNK_LENGTH_STRUCT.size
            ):
                raise ValueError(
                    "Truncated AES chunk length"
                )

            plaintext_length = (
                CHUNK_LENGTH_STRUCT.unpack(
                    length_data
                )[0]
            )

            if plaintext_length > chunk_size:
                raise ValueError(
                    "Invalid AES chunk size"
                )

            ciphertext_length = (
                plaintext_length
                + GCM_TAG_SIZE
            )

            ciphertext = input_file.read(
                ciphertext_length
            )

            if len(ciphertext) != (
                ciphertext_length
            ):
                raise ValueError(
                    "Truncated AES ciphertext"
                )

            nonce = derive_nonce(
                nonce_prefix,
                chunk_index,
            )

            aad = build_aad(
                chunk_index,
                plaintext_length,
            )

            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                aad,
            )

            if len(plaintext) != (
                plaintext_length
            ):
                raise ValueError(
                    "Plaintext size mismatch"
                )

            output_file.write(
                plaintext
            )

            total_plaintext += len(
                plaintext
            )

            chunk_index += 1

        if total_plaintext != original_size:
            raise ValueError(
                "Recovered size mismatch"
            )

        if input_file.read(1):
            raise ValueError(
                "Unexpected trailing data"
            )
