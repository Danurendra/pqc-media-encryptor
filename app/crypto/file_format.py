import math
import struct


MAGIC = b"PQCM"

VERSION = 2

ALGORITHM_ID = 1

NONCE_PREFIX_SIZE = 8

GCM_TAG_SIZE = 16

MAX_CHUNK_SIZE = 64 * 1024 * 1024


# Fields:
#
# 4s  magic
# B   version
# B   algorithm ID
# I   chunk size
# Q   original file size
# I   chunk count
# I   KEM ciphertext length
# 8s  nonce prefix
#
HEADER_STRUCT = struct.Struct(
    ">4sBBIQII8s"
)


CHUNK_LENGTH_STRUCT = struct.Struct(
    ">I"
)


def calculate_chunk_count(
    original_size: int,
    chunk_size: int,
) -> int:

    if chunk_size <= 0:
        raise ValueError(
            "Chunk size must be greater than zero"
        )

    if original_size < 0:
        raise ValueError(
            "Original size cannot be negative"
        )

    # Even an empty file gets one authenticated
    # zero-length AES-GCM chunk.
    if original_size == 0:
        return 1

    return math.ceil(
        original_size / chunk_size
    )


def build_header(
    chunk_size: int,
    original_size: int,
    kem_ciphertext: bytes,
    nonce_prefix: bytes,
) -> bytes:

    if not (
        1 <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise ValueError(
            "Invalid chunk size"
        )

    if original_size < 0:
        raise ValueError(
            "Original size cannot be negative"
        )

    if len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError(
            f"Nonce prefix must be "
            f"{NONCE_PREFIX_SIZE} bytes"
        )

    chunk_count = calculate_chunk_count(
        original_size,
        chunk_size,
    )

    if chunk_count >= 2**32:
        raise ValueError(
            "File requires too many chunks"
        )

    fixed_header = HEADER_STRUCT.pack(
        MAGIC,
        VERSION,
        ALGORITHM_ID,
        chunk_size,
        original_size,
        chunk_count,
        len(kem_ciphertext),
        nonce_prefix,
    )

    return (
        fixed_header
        + kem_ciphertext
    )


def parse_header(
    data: bytes,
):

    if len(data) < HEADER_STRUCT.size:
        raise ValueError(
            "Header is too short"
        )

    (
        magic,
        version,
        algorithm_id,
        chunk_size,
        original_size,
        chunk_count,
        kem_ct_len,
        nonce_prefix,
    ) = HEADER_STRUCT.unpack(
        data[:HEADER_STRUCT.size]
    )

    if magic != MAGIC:
        raise ValueError(
            "Invalid PQCM magic"
        )

    if version != VERSION:
        raise ValueError(
            "Unsupported PQCM version"
        )

    if algorithm_id != ALGORITHM_ID:
        raise ValueError(
            "Unsupported algorithm"
        )

    if not (
        1 <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise ValueError(
            "Invalid chunk size"
        )

    if kem_ct_len <= 0:
        raise ValueError(
            "Invalid KEM ciphertext length"
        )

    expected_chunk_count = (
        calculate_chunk_count(
            original_size,
            chunk_size,
        )
    )

    if chunk_count != expected_chunk_count:
        raise ValueError(
            "Invalid chunk count"
        )

    offset = HEADER_STRUCT.size

    end = offset + kem_ct_len

    if len(data) < end:
        raise ValueError(
            "Incomplete KEM ciphertext"
        )

    kem_ciphertext = data[
        offset:end
    ]

    return {
        "version": version,
        "algorithm_id": algorithm_id,
        "chunk_size": chunk_size,
        "original_size": original_size,
        "chunk_count": chunk_count,
        "kem_ciphertext": kem_ciphertext,
        "kem_ciphertext_length": kem_ct_len,
        "nonce_prefix": nonce_prefix,
        "header_size": end,
    }


def build_chunk_aad(
    header: bytes,
    chunk_index: int,
    plaintext_length: int,
) -> bytes:

    if not (
        0 <= chunk_index < 2**32
    ):
        raise ValueError(
            "Invalid chunk index"
        )

    if not (
        0 <= plaintext_length < 2**32
    ):
        raise ValueError(
            "Invalid plaintext length"
        )

    chunk_metadata = struct.pack(
        ">II",
        chunk_index,
        plaintext_length,
    )

    return (
        header
        + chunk_metadata
    )


def derive_chunk_nonce(
    nonce_prefix: bytes,
    chunk_index: int,
) -> bytes:

    if len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError(
            "Invalid nonce prefix"
        )

    if not (
        0 <= chunk_index < 2**32
    ):
        raise ValueError(
            "Invalid chunk index"
        )

    counter = chunk_index.to_bytes(
        4,
        byteorder="big",
    )

    return (
        nonce_prefix
        + counter
    )
