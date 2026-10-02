import os
import struct

from app.crypto.file_format import (
    build_header,
    build_chunk_aad,
    derive_chunk_nonce,
    CHUNK_LENGTH_STRUCT,
    GCM_TAG_SIZE,
)

from app.crypto.hybrid import (
    derive_content_key,
    encrypt_data,
    decrypt_data,
)

from app.keys.mlkem import (
    generate_keypair,
    encapsulate,
)


def encrypt_file_streaming(
    input_path: str,
    output_path: str,
    seed: bytes,
    chunk_size: int,
):
    """
    Encrypt a file using:

        ML-KEM-768
            ↓
        shared secret
            ↓
        HKDF-SHA-256
            ↓
        AES-256-GCM
            ↓
        chunked streaming encryption
    """

    original_size = os.path.getsize(
        input_path
    )

    public_key, _ = generate_keypair(
        seed
    )

    (
        kem_ciphertext,
        shared_secret,
    ) = encapsulate(
        public_key
    )

    content_key = derive_content_key(
        shared_secret
    )

    nonce_prefix = os.urandom(8)

    header = build_header(
        chunk_size=chunk_size,
        original_size=original_size,
        kem_ciphertext=kem_ciphertext,
        nonce_prefix=nonce_prefix,
    )

    with open(
        input_path,
        "rb",
    ) as input_file, open(
        output_path,
        "wb",
    ) as output_file:

        output_file.write(
            header
        )

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

            nonce = derive_chunk_nonce(
                nonce_prefix,
                chunk_index,
            )

            aad = build_chunk_aad(
                header,
                chunk_index,
                plaintext_length,
            )

            ciphertext = encrypt_data(
                plaintext,
                content_key,
                nonce,
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

        #
        # Special case:
        # empty file
        #
        if original_size == 0:

            plaintext = b""

            nonce = derive_chunk_nonce(
                nonce_prefix,
                0,
            )

            aad = build_chunk_aad(
                header,
                chunk_index=0,
                plaintext_length=0,
            )

            ciphertext = encrypt_data(
                plaintext,
                content_key,
                nonce,
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



def decrypt_file_streaming(
    input_path: str,
    output_path: str,
    seed: bytes,
):
    """
    Decrypt a streaming PQCM file.
    """

    from app.crypto.file_format import (
        HEADER_STRUCT,
        parse_header,
    )

    from app.keys.mlkem import (
        decapsulate_from_seed,
    )

    with open(
        input_path,
        "rb",
    ) as input_file, open(
        output_path,
        "wb",
    ) as output_file:

        # -------------------------------
        # Fixed header
        # -------------------------------

        fixed_header = input_file.read(
            HEADER_STRUCT.size
        )

        if len(fixed_header) != HEADER_STRUCT.size:
            raise ValueError(
                "Encrypted file is too short"
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
            fixed_header
        )

        # -------------------------------
        # KEM ciphertext
        # -------------------------------

        kem_ciphertext = input_file.read(
            kem_ct_len
        )

        if len(kem_ciphertext) != kem_ct_len:
            raise ValueError(
                "Incomplete KEM ciphertext"
            )

        header = (
            fixed_header
            + kem_ciphertext
        )

        parsed = parse_header(
            header
        )

        # -------------------------------
        # ML-KEM decapsulation
        # -------------------------------

        shared_secret = (
            decapsulate_from_seed(
                seed,
                parsed["kem_ciphertext"],
            )
        )

        content_key = derive_content_key(
            shared_secret
        )

        # -------------------------------
        # Chunk processing
        # -------------------------------

        total_plaintext = 0

        for chunk_index in range(
            parsed["chunk_count"]
        ):

            # Read plaintext length
            length_data = input_file.read(
                CHUNK_LENGTH_STRUCT.size
            )

            if len(length_data) != (
                CHUNK_LENGTH_STRUCT.size
            ):
                raise ValueError(
                    "Truncated chunk length"
                )

            plaintext_length = (
                CHUNK_LENGTH_STRUCT.unpack(
                    length_data
                )[0]
            )

            # Validate chunk size
            if plaintext_length > (
                parsed["chunk_size"]
            ):
                raise ValueError(
                    "Chunk plaintext exceeds "
                    "declared chunk size"
                )

            # Ciphertext = plaintext + GCM tag
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
                    "Truncated ciphertext chunk"
                )

            # Reconstruct nonce
            nonce = derive_chunk_nonce(
                parsed["nonce_prefix"],
                chunk_index,
            )

            # Reconstruct authenticated metadata
            aad = build_chunk_aad(
                header,
                chunk_index,
                plaintext_length,
            )

            try:

                plaintext = decrypt_data(
                    ciphertext,
                    content_key,
                    nonce,
                    aad,
                )

            except Exception as exc:

                raise ValueError(
                    f"Chunk {chunk_index} "
                    f"authentication failed"
                ) from exc

            # Verify plaintext length
            if len(plaintext) != (
                plaintext_length
            ):
                raise ValueError(
                    f"Chunk {chunk_index} "
                    f"plaintext length mismatch"
                )

            output_file.write(
                plaintext
            )

            total_plaintext += len(
                plaintext
            )

        # -------------------------------
        # Verify total file size
        # -------------------------------

        if total_plaintext != (
            parsed["original_size"]
        ):
            raise ValueError(
                "Recovered file size does not "
                "match header"
            )

        # -------------------------------
        # No trailing data allowed
        # -------------------------------

        trailing = input_file.read(1)

        if trailing:
            raise ValueError(
                "Unexpected data after "
                "final chunk"
            )
