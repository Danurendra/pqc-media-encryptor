import os

from app.crypto.file_format import (
    build_header,
    parse_header,
    HEADER_STRUCT,
)

from app.crypto.hybrid import (
    derive_content_key,
    encrypt_data,
    decrypt_data,
)

from app.keys.mlkem import (
    generate_keypair,
    encapsulate,
    decapsulate_from_seed,
)


NONCE_SIZE = 12


def encrypt_file(
    input_path: str,
    output_path: str,
    seed: bytes,
):
    """
    Encrypt one complete file using:

    ML-KEM-768
        -> HKDF-SHA256
        -> AES-256-GCM

    This is the single-shot prototype version.
    """

    # ------------------------------------------
    # 1. Generate recipient keypair
    # ------------------------------------------

    public_key, _ = generate_keypair(seed)

    # ------------------------------------------
    # 2. ML-KEM encapsulation
    # ------------------------------------------

    kem_ciphertext, shared_secret = encapsulate(
        public_key
    )

    # ------------------------------------------
    # 3. Derive AES-256 key
    # ------------------------------------------

    content_key = derive_content_key(
        shared_secret
    )

    # ------------------------------------------
    # 4. Read complete plaintext file
    # ------------------------------------------

    with open(input_path, "rb") as f:
        plaintext = f.read()

    # ------------------------------------------
    # 5. Build header
    # ------------------------------------------

    chunk_size = len(plaintext)

    header = build_header(
        chunk_size,
        kem_ciphertext,
    )

    # ------------------------------------------
    # 6. Generate AES-GCM nonce
    # ------------------------------------------

    nonce = os.urandom(NONCE_SIZE)

    # ------------------------------------------
    # 7. Use header as AAD
    # ------------------------------------------

    aad = header

    # ------------------------------------------
    # 8. Encrypt file
    # ------------------------------------------

    ciphertext = encrypt_data(
        plaintext,
        content_key,
        nonce,
        aad,
    )

    # ------------------------------------------
    # 9. Write output
    # ------------------------------------------

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(
    input_path: str,
    output_path: str,
    seed: bytes,
):
    """
    Decrypt the single-shot PQCM file format.
    """

    with open(input_path, "rb") as f:

        # --------------------------------------
        # 1. Read fixed-size header
        # --------------------------------------

        fixed_header = f.read(
            HEADER_STRUCT.size
        )

        if len(fixed_header) != HEADER_STRUCT.size:
            raise ValueError(
                "Encrypted file is too short"
            )

        # --------------------------------------
        # 2. Determine KEM ciphertext length
        # --------------------------------------

        (
            magic,
            version,
            algorithm_id,
            chunk_size,
            kem_ct_len,
        ) = HEADER_STRUCT.unpack(
            fixed_header
        )

        # --------------------------------------
        # 3. Read KEM ciphertext
        # --------------------------------------

        kem_ciphertext = f.read(
            kem_ct_len
        )

        if len(kem_ciphertext) != kem_ct_len:
            raise ValueError(
                "Incomplete KEM ciphertext"
            )

        # Recreate the complete header
        header = (
            fixed_header
            + kem_ciphertext
        )

        # Validate header
        parsed = parse_header(header)

        # --------------------------------------
        # 4. Read nonce
        # --------------------------------------

        nonce = f.read(NONCE_SIZE)

        if len(nonce) != NONCE_SIZE:
            raise ValueError(
                "Incomplete AES-GCM nonce"
            )

        # --------------------------------------
        # 5. Remaining data = ciphertext
        # --------------------------------------

        ciphertext = f.read()

    # ------------------------------------------
    # 6. ML-KEM decapsulation
    # ------------------------------------------

    shared_secret = decapsulate_from_seed(
        seed,
        parsed["kem_ciphertext"],
    )

    # ------------------------------------------
    # 7. Derive AES key
    # ------------------------------------------

    content_key = derive_content_key(
        shared_secret
    )

    # ------------------------------------------
    # 8. AES-GCM decrypt
    # ------------------------------------------

    plaintext = decrypt_data(
        ciphertext,
        content_key,
        nonce,
        header,
    )

    # ------------------------------------------
    # 9. Write recovered file
    # ------------------------------------------

    with open(output_path, "wb") as f:
        f.write(plaintext)
