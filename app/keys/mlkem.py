import oqs


KEM_ALGORITHM = "ML-KEM-768"


def generate_keypair(seed: bytes):
    """
    Generate an ML-KEM-768 keypair from a 64-byte seed.
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    if len(seed) != kem.length_keypair_seed:
        raise ValueError(
            f"Seed must be {kem.length_keypair_seed} bytes"
        )

    public_key = kem.generate_keypair_seed(seed)
    secret_key = kem.export_secret_key()

    return public_key, secret_key


def encapsulate(public_key: bytes):
    """
    Encapsulate a shared secret using an ML-KEM public key.
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    ciphertext, shared_secret = kem.encap_secret(
        public_key
    )

    return ciphertext, shared_secret


def decapsulate_from_seed(
    seed: bytes,
    ciphertext: bytes,
):
    """
    Reconstruct the deterministic ML-KEM keypair
    from the seed and decapsulate the ciphertext.
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    if len(seed) != kem.length_keypair_seed:
        raise ValueError(
            f"Seed must be {kem.length_keypair_seed} bytes"
        )

    kem.generate_keypair_seed(seed)

    return kem.decap_secret(ciphertext)
