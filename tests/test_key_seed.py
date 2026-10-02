import oqs


KEM_ALGORITHM = "ML-KEM-768"


def main():
    print("=" * 50)
    print("ML-KEM-768 Deterministic Key Generation Test")
    print("=" * 50)

    seed = bytes(range(64))

    # ==========================================
    # KEYPAIR A
    # ==========================================

    kem_a = oqs.KeyEncapsulation(KEM_ALGORITHM)

    public_key_a = kem_a.generate_keypair_seed(seed)
    secret_key_a = kem_a.export_secret_key()

    print(f"\nSeed       : {len(seed)} bytes")
    print(f"Public A   : {len(public_key_a)} bytes")
    print(f"Secret A   : {len(secret_key_a)} bytes")

    # ==========================================
    # KEYPAIR B
    # ==========================================

    kem_b = oqs.KeyEncapsulation(KEM_ALGORITHM)

    public_key_b = kem_b.generate_keypair_seed(seed)
    secret_key_b = kem_b.export_secret_key()

    print(f"Public B   : {len(public_key_b)} bytes")
    print(f"Secret B   : {len(secret_key_b)} bytes")

    # ==========================================
    # COMPARE
    # ==========================================

    assert public_key_a == public_key_b
    assert secret_key_a == secret_key_b

    print("\nPublic keys : MATCH")
    print("Secret keys : MATCH")

    # ==========================================
    # TEST ENCAPSULATION / DECAPSULATION
    # ==========================================

    sender = oqs.KeyEncapsulation(KEM_ALGORITHM)

    ciphertext, sender_secret = sender.encap_secret(
        public_key_a
    )

    receiver_secret = kem_b.decap_secret(
        ciphertext
    )

    assert sender_secret == receiver_secret

    print("Shared secret: MATCH")

    print()
    print("=" * 50)
    print("DETERMINISTIC KEY GENERATION TEST: PASS")
    print("=" * 50)


if __name__ == "__main__":
    main()
