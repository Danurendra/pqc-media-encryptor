import os

from app.keys.mlkem import (
    generate_keypair,
    encapsulate,
    decapsulate_from_seed,
)


def main():
    print("=" * 50)
    print("ML-KEM-768 Key Management Test")
    print("=" * 50)

    # Generate 64-byte key seed
    seed = os.urandom(64)

    print(f"\nSeed       : {len(seed)} bytes")

    # Generate recipient keypair
    public_key, secret_key = generate_keypair(seed)

    print(f"Public key : {len(public_key)} bytes")
    print(f"Secret key : {len(secret_key)} bytes")

    # Sender encapsulates
    ciphertext, sender_secret = encapsulate(
        public_key
    )

    print(f"KEM CT     : {len(ciphertext)} bytes")

    # Recipient reconstructs keypair from seed
    receiver_secret = decapsulate_from_seed(
        seed,
        ciphertext,
    )

    print(
        f"Shared secret: "
        f"{len(receiver_secret)} bytes"
    )

    assert sender_secret == receiver_secret

    print("Shared secret: MATCH")

    print()
    print("=" * 50)
    print("KEY MANAGEMENT TEST: PASS")
    print("=" * 50)


if __name__ == "__main__":
    main()
