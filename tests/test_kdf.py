import oqs

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEM_ALGORITHM = "ML-KEM-768"


def derive_aes_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pqc-media-encryptor-content-key",
    )

    return hkdf.derive(shared_secret)


def main():
    print(f"Testing {KEM_ALGORITHM} + HKDF-SHA256...")

    # Receiver generates ML-KEM keypair
    receiver = oqs.KeyEncapsulation(KEM_ALGORITHM)
    public_key = receiver.generate_keypair()

    # Sender encapsulates
    sender = oqs.KeyEncapsulation(KEM_ALGORITHM)
    ciphertext, sender_secret = sender.encap_secret(public_key)

    # Receiver decapsulates
    receiver_secret = receiver.decap_secret(ciphertext)

    # Verify ML-KEM shared secrets
    assert sender_secret == receiver_secret

    print(f"ML-KEM shared secret : {len(sender_secret)} bytes")

    # Derive AES keys
    sender_key = derive_aes_key(sender_secret)
    receiver_key = derive_aes_key(receiver_secret)

    print(f"Derived AES key      : {len(sender_key)} bytes")

    # Verify both sides derive the same key
    assert sender_key == receiver_key

    print()
    print("=" * 40)
    print("ML-KEM + HKDF test: PASS")
    print("=" * 40)


if __name__ == "__main__":
    main()
