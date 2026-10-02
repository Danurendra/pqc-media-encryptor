import oqs
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEM_ALGORITHM = "ML-KEM-768"
HKDF_INFO = b"pqc-media-encryptor-content-key"


def derive_key(shared_secret):
    """
    Convert the ML-KEM shared secret into a 32-byte AES-256 key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )

    return hkdf.derive(shared_secret)


def main():
    print("=" * 50)
    print("Hybrid ML-KEM-768 + AES-256-GCM Test")
    print("=" * 50)

    # ==========================================
    # 1. RECEIVER: Generate ML-KEM keypair
    # ==========================================

    receiver = oqs.KeyEncapsulation(KEM_ALGORITHM)

    public_key = receiver.generate_keypair()

    print(f"\nML-KEM public key : {len(public_key)} bytes")

    # ==========================================
    # 2. SENDER: Encapsulation
    # ==========================================

    sender = oqs.KeyEncapsulation(KEM_ALGORITHM)

    kem_ciphertext, sender_secret = sender.encap_secret(
        public_key
    )

    print(
        f"ML-KEM ciphertext : "
        f"{len(kem_ciphertext)} bytes"
    )

    print(
        f"Sender secret     : "
        f"{len(sender_secret)} bytes"
    )

    # ==========================================
    # 3. RECEIVER: Decapsulation
    # ==========================================

    receiver_secret = receiver.decap_secret(
        kem_ciphertext
    )

    print(
        f"Receiver secret   : "
        f"{len(receiver_secret)} bytes"
    )

    assert sender_secret == receiver_secret

    print("Shared secret     : MATCH")

    # ==========================================
    # 4. HKDF
    # ==========================================

    sender_key = derive_key(sender_secret)
    receiver_key = derive_key(receiver_secret)

    print(
        f"AES-256 key       : "
        f"{len(sender_key)} bytes"
    )

    assert sender_key == receiver_key

    print("Derived key       : MATCH")

    # ==========================================
    # 5. AES-256-GCM ENCRYPTION
    # ==========================================

    plaintext = (
        b"This is an end-to-end hybrid encryption "
        b"test for the PQC Media Encryptor project."
    )

    nonce = os.urandom(12)

    aad = (
        b"pqc-media-encryptor"
        b"|version=1"
        b"|chunk=0"
    )

    aesgcm = AESGCM(sender_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad,
    )

    print(
        f"Plaintext         : "
        f"{len(plaintext)} bytes"
    )

    print(
        f"Ciphertext        : "
        f"{len(ciphertext)} bytes"
    )

    # ==========================================
    # 6. AES-256-GCM DECRYPTION
    # ==========================================

    receiver_aesgcm = AESGCM(receiver_key)

    recovered = receiver_aesgcm.decrypt(
        nonce,
        ciphertext,
        aad,
    )

    assert recovered == plaintext

    print("Decryption        : PASS")

    # ==========================================
    # 7. INTEGRITY TEST
    # ==========================================

    tampered = bytearray(ciphertext)

    tampered[0] ^= 1

    try:
        receiver_aesgcm.decrypt(
            nonce,
            bytes(tampered),
            aad,
        )

        raise AssertionError(
            "Tampered ciphertext was accepted!"
        )

    except Exception:
        print("Tampering         : REJECTED")

    # ==========================================
    # FINAL RESULT
    # ==========================================

    print()
    print("=" * 50)
    print("HYBRID END-TO-END TEST: PASS")
    print("=" * 50)


if __name__ == "__main__":
    main()
