from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def main():
    print("Testing AES-256-GCM...")

    # AES-256 membutuhkan key 32 bytes
    key = os.urandom(32)

    # AES-GCM menggunakan nonce 12 bytes sebagai praktik umum
    nonce = os.urandom(12)

    plaintext = (
        b"Hello from PQC Media Encryptor! "
        b"This is a test message for AES-256-GCM."
    )

    # Additional Authenticated Data
    aad = b"pqc-media-encryptor-test"

    print(f"Key       : {len(key)} bytes")
    print(f"Nonce     : {len(nonce)} bytes")
    print(f"Plaintext : {len(plaintext)} bytes")

    # -----------------------------
    # ENCRYPT
    # -----------------------------
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad,
    )

    print(f"Ciphertext: {len(ciphertext)} bytes")

    # -----------------------------
    # DECRYPT
    # -----------------------------
    recovered = aesgcm.decrypt(
        nonce,
        ciphertext,
        aad,
    )

    assert recovered == plaintext

    print("Normal decryption: PASS")

    # -----------------------------
    # TEST TAMPERED CIPHERTEXT
    # -----------------------------
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 1

    try:
        aesgcm.decrypt(
            nonce,
            bytes(tampered_ciphertext),
            aad,
        )

        raise AssertionError(
            "Tampered ciphertext was accepted!"
        )

    except Exception:
        print("Tampered ciphertext: REJECTED")

    # -----------------------------
    # TEST WRONG AAD
    # -----------------------------
    try:
        aesgcm.decrypt(
            nonce,
            ciphertext,
            b"wrong-aad",
        )

        raise AssertionError(
            "Wrong AAD was accepted!"
        )

    except Exception:
        print("Wrong AAD: REJECTED")

    # -----------------------------
    # TEST WRONG KEY
    # -----------------------------
    wrong_key = os.urandom(32)
    wrong_aesgcm = AESGCM(wrong_key)

    try:
        wrong_aesgcm.decrypt(
            nonce,
            ciphertext,
            aad,
        )

        raise AssertionError(
            "Wrong key was accepted!"
        )

    except Exception:
        print("Wrong key: REJECTED")

    print()
    print("=" * 40)
    print("AES-256-GCM test: PASS")
    print("=" * 40)


if __name__ == "__main__":
    main()
