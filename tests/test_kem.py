import oqs


KEM_ALGORITHM = "ML-KEM-768"


def main():
    print(f"Testing {KEM_ALGORITHM}...")

    # Receiver membuat key pair.
    # Secret key disimpan di dalam object `receiver`.
    receiver = oqs.KeyEncapsulation(KEM_ALGORITHM)

    public_key = receiver.generate_keypair()
    secret_key = receiver.export_secret_key()

    print(f"Public key       : {len(public_key)} bytes")
    print(f"Secret key       : {len(secret_key)} bytes")

    # Sender menggunakan public key receiver
    # untuk melakukan encapsulation.
    sender = oqs.KeyEncapsulation(KEM_ALGORITHM)

    ciphertext, sender_secret = sender.encap_secret(public_key)

    print(f"KEM ciphertext   : {len(ciphertext)} bytes")
    print(f"Sender secret    : {len(sender_secret)} bytes")

    # Receiver menggunakan secret key yang masih tersimpan
    # di object receiver.
    receiver_secret = receiver.decap_secret(ciphertext)

    print(f"Receiver secret  : {len(receiver_secret)} bytes")

    # Kedua pihak harus memperoleh shared secret yang sama.
    assert sender_secret == receiver_secret

    print()
    print("=" * 40)
    print("ML-KEM-768 test: PASS")
    print("=" * 40)


if __name__ == "__main__":
    main()
