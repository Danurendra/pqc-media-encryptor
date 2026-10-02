import oqs

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEM_ALGORITHM = "ML-KEM-768"

HKDF_INFO = b"pqc-media-encryptor-content-key"


def derive_content_key(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 key from the ML-KEM shared secret.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )

    return hkdf.derive(shared_secret)


def generate_keypair(seed: bytes):
    """
    Generate a deterministic ML-KEM-768 keypair.

    The seed is supplied externally by the key-management layer.
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    public_key = kem.generate_keypair_seed(seed)

    secret_key = kem.export_secret_key()

    return public_key, secret_key


def encapsulate(public_key: bytes):
    """
    Encapsulate a shared secret using the recipient public key.
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    ciphertext, shared_secret = kem.encap_secret(
        public_key
    )

    return ciphertext, shared_secret


def decapsulate(secret_key: bytes, ciphertext: bytes):
    """
    Decapsulate a KEM ciphertext.

    NOTE:
    The installed liboqs-python API does not expose
    import_secret_key(). This function is therefore not
    implemented yet until we establish the correct
    secret-key restoration mechanism.
    """

    raise NotImplementedError(
        "Secret-key restoration must be implemented "
        "using the supported liboqs-python API."
    )


def encrypt_data(
    plaintext: bytes,
    content_key: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    """

    aesgcm = AESGCM(content_key)

    return aesgcm.encrypt(
        nonce,
        plaintext,
        aad,
    )


def decrypt_data(
    ciphertext: bytes,
    content_key: bytes,
    nonce: bytes,
    aad: bytes,
) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    """

    aesgcm = AESGCM(content_key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        aad,
    )
