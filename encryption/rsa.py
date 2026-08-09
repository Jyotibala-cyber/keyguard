"""RSA public/private key generation, encryption and decryption.

Uses the `cryptography` library with RSA-OAEP (SHA-256) padding, which is
IND-CCA2 secure and the recommended modern RSA scheme.
"""

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_SIZES = (1024, 2048, 4096)
# Maximum plaintext bytes for RSA-OAEP with SHA-256 for a given modulus size.
MAX_PLAINTEXT = {1024: 62, 2048: 190, 4096: 446}
DEFAULT_KEY_SIZE = 2048


def generate_keypair(bits=DEFAULT_KEY_SIZE):
    """Generate an RSA key pair and return (private_pem, public_pem)."""
    if bits not in RSA_KEY_SIZES:
        raise ValueError("RSA key size must be 1024, 2048 or 4096 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return priv_pem, pub_pem


def _load_public(pub_pem):
    try:
        return serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    except Exception:
        raise ValueError("Invalid public key (expected PEM format)")


def _load_private(priv_pem):
    try:
        return serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
    except Exception:
        raise ValueError("Invalid private key (expected PEM format)")


def _oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_data(pub_pem, data):
    """Encrypt str/bytes with a public key. Returns base64 ciphertext."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    pub = _load_public(pub_pem)
    limit = MAX_PLAINTEXT.get(getattr(pub, "key_size", DEFAULT_KEY_SIZE), 190)
    try:
        ct = pub.encrypt(data, _oaep())
    except ValueError:
        raise ValueError(
            "Plaintext too long for this RSA key — max {} bytes "
            "(use hybrid encryption for larger data)".format(limit)
        )
    return base64.b64encode(ct).decode("utf-8")


def decrypt_data(priv_pem, ct_b64):
    """Decrypt base64 ciphertext with a private key. Returns str."""
    priv = _load_private(priv_pem)
    try:
        ct = base64.b64decode(ct_b64)
    except Exception:
        raise ValueError("Ciphertext is not valid base64")
    try:
        pt = priv.decrypt(ct, _oaep())
    except ValueError:
        raise ValueError("Decryption failed — wrong private key or corrupted data")
    return pt.decode("utf-8")


def public_key_info(pub_pem):
    """Return metadata for a public key (algorithm, size, fingerprint)."""
    pub = _load_public(pub_pem)
    return {
        "algorithm": "RSA",
        "key_size": getattr(pub, "key_size", 0),
    }
