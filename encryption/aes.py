"""AES-256 authenticated encryption using PyCryptodome (GCM mode).

GCM mode provides both confidentiality and integrity/authenticity of the data
through an authentication tag, so tampered ciphertext is rejected on decrypt.
"""

import os
import base64

from Crypto.Cipher import AES

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024


def generate_key(bits=256):
    """Generate a cryptographically secure random AES key, base64 encoded."""
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256 bits")
    key = os.urandom(bits // 8)
    return base64.b64encode(key).decode("ascii")


def key_bytes(key_b64):
    """Decode and validate a base64 AES key (16/24/32 bytes)."""
    try:
        kb = base64.b64decode(key_b64)
    except Exception as exc:
        raise ValueError("Key is not valid base64") from exc
    if len(kb) not in (16, 24, 32):
        raise ValueError("Key must decode to 16, 24 or 32 bytes (128/192/256-bit AES)")
    return kb


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def encrypt_text(key_b64, plaintext):
    """Encrypt a UTF-8 string. Returns base64 of nonce + tag + ciphertext."""
    key = key_bytes(key_b64)
    nonce = os.urandom(GCM_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return _b64(nonce + tag + ct)


def decrypt_text(key_b64, payload_b64):
    """Decrypt output of encrypt_text. Raises ValueError on bad key/data."""
    key = key_bytes(key_b64)
    try:
        payload = base64.b64decode(payload_b64)
    except Exception as exc:
        raise ValueError("Ciphertext is not valid base64") from exc
    if len(payload) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
        raise ValueError("Ciphertext is too short or corrupted")
    nonce = payload[:GCM_NONCE_SIZE]
    tag = payload[GCM_NONCE_SIZE:GCM_NONCE_SIZE + GCM_TAG_SIZE]
    ct = payload[GCM_NONCE_SIZE + GCM_TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ct, tag).decode("utf-8")
    except ValueError:
        raise ValueError("Decryption failed — wrong key or corrupted data")


def encrypt_file(key_b64, in_stream, out_stream):
    """Encrypt a binary stream (chunked, memory safe). Writes nonce + ct + tag."""
    key = key_bytes(key_b64)
    nonce = os.urandom(GCM_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    out_stream.write(nonce)
    while True:
        chunk = in_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        out_stream.write(cipher.encrypt(chunk))
    out_stream.write(cipher.digest())


def decrypt_file(key_b64, in_stream, out_stream):
    """Decrypt a stream produced by encrypt_file. Raises ValueError on bad key/data."""
    key = key_bytes(key_b64)
    nonce = in_stream.read(GCM_NONCE_SIZE)
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("File is corrupted (missing nonce header)")
    data = in_stream.read()
    if len(data) < GCM_TAG_SIZE:
        raise ValueError("File is corrupted (missing authentication tag)")
    tag, ct = data[-GCM_TAG_SIZE:], data[:-GCM_TAG_SIZE]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        out_stream.write(cipher.decrypt_and_verify(ct, tag))
    except ValueError:
        raise ValueError("Decryption failed — wrong key or corrupted file")
