"""Password security: PBKDF2-HMAC-SHA256 hashing, salt generation,
strength analysis and constant-time verification.
"""

import hashlib
import hmac
import math
import os
import re

DEFAULT_ITERATIONS = 150000
PBKDF2_ALGO = "pbkdf2_sha256"

GUESSES_PER_SECOND = 10_000_000_000  # optimistic offline GPU/botnet rate


def generate_salt(length=16):
    """Generate a random salt encoded as hex."""
    return os.urandom(length).hex()


def hash_password(password, iterations=DEFAULT_ITERATIONS):
    """Hash a password with a fresh random salt.

    Storage format: pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "{}${}${}${}".format(PBKDF2_ALGO, iterations, salt.hex(), dk.hex())


def verify_password(password, stored_hash):
    """Constant-time verification of a password against a stored hash."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4:
            return False
        _algo, iterations, salt_hex, hash_hex = parts
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def password_strength(password):
    """Analyze a password and return score, label, entropy and crack time."""
    length = len(password)
    checks = {
        "length_8": length >= 8,
        "length_12": length >= 12,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    score = min(length, 24) * 2
    if checks["lowercase"]:
        score += 8
    if checks["uppercase"]:
        score += 8
    if checks["digit"]:
        score += 8
    if checks["symbol"]:
        score += 10
    if checks["uppercase"] and checks["lowercase"]:
        score += 6
    if checks["digit"] and checks["symbol"]:
        score += 6
    score = max(0, min(100, score))

    if score >= 85:
        level = "Very Strong"
    elif score >= 70:
        level = "Strong"
    elif score >= 50:
        level = "Fair"
    elif score >= 30:
        level = "Weak"
    else:
        level = "Very Weak"

    pool = 0
    if checks["lowercase"]:
        pool += 26
    if checks["uppercase"]:
        pool += 26
    if checks["digit"]:
        pool += 10
    if checks["symbol"]:
        pool += 32
    if pool == 0:
        pool = 1
    entropy = length * math.log2(pool) if length else 0
    seconds = (2 ** entropy) / GUESSES_PER_SECOND

    return {
        "score": score,
        "level": level,
        "entropy": round(entropy, 1),
        "crack_time": _human_time(seconds),
        "checks": checks,
    }


def _human_time(seconds):
    if seconds < 1:
        return "Instantly"
    units = [
        ("century", 3153600000),
        ("year", 31536000),
        ("month", 2592000),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, size in units:
        if seconds >= size:
            value = int(seconds / size)
            return "{} {}".format(value, name if value == 1 else name + "s")
    return "Instantly"
