"""Hash generation and file integrity checking.

Supports SHA-256, SHA-512 and MD5 (plus SHA-1) for compatibility. Hashes are
computed chunked so arbitrarily large files can be processed.
"""

import hashlib

ALLOWED_ALGOS = {"md5", "sha1", "sha256", "sha512"}
CHUNK_SIZE = 1024 * 1024


def _algo_hash(algo):
    algo = algo.lower()
    if algo not in ALLOWED_ALGOS:
        raise ValueError("Unsupported hash algorithm: {}".format(algo))
    return hashlib.new(algo)


def hash_text(data, algo):
    """Hex digest of a UTF-8 string."""
    h = _algo_hash(algo)
    h.update(data.encode("utf-8"))
    return h.hexdigest()


def hash_file(fileobj, algo):
    """Hex digest of a file stream, read in chunks."""
    h = _algo_hash(algo)
    while True:
        chunk = fileobj.read(CHUNK_SIZE)
        if not chunk:
            break
        h.update(chunk)
    return h.hexdigest()


def hashes_for_text(data):
    """Return every supported digest for a string (used by the analyzer)."""
    return {algo: hash_text(data, algo) for algo in sorted(ALLOWED_ALGOS)}


def hashes_for_file(fileobj):
    """Return every supported digest for a file stream (single pass)."""
    digesters = {algo: hashlib.new(algo) for algo in sorted(ALLOWED_ALGOS)}
    while True:
        chunk = fileobj.read(CHUNK_SIZE)
        if not chunk:
            break
        for h in digesters.values():
            h.update(chunk)
    return {algo: h.hexdigest() for algo, h in digesters.items()}
