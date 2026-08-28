"""
TrustOTA - Hash Utilities
SHA-256 hashing for firmware image integrity checks.
"""

import hashlib


def sha256_file(filepath: str) -> str:
    """Return hex-encoded SHA-256 hash of a file, read in chunks (safe for large images)."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
