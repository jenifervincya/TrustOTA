"""
TrustOTA - Hash utility (local copy for diff_module).

Kept identical to crypto_module/hash_utils.py. Duplicated intentionally
so diff_module has no import dependency on crypto_module - the two are
meant to be independently testable, and get wired together later in
the top-level OTA pipeline / update_package.py.
"""

import hashlib


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
