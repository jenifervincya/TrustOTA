"""
TrustOTA - Key Generation
Generates an Ed25519 key pair for a given role.

Uptane's key hierarchy has multiple roles (root, targets, snapshot, timestamp).
For this project we use a simplified two-tier model:
  - ROOT key   : offline, highest trust, signs/rotates the image-signing key (not used to sign firmware directly)
  - IMAGE key  : signs firmware metadata (hash, version, size) for each release

Usage:
    python keygen.py root
    python keygen.py image
"""

import sys
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")


def generate_keypair(role: str):
    if role not in ("root", "image"):
        raise ValueError("role must be 'root' or 'image'")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    os.makedirs(KEY_DIR, exist_ok=True)
    priv_path = os.path.join(KEY_DIR, f"{role}_private.key")
    pub_path = os.path.join(KEY_DIR, f"{role}_public.key")

    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    print(f"[keygen] {role} key pair generated")
    print(f"  private -> {priv_path} ({len(priv_bytes)} bytes)")
    print(f"  public  -> {pub_path} ({len(pub_bytes)} bytes)")
    return priv_path, pub_path


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("root", "image"):
        print("Usage: python keygen.py [root|image]")
        sys.exit(1)
    generate_keypair(sys.argv[1])
