"""
TrustOTA - Metadata Signing

Two signing operations, mirroring Uptane's root -> targets trust chain:

1. delegate_image_key(): the offline ROOT key signs the IMAGE public key.
   This is the "root of trust" statement: "this image key is authorized
   to sign firmware releases." Root key never touches firmware directly.

2. sign_release(): the IMAGE key signs a metadata blob describing one
   firmware release (version, sha256 hash, size, timestamp). This is
   the artifact that actually ships with (or ahead of) an OTA update.
"""

import json
import os
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from hash_utils import sha256_file

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
META_DIR = os.path.join(os.path.dirname(__file__), "metadata")


def _load_private(role: str) -> Ed25519PrivateKey:
    with open(os.path.join(KEY_DIR, f"{role}_private.key"), "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def _load_public_bytes(role: str) -> bytes:
    with open(os.path.join(KEY_DIR, f"{role}_public.key"), "rb") as f:
        return f.read()


def delegate_image_key():
    """Root key signs the image public key -> delegation.json"""
    root_priv = _load_private("root")
    image_pub = _load_public_bytes("image")

    signature = root_priv.sign(image_pub)

    delegation = {
        "delegated_key": image_pub.hex(),
        "role": "image",
        "signature": signature.hex(),
        "signed_by": "root",
        "timestamp": int(time.time()),
    }

    os.makedirs(META_DIR, exist_ok=True)
    path = os.path.join(META_DIR, "delegation.json")
    with open(path, "w") as f:
        json.dump(delegation, f, indent=2)

    print(f"[sign_metadata] root delegated trust to image key -> {path}")
    return path


def sign_release(firmware_path: str, version: str, ecu_target: str):
    """Image key signs release metadata for a firmware binary."""
    image_priv = _load_private("image")

    fw_hash = sha256_file(firmware_path)
    fw_size = os.path.getsize(firmware_path)

    release = {
        "ecu_target": ecu_target,
        "version": version,
        "filename": os.path.basename(firmware_path),
        "sha256": fw_hash,
        "size_bytes": fw_size,
        "timestamp": int(time.time()),
    }

    # Sign the canonical JSON bytes of the release dict (sorted keys = deterministic)
    payload = json.dumps(release, sort_keys=True).encode()
    signature = image_priv.sign(payload)

    signed_release = {
        "signed": release,
        "signature": signature.hex(),
        "signed_by": "image",
    }

    os.makedirs(META_DIR, exist_ok=True)
    out_path = os.path.join(META_DIR, f"release_{ecu_target}_{version}.json")
    with open(out_path, "w") as f:
        json.dump(signed_release, f, indent=2)

    print(f"[sign_metadata] signed release metadata -> {out_path}")
    print(f"  ecu_target = {ecu_target}, version = {version}")
    print(f"  sha256     = {fw_hash}")
    return out_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python sign_metadata.py <firmware_path> <version> <ecu_target>")
        print("Or:    python sign_metadata.py delegate _ _   (to run delegation only)")
        sys.exit(1)

    if sys.argv[1] == "delegate":
        delegate_image_key()
    else:
        firmware_path, version, ecu_target = sys.argv[1], sys.argv[2], sys.argv[3]
        sign_release(firmware_path, version, ecu_target)
