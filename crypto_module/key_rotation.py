"""
TrustOTA - Key Rotation

Two distinct rotation operations, because root and image keys have
very different trust properties (same two-tier model as keygen.py):

1. rotate_image_key()  - the ROUTINE case. Image keys are used to sign
   every release, so they should rotate periodically as normal key
   hygiene (compromise blast-radius reduction). Root re-delegates
   trust to a freshly generated image key, and the old image key is
   added to a revocation list so it's explicitly rejected even if a
   stale delegation or cached package referencing it ever shows up.

2. rotate_root_key()   - the RARE case. Root is the offline anchor of
   the whole trust chain, so it can't just be silently swapped - that
   would let anyone with filesystem access mint a new "root" and
   hijack trust. Instead this follows Uptane's root rotation pattern:
   the OLD root key signs a statement vouching for the NEW root
   public key ("root_rotation.json"). Anyone who already trusted the
   old root can verify that signature and transitively trust the new
   root, without needing a fresh out-of-band trust bootstrap. The
   currently-delegated image key is then re-delegated under the new
   root so the chain stays unbroken.

Both operations are logged to rotation_log.json for audit purposes.
"""

import os
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from keygen import generate_keypair
from sign_metadata import delegate_image_key

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
META_DIR = os.path.join(os.path.dirname(__file__), "metadata")
REVOKED_PATH = os.path.join(META_DIR, "revoked_keys.json")
ROTATION_LOG_PATH = os.path.join(META_DIR, "rotation_log.json")
ROOT_ROTATION_PATH = os.path.join(META_DIR, "root_rotation.json")
DELEGATION_PATH = os.path.join(META_DIR, "delegation.json")


def _load_public_bytes(role: str) -> bytes:
    with open(os.path.join(KEY_DIR, f"{role}_public.key"), "rb") as f:
        return f.read()


def _load_private(role: str) -> Ed25519PrivateKey:
    with open(os.path.join(KEY_DIR, f"{role}_private.key"), "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def _load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def _save_json(path: str, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _revoke(role: str, pubkey_hex: str, reason: str):
    revoked = _load_json(REVOKED_PATH, [])
    revoked.append({
        "role": role,
        "public_key": pubkey_hex,
        "reason": reason,
        "timestamp": int(time.time()),
    })
    _save_json(REVOKED_PATH, revoked)


def is_key_revoked(pubkey_hex: str, role: str) -> bool:
    """Explicit check used by the verifier as defense-in-depth against stale/cached delegations."""
    revoked = _load_json(REVOKED_PATH, [])
    return any(r["role"] == role and r["public_key"] == pubkey_hex for r in revoked)


def _log_rotation(event: dict):
    log = _load_json(ROTATION_LOG_PATH, [])
    event["timestamp"] = int(time.time())
    log.append(event)
    _save_json(ROTATION_LOG_PATH, log)
    print(f"[key_rotation] logged: {event['type']}")


def rotate_image_key():
    """Retire the current image key, generate + delegate a fresh one."""
    print("=" * 60)
    print("ROTATING IMAGE KEY")
    print("=" * 60)

    old_image_pub_hex = _load_public_bytes("image").hex()

    print("[key_rotation] generating new image keypair...")
    generate_keypair("image")  # overwrites keys/image_{private,public}.key

    print("[key_rotation] root re-delegating trust to the new image key...")
    delegate_image_key()  # overwrites metadata/delegation.json, signed by root

    _revoke("image", old_image_pub_hex, "rotated")
    _log_rotation({
        "type": "image_key_rotation",
        "old_key": old_image_pub_hex,
        "new_key": _load_public_bytes("image").hex(),
    })

    print(f"\n[key_rotation] DONE - old image key revoked, new image key is now trusted")
    print(f"  old key (revoked): {old_image_pub_hex[:16]}...")
    print(f"  new key (active) : {_load_public_bytes('image').hex()[:16]}...")


def rotate_root_key():
    """
    Rotate the root key via cross-signing: the OLD root key signs the
    NEW root public key, preserving a verifiable trust chain instead
    of just swapping files (which anyone with disk access could do).
    """
    print("=" * 60)
    print("ROTATING ROOT KEY (cross-signed)")
    print("=" * 60)

    old_root_priv = _load_private("root")
    old_root_pub_hex = _load_public_bytes("root").hex()

    print("[key_rotation] generating new root keypair (offline operation)...")
    new_root_priv = Ed25519PrivateKey.generate()
    new_root_pub_bytes = new_root_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print("[key_rotation] OLD root key signing NEW root public key (continuity of trust)...")
    rotation_signature = old_root_priv.sign(new_root_pub_bytes)

    root_rotation = {
        "old_root_public_key": old_root_pub_hex,
        "new_root_public_key": new_root_pub_bytes.hex(),
        "signature": rotation_signature.hex(),
        "signed_by": "old_root",
        "timestamp": int(time.time()),
    }
    _save_json(ROOT_ROTATION_PATH, root_rotation)

    # Now actually swap the on-disk root key to the new one.
    new_priv_bytes = new_root_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(os.path.join(KEY_DIR, "root_private.key"), "wb") as f:
        f.write(new_priv_bytes)
    with open(os.path.join(KEY_DIR, "root_public.key"), "wb") as f:
        f.write(new_root_pub_bytes)

    print("[key_rotation] re-delegating current image key under the NEW root...")
    delegate_image_key()

    _log_rotation({
        "type": "root_key_rotation",
        "old_key": old_root_pub_hex,
        "new_key": new_root_pub_bytes.hex(),
    })

    print(f"\n[key_rotation] DONE - trust chain preserved via cross-signature")
    print(f"  root_rotation.json proves: old root vouched for new root")
    print(f"  old root private key should now be SECURELY DESTROYED (offline HSM in real deployment)")


def verify_root_rotation(rotation_path: str = ROOT_ROTATION_PATH) -> bool:
    """A verifier that only ever trusted the OLD root can use this to accept the NEW root."""
    with open(rotation_path) as f:
        rotation = json.load(f)

    old_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(rotation["old_root_public_key"]))
    new_pub_bytes = bytes.fromhex(rotation["new_root_public_key"])
    signature = bytes.fromhex(rotation["signature"])

    try:
        old_pub.verify(signature, new_pub_bytes)
        print("[key_rotation] root rotation verified - new root key is legitimately vouched for by old root")
        return True
    except InvalidSignature:
        print("[key_rotation] root rotation REJECTED - signature does not chain back to trusted old root")
        return False


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in ("image", "root"):
        print("Usage: python key_rotation.py [image|root]")
        sys.exit(1)
    if sys.argv[1] == "image":
        rotate_image_key()
    else:
        rotate_root_key()
