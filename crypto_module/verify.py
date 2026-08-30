"""
TrustOTA - Verification Gate

This is the routine that (conceptually) runs ON THE ECU before an OTA
update is accepted into the inactive A/B slot. It is the piece that
will later be ported to C for STM32CubeIDE / Renesas FSP.

Checks, all must pass:
  1. Trust chain check  - is the image key actually delegated by root?
  2. Revocation check    - has that delegated image key been rotated
                            out and explicitly revoked? (defense in
                            depth against a stale/cached delegation
                            file still pointing at a retired key)
  3. Release check       - is the release metadata signed by that image
                            key, AND does the firmware's actual SHA-256
                            match what the signed metadata claims?

If any check fails, the update must be rejected and the ECU stays
on its current running slot (fail-safe default).
"""

import json
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from hash_utils import sha256_file
from key_rotation import is_key_revoked

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")


class VerificationError(Exception):
    pass


def _load_root_public() -> Ed25519PublicKey:
    with open(os.path.join(KEY_DIR, "root_public.key"), "rb") as f:
        return Ed25519PublicKey.from_public_bytes(f.read())


def verify_delegation(delegation_path: str) -> Ed25519PublicKey:
    """Check that the image key was validly delegated by root AND hasn't since been revoked. Returns the trusted image public key."""
    with open(delegation_path) as f:
        delegation = json.load(f)

    root_pub = _load_root_public()
    image_pub_bytes = bytes.fromhex(delegation["delegated_key"])
    signature = bytes.fromhex(delegation["signature"])

    try:
        root_pub.verify(signature, image_pub_bytes)
    except InvalidSignature:
        raise VerificationError("Delegation signature invalid — image key NOT trusted by root")

    if is_key_revoked(image_pub_bytes.hex(), role="image"):
        raise VerificationError("Delegated image key has been REVOKED (rotated out) — reject stale delegation")

    print("[verify] delegation OK — image key is trusted by root and not revoked")
    return Ed25519PublicKey.from_public_bytes(image_pub_bytes)


def verify_release(release_path: str, firmware_path: str, trusted_image_key: Ed25519PublicKey):
    """Check release metadata signature and that firmware hash matches."""
    with open(release_path) as f:
        signed_release = json.load(f)

    release = signed_release["signed"]
    signature = bytes.fromhex(signed_release["signature"])
    payload = json.dumps(release, sort_keys=True).encode()

    try:
        trusted_image_key.verify(signature, payload)
    except InvalidSignature:
        raise VerificationError("Release metadata signature invalid — reject update")

    print("[verify] release metadata signature OK")

    actual_hash = sha256_file(firmware_path)
    claimed_hash = release["sha256"]

    if actual_hash != claimed_hash:
        raise VerificationError(
            f"Hash mismatch — firmware may be corrupted or tampered.\n"
            f"  claimed : {claimed_hash}\n"
            f"  actual  : {actual_hash}"
        )

    print("[verify] firmware SHA-256 matches signed metadata")
    print(f"[verify] ACCEPT update: {release['ecu_target']} v{release['version']}")
    return True


def full_verification(delegation_path: str, release_path: str, firmware_path: str) -> bool:
    """Run the full gate sequence. Returns True if update should be accepted."""
    try:
        trusted_image_key = verify_delegation(delegation_path)
        verify_release(release_path, firmware_path, trusted_image_key)
        return True
    except VerificationError as e:
        print(f"[verify] REJECT update — {e}")
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python verify.py <delegation.json> <release.json> <firmware_path>")
        sys.exit(1)

    ok = full_verification(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(0 if ok else 1)
