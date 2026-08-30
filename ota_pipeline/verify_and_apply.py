"""
TrustOTA - Full OTA Application Pipeline (ECU side)

This is the routine that would run ON THE ECU when a signed update
package arrives. THREE gates, all of which must pass before the new
firmware is ever written to the inactive A/B slot:

    GATE 1 - AUTHENTICITY   Is signed_manifest.json actually signed by
                             an image key that root delegated trust to?
                             (crypto_module logic)

    GATE 2 - COMPATIBILITY  Does the currently running firmware match
                             the base_sha256 this patch expects?
                             (diff_module logic - prevents corrupting
                             an ECU that's on the wrong version)

    GATE 3 - INTEGRITY      After applying the patch, does the
                             reconstructed image's hash match the
                             signed target_sha256?
                             (catches any corruption during patch
                             application itself)

Any single failure = REJECT, ECU stays on its current running image.
This fail-safe default (reject unless every check independently
passes) is the same posture Uptane and UNECE R156 both require.
"""

import os
import sys
import json
import hashlib
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "crypto_module"))
sys.path.insert(0, os.path.join(BASE, "diff_module"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
import bsdiff4  # noqa: E402

from rollback_manager import stage_update  # noqa: E402

CRYPTO_KEY_DIR = os.path.join(BASE, "crypto_module", "keys")
CRYPTO_META_DIR = os.path.join(BASE, "crypto_module", "metadata")


class PipelineRejected(Exception):
    pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_root_public() -> Ed25519PublicKey:
    with open(os.path.join(CRYPTO_KEY_DIR, "root_public.key"), "rb") as f:
        return Ed25519PublicKey.from_public_bytes(f.read())


def _trusted_image_key() -> Ed25519PublicKey:
    """GATE 1a: confirm the image key is validly delegated by root."""
    delegation_path = os.path.join(CRYPTO_META_DIR, "delegation.json")
    with open(delegation_path) as f:
        delegation = json.load(f)

    root_pub = _load_root_public()
    image_pub_bytes = bytes.fromhex(delegation["delegated_key"])
    signature = bytes.fromhex(delegation["signature"])

    try:
        root_pub.verify(signature, image_pub_bytes)
    except InvalidSignature:
        raise PipelineRejected("GATE 1 FAILED: image key delegation invalid - root does not trust this key")

    return Ed25519PublicKey.from_public_bytes(image_pub_bytes)


def apply_signed_update(package_path: str, running_firmware_path: str, output_path: str) -> bool:
    print("=" * 60)
    print(f"Applying update package: {os.path.basename(package_path)}")
    print("=" * 60)

    extract_dir = os.path.join(os.path.dirname(output_path), "_extracted")
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(package_path) as zf:
        zf.extractall(extract_dir)

    manifest_path = os.path.join(extract_dir, "signed_manifest.json")
    patch_path = os.path.join(extract_dir, "patch.bin")

    with open(manifest_path) as f:
        signed_manifest = json.load(f)

    manifest = signed_manifest["manifest"]
    signature = bytes.fromhex(signed_manifest["signature"])

    try:
        # --- GATE 1: AUTHENTICITY ---
        print("\n[GATE 1] Checking authenticity (signature chain)...")
        trusted_image_key = _trusted_image_key()
        payload = json.dumps(manifest, sort_keys=True).encode()
        try:
            trusted_image_key.verify(signature, payload)
        except InvalidSignature:
            raise PipelineRejected("GATE 1 FAILED: manifest signature invalid - reject, possible tampering")
        print(f"[GATE 1] PASS - package signed by trusted image key")
        print(f"          target: {manifest['ecu_target']} {manifest['base_version']} -> {manifest['target_version']}")

        # --- GATE 2: COMPATIBILITY ---
        print("\n[GATE 2] Checking version compatibility...")
        running_hash = _sha256_file(running_firmware_path)
        if running_hash != manifest["base_sha256"]:
            raise PipelineRejected(
                f"GATE 2 FAILED: running firmware does not match patch's expected base version\n"
                f"  expected: {manifest['base_sha256']}\n"
                f"  running : {running_hash}\n"
                f"  -> fall back to full-image update"
            )
        print(f"[GATE 2] PASS - running firmware matches expected base ({manifest['base_version']})")

        # --- Apply patch ---
        print("\n[APPLY] Reconstructing new firmware from patch...")
        bsdiff4.file_patch(running_firmware_path, output_path, patch_path)

        # --- GATE 3: INTEGRITY ---
        print("\n[GATE 3] Checking reconstructed image integrity...")
        reconstructed_hash = _sha256_file(output_path)
        if reconstructed_hash != manifest["target_sha256"]:
            raise PipelineRejected(
                f"GATE 3 FAILED: reconstructed image hash mismatch - patch application corrupted\n"
                f"  expected: {manifest['target_sha256']}\n"
                f"  actual  : {reconstructed_hash}\n"
                f"  -> discard reconstructed image, do NOT switch A/B slot"
            )
        print(f"[GATE 3] PASS - reconstructed image matches signed target hash")

        # --- STAGE FOR ROLLBACK-MONITORED BOOT ---
        # All 3 gates passing only proves the package is authentic and
        # intact - it says nothing about whether the firmware actually
        # runs. Hand off to rollback_manager: write to the inactive
        # slot, flip it active, and open a boot-attempt window. The
        # slot is only COMMITTED once it proves itself healthy at boot
        # (see rollback_manager.record_boot_attempt).
        print("\n[STAGE] Handing off to rollback manager (pending verified boot)...")
        stage_update(version=manifest["target_version"], sha256=manifest["target_sha256"])

        print("\n" + "=" * 60)
        print(f"ALL GATES PASSED - update ACCEPTED: {manifest['ecu_target']} -> v{manifest['target_version']}")
        print("Staged to inactive A/B slot, active on next boot - pending boot health check.")
        print("=" * 60)
        return True

    except PipelineRejected as e:
        print("\n" + "=" * 60)
        print(f"UPDATE REJECTED\n{e}")
        print("ECU remains on current running image (fail-safe default).")
        print("=" * 60)
        return False


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python verify_and_apply.py <signed_package.toup> <running_firmware> <output_path>")
        sys.exit(1)

    ok = apply_signed_update(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(0 if ok else 1)
