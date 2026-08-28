"""
TrustOTA - Full OTA Release Pipeline (Server / Update-Server side)

Ties together diff_module + crypto_module into the actual release flow:

    old firmware + new firmware
        -> diff_module: create binary patch
        -> diff_module: wrap patch + version metadata into a .toup package
        -> crypto_module: SIGN the package manifest with the image key
        -> output: a signed .toup ready to publish to an update server

This mirrors Uptane's Image Repository role: it's the trusted party
that produces a signed statement about what a "target" (here, an
update package) is, so the ECU never has to trust the transport layer
(server, network) - it only has to trust the signature.

Run crypto_module's keygen.py + sign_metadata.py (delegate step) at
least once before using this, so keys/ and metadata/delegation.json
already exist.
"""

import os
import sys
import json
import hashlib
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "crypto_module"))
sys.path.insert(0, os.path.join(BASE, "diff_module"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from create_diff import create_diff  # noqa: E402

CRYPTO_KEY_DIR = os.path.join(BASE, "crypto_module", "keys")
OUT_DIR = os.path.join(os.path.dirname(__file__), "signed_packages")


def _load_image_private() -> Ed25519PrivateKey:
    path = os.path.join(CRYPTO_KEY_DIR, "image_private.key")
    with open(path, "rb") as f:
        return Ed25519PrivateKey.from_private_bytes(f.read())


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_signed_release(
    old_firmware_path: str,
    new_firmware_path: str,
    ecu_target: str,
    base_version: str,
    target_version: str,
) -> str:
    print("=" * 60)
    print(f"Building signed release: {ecu_target} {base_version} -> {target_version}")
    print("=" * 60)

    # 1. Create the binary diff patch
    patch_name = f"{ecu_target}_{base_version}_to_{target_version}.patch"
    patch_path = create_diff(old_firmware_path, new_firmware_path, patch_name)

    # 2. Build the manifest (same fields as update_package.py, kept inline here
    #    so the manifest can be signed before zipping)
    manifest = {
        "ecu_target": ecu_target,
        "base_version": base_version,
        "base_sha256": _sha256_file(old_firmware_path),
        "target_version": target_version,
        "target_sha256": _sha256_file(new_firmware_path),
        "patch_size": os.path.getsize(patch_path),
        "compression": "none",
    }

    # 3. Sign the canonical manifest bytes with the image key
    image_priv = _load_image_private()
    payload = json.dumps(manifest, sort_keys=True).encode()
    signature = image_priv.sign(payload)

    signed_manifest = {
        "manifest": manifest,
        "signature": signature.hex(),
        "signed_by": "image",
    }

    # 4. Package everything: signed_manifest.json + patch.bin
    os.makedirs(OUT_DIR, exist_ok=True)
    pkg_name = f"{ecu_target}_{base_version}_to_{target_version}.signed.toup"
    pkg_path = os.path.join(OUT_DIR, pkg_name)

    with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("signed_manifest.json", json.dumps(signed_manifest, indent=2))
        zf.write(patch_path, arcname="patch.bin")

    print(f"\n[build_release] SIGNED package ready -> {pkg_path}")
    print(f"[build_release] patch size = {manifest['patch_size']} bytes")
    return pkg_path


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(
            "Usage: python build_release.py <old_fw> <new_fw> <ecu_target> "
            "<base_version> <target_version>"
        )
        sys.exit(1)

    build_signed_release(*sys.argv[1:])
