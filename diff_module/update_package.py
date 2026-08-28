"""
TrustOTA - Update Package Format

Defines the ".toup" (TrustOTA Update Package) format: a JSON manifest
describing which base version a patch applies to, what it produces,
and hashes for compatibility + integrity checking - PLUS the patch
bytes itself, packaged together as one file.

Why version compatibility matters:
A patch is only valid against the EXACT old firmware it was diffed
against. If an ECU is on a different version than expected (e.g. it
missed an update, or was rolled back), applying the wrong patch would
produce a corrupted image. So before applying, the ECU checks:
    sha256(currently_running_firmware) == manifest["base_sha256"]
If it doesn't match, the update is rejected and (ideally) a full-image
fallback is requested instead of a patch.

Package layout (a package is just a zip with two entries):
    manifest.json   - metadata below
    patch.bin       - the raw bsdiff patch bytes

manifest.json fields:
    ecu_target      - e.g. "stm32_nucleo_f411re"
    base_version    - version string the patch expects as input
    base_sha256     - sha256 of the expected old firmware
    target_version  - version string the patch produces
    target_sha256   - sha256 of the expected new firmware (post-patch)
    patch_size      - size of patch.bin in bytes
    compression     - compression used ("none" for now; bsdiff patches
                       are already fairly compact, but see note below)
"""

import os
import json
import zipfile

from hash_utils_local import sha256_file

PKG_DIR = os.path.join(os.path.dirname(__file__), "packages")


def build_package(
    old_firmware_path: str,
    new_firmware_path: str,
    patch_path: str,
    ecu_target: str,
    base_version: str,
    target_version: str,
) -> str:
    os.makedirs(PKG_DIR, exist_ok=True)

    manifest = {
        "ecu_target": ecu_target,
        "base_version": base_version,
        "base_sha256": sha256_file(old_firmware_path),
        "target_version": target_version,
        "target_sha256": sha256_file(new_firmware_path),
        "patch_size": os.path.getsize(patch_path),
        "compression": "none",
    }

    pkg_name = f"{ecu_target}_{base_version}_to_{target_version}.toup"
    pkg_path = os.path.join(PKG_DIR, pkg_name)

    with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        zf.write(patch_path, arcname="patch.bin")

    print(f"[package] built update package -> {pkg_path}")
    print(f"[package] {base_version} -> {target_version}, patch = {manifest['patch_size']} bytes")
    return pkg_path


def check_compatibility(pkg_path: str, running_firmware_path: str) -> bool:
    """ECU-side check: is this package valid to apply against the firmware currently running?"""
    with zipfile.ZipFile(pkg_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))

    running_hash = sha256_file(running_firmware_path)
    expected_hash = manifest["base_sha256"]

    if running_hash != expected_hash:
        print("[package] INCOMPATIBLE - running firmware does not match patch's expected base version")
        print(f"  expected base_sha256 : {expected_hash}")
        print(f"  running   sha256     : {running_hash}")
        print("  -> reject patch, fall back to full-image update")
        return False

    print(f"[package] COMPATIBLE - patch applies cleanly to running {manifest['base_version']}")
    return True


def extract_package(pkg_path: str, extract_dir: str):
    """Unpack manifest.json and patch.bin from a .toup package."""
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(pkg_path) as zf:
        zf.extractall(extract_dir)
    manifest_path = os.path.join(extract_dir, "manifest.json")
    patch_path = os.path.join(extract_dir, "patch.bin")
    with open(manifest_path) as f:
        manifest = json.load(f)
    return manifest, patch_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 7:
        print(
            "Usage: python update_package.py <old_fw> <new_fw> <patch_file> "
            "<ecu_target> <base_version> <target_version>"
        )
        sys.exit(1)

    build_package(*sys.argv[1:])
