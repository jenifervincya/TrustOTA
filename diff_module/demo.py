"""
TrustOTA - Differential Update Packaging: End-to-end demo

Simulates:
  1. An "old" firmware image (v1.2.0) and a "new" one (v1.3.0) that
     shares most of its bytes with the old one (realistic: firmware
     updates usually change a small fraction of the binary)
  2. Creating a binary diff/patch between them
  3. Packaging the patch (compressed) with version-compatibility metadata
  4. ECU-side: checking compatibility against its running firmware
     -> should PASS when running the correct base version
     -> should FAIL when running a different/unexpected version
  5. ECU-side: extracting (decompressing) and applying the patch to
     reconstruct v1.3.0, confirming the reconstructed image matches
     the expected hash
"""

import os
from create_diff import create_diff
from apply_patch import apply_patch
from update_package import build_package, check_compatibility, extract_package
from hash_utils_local import sha256_file

BASE = os.path.dirname(__file__)
FW_DIR = os.path.join(BASE, "firmware_versions")


def make_firmware(path, base_content, mutate_fraction=0.05):
    """Create firmware that's mostly base_content with a small % of bytes changed,
    simulating a realistic small incremental update."""
    import random
    data = bytearray(base_content)
    n_mutate = int(len(data) * mutate_fraction)
    random.seed(42)
    for _ in range(n_mutate):
        idx = random.randrange(len(data))
        data[idx] = random.randrange(256)
    with open(path, "wb") as f:
        f.write(data)


def main():
    os.makedirs(FW_DIR, exist_ok=True)

    print("=" * 60)
    print("STEP 1: Create realistic old/new firmware pair (v1.2.0 -> v1.3.0)")
    print("=" * 60)
    old_path = os.path.join(FW_DIR, "firmware_v1.2.0.bin")
    new_path = os.path.join(FW_DIR, "firmware_v1.3.0.bin")

    base = os.urandom(65536)  # 64KB stand-in firmware image
    with open(old_path, "wb") as f:
        f.write(base)
    make_firmware(new_path, base, mutate_fraction=0.05)  # 5% of bytes changed

    print(f"old firmware: {os.path.getsize(old_path)} bytes")
    print(f"new firmware: {os.path.getsize(new_path)} bytes")

    print("\n" + "=" * 60)
    print("STEP 2: Create binary diff/patch")
    print("=" * 60)
    patch_path = create_diff(old_path, new_path, "v1.2.0_to_v1.3.0.patch")

    print("\n" + "=" * 60)
    print("STEP 3: Build update package (.toup) with version metadata + compression")
    print("=" * 60)
    pkg_path = build_package(
        old_path, new_path, patch_path,
        ecu_target="stm32_nucleo_f411re",
        base_version="1.2.0",
        target_version="1.3.0",
    )

    print("\n" + "=" * 60)
    print("STEP 4a: ECU running the CORRECT base version -> compatibility check")
    print("=" * 60)
    ok = check_compatibility(pkg_path, old_path)

    print("\n" + "=" * 60)
    print("STEP 4b: ECU running a DIFFERENT/unexpected version -> compatibility check")
    print("=" * 60)
    wrong_version_path = os.path.join(FW_DIR, "firmware_v1.1.0_unexpected.bin")
    make_firmware(wrong_version_path, base, mutate_fraction=0.08)
    ok_wrong = check_compatibility(pkg_path, wrong_version_path)

    print("\n" + "=" * 60)
    print("STEP 5: Extract (decompress) + apply patch on ECU (only proceeds because 4a passed)")
    print("=" * 60)
    if ok:
        extract_dir = os.path.join(BASE, "extracted")
        manifest, extracted_patch_path = extract_package(pkg_path, extract_dir)
        reconstructed_path = os.path.join(FW_DIR, "firmware_v1.3.0_reconstructed.bin")
        apply_patch(old_path, extracted_patch_path, reconstructed_path)

        actual_hash = sha256_file(reconstructed_path)
        expected_hash = manifest["target_sha256"]
        match = actual_hash == expected_hash
        print(f"\nreconstructed matches expected v1.3.0 hash: {match}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    import zipfile, json as _json
    with zipfile.ZipFile(pkg_path) as zf:
        pkg_manifest = _json.loads(zf.read("manifest.json"))
    new_size = os.path.getsize(new_path)
    uncompressed_patch_size = pkg_manifest["patch_size_uncompressed"]
    shipped_patch_size = pkg_manifest["patch_size"]
    method = pkg_manifest["compression"]
    print(f"Full image size            : {new_size} bytes")
    print(f"Raw bsdiff patch           : {uncompressed_patch_size} bytes ({100*uncompressed_patch_size/new_size:.1f}% of full image)")
    print(f"Shipped patch (method={method}) : {shipped_patch_size} bytes ({100*shipped_patch_size/new_size:.1f}% of full image)")
    if method == "zlib":
        print(f"Compression saved an extra : {100*(1 - shipped_patch_size/uncompressed_patch_size):.1f}% on top of the diff")
    else:
        print(f"Compression skipped - raw patch was already smaller (typical for high-entropy test data)")
    print(f"Correct-version check      : {'PASS (correct)' if ok else 'FAIL (WRONG)'}")
    print(f"Wrong-version check        : {'FAIL (correct)' if not ok_wrong else 'PASS (WRONG)'}")
    if ok:
        print(f"Patch application          : {'reconstructed image matches (correct)' if match else 'MISMATCH (WRONG)'}")


if __name__ == "__main__":
    main()
