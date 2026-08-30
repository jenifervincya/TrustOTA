"""
TrustOTA - Key Rotation Demo

Shows the full lifecycle:
  1. Sign a release with the CURRENT (v1) image key -> verify ACCEPT
  2. Rotate the image key -> v1 is now revoked, v2 is delegated
  3. Try to verify a release signed by v1 against the CURRENT
     delegation -> should REJECT (key no longer trusted, explicitly
     flagged as revoked, not just "wrong key")
  4. Sign + verify a release with the NEW (v2) key -> ACCEPT, proving
     rotation didn't break anything going forward
  5. Root key rotation -> cross-signed continuity check
"""

import os

from keygen import generate_keypair
from sign_metadata import delegate_image_key, sign_release
from verify import full_verification
from key_rotation import rotate_image_key, rotate_root_key, verify_root_rotation

BASE = os.path.dirname(__file__)
FW_DIR = os.path.join(BASE, "firmware_samples")
META_DIR = os.path.join(BASE, "metadata")
DELEGATION_PATH = os.path.join(META_DIR, "delegation.json")


def main():
    print("=" * 60)
    print("SETUP: fresh root + image keys, initial delegation")
    print("=" * 60)
    generate_keypair("root")
    generate_keypair("image")
    delegate_image_key()

    os.makedirs(FW_DIR, exist_ok=True)
    fw_path = os.path.join(FW_DIR, "firmware_v1.0.0.bin")
    with open(fw_path, "wb") as f:
        f.write(os.urandom(4096))

    print("\n" + "=" * 60)
    print("STEP 1: sign + verify a release with the ORIGINAL (v1) image key")
    print("=" * 60)
    release_v1_path = sign_release(fw_path, version="1.0.0", ecu_target="stm32_nucleo_f411re")
    ok_v1_before_rotation = full_verification(DELEGATION_PATH, release_v1_path, fw_path)
    print(f">>> Result: {'ACCEPTED' if ok_v1_before_rotation else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("STEP 2: ROTATE the image key")
    print("=" * 60)
    rotate_image_key()

    print("\n" + "=" * 60)
    print("STEP 3: re-check the OLD (v1) release against the CURRENT delegation")
    print("=" * 60)
    print("(v1 release still exists on disk with its original signature - this")
    print(" simulates a package that was built before rotation but arrives late)")
    ok_v1_after_rotation = full_verification(DELEGATION_PATH, release_v1_path, fw_path)
    print(f">>> Result: {'ACCEPTED' if ok_v1_after_rotation else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("STEP 4: sign + verify a NEW release with the NEW (v2) image key")
    print("=" * 60)
    fw2_path = os.path.join(FW_DIR, "firmware_v1.1.0.bin")
    with open(fw2_path, "wb") as f:
        f.write(os.urandom(4096))
    release_v2_path = sign_release(fw2_path, version="1.1.0", ecu_target="stm32_nucleo_f411re")
    ok_v2 = full_verification(DELEGATION_PATH, release_v2_path, fw2_path)
    print(f">>> Result: {'ACCEPTED' if ok_v2 else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("STEP 5: ROTATE the root key (cross-signed continuity)")
    print("=" * 60)
    rotate_root_key()
    root_rotation_valid = verify_root_rotation()
    print(f">>> Old root vouches for new root: {'VALID' if root_rotation_valid else 'INVALID'}")

    print("\n" + "=" * 60)
    print("STEP 6: confirm v2 image key still works under the NEW root")
    print("=" * 60)
    ok_v2_after_root_rotation = full_verification(DELEGATION_PATH, release_v2_path, fw2_path)
    print(f">>> Result: {'ACCEPTED' if ok_v2_after_root_rotation else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"v1 key, before rotation           -> {'ACCEPTED (correct)' if ok_v1_before_rotation else 'REJECTED (WRONG)'}")
    print(f"v1 key, after rotation (stale pkg) -> {'REJECTED (correct)' if not ok_v1_after_rotation else 'ACCEPTED (WRONG)'}")
    print(f"v2 key, right after rotation       -> {'ACCEPTED (correct)' if ok_v2 else 'REJECTED (WRONG)'}")
    print(f"root rotation cross-signature      -> {'VALID (correct)' if root_rotation_valid else 'INVALID (WRONG)'}")
    print(f"v2 key, after root rotation too    -> {'ACCEPTED (correct)' if ok_v2_after_root_rotation else 'REJECTED (WRONG)'}")


if __name__ == "__main__":
    main()
