"""
TrustOTA - End-to-end demo of the crypto/authenticity module.

Simulates:
  1. Generating root + image keys
  2. Root delegating trust to image key
  3. Signing a firmware release
  4. Verifying it on the "ECU" side -> should ACCEPT
  5. Tampering with the firmware -> should REJECT
"""

import os
import shutil
from keygen import generate_keypair
from sign_metadata import delegate_image_key, sign_release
from verify import full_verification

BASE = os.path.dirname(__file__)
FW_DIR = os.path.join(BASE, "firmware_samples")


def make_fake_firmware(path: str, content: bytes):
    with open(path, "wb") as f:
        f.write(content)


def main():
    print("=" * 60)
    print("STEP 1: Generate keys")
    print("=" * 60)
    generate_keypair("root")
    generate_keypair("image")

    print("\n" + "=" * 60)
    print("STEP 2: Root delegates trust to image key")
    print("=" * 60)
    delegation_path = delegate_image_key()

    print("\n" + "=" * 60)
    print("STEP 3: Create + sign a firmware release (v1.2.0, STM32 ECU)")
    print("=" * 60)
    os.makedirs(FW_DIR, exist_ok=True)
    fw_path = os.path.join(FW_DIR, "firmware_v1.2.0.bin")
    make_fake_firmware(fw_path, os.urandom(4096))  # stand-in for a real .bin
    release_path = sign_release(fw_path, version="1.2.0", ecu_target="stm32_nucleo_f411re")

    print("\n" + "=" * 60)
    print("STEP 4: ECU-side verification of a GENUINE update")
    print("=" * 60)
    ok = full_verification(delegation_path, release_path, fw_path)
    print(f"\n>>> Result: {'ACCEPTED' if ok else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("STEP 5: Simulate tampering — flip a byte in the firmware")
    print("=" * 60)
    tampered_path = os.path.join(FW_DIR, "firmware_v1.2.0_tampered.bin")
    shutil.copy(fw_path, tampered_path)
    with open(tampered_path, "r+b") as f:
        f.seek(0)
        b = f.read(1)
        f.seek(0)
        f.write(bytes([b[0] ^ 0xFF]))  # flip bits of first byte

    ok2 = full_verification(delegation_path, release_path, tampered_path)
    print(f"\n>>> Result: {'ACCEPTED' if ok2 else 'REJECTED'}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Genuine firmware  -> {'ACCEPTED (correct)' if ok else 'REJECTED (WRONG)'}")
    print(f"Tampered firmware -> {'REJECTED (correct)' if not ok2 else 'ACCEPTED (WRONG)'}")


if __name__ == "__main__":
    main()
