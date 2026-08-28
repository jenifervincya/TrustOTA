"""
TrustOTA - Differential Update: Patch Application

This runs ON THE ECU. Given the currently-running firmware (old) and a
received patch, reconstructs the new firmware image locally. This is
the inverse operation of create_diff.py.

In the real pipeline this reconstructed image would then be written to
the INACTIVE A/B slot and only switched to active after the crypto
verification gate (see crypto_module/verify.py) passes on it.
"""

import os
import bsdiff4
from hash_utils_local import sha256_file  # local copy to keep module self-contained


def apply_patch(old_path: str, patch_path: str, output_path: str) -> str:
    """Reconstruct the new firmware image by applying patch_path to old_path."""
    bsdiff4.file_patch(old_path, output_path, patch_path)

    print(f"[apply_patch] reconstructed firmware -> {output_path}")
    print(f"[apply_patch] reconstructed sha256    : {sha256_file(output_path)}")
    return output_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python apply_patch.py <old_firmware> <patch_file> <output_firmware>")
        sys.exit(1)

    apply_patch(sys.argv[1], sys.argv[2], sys.argv[3])
