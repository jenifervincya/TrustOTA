"""
TrustOTA - Differential Update: Diff Creation

Generates a binary patch (delta) between an OLD firmware image and a
NEW firmware image, using bsdiff (the same class of algorithm used by
Chrome, Android, and most real-world OTA systems for binary diffing).

Instead of shipping the full new firmware image over the air, we ship
this much smaller patch. The ECU already has the old image; applying
the patch reconstructs the new one locally.
"""

import os
import bsdiff4

OUT_DIR = os.path.join(os.path.dirname(__file__), "patches")


def create_diff(old_path: str, new_path: str, patch_name: str) -> str:
    """Create a binary patch that transforms old_path's content into new_path's content."""
    os.makedirs(OUT_DIR, exist_ok=True)
    patch_path = os.path.join(OUT_DIR, patch_name)

    bsdiff4.file_diff(old_path, new_path, patch_path)

    old_size = os.path.getsize(old_path)
    new_size = os.path.getsize(new_path)
    patch_size = os.path.getsize(patch_path)

    print(f"[create_diff] old firmware  : {old_size} bytes")
    print(f"[create_diff] new firmware  : {new_size} bytes")
    print(f"[create_diff] patch created : {patch_size} bytes -> {patch_path}")
    print(f"[create_diff] size reduction: {100 * (1 - patch_size / new_size):.1f}% vs shipping full image")

    return patch_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python create_diff.py <old_firmware> <new_firmware> <patch_output_name>")
        sys.exit(1)

    create_diff(sys.argv[1], sys.argv[2], sys.argv[3])
