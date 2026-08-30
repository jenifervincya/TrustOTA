"""
TrustOTA - Payload Compression

bsdiff4 already produces a small patch (it's diffing, not the full
image), but the patch bytes themselves still have compressible
structure (the control stream especially - lots of small repeated
integers encoding copy/insert lengths). Running zlib over the patch on
top of the diff step gets a further reduction essentially for free -
this is exactly what real embedded OTA systems (e.g. Android's
block-based OTA) do: diff, THEN compress the diff.

This is a separate, optional layer on top of diff_module/create_diff.py
and apply_patch.py:

    old fw, new fw --[bsdiff]--> patch.bin --[compress]--> patch.bin.z

On the ECU side this reverses cleanly:

    patch.bin.z --[decompress]--> patch.bin --[bsdiff apply]--> new fw

Compression level 9 (max) is used since these are small embedded
patches (tens of KB) - the extra CPU time is negligible and this
mostly runs on a comparatively powerful build server anyway, not the
ECU. Decompression on the ECU side is cheap regardless of level.
"""

import os
import zlib

COMPRESSION_METHOD = "zlib"
COMPRESSION_LEVEL = 9


def compress_patch(patch_path: str, out_path: str = None) -> tuple:
    """Compress a bsdiff patch file. Returns (out_path, original_size, compressed_size)."""
    out_path = out_path or f"{patch_path}.z"

    with open(patch_path, "rb") as f:
        raw = f.read()

    compressed = zlib.compress(raw, COMPRESSION_LEVEL)

    with open(out_path, "wb") as f:
        f.write(compressed)

    original_size = len(raw)
    compressed_size = len(compressed)
    reduction = 100 * (1 - compressed_size / original_size) if original_size else 0

    print(f"[compress] patch (uncompressed) : {original_size} bytes")
    print(f"[compress] patch (compressed)   : {compressed_size} bytes -> {out_path}")
    print(f"[compress] additional reduction : {reduction:.1f}% on top of the diff itself")

    return out_path, original_size, compressed_size


def compress_patch_if_beneficial(patch_path: str, out_path: str = None) -> tuple:
    """
    Compress the patch, but only actually ship the compressed version
    if it's smaller. bsdiff patches on high-entropy data (or already
    tightly packed control streams) can end up marginally LARGER after
    zlib overhead - shipping a "compressed" patch that's bigger than
    the original would be a real bug, not just a missed optimization.

    Returns (path_to_ship, compression_method, original_size, shipped_size)
    where compression_method is "zlib" or "none".
    """
    compressed_path, original_size, compressed_size = compress_patch(patch_path, out_path)

    if compressed_size < original_size:
        return compressed_path, "zlib", original_size, compressed_size

    print(f"[compress] compression didn't help here ({compressed_size} >= {original_size}) "
          f"- shipping the raw patch instead")
    return patch_path, "none", original_size, original_size


def decompress_patch(compressed_path: str, out_path: str) -> str:
    """Decompress a .z patch back into the raw bsdiff patch bytes bsdiff4 expects."""
    with open(compressed_path, "rb") as f:
        compressed = f.read()

    raw = zlib.decompress(compressed)

    with open(out_path, "wb") as f:
        f.write(raw)

    print(f"[decompress] reconstructed raw patch -> {out_path} ({len(raw)} bytes)")
    return out_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3 or sys.argv[1] not in ("compress", "decompress"):
        print("Usage: python compress_utils.py compress <patch.bin>")
        print("       python compress_utils.py decompress <patch.bin.z>")
        sys.exit(1)

    if sys.argv[1] == "compress":
        compress_patch(sys.argv[2])
    else:
        decompress_patch(sys.argv[2], sys.argv[2].removesuffix(".z"))
