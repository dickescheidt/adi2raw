#!/usr/bin/env python3
"""Validate the reverse-order regression image.

Usage: check_out_of_order.py IMAGE EXPECTED_SIZE
"""
import struct
import sys

REGION = 256 * 1024
ORIGIN = 1 << 20


def main() -> None:
    path, expected = sys.argv[1], int(sys.argv[2])
    with open(path, "rb") as f:
        d = f.read()

    assert len(d) == expected, f"size {len(d)} != {expected}"
    assert d[510:512] == b"\x55\xaa", "protective MBR missing"
    assert d[512:520] == b"EFI PART", "primary GPT missing"
    last = len(d) // 512 - 1
    assert d[last * 512:last * 512 + 8] == b"EFI PART", "backup GPT missing"

    ents = d[1024:1024 + 128 * 128]
    live = [i for i in range(128) if any(ents[i * 128:(i + 1) * 128][:16])]
    assert len(live) == 1, f"expected 1 GPT entry, got {len(live)}"
    assert struct.unpack_from("<Q", ents, 32)[0] == 2048

    assert d[ORIGIN:ORIGIN + 3] == b"\xeb\x52\x90", "boot sector missing"
    assert d[ORIGIN + 3:ORIGIN + 11] == b"NTFS    ", "NTFS marker missing"
    assert d[ORIGIN + 512] == 0x10, "region 0 payload missing"
    for region in range(1, 8):
        off = ORIGIN + region * REGION
        assert d[off] == 0x10 + region, f"region {region} payload missing at {off}"
        assert d[off + REGION - 1] == 0x10 + region, f"region {region} truncated"

    print(f"{path}: OK ({len(d)} bytes, all 8 reversed regions at their disk offsets)")


if __name__ == "__main__":
    main()
