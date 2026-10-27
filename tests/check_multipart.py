#!/usr/bin/env python3
"""Validate the four-partition regression image.

Usage: check_multipart.py IMAGE EXPECTED_SIZE
"""
import struct
import sys


def main() -> None:
    path, expected = sys.argv[1], int(sys.argv[2])
    with open(path, "rb") as f:
        d = f.read()
    assert len(d) == expected, f"size {len(d)} != {expected}"
    assert d[510:512] == b"\x55\xaa", "protective MBR signature missing"
    assert d[512:520] == b"EFI PART", "primary GPT header missing"

    ents = d[1024 : 1024 + 128 * 128]
    live = [ents[i * 128 : (i + 1) * 128] for i in range(128)
            if any(ents[i * 128 : (i + 1) * 128][:16])]
    assert len(live) == 4, f"expected 4 GPT entries, got {len(live)}"

    for n, off in enumerate([1 << 20, 2 << 20, 3 << 20, 4 << 20]):
        assert d[off + 3 : off + 11] == b"NTFS    ", f"partition {n} boot sector missing"
        assert d[off + 510 : off + 512] == b"\x55\xaa", f"partition {n} signature missing"
        hidden = struct.unpack_from("<I", d, off + 28)[0]
        assert hidden == 2048 + n * 2048, f"partition {n} hidden={hidden}"

    assert d[1310720] == 0xA0, "partition 1 data missing"
    assert d[(3 << 20) + 262144] == 0xA2, "partition 3 data missing"
    assert d[(2 << 20) + 262144] == 0, "zero cluster not preserved"
    assert d[(4 << 20) + 262144] == 0, "zero cluster not preserved"

    last = len(d) // 512 - 1
    assert d[last * 512 : last * 512 + 8] == b"EFI PART", "backup GPT missing"
    print(f"{path}: OK ({len(d)} bytes, 4 partitions, all boot sectors at their LBAs)")


if __name__ == "__main__":
    main()
