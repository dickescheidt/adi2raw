#!/usr/bin/env python3
"""Sanity-check a raw disk image emitted by `adi2raw dump`.

Usage: check_raw.py IMAGE EXPECTED_SIZE [OFFSET=HEXBYTE ...]

The optional OFFSET=HEXBYTE pairs verify marker bytes left by the synthetic
test images, which is how out-of-order cluster placement is checked.
"""
import struct
import sys
import zlib


def main() -> None:
    path = sys.argv[1]
    expected = int(sys.argv[2])
    with open(path, "rb") as f:
        d = f.read()

    assert len(d) == expected, f"size {len(d)} != {expected}"
    assert d[510:512] == b"\x55\xaa", "missing protective MBR signature"
    assert d[512:520] == b"EFI PART", "missing primary GPT header"
    last = len(d) // 512 - 1
    assert d[last * 512:last * 512 + 8] == b"EFI PART", "missing backup GPT header"

    hdr = bytearray(d[512:1024])
    stored_hcrc = struct.unpack_from("<I", hdr, 16)[0]
    hdr[16:20] = b"\0" * 4
    assert zlib.crc32(bytes(hdr[:92])) & 0xFFFFFFFF == stored_hcrc, "bad GPT header CRC"

    ents = d[2 * 512:34 * 512]
    assert zlib.crc32(ents) & 0xFFFFFFFF == struct.unpack_from("<I", hdr, 88)[0], \
        "bad GPT entry array CRC"

    count = sum(1 for i in range(128) if any(ents[i * 128:i * 128 + 16]))
    assert count >= 1, "no partition entries"

    lba = struct.unpack_from("<Q", ents, 32)[0]
    off = lba * 512
    assert d[off + 3:off + 11] == b"NTFS    ", "missing NTFS boot sector at first volume"
    assert d[off + 510:off + 512] == b"\x55\xaa", "missing boot sector signature"

    for marker in sys.argv[3:]:
        o, _, hexbyte = marker.partition("=")
        assert d[int(o)] == int(hexbyte, 16), f"marker {marker} mismatch at {o}"

    print(f"{path}: OK ({len(d)} bytes, {count} GPT entries, first volume LBA {lba})")


if __name__ == "__main__":
    main()
