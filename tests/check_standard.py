#!/usr/bin/env python3
"""Verify a raw image produced from make_standard_adi.py.

Usage: python3 tests/check_standard.py IMAGE EXPECTED_SIZE
"""
import struct
import sys
import zlib

BPS = 512
SPC = 64
CLUSTER = BPS * SPC
PART_START = 2048
PART_SECTORS = 4096
ORIGIN = PART_START * BPS
TYPE_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
UNIQUE_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def expect(data: bytes, at: int, value: int, what: str) -> None:
    got = data[at]
    if got != value:
        sys.exit(f"FAIL: {what}: byte 0x{at:x} is 0x{got:02x}, expected 0x{value:02x}")


def expect_zeros(data: bytes, at: int, length: int, what: str) -> None:
    if any(data[at:at + length]):
        sys.exit(f"FAIL: {what}: bytes 0x{at:x}..0x{at + length:x} are not zero")


def main() -> None:
    path, size = sys.argv[1], int(sys.argv[2])
    with open(path, "rb") as f:
        d = f.read()
    if len(d) != size:
        sys.exit(f"FAIL: {path} is {len(d)} bytes, expected {size}")

    assert d[510:512] == b"\x55\xaa", "protective MBR signature missing"
    assert d[512:520] == b"EFI PART", "primary GPT header missing"
    hdr = bytearray(d[512:1024])
    stored = struct.unpack_from("<I", hdr, 16)[0]
    hdr[16:20] = b"\0" * 4
    assert zlib.crc32(bytes(hdr[:92])) & 0xFFFFFFFF == stored, "GPT header CRC bad"
    ents = d[1024 : 1024 + 128 * 128]
    assert zlib.crc32(ents) & 0xFFFFFFFF == struct.unpack_from("<I", hdr, 88)[0], \
        "GPT entry array CRC bad"

    e = ents[:128]
    assert e[:16] == TYPE_GUID, "recovered type GUID was not used"
    assert e[16:32] == UNIQUE_GUID, "recovered unique GUID was not used"
    first, last = struct.unpack_from("<QQ", e, 32)
    assert (first, last) == (PART_START, PART_START + PART_SECTORS - 1), \
        f"wrong partition LBA range: {first}..{last}"
    assert e[56:64] == "DATA".encode("utf-16le"), "recovered partition name missing"

    # Imported volume metadata must place the volume at its source-disk LBA.
    assert d[ORIGIN + 510 : ORIGIN + 512] == b"\x55\xaa", "boot sector missing"
    assert d[ORIGIN : ORIGIN + 11] == b"\xeb\x52\x90NTFS    ", "boot sector content wrong"

    # Region 0, block 0: bitmap 0x0f -> clusters 0..3 present.
    expect(d, ORIGIN + CLUSTER, 0xA1, "block 0 cluster 1")
    expect(d, ORIGIN + 2 * CLUSTER, 0xA2, "block 0 cluster 2")
    expect(d, ORIGIN + 3 * CLUSTER, 0xA3, "block 0 cluster 3")
    expect_zeros(d, ORIGIN + 4 * CLUSTER, 4 * CLUSTER, "block 0 clusters 4-7")

    # Region 0, block 1: bitmap 0x81 -> clusters 0 and 7 present.
    second = ORIGIN + 8 * CLUSTER
    expect(d, second, 0xB0, "block 1 cluster 0")
    expect_zeros(d, second + CLUSTER, 6 * CLUSTER, "block 1 clusters 1-6")
    expect(d, second + 7 * CLUSTER, 0xB7, "block 1 cluster 7")

    print(f"{path}: OK ({size} bytes, standard records, exact GPT metadata)")


if __name__ == "__main__":
    main()
