#!/usr/bin/env python3
"""Verify a dumped image made by make_test_adi.py bigcluster.

Usage: python3 tests/check_bigcluster.py IMAGE EXPECTED_SIZE
"""
import sys

REGION = 256 * 1024
CLUSTER = 32768
ORIGIN = 2048 * 512  # hidden_sectors in the synthetic NTFS boot record


def expect(data: bytes, at: int, value: int, what: str) -> None:
    got = data[at]
    if got != value:
        sys.exit(f"FAIL: {what}: byte 0x{at:x} is 0x{got:02x}, expected 0x{value:02x}")


def expect_zeros(data: bytes, at: int, length: int, what: str) -> None:
    if any(data[at:at + length]):
        sys.exit(f"FAIL: {what}: bytes 0x{at:x}..0x{at + length:x} are not zero")


def main() -> None:
    path = sys.argv[1]
    size = int(sys.argv[2])
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != size:
        sys.exit(f"FAIL: {path} is {len(data)} bytes, expected {size}")

    # Boot sector from the first 32 KiB cluster.
    if data[ORIGIN + 510:ORIGIN + 512] != b"\x55\xaa":
        sys.exit("FAIL: NTFS boot sector missing at its LBA")
    if data[ORIGIN + 13] != 64:
        sys.exit("FAIL: sectors-per-cluster in boot record is not 64 (32 KiB)")

    expect(data, ORIGIN + CLUSTER, 0xA1, "first region, unit 1")
    expect_zeros(data, ORIGIN + 2 * CLUSTER, CLUSTER, "first region, unit 2 hole")
    expect(data, ORIGIN + 3 * CLUSTER, 0xA3, "first region, unit 3")
    expect_zeros(data, ORIGIN + 4 * CLUSTER, 2 * CLUSTER, "first region, units 4-5 hole")
    expect(data, ORIGIN + 6 * CLUSTER, 0xA6, "first region, unit 6")
    expect_zeros(data, ORIGIN + 7 * CLUSTER, CLUSTER, "first region, unit 7 hole")

    second = ORIGIN + REGION
    expect(data, second, 0xB0, "second region, unit 0")
    expect_zeros(data, second + CLUSTER, 6 * CLUSTER, "second region, units 1-6 hole")
    expect(data, second + 7 * CLUSTER, 0xB7, "second region, unit 7")

    print(f"{path}: OK ({size} bytes, sparse 32 KiB clusters)")


if __name__ == "__main__":
    main()
