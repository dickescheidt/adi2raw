#!/usr/bin/env python3
"""Synthetic .adi with a perfectly ordered index that resolve_regions() mangles.

Six compressed blocks in three chain runs, separated by metadata gaps. The
raw region fields in the index records are strictly increasing (100000..100005)
-- i.e. the file is in perfect disk order. But resolve_regions() forces every
run head to the lowest unused region (0) and shifts the other values, producing
resolved regions like [0, 100000, 0, 100002, 0, 100004]. The resulting target
offsets oscillate by tens of GiB even though nothing in the .adi is scrambled.

This is a diagnostic fixture: `adi2raw info` on it must report
"raw yes, after resolve_regions no". Do not dump it (the disk is huge).

Usage: python3 make_gap_regions_adi.py OUTPUT.adi
"""
import struct
import sys

REGION = 256 * 1024
CLUSTER = 512
HDR = REGION // CLUSTER // 8
HIDDEN = 2048


def boot_sector() -> bytes:
    b = bytearray(CLUSTER)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, 512)
    b[13] = 1
    struct.pack_into("<H", b, 14, 1)
    struct.pack_into("<I", b, 28, HIDDEN)
    struct.pack_into("<Q", b, 40, 4096)
    struct.pack_into("<Q", b, 48, 16)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def block(cluster_bytes: bytes) -> bytes:
    bitmap = bytearray(HDR)
    bitmap[0] = 0x01
    return bytes(bitmap) + cluster_bytes


def lz4_literals(data: bytes) -> bytes:
    n = len(data)
    out = bytearray([min(n, 15) << 4])
    left = n - min(n, 15)
    if n >= 15:
        while left >= 255:
            out.append(255)
            left -= 255
        out.append(left)
    out += data
    return bytes(out)


def record(off, usize, csize, raw_region) -> bytes:
    return struct.pack("<QIIIIII", off, usize, csize, 0, 0, raw_region, 0)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "gap-regions.adi"

    raw_regions = [100000 + i for i in range(6)]
    comps = [
        lz4_literals(block(boot_sector() if i == 0 else bytes([0xC3]) * CLUSTER))
        for i in range(6)
    ]

    # Three runs of two blocks; 128 bytes of padding between runs creates a
    # gap in the compressed chain (end of one block != start of the next).
    payload = bytearray()
    offs = []
    for i, comp in enumerate(comps):
        if i and i % 2 == 0:
            payload += bytes(128)
        offs.append(len(payload))
        payload += comp

    index = bytearray()
    for i, (off, comp) in enumerate(zip(offs, comps)):
        index += record(off, HDR + CLUSTER, len(comp), raw_regions[i])
    payload += index
    payload += bytes(256)

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"

    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)
        f.write(footer)
    print(f"wrote {path} ({len(header) + len(payload) + len(footer)} bytes, "
          f"3 chain runs, raw regions {raw_regions[0]}..{raw_regions[-1]})")


if __name__ == "__main__":
    main()
