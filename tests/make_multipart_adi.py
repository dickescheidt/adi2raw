#!/usr/bin/env python3
"""Synthetic .adi reproducing a 4-partition disk backed up as ONE chain.

AOMEI writes all partitions into a single contiguous block-index run. The old
volume discovery split volumes only at gaps in that chain, so it found one
volume and clipped every cluster past the first partition's end.

Layout: four NTFS boot sectors at regions 0/4/8/12, hidden sectors
2048/4096/6144/8192 -> a constant 1 MiB stream origin. Two filler clusters
are deliberately all-zero to exercise sparse writing.

Usage: python3 tests/make_multipart_adi.py multipart.adi
"""
import struct
import sys

CLUSTER = 512
UNITS = 262144 // CLUSTER
HDR = UNITS // 8
TOTAL_SECTORS = 1024          # 512 KiB per partition; +1 for NTFS
BASE_LBA = 2048               # 1 MiB stream origin

# (region, kind), in compressed-payload order
BLOCKS = [
    (0,  "boot"),
    (1,  "fill"),
    (4,  "boot"),
    (5,  "zero"),
    (8,  "boot"),
    (9,  "fill"),
    (12, "boot"),
    (13, "zero"),
]


def boot_sector(region: int) -> bytes:
    b = bytearray(CLUSTER)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, 512)
    b[13] = 1
    struct.pack_into("<H", b, 14, 1)
    struct.pack_into("<I", b, 28, BASE_LBA + region * 512)  # hidden sectors
    struct.pack_into("<Q", b, 40, TOTAL_SECTORS)
    struct.pack_into("<Q", b, 48, 16)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def cluster(region: int, kind: str) -> bytes:
    if kind == "boot":
        return boot_sector(region)
    if kind == "zero":
        return bytes(CLUSTER)
    return bytes([0xA0 | (region // 4)]) * CLUSTER


def block(payload: bytes) -> bytes:
    bitmap = bytearray(HDR)
    bitmap[0] = 0x01
    return bytes(bitmap) + payload


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


def record(off, usize, csize, stream, region) -> bytes:
    return struct.pack("<QIIIIII", off, usize, csize, 0, stream, region, 0)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "multipart.adi"

    payload = bytearray()
    recs = []
    for region, kind in BLOCKS:
        comp = lz4_literals(block(cluster(region, kind)))
        off = len(payload)
        payload += comp
        recs.append((off, len(comp), HDR + CLUSTER))

    # resolve_regions() shifts record i's raw region onto block i+1 and
    # recomputes block 0's region as the lowest unused value. Choose raw
    # values so the final regions are exactly the ones in BLOCKS.
    final = [r for r, _ in BLOCKS]
    raw = final[1:] + [0]
    index = bytearray()
    for i, (off, csize, usize) in enumerate(recs):
        index += record(off, usize, csize, 0, raw[i])

    payload += index
    payload += bytes(256)      # keep the index out of the scanner's 64-byte tail

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"

    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)
        f.write(footer)
    print(f"wrote {path} ({len(header) + len(payload) + len(footer)} bytes, "
          f"{len(BLOCKS)} blocks, 4 partitions)")


if __name__ == "__main__":
    main()
