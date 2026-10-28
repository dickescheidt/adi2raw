#!/usr/bin/env python3
"""Regression fixture: an ordered index with chain gaps must stay ordered.

Six compressed blocks in three chain runs, separated by metadata gaps. The
raw region fields in the index records are strictly increasing (100000..100005)
-- i.e. the file is in perfect disk order.

An older resolve_regions() split the chain at those gaps and forced every run
head to the "lowest unused" region (0), producing resolved regions like
[0, 100000, 0, 100002, 0, 100004]. The target offsets then oscillated by tens
of GiB and adi2raw reported "image blocks are too far out of disk order to
stream" even though nothing in the .adi was scrambled. The fix is one global
one-record shift, so `adi2raw info` must now report
"raw yes, after resolve_regions yes" and a 0 MiB reorder need.

This is a diagnostic fixture. Do not dump it (the disk is huge).

Usage: python3 make_gap_regions_adi.py OUTPUT.adi
"""
import struct
import sys

from adi_fixture import br_crc32, lz4_literals, record

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


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "gap-regions.adi"

    raw_regions = [100000 + i for i in range(6)]
    decoded_blocks = [
        block(boot_sector() if i == 0 else bytes([0xC3]) * CLUSTER)
        for i in range(6)
    ]
    comps = [lz4_literals(d) for d in decoded_blocks]

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
        checksum = br_crc32(decoded_blocks[i])
        index += record(off, len(decoded_blocks[i]), len(comp), 0,
                        raw_regions[i], checksum)
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
