#!/usr/bin/env python3
"""Synthetic .adi whose blocks are stored in reverse disk order.

Eight contiguous compressed blocks, each an "all units present" 256 KiB
region. Chain order carries regions 0,7,6,..,1, so a strictly sequential
stdout writer cannot emit them without buffering most of the image. Used to
regression-test adi2raw's sparse spool fallback.

Usage: python3 make_out_of_order_adi.py OUTPUT.adi
"""
import struct
import sys

from adi_fixture import br_crc32, lz4_literals, record

REGION = 256 * 1024
BLOCKS = 8
HIDDEN = 2048                 # stream origin = 1 MiB
TOTAL_SECTORS = 4096


def boot_sector() -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, 512)
    b[13] = 1
    struct.pack_into("<H", b, 14, 1)
    struct.pack_into("<I", b, 28, HIDDEN)
    struct.pack_into("<Q", b, 40, TOTAL_SECTORS)
    struct.pack_into("<Q", b, 48, 16)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def payload(region: int) -> bytes:
    # "all present" shorthand: 1 marker byte + the whole 256 KiB region.
    body = bytearray([0x10 + region]) * REGION
    if region == 0:
        body[:512] = boot_sector()
    return b"\x01" + bytes(body)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "out-of-order.adi"

    # Final regions in chain order: 0,7,6,5,4,3,2,1.
    # resolve_regions() shifts record i-1's raw region onto block i and sets
    # block 0's region to 0, so raw = final[1:] + [0].
    final = [0] + list(range(BLOCKS - 1, 0, -1))
    raw = final[1:] + [0]

    payload_bytes = bytearray()
    recs = []
    for region in final:
        decoded = payload(region)
        comp = lz4_literals(decoded)
        off = len(payload_bytes)
        payload_bytes += comp
        recs.append((off, len(decoded), len(comp), br_crc32(decoded)))

    index = bytearray()
    for i, (off, usize, csize, checksum) in enumerate(recs):
        index += record(off, usize, csize, 0, raw[i], checksum)
    payload_bytes += index
    payload_bytes += bytes(256)

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"

    with open(path, "wb") as f:
        f.write(header)
        f.write(payload_bytes)
        f.write(footer)
    print(f"wrote {path} ({len(header) + len(payload_bytes) + len(footer)} bytes, "
          f"{BLOCKS} blocks in reverse disk order)")


if __name__ == "__main__":
    main()
