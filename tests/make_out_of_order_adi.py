#!/usr/bin/env python3
"""Synthetic .adi whose blocks are stored in reverse disk order.

Eight contiguous compressed blocks, each an "all units present" 256 KiB
region. Chain order carries regions 7,6,..,0, so a strictly sequential
stdout writer cannot emit them without buffering most of the image. Used to
regression-test adi2raw's sparse spool fallback.

Usage: python3 make_out_of_order_adi.py OUTPUT.adi
"""
import struct
import sys

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


def payload(region: int) -> bytes:
    # "all present" shorthand: 1 marker byte + the whole 256 KiB region.
    body = bytearray([0x10 + region]) * REGION
    if region == 0:
        body[:512] = boot_sector()
    return b"\x01" + bytes(body)


def record(off, usize, csize, region) -> bytes:
    return struct.pack("<QIIIIII", off, usize, csize, 0, 0, region, 0)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "out-of-order.adi"

    # Final regions in chain order: 7,6,5,4,3,2,1,0.
    # resolve_regions() shifts record i's raw region onto block i+1 and
    # recomputes block 0 as the lowest unused value, so raw = final[1:] + [0].
    final = list(range(BLOCKS - 1, -1, -1))
    raw = final[1:] + [0]

    payload_bytes = bytearray()
    recs = []
    for region in final:
        comp = lz4_literals(payload(region))
        off = len(payload_bytes)
        payload_bytes += comp
        recs.append((off, 1 + REGION, len(comp)))

    index = bytearray()
    for i, (off, usize, csize) in enumerate(recs):
        index += record(off, usize, csize, raw[i])
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
