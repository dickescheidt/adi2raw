#!/usr/bin/env python3
"""Generate synthetic AOMEI-style .adi files for testing adi2raw.

These are NOT real backups. They exercise the container layout that the
format reader cares about: BIFH/BIFT framing, a signature-scanned block index,
LZ4 literal blocks, used-sector bitmaps, multiple volumes, two cluster sizes,
sparse units and out-of-order regions.

Usage: python3 make_test_adi.py OUTPUT.adi [simple|multi]
"""
import struct
import sys

REGION = 256 * 1024


def lz4_literals(data: bytes) -> bytes:
    """One LZ4 literal run in the dialect used inside .adi blocks."""
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


def boot_sector(hidden: int, total: int, spc: int) -> bytes:
    """NTFS boot sector padded out to a full cluster."""
    b = bytearray(512)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, 512)       # bytes per sector
    b[13] = spc                             # sectors per cluster
    struct.pack_into("<H", b, 14, 1)         # reserved sectors
    struct.pack_into("<I", b, 28, hidden)    # hidden sectors == partition LBA
    struct.pack_into("<Q", b, 40, total)
    struct.pack_into("<Q", b, 48, 16)        # MFT LCN
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def make_block(cluster: int, present: dict[int, bytes]) -> bytes:
    """bitmap + only the clusters whose bits are set, in ascending unit order."""
    units = REGION // cluster
    bitmap = bytearray(units // 8)
    body = bytearray()
    for u in sorted(present):
        bitmap[u >> 3] |= 1 << (u & 7)
        body += present[u].ljust(cluster, b"\x00")[:cluster]
    return bytes(bitmap) + bytes(body)


def record(off, usize, csize, stream, region) -> bytes:
    return struct.pack("<QIIIIII", off, usize, csize, 0, stream, region, 0)


def build(recipes) -> bytes:
    """recipes: list of (cluster, {unit: bytes}, raw_region, gap_before)."""
    payload = bytearray()
    recs = []
    for cluster, units, raw_region, gap_before in recipes:
        payload += bytes(gap_before)
        data = lz4_literals(make_block(cluster, units))
        off = len(payload)
        payload += data
        recs.append([off, len(data), raw_region])

    # Index records sit physically adjacent. Adjacent pairs must chain via
    # end()==off; a gap in off creates a new volume (a new index run).
    index = bytearray()
    for i, (off, csize, raw_region) in enumerate(recs):
        usize = REGION // recipes[i][0] // 8 + len(recipes[i][1]) * recipes[i][0]
        index += record(off, usize, csize, 0, raw_region)
    payload += index
    payload += bytes(256)  # keep the index out of the scanner's 64-byte tail

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"
    return bytes(header) + bytes(payload) + footer


def simple() -> bytes:
    """One NTFS volume, 512-byte clusters, two regions."""
    c = 512
    bs = boot_sector(2048, 4096, 1)
    return build([
        (c, {0: bs}, 1, 0),
        (c, {0: bytes([0xC3]) * c}, 0, 0),
    ])


def multi() -> bytes:
    """Two volumes, 512/4096-byte clusters, out-of-order regions and gaps.

    Volume A (regions 0,2,1 in decode order -> needs reordering on stream).
    Volume B starts after a 128-byte gap in the compressed payload.
    """
    c1, c2 = 512, 4096
    bs_a = boot_sector(2048, 4096, 1)            # cluster 512,  LBA 2048
    bs_b = boot_sector(8192, 8192, 8).ljust(c2, b"\x00")  # cluster 4096, LBA 8192
    return build([
        (c1, {0: bs_a}, 2, 0),
        (c1, {3: bytes([0x11]) * c1}, 1, 0),    # sparse: unit 3 only
        (c1, {0: bytes([0x22]) * c1}, 0, 0),
        (c2, {0: bs_b, 5: bytes([0x33]) * c2}, 1, 128),
        (c2, {2: bytes([0x44]) * c2}, 0, 0),
    ])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "test.adi"
    kind = sys.argv[2] if len(sys.argv) > 2 else "multi"
    data = {"simple": simple, "multi": multi}[kind]()
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes, {kind})")


if __name__ == "__main__":
    main()
