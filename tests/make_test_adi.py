#!/usr/bin/env python3
"""Generate synthetic AOMEI-style .adi files for testing adi2raw.

These are NOT real backups. They exercise the container layout that the
format reader cares about: BIFH/BIFT framing, a signature-scanned block index,
LZ4 literal blocks, used-sector bitmaps, multiple volumes, two cluster sizes,
sparse units and out-of-order regions.

Every index record carries a real AOMEI BRCrc32 (CRC32C) over its decoded
block, so the tests also verify the checksum path end to end.

Usage: python3 make_test_adi.py OUTPUT.adi [simple|multi|bigcluster|simple-badcrc]
"""
import struct
import sys

from adi_fixture import br_crc32, lz4_literals, record

REGION = 256 * 1024


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


def build(recipes, bad_crc_index: int | None = None) -> bytes:
    """recipes: list of (cluster, {unit: bytes}, raw_region, gap_before)."""
    payload = bytearray()
    recs = []
    for cluster, units, raw_region, gap_before in recipes:
        payload += bytes(gap_before)
        decoded = make_block(cluster, units)
        data = lz4_literals(decoded)
        off = len(payload)
        payload += data
        recs.append((off, len(data), len(decoded), raw_region, br_crc32(decoded)))

    # Index records sit physically adjacent. Adjacent pairs must chain via
    # end()==off; a gap in off creates a new volume (a new index run).
    index = bytearray()
    for i, (off, csize, usize, raw_region, checksum) in enumerate(recs):
        if bad_crc_index is not None and i == bad_crc_index:
            checksum = 0xDEADBEEF
        index += record(off, usize, csize, 0, raw_region, checksum)
    payload += index
    payload += bytes(256)  # keep the index out of the scanner's 64-byte tail

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"
    return bytes(header) + bytes(payload) + footer


def simple(bad_crc: bool = False) -> bytes:
    """One NTFS volume, 512-byte clusters, two regions."""
    c = 512
    bs = boot_sector(2048, 4096, 1)
    return build([
        (c, {0: bs}, 1, 0),
        (c, {0: bytes([0xC3]) * c}, 0, 0),
    ], bad_crc_index=1 if bad_crc else None)


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


def bigcluster() -> bytes:
    """32 KiB clusters, as real AOMEI C: regions use (2 MiB / 64 SPC).

    The used-sector bitmap is a single byte, and some of its bits are clear:
    the reader must honour the bits rather than treat hdr==1 as "all present".
    """
    c = 32768
    bs = boot_sector(2048, 4096, 64)
    return build([
        (c, {
            0: bs,
            1: bytes([0xA1]) * c,
            3: bytes([0xA3]) * c,
            6: bytes([0xA6]) * c,
        }, 1, 0),
        (c, {0: bytes([0xB0]) * c, 7: bytes([0xB7]) * c}, 0, 0),
    ])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "test.adi"
    kind = sys.argv[2] if len(sys.argv) > 2 else "multi"
    kinds = {
        "simple": simple,
        "multi": multi,
        "bigcluster": bigcluster,
        "simple-badcrc": lambda: simple(bad_crc=True),
    }
    data = kinds[kind]()
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes, {kind})")


if __name__ == "__main__":
    main()
