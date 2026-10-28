#!/usr/bin/env python3
"""Build a synthetic .adi using the REAL AOMEI standard-record layout.

Unlike the legacy fixtures, this one contains:

  * a 0x65c BIFH header and 0x674 BIFT tail, with valid BRCrc32 in both and
    DataLenInSet / DataOffInSet at tail +0x620 / +0x628;
  * CRC-valid 0x201 volume index, 0x202 data-block index, 0x109 region,
    0x102 volume metadata and 0x105/0x106 mode records;
  * a real 0x20-byte VDB table (RegNo, BlockNo, ImgOffset, OldSize, NewSize,
    Crc32) rather than a signature-scanned 12-byte-shifted window;
  * stored block payloads addressed by image-set LOGICAL offsets.

`split` mode puts the second stored block into a second image-set member, so
the reader must apply `logical - DataOffInSet + BIFH.size` and choose the
right member file.

Usage:
  python3 make_standard_adi.py OUT.adi [single|split]
  # split also writes OUT.member1.adi
"""
import struct
import sys

from adi_fixture import br_crc32, lz4_literals

BIFH_SIZE = 0x65C
BIFT_SIZE = 0x674
TAIL_LEN_OFF = 0x620
TAIL_OFF_OFF = 0x628

TYPE_VOLUME_INDEX = 0x201
TYPE_DATABLOCK_INDEX = 0x202
TYPE_METADATA = 0x102
TYPE_COMPRESS = 0x105
TYPE_ENCRYPT = 0x106
TYPE_REGION = 0x109

BPS = 512
SPC = 64
CPB = 8
CLUSTER = BPS * SPC           # 32768, as in real sparse C: regions
BMP_LEN = (CPB + 7) // 8     # 1
PART_START = 2048
PART_SECTORS = 4096

TYPE_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
UNIQUE_GUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def record(rec_type: int, size: int, fill=None) -> bytearray:
    """A 16-byte BR_STANDARD_HEADER + body, with a valid BRCrc32."""
    r = bytearray(size)
    struct.pack_into("<IIII", r, 0, rec_type, size, 0, 0)
    if fill:
        fill(r)
    crc = br_crc32(bytes(r))
    struct.pack_into("<I", r, 8, crc)
    return r


def boot_sector() -> bytes:
    b = bytearray(BPS)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, BPS)
    b[13] = SPC
    struct.pack_into("<H", b, 14, 1)
    struct.pack_into("<I", b, 28, PART_START)
    struct.pack_into("<Q", b, 40, PART_SECTORS)
    struct.pack_into("<Q", b, 48, 16)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def decoded_container(bitmap: int, clusters: dict) -> bytes:
    body = bytearray()
    for u in range(CPB):
        if bitmap & (1 << u):
            body += clusters[u].ljust(CLUSTER, b"\x00")[:CLUSTER]
    return bytes([bitmap]) + bytes(body)


def container_header(header_size: int) -> bytearray:
    h = bytearray(header_size)
    h[0:4] = b"BIFH"
    struct.pack_into("<I", h, 4, header_size)
    name = "Standard test".encode("utf-16le")
    h[0x44:0x44 + len(name)] = name
    struct.pack_into("<I", h, 8, br_crc32(bytes(h)))
    return h


def container_tail(data_len: int, data_off: int) -> bytearray:
    t = bytearray(BIFT_SIZE)
    name = "Standard.adi".encode("utf-16le")
    t[0:len(name)] = name
    struct.pack_into("<Q", t, TAIL_LEN_OFF, data_len)
    struct.pack_into("<Q", t, TAIL_OFF_OFF, data_off)
    struct.pack_into("<I", t, BIFT_SIZE - 8, BIFT_SIZE)
    t[BIFT_SIZE - 4:BIFT_SIZE] = b"BIFT"
    struct.pack_into("<I", t, BIFT_SIZE - 12, br_crc32(bytes(t)))
    return t


def vdb_entry(reg_no, block_no, img_offset, old_size, new_size, crc) -> bytes:
    return struct.pack("<IQQIII", reg_no, block_no, img_offset,
                       old_size, new_size, crc)


def build(mode: str, primary: str, secondary: str | None):
    dec0 = decoded_container(0x0F, {
        0: boot_sector(),
        1: bytes([0xA1]) * CLUSTER,
        2: bytes([0xA2]) * CLUSTER,
        3: bytes([0xA3]) * CLUSTER,
    })
    dec1 = decoded_container(0x81, {
        0: bytes([0xB0]) * CLUSTER,
        7: bytes([0xB7]) * CLUSTER,
    })
    boundary = mode in ("boundary", "boundary-padded", "boundary-bad", "boundary-sparse")
    if boundary:
        bitmap = 0x85 if mode == "boundary-sparse" else 0xFF
        dec1 = bytes([bitmap]) + bytes([0xB0]) * CLUSTER
        if bitmap == 0xFF:
            dec1 += bytes([0xB1]) * CLUSTER
        dec1 += bytes([0xB2]) * 6144
        if mode == "boundary-padded":
            dec1 += bytes([0xB2]) * (CLUSTER - 6144) + bytes([0xBE]) * (5 * CLUSTER)
        if mode == "boundary-bad":
            dec1 = dec1[:-512]
    # Block 0 is AOMEI/LZ4 compressed; block 1 exercises the direct path.
    comp0 = lz4_literals(dec0)
    comp1 = dec1

    L0 = 0x40
    # In single-member mode both stored blocks precede the VDB table. In split
    # mode only block 0 lives in the primary member; block 1 goes in member 1.
    L1 = L0 + len(comp0) if mode != "split" else None
    table_after = L0 + len(comp0) + (len(comp1) if mode != "split" else 0)
    V = align(table_after, 0x40)
    dir_off = V + 0x40

    rec_202_logical = dir_off
    region_logical = align(rec_202_logical + 0x34, 0x10)
    metadata_logical = region_logical + 0x30
    compress_logical = metadata_logical + 0x200
    encrypt_logical = compress_logical + 0x18
    volindex_logical = encrypt_logical + 0x18
    records_end = volindex_logical + 0x64

    if mode == "split":
        primary_len = align(records_end + 0x40, 0x100)
        L1 = primary_len + 0x40
    else:
        primary_len = align(records_end + 0x100, 0x100)

    entries = b"".join([
        vdb_entry(0, 0, L0, len(dec0), len(comp0), br_crc32(dec0)),
        vdb_entry(0, 1, L1, len(dec1), len(comp1), br_crc32(dec1)),
    ])

    def fill_202(r):
        struct.pack_into("<IIII", r, 0x10, 1, 2, 0x20, 0)
        struct.pack_into("<QII", r, 0x24, V, len(entries), 2)

    def fill_109(r):
        values = (0, 0, 0, 652 if boundary else PART_SECTORS, 0, CPB, SPC, BPS)
        for i, v in enumerate(values):
            struct.pack_into("<I", r, 0x10 + i * 4, v)

    def fill_102(r):
        struct.pack_into("<I", r, 0x14, BPS)
        struct.pack_into("<Q", r, 0x18, PART_START)
        struct.pack_into("<Q", r, 0x20, PART_SECTORS)
        label = "DATA".encode("utf-16le")
        r[0x34:0x34 + len(label)] = label
        desc = "Test partition".encode("utf-16le")
        r[0x12A:0x12A + len(desc)] = desc
        r[0x172:0x182] = TYPE_GUID
        r[0x182:0x192] = UNIQUE_GUID

    def fill_105(r):
        struct.pack_into("<I", r, 0x14, 1)

    def fill_106(r):
        struct.pack_into("<I", r, 0x14, 0)

    def fill_201(r):
        struct.pack_into("<I", r, 0x10, 5)
        pairs = [
            (TYPE_DATABLOCK_INDEX, 0x34, dir_off),
            (TYPE_REGION, 0x30, region_logical),
            (TYPE_METADATA, 0x200, metadata_logical),
            (TYPE_COMPRESS, 0x18, compress_logical),
            (TYPE_ENCRYPT, 0x18, encrypt_logical),
        ]
        for i, (t, size, off) in enumerate(pairs):
            struct.pack_into("<IIQ", r, 0x14 + i * 0x10, t, size, off)

    recs = [
        (rec_202_logical, record(TYPE_DATABLOCK_INDEX, 0x34, fill_202)),
        (region_logical, record(TYPE_REGION, 0x30, fill_109)),
        (metadata_logical, record(TYPE_METADATA, 0x200, fill_102)),
        (compress_logical, record(TYPE_COMPRESS, 0x18, fill_105)),
        (encrypt_logical, record(TYPE_ENCRYPT, 0x18, fill_106)),
        (volindex_logical, record(TYPE_VOLUME_INDEX, 0x64, fill_201)),
    ]

    payload = bytearray(primary_len)
    payload[L0:L0 + len(comp0)] = comp0
    if mode != "split":
        payload[L1:L1 + len(comp1)] = comp1
    payload[V:V + len(entries)] = entries
    for off, r in recs:
        payload[off:off + len(r)] = r

    head = container_header(BIFH_SIZE)
    tail = container_tail(primary_len, 0)
    with open(primary, "wb") as f:
        f.write(head)
        f.write(payload)
        f.write(tail)
    print(f"wrote {primary} ({BIFH_SIZE + primary_len + BIFT_SIZE} bytes, "
          f"{mode}, data range 0..0x{primary_len:x})")

    if mode == "split":
        second_len = align(0x40 + len(comp1) + 0x40, 0x100)
        second = bytearray(second_len)
        rel = L1 - primary_len
        second[rel:rel + len(comp1)] = comp1
        head2 = container_header(BIFH_SIZE)
        tail2 = container_tail(second_len, primary_len)
        with open(secondary, "wb") as f:
            f.write(head2)
            f.write(second)
            f.write(tail2)
        print(f"wrote {secondary} ({BIFH_SIZE + second_len + BIFT_SIZE} bytes, "
              f"data range 0x{primary_len:x}..0x{primary_len + second_len:x})")


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "standard.adi"
    mode = sys.argv[2] if len(sys.argv) > 2 else "single"
    if mode not in ("single", "split", "boundary", "boundary-padded", "boundary-bad", "boundary-sparse"):
        sys.exit("mode must be single or split")
    secondary = path + ".member1.adi" if mode == "split" else None
    build(mode, path, secondary)


if __name__ == "__main__":
    main()
