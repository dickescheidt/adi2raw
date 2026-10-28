#!/usr/bin/env python3
"""Shared helpers for adi2raw's synthetic .adi fixtures.

The 32-byte records below are the window our signature scanner finds: a real
VDB index entry read 12 bytes late. Field 4 (offset 16) is the VDB ``Crc32``,
i.e. ``Encrypt.dll!BRCrc32`` over the *decoded* block bytes.
"""
import struct

_POLY = 0x82F63B78
_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _POLY if _c & 1 else _c >> 1
    _TAB.append(_c)


def br_crc32(data: bytes) -> int:
    """CRC32C/Castagnoli, zero seed, final inversion (AOMEI BRCrc32)."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _TAB[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF


def record(off, usize, csize, stream, region, crc=0) -> bytes:
    """One 32-byte block-index record as seen by the scanner."""
    return struct.pack("<QIIIIII", off, usize, csize, crc, stream, region, 0)


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
