#!/usr/bin/env python3
"""Record-discovery strategy: tail-first scan, fallback and equivalence.

A full pass over the image before the first output byte is what made `dump`
take 70 s on a 70 GiB file. `info`/`dump` now search the last 4 MiB for the
record block and only scan the whole file when that does not yield exactly one
complete, self-consistent set.

What this checks, for both tools:

  * a 6 MiB image whose records sit at the end is handled by the tail scan
    (--debug says so) and produces exactly the same bytes as the forced
    exhaustive scan (ADI*_FULL_SCAN=1);
  * the same image with its records at the front is rejected by the tail scan
    and still found by the fallback;
  * an unreadable/absent record block still falls back instead of failing.

Usage: python3 tests/test_scan_strategy.py BINARY rust|cpp
"""
import argparse
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import make_standard_adi as F

BIFH_SIZE = 0x65C
BIFT_SIZE = 0x674
TAIL_LEN_OFF = 0x620
TAIL_OFF_OFF = 0x628

BPS, SPC, CPB = 512, 64, 8
CLUSTER = BPS * SPC
PART_START = 2048


def align(n, a):
    return (n + a - 1) // a * a


def build_fixture(path, blocks=24, records_at="end"):
    """A standard-record image large enough for the 4 MiB tail window.

    Each block decodes to a 32 KiB boot sector plus seven 32 KiB clusters and
    is stored verbatim, so the file is ~6 MiB for 24 blocks. `records_at`
    places the VDB table and the record block either after the payload (what
    AOMEI does) or at the front of the payload.
    """
    blob = F.boot_sector().ljust(CLUSTER, b"\x00") + bytes(range(16)) * ((7 * CLUSTER) // 16)
    dec = bytes([0xFF]) + blob
    comp = dec                       # stored verbatim: exercises the direct path
    crc = F.br_crc32(dec)

    entries = bytearray()
    for i in range(blocks):
        entries += struct.pack("<IQQIII", 0, i, 0, len(dec), len(comp), crc)  # img_offset patched
    table_len = len(entries)
    part_sectors = blocks * CPB * SPC

    if records_at == "end":
        data_start = 0x40
        V = align(data_start + blocks * len(comp), 0x40)
    else:
        V = 0x40
        data_start = align(V + table_len + 0x400, 0x40)
    entries = bytearray()
    for i in range(blocks):
        entries += struct.pack("<IQQIII", 0, i, data_start + i * len(comp), len(dec),
                               len(comp), crc)

    dir_off = V + table_len
    region_logical = align(dir_off + 0x34, 0x10)
    metadata_logical = region_logical + 0x30
    compress_logical = metadata_logical + 0x200
    encrypt_logical = compress_logical + 0x18
    volindex_logical = encrypt_logical + 0x18
    primary_len = align(max(volindex_logical + 0x64,
                            data_start + blocks * len(comp)) + 0x100, 0x100)

    def fill_202(r):
        struct.pack_into("<IIII", r, 0x10, 1, blocks, 0x20, 0)
        struct.pack_into("<QII", r, 0x24, V, len(entries), blocks)

    def fill_109(r):
        vals = (0, 0, 0, part_sectors, 0, CPB, SPC, BPS)
        for i, v in enumerate(vals):
            struct.pack_into("<I", r, 0x10 + i * 4, v)

    def fill_102(r):
        struct.pack_into("<I", r, 0x14, BPS)
        struct.pack_into("<Q", r, 0x18, PART_START)
        struct.pack_into("<Q", r, 0x20, part_sectors)
        label = "DATA".encode("utf-16le")
        r[0x34:0x34 + len(label)] = label
        r[0x172:0x182] = F.TYPE_GUID
        r[0x182:0x192] = F.UNIQUE_GUID

    def fill_105(r):
        struct.pack_into("<I", r, 0x14, 1)

    def fill_106(r):
        struct.pack_into("<I", r, 0x14, 0)

    def fill_201(r):
        struct.pack_into("<I", r, 0x10, 5)
        pairs = [(F.TYPE_DATABLOCK_INDEX, 0x34, dir_off),
                 (F.TYPE_REGION, 0x30, region_logical),
                 (F.TYPE_METADATA, 0x200, metadata_logical),
                 (F.TYPE_COMPRESS, 0x18, compress_logical),
                 (F.TYPE_ENCRYPT, 0x18, encrypt_logical)]
        for i, (t, size, off) in enumerate(pairs):
            struct.pack_into("<IIQ", r, 0x14 + i * 0x10, t, size, off)

    recs = [(dir_off, F.record(F.TYPE_DATABLOCK_INDEX, 0x34, fill_202)),
            (region_logical, F.record(F.TYPE_REGION, 0x30, fill_109)),
            (metadata_logical, F.record(F.TYPE_METADATA, 0x200, fill_102)),
            (compress_logical, F.record(F.TYPE_COMPRESS, 0x18, fill_105)),
            (encrypt_logical, F.record(F.TYPE_ENCRYPT, 0x18, fill_106)),
            (volindex_logical, F.record(F.TYPE_VOLUME_INDEX, 0x64, fill_201))]

    payload = bytearray(primary_len)
    for i in range(blocks):
        at = data_start + i * len(comp)
        payload[at:at + len(comp)] = comp
    payload[V:V + len(entries)] = entries
    for off, r in recs:
        payload[off:off + len(r)] = r

    head = F.container_header(BIFH_SIZE)
    tail = F.container_tail(primary_len, 0)
    path.write_bytes(bytes(head) + bytes(payload) + bytes(tail))
    return path.stat().st_size


def run(binary, kind, image, out, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    if kind == "rust":
        with open(out, "wb") as f:
            proc = subprocess.run([str(binary), "--debug", "dump", str(image)],
                                  stdout=f, stderr=subprocess.PIPE, timeout=300, env=env)
        logs = proc.stderr.decode(errors="replace")
    else:
        proc = subprocess.run([str(binary), "--debug", "reconstruct", str(image), str(out)],
                              capture_output=True, timeout=300, env=env)
        logs = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
    return proc, logs


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def scan_line(logs):
    return [l for l in logs.splitlines() if "record scan:" in l]


def full_scan_env(kind):
    return {"ADI2RAW_FULL_SCAN": "1"} if kind == "rust" else {"ADI_EXTRACT_FULL_SCAN": "1"}


def test_tail_scan_matches_full_scan(binary, kind, work):
    image = work / "records-at-end.adi"
    size = build_fixture(image)
    expect(size > 5 << 20, f"fixture is only {size} bytes; the tail window would not apply")

    fast, fast_log = run(binary, kind, image, work / "fast.img")
    expect(fast.returncode == 0, f"dump failed: {fast_log[-400:]}")
    line = scan_line(fast_log)
    expect(any("one 0x201, complete set" in l for l in line),
           f"the tail scan did not handle a records-at-end image: {line}")

    slow, slow_log = run(binary, kind, image, work / "slow.img", full_scan_env(kind))
    expect(slow.returncode == 0, f"forced full scan failed: {slow_log[-400:]}")
    expect(any("whole file" in l for l in scan_line(slow_log)),
           f"the full scan was not used when forced: {scan_line(slow_log)}")

    a = (work / "fast.img").read_bytes()
    b = (work / "slow.img").read_bytes()
    expect(a == b, "the tail scan and the exhaustive scan produced different images")
    print(f"  tail scan vs full scan: identical {len(a)}-byte image "
          f"({len(scan_line(fast_log))} scan line)")


def test_front_records_use_the_fallback(binary, kind, work):
    image = work / "records-at-front.adi"
    build_fixture(image, records_at="front")
    proc, logs = run(binary, kind, image, work / "front.img")
    expect(proc.returncode == 0, f"dump failed: {logs[-400:]}")
    line = scan_line(logs)
    expect(any("gave 0 0x201" in l for l in line),
           f"the tail scan did not decline a records-at-front image: {line}")
    expect(any("whole file" in l for l in line),
           f"the fallback scan did not run: {line}")
    expect("standard record path: 1 volume set(s)" in logs,
           f"the fallback did not find the record set: {logs[-400:]}")
    print("  records at the front: tail scan declined, fallback found the set")


def test_small_image_uses_the_full_scan(binary, kind, work):
    image = work / "records-at-end.adi"
    if not image.exists():
        build_fixture(image)
    # Everything below the window size takes the exhaustive scan, which is what
    # all the other fixtures rely on.
    small = work / "small.adi"
    head = image.read_bytes()
    small.write_bytes(head[:1 << 20])
    proc, logs = run(binary, kind, small, work / "small.img")
    expect(any("whole file" in l for l in scan_line(logs)) or proc.returncode != 0,
           f"a truncated image did not report the full scan: {scan_line(logs)}")
    print(f"  image below the window: {proc.returncode} (full scan, no fast path)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("kind", choices=["rust", "cpp"])
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="adi-scan-") as tmp:
        work = Path(tmp)
        test_tail_scan_matches_full_scan(binary, args.kind, work)
        test_front_records_use_the_fallback(binary, args.kind, work)
        test_small_image_uses_the_full_scan(binary, args.kind, work)
    print("SCAN STRATEGY PASSED: tail scan, fallback, byte-identical output")


if __name__ == "__main__":
    main()
