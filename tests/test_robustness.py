#!/usr/bin/env python3
"""Regression tests for the 2026-10-29 code review.

Covers, against whichever binary is passed on the command line:

  * a crafted block whose LZ4 length extension would allocate ~255x its stored
    size must be rejected and skipped, not decoded or allowed to exhaust memory;
  * a damaged block must not abort the whole extraction (skip + warning), while a
    run that recovers nothing at all must fail;
  * non-ASCII partition labels must be written as real UTF-16LE in the GPT;
  * the out-of-order spool file must be owner-only (Rust only; C++ writes
    directly to a sparse output file and has no spool).

Usage: python3 tests/test_robustness.py BINARY rust|cpp
"""
import argparse
import os
import resource
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from adi_fixture import br_crc32
from make_standard_adi import BIFH_SIZE, build as build_standard
from test_properties import build

KINDS = (0x201, 0x202, 0x102, 0x105, 0x106, 0x109)
SECTOR = 512
GPT_ENTRY_OFFSET = 2 * SECTOR  # primary entry array starts at LBA 2


# --------------------------------------------------------------------------
# Fixture inspection helpers
# --------------------------------------------------------------------------

def valid_records(data):
    """offset lists of CRC-valid standard records, keyed by record type."""
    found = {}
    for at in range(len(data) - 16):
        kind, size = struct.unpack_from("<II", data, at)
        if kind not in KINDS or not 16 <= size <= 4096 or at + size > len(data):
            continue
        body = bytearray(data[at:at + size])
        expected = struct.unpack_from("<I", body, 8)[0]
        struct.pack_into("<I", body, 8, 0)
        if br_crc32(bytes(body)) == expected:
            found.setdefault(kind, []).append(at)
    return found


def repair_record(data, off):
    size = struct.unpack_from("<I", data, off + 4)[0]
    struct.pack_into("<I", data, off + 8, 0)
    struct.pack_into("<I", data, off + 8, br_crc32(bytes(data[off:off + size])))


def vdb_entries(data):
    """VDB entries of the first data-block index, with physical file offsets.

    The fixtures store payloads at image-set logical offset 0, so a physical
    offset is `ImgOffset + BIFH.size`; split sets are exercised elsewhere.
    """
    entries = []
    for index in valid_records(data).get(0x202, []):
        refs = struct.unpack_from("<I", data, index + 0x10)[0]
        for ref in range(refs):
            offset = struct.unpack_from("<Q", data, index + 0x24 + 16 * ref)[0]
            count = struct.unpack_from("<I", data, index + 0x24 + 16 * ref + 12)[0]
            for i in range(count):
                at = offset + i * 32 + BIFH_SIZE
                entries.append({
                    "at": at,
                    "reg_no": struct.unpack_from("<I", data, at)[0],
                    "block_no": struct.unpack_from("<Q", data, at + 4)[0],
                    "file": struct.unpack_from("<Q", data, at + 0x0C)[0] + BIFH_SIZE,
                    "old": struct.unpack_from("<I", data, at + 0x14)[0],
                    "new": struct.unpack_from("<I", data, at + 0x18)[0],
                    "crc": struct.unpack_from("<I", data, at + 0x1C)[0],
                })
    return entries


def metadata_record(data):
    offsets = valid_records(data).get(0x102, [])
    assert offsets, "fixture has no 0x102 metadata record"
    return offsets[0]


def gpt_name(image, index=0):
    at = GPT_ENTRY_OFFSET + index * 128 + 56
    return image[at:at + 72]


# --------------------------------------------------------------------------
# Running the tool
# --------------------------------------------------------------------------

def run(binary, kind, image, out, limit=None, timeout=60):
    def preexec():
        if limit is not None:
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    if kind == "rust":
        with open(out, "wb") as stream:
            proc = subprocess.run([str(binary), "dump", str(image)], stdout=stream,
                                  stderr=subprocess.PIPE, timeout=timeout,
                                  preexec_fn=preexec if os.name == "posix" else None)
    else:
        proc = subprocess.run([str(binary), "reconstruct", str(image), str(out)],
                              capture_output=True, timeout=timeout,
                              preexec_fn=preexec if os.name == "posix" else None)
    return proc, proc.stderr.decode(errors="replace")


def expansion_bomb(length):
    """An LZ4 stream that expands to ~255 bytes per input byte."""
    return bytes([0x1F]) + b"A" + bytes([0x01, 0x00]) + b"\xff" * (length - 5) + b"\x00"


def make_expansion_image(path, stored_len=2 << 20):
    """Standard-record fixture whose first block expands to ~255x `stored_len`.

    The stored block is replaced in place and every offset that follows it is
    shifted, so the container, records and VDB table stay internally consistent.
    """
    build_standard("single", str(path), str(path) + ".m1")
    data = bytearray(path.read_bytes())
    header_size = struct.unpack_from("<I", data, 4)[0]
    tail_size = struct.unpack_from("<I", data, len(data) - 8)[0]
    payload = bytearray(data[header_size:len(data) - tail_size])
    tail = bytearray(data[len(data) - tail_size:])

    records = valid_records(payload)
    index = records[0x202][0]
    directory = records[0x201][0]
    table = struct.unpack_from("<Q", payload, index + 0x24)[0]
    first_len = struct.unpack_from("<I", payload, table + 0x18)[0]
    second_at = struct.unpack_from("<Q", payload, table + 32 + 0x0C)[0]
    assert second_at == 0x40 + first_len, (second_at, first_len)

    bomb = expansion_bomb(stored_len)
    delta = stored_len - first_len
    payload = payload[:0x40] + bomb + payload[second_at:]

    table += delta
    index += delta
    directory += delta
    struct.pack_into("<I", payload, table + 0x18, stored_len)   # first new_size
    struct.pack_into("<I", payload, table + 0x1C, 0)            # decode fails first
    struct.pack_into("<Q", payload, table + 32 + 0x0C, second_at + delta)
    struct.pack_into("<Q", payload, index + 0x24, table)
    for i in range(5):
        at = directory + 0x14 + 16 * i + 8
        struct.pack_into("<Q", payload, at, struct.unpack_from("<Q", payload, at)[0] + delta)
    repair_record(payload, index)
    repair_record(payload, directory)

    struct.pack_into("<Q", tail, 0x620, len(payload))
    tail[-12:-8] = bytes(4)
    struct.pack_into("<I", tail, len(tail) - 12, br_crc32(bytes(tail)))
    path.write_bytes(bytes(data[:header_size]) + bytes(payload) + bytes(tail))


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_expansion_is_capped(binary, kind, work):
    """Finding 1: declared size caps decoder output; a bomb is skipped."""
    image = work / "bomb.adi"
    build(image, 3, "compressed")
    baseline = work / "baseline.img"
    proc, err = run(binary, kind, image, baseline)
    expect(proc.returncode == 0, f"fixture did not extract cleanly: {err[-300:]}")
    expected_size = baseline.stat().st_size
    data = bytearray(image.read_bytes())
    entries = vdb_entries(data)
    expect(len(entries) >= 2, "fixture should have at least two blocks")
    target = entries[0]
    expect(target["new"] >= 64, "stored block too small for this test")
    crafted = expansion_bomb(target["new"])
    data[target["file"]:target["file"] + target["new"]] = crafted
    image.write_bytes(data)

    out = work / "bomb.img"
    # 128 MiB is far below the ~255x expansion the crafted stream requests, but
    # comfortably above what a correct run needs.
    proc, err = run(binary, kind, image, out, limit=128 << 20)
    expect(proc.returncode == 0, f"bomb run should skip and succeed, rc={proc.returncode}: {err[-300:]}")
    expect("decode failed" in err.lower() or "exceeds" in err.lower(),
           f"expected a decode warning, got: {err[-300:]}")
    expect(out.stat().st_size == expected_size, "output size changed")
    print("  expansion bomb: declared size enforced, run completed")

    # Same defect at scale: 2 MiB of stored bytes ask for ~510 MiB of output.
    # A 256 MiB address-space cap leaves no room for that allocation, but the
    # bounded decoder never attempts it.
    big = work / "big-bomb.adi"
    make_expansion_image(big)
    out = work / "big-bomb.img"
    proc, err = run(binary, kind, big, out, limit=256 << 20, timeout=120)
    expect(proc.returncode == 0,
           f"large expansion should be skipped, rc={proc.returncode}: {err[-300:]}")
    expect("decode failed" in err.lower() or "exceeds" in err.lower(),
           f"expected a decode warning, got: {err[-300:]}")
    expect("bad_alloc" not in err and "memory allocation" not in err.lower(),
           f"allocation failure leaked through: {err[-300:]}")
    print("  large expansion: 510 MiB requested from 2 MiB, refused without allocating")


def test_all_blocks_damaged_fails(binary, kind, work):
    """Finding 2: recovering nothing is a failure, not a zero-filled success."""
    image = work / "damaged-crc.adi"
    build(image, 4, "compressed")
    data = bytearray(image.read_bytes())
    entries = vdb_entries(data)
    expect(entries, "fixture has no VDB entries")
    for entry in entries:
        struct.pack_into("<I", data, entry["at"] + 0x1C, 0xDEADBEEF)
    image.write_bytes(data)

    out = work / "damaged-crc.img"
    proc, err = run(binary, kind, image, out)
    expect(proc.returncode != 0, "a run that recovered nothing must fail")
    expect("nothing was recovered" in err.lower(), f"missing failure message: {err[-300:]}")
    print("  all blocks damaged: run fails as expected")


def test_all_blocks_undecodable_fails(binary, kind, work):
    """Finding 1+2 together: undecodable blocks are skipped, then reported."""
    image = work / "damaged-bomb.adi"
    build(image, 5, "compressed")
    data = bytearray(image.read_bytes())
    for entry in vdb_entries(data):
        expect(entry["new"] >= 64, "stored block too small for this test")
        data[entry["file"]:entry["file"] + entry["new"]] = expansion_bomb(entry["new"])
    image.write_bytes(data)

    out = work / "damaged-bomb.img"
    proc, err = run(binary, kind, image, out, limit=256 << 20)
    expect(proc.returncode != 0, "all-undecodable run must fail")
    expect("nothing was recovered" in err.lower(), f"missing failure message: {err[-300:]}")
    print("  all blocks undecodable: skipped, then reported as failure")


def test_non_ascii_labels(binary, kind, work):
    """Finding 4: labels become real UTF-16LE GPT names."""
    for label in ("DATEN-\u00c4\u00d6\u00dc", "PLATTE-\U0001f4be"):
        name = f"label-{len(label)}.adi"
        image = work / name
        build(image, 2, "compressed")
        data = bytearray(image.read_bytes())
        meta = metadata_record(data)
        encoded = label.encode("utf-16le")
        field = data[meta + 0x34:meta + 0x34 + 0x7C]
        expect(len(encoded) <= len(field), "label too long for the record")
        data[meta + 0x34:meta + 0x34 + 0x7C] = encoded + bytes(len(field) - len(encoded))
        repair_record(data, meta)
        image.write_bytes(data)

        out = work / f"label-{len(label)}.img"
        proc, err = run(binary, kind, image, out)
        expect(proc.returncode == 0, f"label run failed: {err[-300:]}")
        got = gpt_name(out.read_bytes())
        want = encoded + bytes(72 - len(encoded))
        expect(got == want,
               f"GPT name mismatch for {label!r}: got {got[:len(encoded) + 4]!r}, want {want[:len(encoded) + 4]!r}")
    print("  non-ASCII labels: encoded as UTF-16LE in the GPT")


def test_spool_is_owner_only(binary, kind, work):
    """Finding 5: the spill file is created 0600, not umask-dependent."""
    if kind != "rust":
        print("  spool permissions: not applicable to this tool")
        return
    image = work / "spool.adi"
    build(image, 1, "compressed")
    spool_dir = work / "spool"
    spool_dir.mkdir(exist_ok=True)
    env = dict(os.environ, ADI2RAW_MAX_PENDING_MB="0", ADI2RAW_SPOOL_DIR=str(spool_dir))
    proc = subprocess.Popen([str(binary), "dump", str(image)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    mode = None
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            found = list(spool_dir.glob("*.spool"))
            if found:
                mode = found[0].stat().st_mode & 0o777
                break
            if proc.poll() is not None:
                break
            time.sleep(0.02)
        proc.stdout.read()
        err = proc.stderr.read().decode(errors="replace")
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    expect(proc.returncode == 0, f"spool run failed: {proc.returncode} {err[-200:]}")
    expect(mode is not None, "no spool file observed")
    expect(mode == 0o600, f"spool file mode is {oct(mode)}, expected 0o600")
    expect(not list(spool_dir.glob("*.spool")), "spool file was not removed")
    print("  spool permissions: created 0600 and removed afterwards")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("kind", choices=["rust", "cpp"])
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="adi-robust-") as tmp:
        work = Path(tmp)
        test_expansion_is_capped(binary, args.kind, work)
        test_all_blocks_damaged_fails(binary, args.kind, work)
        test_all_blocks_undecodable_fails(binary, args.kind, work)
        test_non_ascii_labels(binary, args.kind, work)
        test_spool_is_owner_only(binary, args.kind, work)
    print("ROBUSTNESS PASSED: decoder cap, failure policy, UTF-16 labels, private spool")


if __name__ == "__main__":
    main()
