#!/usr/bin/env python3
"""Filesystem type, GPT type and reporting checks for both tools.

Covers what the real `microSD.adi` run exposed:

  * the volume's filesystem must come from its boot sector, not from a label
    heuristic that answers "NTFS" for everything that is not called ESP/EFI;
  * a FAT volume must not become an EFI system partition just because it is FAT,
    while a volume labelled ESP/EFI keeps that type;
  * an unreadable boot sector must be reported as a guess ('?') instead of
    silently claiming a filesystem;
  * `dump` must say how many bytes it placed and how much it left zero;
  * `info` must actually test BRCrc32 instead of only counting checksums.

Usage: python3 tests/test_fs_detect.py BINARY rust|cpp
"""
import argparse
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import make_standard_adi
from test_robustness import metadata_record, repair_record, vdb_entries

SECTOR = 512
GPT_ENTRY_OFFSET = 2 * SECTOR
ESP_GUID = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
DATA_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
RECOVERY_GUID = bytes.fromhex("a4bb94ded106404da16abfd50179d6ac")


def fat32_boot_sector(label="DARMB", total_sectors=4096, spc=64):
    """A FAT32 boot sector the way mkfs.vfat writes one (headers only)."""
    b = bytearray(SECTOR)
    b[0:3] = b"\xeb\x58\x90"
    b[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", b, 11, SECTOR)
    b[13] = spc
    struct.pack_into("<H", b, 14, 32)      # reserved sectors
    b[16] = 2                              # FAT copies
    struct.pack_into("<H", b, 17, 0)       # no fixed root directory
    struct.pack_into("<H", b, 19, 0)       # 16-bit total sectors: unused
    b[21] = 0xF8
    struct.pack_into("<H", b, 22, 0)       # FAT32: 16-bit FAT size must be 0
    struct.pack_into("<I", b, 28, 2048)    # hidden sectors
    struct.pack_into("<I", b, 32, total_sectors)
    struct.pack_into("<I", b, 36, 512)     # FAT size in sectors
    struct.pack_into("<I", b, 44, 2)       # root cluster
    struct.pack_into("<H", b, 48, 1)       # FSInfo sector
    struct.pack_into("<H", b, 50, 6)       # backup boot sector
    b[64] = 0x80
    b[66] = 0x29
    struct.pack_into("<I", b, 67, 0x1234ABCD)
    b[71:82] = label.encode("ascii").ljust(11)[:11]
    b[82:90] = b"FAT32   "
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def build_fixture(path, boot=None, mode="single"):
    """Standard-record fixture; `boot` replaces the volume's boot sector."""
    saved = make_standard_adi.boot_sector
    if boot is not None:
        make_standard_adi.boot_sector = lambda: boot
    try:
        make_standard_adi.build(mode, str(path), str(path) + ".m1")
    finally:
        make_standard_adi.boot_sector = saved


def set_label(path, label):
    """Rewrite the 0x102 volume label and repair its record CRC."""
    data = bytearray(path.read_bytes())
    meta = metadata_record(data)
    field_len = 0x7C
    encoded = label.encode("utf-16le")
    assert len(encoded) <= field_len
    data[meta + 0x34:meta + 0x34 + field_len] = encoded + bytes(field_len - len(encoded))
    repair_record(data, meta)
    path.write_bytes(bytes(data))


def clear_guids(path):
    """Drop the 0x102 type/unique GUIDs so the GPT type fallback has to decide."""
    data = bytearray(path.read_bytes())
    meta = metadata_record(data)
    data[meta + 0x172:meta + 0x172 + 16] = bytes(16)
    data[meta + 0x182:meta + 0x182 + 16] = bytes(16)
    repair_record(data, meta)
    path.write_bytes(bytes(data))


def run(binary, kind, image, out=None, command=None, debug=False):
    flags = ["--debug"] if debug else []
    if command == "info":
        proc = subprocess.run([str(binary), *flags, "info", str(image)],
                              capture_output=True, timeout=120)
        return proc, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")
    if kind == "rust":
        proc = subprocess.run([str(binary), "dump", str(image)],
                              capture_output=True, timeout=180)
    else:
        proc = subprocess.run([str(binary), "reconstruct", str(image), str(out)],
                              capture_output=True, timeout=180)
        if out is not None and out.exists():
            out.rename(out)
    return proc, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace")


def image_bytes(kind, proc, out):
    if kind == "rust":
        return proc.stdout if isinstance(proc.stdout, bytes) else proc.stdout.encode()
    return out.read_bytes()


def dump_image(binary, kind, image, out):
    """Run a dump and return (proc, every diagnostic line, stdout and stderr).

    The Rust tool writes diagnostics to stderr, the C++ tool to stdout, so the
    assertions below look at both.
    """
    import subprocess as sp
    if kind == "rust":
        with open(out, "wb") as f:
            proc = sp.run([str(binary), "dump", str(image)], stdout=f,
                          stderr=sp.PIPE, timeout=180)
        return proc, proc.stderr.decode(errors="replace")
    proc = sp.run([str(binary), "reconstruct", str(image), str(out)],
                  capture_output=True, timeout=180)
    text = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
    return proc, text


def gpt_type(img):
    entry = img[GPT_ENTRY_OFFSET:GPT_ENTRY_OFFSET + 128]
    return bytes(entry[0:16])


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def volume_line(info):
    for line in info.splitlines():
        if line.strip().startswith("v0 "):
            return line
    raise AssertionError("no volume line in info output")


def test_fat_is_read_from_the_boot_sector(binary, kind, work):
    image = work / "fat.adi"
    build_fixture(image, boot=fat32_boot_sector())
    clear_guids(image)     # nothing but the fallback can type this volume
    proc, info, err = run(binary, kind, image, command="info")
    expect(proc.returncode == 0, f"info failed: {err[-300:]}")
    line = volume_line(info)
    expect("FAT32" in line, f"filesystem not read from the boot sector: {line!r}")
    expect("NTFS" not in line, f"info still says NTFS: {line!r}")
    expect("FAT32?" not in line, f"detected filesystem marked as a guess: {line!r}")
    print("  FAT boot sector: info reports FAT32")

    out = work / "fat.img"
    proc, err = dump_image(binary, kind, image, out)
    expect(proc.returncode == 0, f"dump failed: {err[-300:]}")
    kind_guid = gpt_type(out.read_bytes())
    expect(kind_guid != ESP_GUID,
           "a FAT volume without an ESP label was typed as an EFI system partition")
    expect(kind_guid in (DATA_GUID, RECOVERY_GUID),
           f"FAT volume typed as {kind_guid.hex()}, expected a data partition type")
    print("  FAT boot sector: GPT type stays a data partition (not ESP)")


def test_esp_label_keeps_esp_type(binary, kind, work):
    image = work / "esp.adi"
    build_fixture(image, boot=fat32_boot_sector(label="ESP-BOOT"))
    set_label(image, "ESP-BOOT")
    clear_guids(image)
    proc, info, err = run(binary, kind, image, command="info")
    expect(proc.returncode == 0, f"info failed: {err[-300:]}")
    expect("FAT32" in volume_line(info), f"filesystem wrong: {volume_line(info)!r}")
    out = work / "esp.img"
    proc, err = dump_image(binary, kind, image, out)
    expect(proc.returncode == 0, f"dump failed: {err[-300:]}")
    expect(gpt_type(out.read_bytes()) == ESP_GUID,
           "a volume labelled ESP lost its EFI system partition type")
    print("  ESP label: still typed as EFI system partition")


def test_unreadable_boot_sector_is_reported(binary, kind, work):
    image = work / "blank.adi"
    build_fixture(image, boot=bytes(SECTOR))
    proc, info, err = run(binary, kind, image, command="info")
    expect(proc.returncode == 0, f"info failed: {err[-300:]}")
    line = volume_line(info)
    expect("?" in line.split("lba")[0],
           f"guessed filesystem is not marked as a guess: {line!r}")
    expect("guessed from the label" in info,
           f"info does not explain the '?' marker: {info[-300:]}")
    proc, info, err = run(binary, kind, image, command="info", debug=True)
    expect("boot sector" in err.lower() and "label" in err.lower(),
           f"no diagnostic about the unrecoverable boot sector: {err[-300:]}")
    print("  missing boot sector: filesystem marked as a guess, warning printed")


def test_dump_reports_coverage(binary, kind, work):
    image = work / "cov.adi"
    build_fixture(image, boot=fat32_boot_sector())
    out = work / "cov.img"
    proc, err = dump_image(binary, kind, image, out)
    expect(proc.returncode == 0, f"dump failed: {err[-300:]}")
    expect("bytes of block data placed" in err,
           f"dump does not report how much data it placed: {err[-300:]}")
    expect("left zero" in err, f"dump does not report the zero-filled part: {err[-300:]}")
    size = out.stat().st_size
    placed = int(err.split("data: ")[1].split(" bytes of block data placed")[0])
    zero = int(err.split("bytes of block data placed, ")[1].split(" bytes left zero")[0])
    expect(placed + zero == size,
           f"placed {placed} + zero {zero} does not add up to the image size {size}")
    expect(0 < placed < size, f"implausible placement count {placed} of {size}")
    print(f"  dump coverage: {placed} bytes placed, {zero} left zero")


def test_info_verifies_checksums(binary, kind, work):
    image = work / "crc.adi"
    build_fixture(image, boot=fat32_boot_sector())
    proc, info, err = run(binary, kind, image, command="info")
    expect(proc.returncode == 0, f"info failed: {err[-300:]}")
    line = [l for l in info.splitlines() if "verified:" in l]
    expect(line, f"info does not verify any block: {info[-400:]}")
    expect("0 mismatches" in line[0], f"a clean fixture reported mismatches: {line[0]!r}")
    checked = int(line[0].split("verified:")[1].split("of")[0])
    expect(checked >= 1, f"no block checked: {line[0]!r}")
    print(f"  info verification: {line[0].strip()}")

    data = bytearray(image.read_bytes())
    blocks = vdb_entries(data)
    expect(blocks, "fixture has no VDB entries")
    # Break the expected checksum only: the block still decodes, so `info` has to
    # compare CRCs instead of silently counting them.
    struct.pack_into("<I", data, blocks[0]["at"] + 0x1C, blocks[0]["crc"] ^ 0xFFFF)
    image.write_bytes(bytes(data))
    proc, info, err = run(binary, kind, image, command="info")
    line = [l for l in info.splitlines() if "verified:" in l]
    expect(line and "mismatch" in line[0], "info lost its verification line")
    expect("0 mismatches" not in line[0],
           f"a corrupted block was not reported as a mismatch: {line[0]!r}")
    print("  info verification: a corrupted block is reported")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("kind", choices=["rust", "cpp"])
    args = parser.parse_args()
    binary = args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="adi-fs-") as tmp:
        work = Path(tmp)
        test_fat_is_read_from_the_boot_sector(binary, args.kind, work)
        test_esp_label_keeps_esp_type(binary, args.kind, work)
        test_unreadable_boot_sector_is_reported(binary, args.kind, work)
        test_dump_reports_coverage(binary, args.kind, work)
        test_info_verifies_checksums(binary, args.kind, work)
    print("FS DETECT PASSED: boot-sector filesystem, GPT types, coverage report, info checks")


if __name__ == "__main__":
    main()
