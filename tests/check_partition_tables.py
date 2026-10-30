#!/usr/bin/env python3
"""Validate synthesized MBR and GPT headers in dump output."""
import pathlib
import sys

mbr_path, gpt_path, default_path, multipart_path = map(pathlib.Path, sys.argv[1:5])
mbr = mbr_path.read_bytes()
gpt = gpt_path.read_bytes()
default = default_path.read_bytes()
assert len(mbr) == len(gpt) == len(default)
assert mbr[510:512] == b"\x55\xaa"
assert mbr[450] == 0x07, f"expected inferred NTFS MBR type 0x07, got {mbr[450]:#x}"
assert mbr[512:520] != b"EFI PART", "MBR output unexpectedly contains a GPT header"
assert gpt[512:520] == b"EFI PART", "explicit GPT output has no primary GPT header"
assert default[512:520] == b"EFI PART", "GPT is not the default synthesized table"
assert gpt == default, "explicit GPT output differs from the default output"

four = multipart_path.read_bytes()
assert four[510:512] == b"\x55\xaa"
assert four[512:520] != b"EFI PART"
entries = [four[446 + 16 * i : 446 + 16 * (i + 1)] for i in range(4)]
assert all(entry[4] != 0 for entry in entries), "expected four non-empty MBR entries"
assert all(int.from_bytes(entry[12:16], "little") > 0 for entry in entries)
print("partition table selection: OK")
