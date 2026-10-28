#!/usr/bin/env python3
"""Validate opt-in, payload-free placement traces, including cross-member reads."""
from pathlib import Path
import re
import struct
import sys
import tempfile
from make_standard_adi import BIFH_SIZE, BIFT_SIZE
from test_properties import build, model, run, BPS, START

binary = Path(sys.argv[1]).resolve()
kind = sys.argv[2]
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    path = tmp / 'private-backup-name.adi'
    output = tmp / 'out.img'
    expected, extra = build(path, 0, 'split')
    cpb, spc, begin, sectors, _, blocks, _ = model(0)
    proc = run(binary, kind, path, output, extra, debug=True)
    assert proc.returncode == 0, proc.stderr
    image = output.read_bytes()
    lines = [line for line in proc.stderr.decode().splitlines() if 'trace:' in line]
    assert lines and all(str(path) not in line and path.name not in line for line in lines), lines
    vdb = re.findall(r'vdb region=(\d+) block=(\d+) logical=0x([0-9a-f]+).*output_base=0x([0-9a-f]+)', '\n'.join(lines))
    assert len(vdb) == len(blocks), vdb
    for reg, block, logical, base in vdb:
        assert int(reg) == 0
        assert int(base, 16) == (START + begin + int(block) * cpb * spc) * BPS
    reads = re.findall(r'read member=(\d+) logical=0x([0-9a-f]+) physical=0x([0-9a-f]+) bytes=(\d+)', '\n'.join(lines))
    cut = struct.unpack_from('<Q', path.read_bytes(), path.stat().st_size - BIFT_SIZE + 0x620)[0]
    assert {int(m) for m, *_ in reads} == {0, 1}, reads
    for member, logical, physical, length in reads:
        start = 0 if int(member) == 0 else cut
        assert int(physical, 16) == BIFH_SIZE + int(logical, 16) - start
        assert int(length) > 0
    writes = re.findall(r'write logical=0x[0-9a-f]+ decoded_offset=\d+ output=0x([0-9a-f]+) bytes=(\d+)', '\n'.join(lines))
    assert writes
    assert sum(int(n) for _, n in writes) == sum(byte != 0 for byte in expected)
    for offset, length in writes:
        offset, length = int(offset, 16), int(length)
        assert (START + begin) * BPS <= offset < offset + length <= (START + begin + sectors) * BPS
    checksums = re.findall(r'crc_actual=0x([0-9a-f]+) crc_expected=0x([0-9a-f]+)', '\n'.join(lines))
    assert len(checksums) == len(blocks) and all(int(a, 16) == int(b, 16) for a, b in checksums)
    assert any('trace: bitmap ' in line for line in lines)
    quiet = run(binary, kind, path, output, extra, debug=False)
    assert quiet.returncode == 0 and b'trace:' not in quiet.stderr
    assert image == output.read_bytes(), 'trace changed recovered bytes'
    print('TRACE PASSED: VDB identity, split-member translation, CRCs, bitmap and bounded writes')
