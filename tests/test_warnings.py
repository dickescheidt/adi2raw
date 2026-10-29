#!/usr/bin/env python3
"""Extended audit diagnostics are opt-in; raw output and real damage warnings stay unchanged."""
import pathlib
import struct
import subprocess
import sys
import tempfile
from adi_fixture import br_crc32
from make_standard_adi import BIFH_SIZE, BIFT_SIZE

HERE = pathlib.Path(__file__).resolve().parent
BINARY = str(pathlib.Path(sys.argv[1]).resolve())
RUST = sys.argv[2] == 'rust'

def u32(data, pos):
    return struct.unpack_from('<I', data, pos)[0]

def put32(data, pos, value):
    struct.pack_into('<I', data, pos, value)

def crc_record(data, off):
    size = u32(data, off + 4)
    put32(data, off + 8, 0)
    put32(data, off + 8, br_crc32(bytes(data[off:off + size])))

def find_record(data, kind):
    for off in range(BIFH_SIZE, len(data) - BIFT_SIZE - 16):
        if u32(data, off) == kind:
            size = u32(data, off + 4)
            if size < 16 or size > 4096:
                continue
            raw = bytearray(data[off:off + size])
            expected = u32(raw, 8)
            put32(raw, 8, 0)
            if br_crc32(bytes(raw)) == expected:
                return off
    raise AssertionError(hex(kind))

with tempfile.TemporaryDirectory() as tmp:
    base = pathlib.Path(tmp) / 'base.adi'
    subprocess.run([sys.executable, str(HERE / 'make_standard_adi.py'), str(base), 'single'], check=True, stdout=subprocess.DEVNULL)
    original = base.read_bytes()
    directory = find_record(original, 0x201)
    index = find_record(original, 0x202)
    table = struct.unpack_from('<Q', original, index + 0x24)[0] + BIFH_SIZE
    for case, expected in [
        ('unknown', b'unknown referenced record'),
        ('missing-mode', b'missing compression/encryption mode'),
        ('missing-metadata', b'metadata'),
        ('missing-region', b'skipped'),
        ('zero-size', b'skipped'),
        ('no-checksum', b'no decoded checksum'),
        ('bad-checksum', b'mismatch'),
        ('bad-container', b'checksum'),
        ('bad-reference', b'candidate skipped'),
        ('count', b'count'),
        ('bad-sector-size', b'sector size'),
    ]:
        data = bytearray(original)
        if case in ('unknown', 'missing-mode', 'missing-metadata'):
            types = {'unknown': [0x105], 'missing-mode': [0x105, 0x106], 'missing-metadata': [0x102]}[case]
            for kind in types:
                pos = find_record(data, kind)
                put32(data, pos, kind + 0x700)
                crc_record(data, pos)
                for i in range(u32(data, directory + 0x10)):
                    entry = directory + 0x14 + i * 16
                    if u32(data, entry) == kind:
                        put32(data, entry, kind + 0x700)
            crc_record(data, directory)
        elif case == 'missing-region':
            put32(data, table + 32, 999)
        elif case == 'zero-size':
            put32(data, table + 32 + 0x18, 0)
        elif case == 'no-checksum':
            put32(data, table + 32 + 0x1c, 0)
        elif case == 'bad-checksum':
            put32(data, table + 32 + 0x1c, 123)
        elif case == 'bad-container':
            data[8] ^= 1
        elif case == 'bad-reference':
            pos = find_record(data, 0x109)
            data[pos + 8] ^= 1
        elif case == 'count':
            put32(data, index + 0x14, 3)
            crc_record(data, index)
        elif case == 'bad-sector-size':
            pos = find_record(data, 0x102)
            put32(data, pos + 0x14, 0)
            crc_record(data, pos)
        image = pathlib.Path(tmp) / (case + '.adi')
        image.write_bytes(data)
        for command in ('info', 'dump' if RUST else 'reconstruct'):
            raw = pathlib.Path(tmp) / (case + '.raw')
            args = [BINARY, '--debug', command, str(image)]
            if command == 'reconstruct':
                args.append(str(raw))
            proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Invalid references can force legacy fallback and fail; they must still warn.
            if case not in ('bad-reference',):
                assert proc.returncode == 0, (case, command, proc.stderr)
            wanted = b'info verifies a sample' if case == 'bad-checksum' and command == 'info' else expected
            assert wanted in proc.stderr.lower(), (case, command, proc.stderr)
            if RUST and command == 'dump':
                assert b'adi2raw: warn:' not in proc.stdout, 'diagnostics contaminated raw stdout'
            debug_image = raw.read_bytes() if command == 'reconstruct' and raw.exists() else None
            quiet = subprocess.run([a for a in args if a != '--debug'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert quiet.returncode == proc.returncode, (case, 'debug changed status')
            assert quiet.stdout == proc.stdout, (case, 'debug changed stdout')
            if debug_image is not None:
                assert debug_image == raw.read_bytes(), (case, 'debug changed image')
            if case == 'bad-checksum' and command != 'info':
                assert b'mismatch' in quiet.stderr.lower(), 'actual corruption warning hidden'
            else:
                assert wanted not in quiet.stderr.lower(), (case, 'extended message leaked without --debug', quiet.stderr)
        print(case + ': opt-in diagnostics / identical output OK')

# Checksums of extra members must not go unchecked just because the primary is valid.
with tempfile.TemporaryDirectory() as tmp:
    image = pathlib.Path(tmp) / 'split.adi'
    subprocess.run([sys.executable, str(HERE / 'make_standard_adi.py'), str(image), 'split'], check=True, stdout=subprocess.DEVNULL)
    member = pathlib.Path(str(image) + '.member1.adi')
    data = bytearray(member.read_bytes())
    data[8] ^= 1
    member.write_bytes(data)
    import os
    env = dict(os.environ)
    env['ADI2RAW_MEMBERS' if RUST else 'ADI_EXTRACT_MEMBERS'] = str(member)
    proc = subprocess.run([BINARY, '--debug', 'info', str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr
    assert member.name.encode() in proc.stderr and b'checksum' in proc.stderr, proc.stderr
    quiet = subprocess.run([BINARY, 'info', str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert b'checksum' not in quiet.stderr.lower(), quiet.stderr
    print('extra-member-checksum: opt-in diagnostics OK')
    # An invalid logical range is visible even when info does not read that payload.
    put32(data, 8, u32(data, 8) ^ 1)
    tail = len(data) - BIFT_SIZE
    logical = struct.unpack_from('<Q', data, tail + 0x628)[0]
    struct.pack_into('<Q', data, tail + 0x628, logical + 512)
    put32(data, len(data) - 12, 0)
    put32(data, len(data) - 12, br_crc32(bytes(data[tail:])))
    member.write_bytes(data)
    proc = subprocess.run([BINARY, '--debug', 'info', str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr
    assert b'gap or overlap' in proc.stderr, proc.stderr
    quiet = subprocess.run([BINARY, 'info', str(image)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert b'gap or overlap' not in quiet.stderr, quiet.stderr
    print('member-gap: opt-in diagnostics OK')

# Global option positions and literal --debug filename after the option terminator.
with tempfile.TemporaryDirectory() as tmp:
    image = pathlib.Path(tmp) / '--debug'
    subprocess.run([sys.executable, str(HERE / 'make_standard_adi.py'), str(image), 'single'], check=True, stdout=subprocess.DEVNULL)
    baseline = subprocess.run([BINARY, 'info', str(image)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert baseline.returncode == 0 and b'warn' not in baseline.stderr.lower(), baseline.stderr
    for args in ([BINARY, '--debug', 'info', str(image)],
                 [BINARY, 'info', '--debug', str(image)],
                 [BINARY, 'info', str(image), '--debug']):
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.returncode == 0 and proc.stdout == baseline.stdout, proc.stderr
        assert b'info verifies a sample' in proc.stderr, proc.stderr
    literal = subprocess.run([BINARY, 'info', '--', '--debug'], cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert literal.returncode == 0 and b'warn' not in literal.stderr.lower(), literal.stderr
    print('flag positions / -- terminator / quiet default: OK')
