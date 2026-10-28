#!/usr/bin/env python3
"""Deterministic bounded CLI mutation smoke tests, NOT exhaustive fuzzing.

Every subprocess has address-space, CPU, output-file and wall-clock limits on
POSIX. Nonzero error exits are allowed; signals, panics and hangs are failures.
"""
import argparse
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from test_properties import build, model
from adi_fixture import br_crc32
from make_standard_adi import BIFH_SIZE


def limits():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def invoke(binary, kind, path, output, command):
    args = [str(binary), '--debug', command, str(path)]
    if command == 'reconstruct':
        args.append(str(output))
    with output.open('wb') as stream:
        proc = subprocess.run(args, stdout=stream if command == 'dump' else subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=6,
                              preexec_fn=limits if os.name == 'posix' else None)
    assert proc.returncode in (0, 1, 2), (path.name, proc.returncode, proc.stderr[-4000:])
    assert b'panicked at' not in proc.stderr, (path.name, proc.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('kind', choices=['rust', 'cpp'])
    args = parser.parse_args()
    rng = random.Random(0xAD12026)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        base = tmp / 'base.adi'
        build(base, 3, 'compressed')
        original = base.read_bytes()
        # Framing and metadata corruption, including truncated containers. info
        # avoids turning mutated partition extents into huge raw output streams.
        for case in range(64):
            data = bytearray(original)
            if case < 16:
                data = data[:rng.randrange(len(data))]
            elif case < 32:
                pos = rng.choice([4, 8, len(data) - 12, len(data) - 8])
                struct.pack_into('<I', data, pos, rng.choice([0, 1, 15, 0xFFFFFFFF]))
            else:
                for _ in range(rng.randint(1, 8)):
                    pos = rng.randrange(len(data))
                    data[pos] ^= rng.randint(1, 255)
            path = tmp / f'container-{case}.adi'
            path.write_bytes(data)
            invoke(args.binary.resolve(), args.kind, path, tmp / 'out.img', 'info')
        # Repair record CRC after structural mutations, so semantic parsers are
        # exercised rather than merely rejecting corrupt checksums.
        table = 0x40 + (3 % 7) * 16 + 0x200
        index = BIFH_SIZE + table + len(model(3)[5]) * 32
        region = index + 0x34
        metadata = region + 0x30
        directory = metadata + 0x200 + 0x18 + 0x18
        targets = [(index, 0x10), (index, 0x14), (index, 0x18),
                   (region, 0x24), (region, 0x28), (region, 0x2c),
                   (metadata, 0x14), (directory, 0x10)]
        for case in range(32):
            data = bytearray(original)
            record, field = targets[case % len(targets)]
            struct.pack_into('<I', data, record + field, rng.choice([0, 1, 512, 4097, 0xFFFFFFFF]))
            size = struct.unpack_from('<I', data, record + 4)[0]
            struct.pack_into('<I', data, record + 8, 0)
            struct.pack_into('<I', data, record + 8, br_crc32(bytes(data[record:record + size])))
            path = tmp / f'structural-{case}.adi'
            path.write_bytes(data)
            invoke(args.binary.resolve(), args.kind, path, tmp / 'out.img', 'info')
        # Mutate compressed payload only: lengths/geometry stay bounded, but
        # literals, offsets and length extensions exercise decoder error paths.
        table = 0x40 + (3 % 7) * 16 + 0x200
        offset = struct.unpack_from('<Q', original, BIFH_SIZE + table + 0x0c)[0]
        size = struct.unpack_from('<I', original, BIFH_SIZE + table + 0x18)[0]
        for case in range(32):
            data = bytearray(original)
            for _ in range(rng.randint(1, 6)):
                pos = BIFH_SIZE + offset + rng.randrange(size)
                data[pos] ^= rng.randint(1, 255)
            path = tmp / f'payload-{case}.adi'
            path.write_bytes(data)
            invoke(args.binary.resolve(), args.kind, path, tmp / 'out.img',
                   'dump' if args.kind == 'rust' else 'reconstruct')
        print('MALFORMED PASSED: 128 resource-limited deterministic CLI mutations')

if __name__ == '__main__':
    main()
