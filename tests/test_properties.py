#!/usr/bin/env python3
"""Seeded placement oracle and equivalent-layout tests; no real backup required.

The oracle writes byte strings to sector addresses directly. It does not use the
production layout/decoder code or infer positions from decoded fixture bytes.
Only framing/CRC and literal encoding helpers are shared with older fixtures.
"""
import argparse
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from adi_fixture import br_crc32, lz4_literals
from make_standard_adi import container_header, container_tail, record, vdb_entry, BIFH_SIZE

BPS = 512
START = 2048

def model(seed):
    rng = random.Random(seed)
    cpb = rng.choice([1, 7, 8, 9, 17, 64])
    spc = rng.choice([1, 8, 64])
    count = rng.randint(2, 5)
    begin = rng.choice([0, 3, 32])
    sectors = (count - 1) * cpb * spc + rng.randint(1, cpb * spc)
    partition = begin + sectors + 64
    expected = bytearray(partition * BPS)
    blocks = []
    for block in range(count):
        bitmap = bytearray((cpb + 7) // 8)
        values = {}
        for cluster in range(cpb):
            # Always include the final cluster and some beyond the region boundary.
            if rng.random() < .55 or block == count - 1:
                bitmap[cluster // 8] |= 1 << (cluster % 8)
                value = bytes([1 + (seed * 11 + block * 17 + cluster) % 254]) * (spc * BPS)
                values[cluster] = value
                sector = block * cpb * spc + cluster * spc
                available = max(0, min(spc, sectors - sector)) * BPS
                destination = (begin + sector) * BPS
                if available:
                    expected[destination:destination + available] = value[:available]
        # Unused bitmap bits are not clusters.
        for bit in range(cpb, len(bitmap) * 8):
            bitmap[bit // 8] |= 1 << (bit % 8)
        blocks.append((bytes(bitmap), values))
    return cpb, spc, begin, sectors, partition, blocks, bytes(expected)


def lz4_runs(data):
    """Small independent encoder: literals plus offset-1 overlapping matches."""
    result = bytearray()
    pending = bytearray()
    def length_extension(n):
        result.extend(bytes([255]) * (n // 255))
        result.append(n % 255)
    i = 0
    while i < len(data):
        end = i + 1
        while end < len(data) and data[end] == data[i]:
            end += 1
        run = end - i
        if run < 5:
            pending += data[i:end]
        else:
            pending.append(data[i])
            match = run - 1 - 4
            result.append((min(len(pending), 15) << 4) | min(match, 15))
            if len(pending) >= 15:
                length_extension(len(pending) - 15)
            result += pending
            pending.clear()
            result += b'\x01\x00'
            if match >= 15:
                length_extension(match - 15)
        i = end
    if pending:
        result.append(min(len(pending), 15) << 4)
        if len(pending) >= 15:
            length_extension(len(pending) - 15)
        result += pending
    return bytes(result)


def build(path, seed, variant):
    cpb, spc, begin, sectors, partition, blocks, expected = model(seed)
    rng = random.Random(seed + 1000)
    entries_order = list(range(len(blocks)))
    physical_order = list(entries_order)
    if variant != 'plain':
        rng.shuffle(entries_order)
        rng.shuffle(physical_order)
    grouped = variant in ('grouped', 'split')
    refs = len(blocks) if grouped else 1
    table = 0x40 + (seed % 7) * 16 + (0x200 if variant != 'plain' else 0)
    index = table + len(blocks) * 32
    index_size = 0x24 + refs * 16
    region = index + index_size
    metadata = region + 0x30
    compress = metadata + 0x200
    encrypt = compress + 0x18
    directory = encrypt + 0x18
    data_start = directory + 0x64 + 31
    payload = bytearray(data_start)
    stored = {}
    for number in physical_order:
        bitmap, values = blocks[number]
        decoded = bytearray(bitmap)
        for cluster in range(cpb):
            if cluster not in values:
                continue
            available = max(0, min(spc, sectors - number * cpb * spc - cluster * spc)) * BPS
            decoded += values[cluster] if variant == 'padded' else values[cluster][:available]
        decoded = bytes(decoded)
        encoded = decoded if variant in ('plain', 'padded') else (lz4_literals(decoded) if variant == 'literals' else lz4_runs(decoded))
        offset = len(payload)
        payload += encoded
        stored[number] = (offset, len(decoded), len(encoded), br_crc32(decoded))
    for slot, number in enumerate(entries_order):
        off, old, new, crc = stored[number]
        payload[table + slot * 32:table + (slot + 1) * 32] = vdb_entry(0, number, off, old, new, crc)

    def fill_index(r):
        struct.pack_into('<IIII', r, 0x10, refs, len(blocks), 32, 0)
        for i in range(refs):
            offset = table + (32 * i if grouped else 0)
            count = 1 if grouped else len(blocks)
            struct.pack_into('<QII', r, 0x24 + 16 * i, offset, count * 32, count)
    def fill_region(r):
        struct.pack_into('<IQQIII', r, 0x10, 0, begin, sectors, cpb, spc, BPS)
    def fill_meta(r):
        struct.pack_into('<IQQ', r, 0x14, BPS, START, partition)
        r[0x34:0x3c] = 'DATA'.encode('utf-16le')
        r[0x172:0x182] = bytes.fromhex('a2a0d0ebe5b9334487c068b6b72699c7')
        r[0x182:0x192] = bytes.fromhex('00112233445566778899aabbccddeeff')
    def fill_dir(r):
        struct.pack_into('<I', r, 0x10, 5)
        for i, (kind, size, off) in enumerate([(0x202, index_size, index), (0x109, 0x30, region),
                                               (0x102, 0x200, metadata), (0x105, 0x18, compress),
                                               (0x106, 0x18, encrypt)]):
            struct.pack_into('<IIQ', r, 0x14 + i * 16, kind, size, off)
    records = [(index, record(0x202, index_size, fill_index)),
               (region, record(0x109, 0x30, fill_region)),
               (metadata, record(0x102, 0x200, fill_meta)),
               (compress, record(0x105, 0x18, lambda r: struct.pack_into('<I', r, 0x14, 1))),
               (encrypt, record(0x106, 0x18, lambda r: struct.pack_into('<I', r, 0x14, 0))),
               (directory, record(0x201, 0x64, fill_dir))]
    for off, raw in records:
        payload[off:off + len(raw)] = raw
    extra = None
    if variant == 'split':
        # Boundary is inside a stored block, not merely between blocks.
        off, _, size, _ = stored[physical_order[0]]
        cut = off + max(1, size // 2)
        parts = [payload[:cut], payload[cut:]]
        extra = Path(str(path) + '.member1.adi')
        for member, data, start in [(path, parts[0], 0), (extra, parts[1], cut)]:
            member.write_bytes(container_header(BIFH_SIZE) + data + container_tail(len(data), start))
    else:
        path.write_bytes(container_header(BIFH_SIZE) + payload + container_tail(len(payload), 0))
    return expected, extra


def run(binary, kind, path, output, extra=None, debug=False, timeout=10):
    env = dict(os.environ)
    env.pop('ADI2RAW_MEMBERS', None)
    env.pop('ADI_EXTRACT_MEMBERS', None)
    if extra:
        env['ADI2RAW_MEMBERS' if kind == 'rust' else 'ADI_EXTRACT_MEMBERS'] = str(extra)
    args = [str(binary)] + (['--debug'] if debug else []) + ['dump' if kind == 'rust' else 'reconstruct', str(path)]
    if kind != 'rust':
        args.append(str(output))
    with output.open('wb') as stream:
        return subprocess.run(args, env=env, stdout=stream if kind == 'rust' else subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('kind', choices=['rust', 'cpp'])
    parser.add_argument('--seeds', type=int, default=24)
    args = parser.parse_args()
    binary = args.binary.resolve()
    count = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for seed in range(args.seeds):
            baseline = None
            for variant in ('plain', 'literals', 'compressed', 'padded', 'grouped', 'split'):
                path = tmp / f'{seed}-{variant}.adi'
                output = tmp / 'out.img'
                expected, extra = build(path, seed, variant)
                proc = run(binary, args.kind, path, output, extra)
                assert proc.returncode == 0, (seed, variant, proc.stderr)
                data = output.read_bytes()
                got = data[START * BPS:(START * BPS) + len(expected)]
                assert got == expected, (seed, variant, 'placement oracle mismatch')
                # Whole disk, including GPT, must also be equivalent across variants.
                if baseline is None:
                    baseline = data
                assert data == baseline, (seed, variant, 'metamorphic mismatch')
                count += 1
        print(f'PROPERTIES PASSED: {args.seeds} seeds, {count} layouts, independent byte oracle')

if __name__ == '__main__':
    main()
