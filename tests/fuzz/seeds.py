"""Reproducible public synthetic corpus; no user backups."""
import sys
from pathlib import Path
import struct
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_properties import build
from make_standard_adi import BIFH_SIZE

def seed_corpus(root):
    for name in ('codec', 'records', 'image_file', 'legacy'):
        (root / name).mkdir(parents=True, exist_ok=True)
    codec = [b'', b'\xf0', b'\x30ABC', b'\x1fA\x01\x00\x00', b'\x1fA\x01\x00\xff\x00']
    for i, data in enumerate(codec):
        (root / 'codec' / f'seed-{i}').write_bytes(data)
        (root / 'legacy' / f'seed-{i}').write_bytes(data)
    rng = 0x2026AD1
    for i in range(8):
        blob = bytearray()
        for _ in range(16):
            rng = (rng * 1103515245 + 12345) & 0xFFFFFFFF
            blob.append(rng >> 24)
        (root / 'legacy' / f'random-{i}').write_bytes(blob)
    import make_standard_adi as fixture
    for seed in range(4):
        path = root / 'image_file' / f'valid-{seed}.adi'
        build(path, seed, 'compressed')
        data = path.read_bytes()
        # Raw bodies for each independent standard-record parser (CRC bypass intentional).
        for at in range(BIFH_SIZE, len(data) - 16):
            kind, size = struct.unpack_from('<II', data, at)
            if kind in (0x201, 0x202, 0x102, 0x105, 0x106, 0x109) and 16 <= size <= 4096 and at + size <= len(data):
                (root / 'records' / f'{seed}-{kind:x}').write_bytes(data[at:at + size])
