#!/usr/bin/env python3
"""Region-end regression: full bitmap, partial cluster, padding, sparse, invalid."""
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
binary = str(pathlib.Path(sys.argv[1]).resolve())
rust = sys.argv[2] == 'rust'
with tempfile.TemporaryDirectory() as tmp:
    for mode in ('boundary', 'boundary-padded', 'boundary-sparse', 'boundary-bad'):
        adi = pathlib.Path(tmp) / (mode + '.adi')
        raw = pathlib.Path(tmp) / (mode + '.img')
        subprocess.run([sys.executable, str(HERE / 'make_standard_adi.py'), str(adi), mode], check=True, stdout=subprocess.DEVNULL)
        args = [binary, 'dump' if rust else 'reconstruct', str(adi)]
        if not rust:
            args.append(str(raw))
        with raw.open('wb') as out:
            proc = subprocess.run(args, stdout=out if rust else subprocess.PIPE, stderr=subprocess.PIPE)
        if mode == 'boundary-bad':
            assert proc.returncode != 0, 'invalid region geometry silently accepted'
            assert b'0x109 geometry' in proc.stderr, proc.stderr
            print(mode + ': correctly rejected')
            continue
        assert proc.returncode == 0, proc.stderr
        assert b'geometry' not in proc.stderr.lower() and b'skipped' not in proc.stderr.lower(), proc.stderr
        data = raw.read_bytes()
        origin = 2048 * 512
        start = origin + 512 * 512
        expected = bytes([0xB0]) * 32768
        expected += bytes([0 if mode == 'boundary-sparse' else 0xB1]) * 32768
        expected += bytes([0xB2]) * 6144
        assert data[start:start + 71680] == expected, mode
        assert not any(data[start + 71680:start + 8 * 32768]), 'write crossed region boundary'
        assert data[origin + 32768:origin + 2 * 32768] == bytes([0xA1]) * 32768
        print(mode + ': OK')
