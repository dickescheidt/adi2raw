# Development notes

This file contains implementation and test details that are not needed for
ordinary installation and use. The user-facing guide is in `README.md`.

## Extraction paths

`open_image` tries the standard AOMEI record stream first. It uses the exact
0x20-byte VDB entries and 0x109 region geometry when a complete, CRC-valid
record set is found. If none is found, it automatically falls back to the
legacy signature scanner and boot-sector volume mapper. No user option is
needed to select that fallback.

The standard parser searches the final 4 MiB first for the record block because
it is normally near the end of the container. It accepts that fast path only
when it finds one complete, self-consistent record set; otherwise it scans the
whole file. `--full-scan` skips the fast path and searches the entire file
immediately.

VDB block checksums are checked against decoded data. `info` verifies a sample
on the standard-record path; `dump` checks every decoded block and skips blocks
whose checksum does not match. Output offsets are inferred from record metadata
or, on the legacy path, from boot-sector geometry. These checks do not prove
that the reconstructed image matches the source disk byte-for-byte.

## Streaming and temporary files

The output stream is sequential, while compressed blocks can arrive out of disk
order. `Streamer` buffers pending ranges in memory until the configured limit
is reached. It then writes them to a sparse temporary file, streams that file
to stdout in order, and removes it on completion. The default memory limit is
256 MiB; `--max-pending-mb N` changes it, `--no-spool` disables spill-to-disk,
and `--spool-dir DIR` selects the temporary-file directory.

Temporary spool files are created owner-only on Unix. On filesystems that
support sparse files, holes do not consume storage. The apparent file size can
still be large, and stdout remains empty until spooled data has been assembled
for ordered output.

## Partition tables

GPT is synthesized by default from recovered volume metadata. `--partition-table
gpt` explicitly selects it. MBR output is synthetic because the ADI metadata
does not retain all original MBR fields; partition type codes are inferred from
filesystem metadata. MBR output supports at most four primary partitions and
2^32 512-byte sectors. Legacy whole-disk streams with a detected native table
are preserved by default; an explicit synthesized-table selection is rejected
for those streams rather than overwriting their native metadata.

## Tests

Run the complete suite from the repository root:

```bash
./tests/run-tests.sh
```

The suite runs Rust unit tests and generates synthetic `.adi` fixtures for
partition placement, GPT/MBR selection, CRC failures, sparse bitmaps, ordered
and out-of-order blocks, scan strategy, malformed input, and a real `dump | dd`
pipeline. Test-only scripts also include randomized placement checks, decoder
robustness tests, filesystem detection checks, and offset-only debug traces.

Optional fuzzing harnesses are under `tests/fuzz/`; their prerequisites and
commands are documented in `tests/fuzz/README.md`.

## Diagnostics

`--debug` adds format-audit details and offset traces to stderr. It does not
change recovered bytes. Logs can disclose filenames, labels, disk geometry and
checksums, so review them before sharing.
