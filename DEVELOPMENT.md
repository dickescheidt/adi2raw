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

## Linux pipe output

On Linux, `dump` selects a `vmsplice(2)` writer only when stdout is a pipe and
its capacity is page-aligned and no larger than 1 MiB. It best-effort requests
128 KiB when the pipe is smaller and falls back to the capacity already
available if the request is denied. By default, the two staging buffers are
2 MiB-aligned and receive a best-effort `MADV_HUGEPAGE` hint; if allocation or
the hint fails, ordinary page-aligned buffers are used. `--no-huge-pages`
disables that attempt. `--busy-loop` opts into nonblocking `vmsplice` calls and
spins on a full pipe; the default is blocking, avoiding busy CPU use.

`--no-vmsplice` forces the ordinary buffered `Write` path and skips pipe
resizing and these buffer options. Other outputs and non-Linux builds use that
fallback automatically; no extra crate is required. The isolated unsafe
syscalls and buffer management live in `src/linux_pipe.rs`.

The writer copies output into two page-aligned staging buffers sized for the
pipe capacity. This copy is not inherent to `vmsplice`, but keeps borrowed and
reused source slices stable until the kernel no longer references them. A
buffer is not reused until a full subsequent buffer has entered the pipe, which
means the pipe had to drain the older full buffer first. After any successful
splice, both allocations are intentionally retained until process exit so the
final queued pages cannot be reused while a downstream reader may still
reference them. This bounds retained staging memory to 4 MiB per dump process
when huge-page allocation succeeds, or at most 2 MiB with ordinary buffers.

The Linux unit test checks the fast path over an anonymous pipe, including
multiple full buffers, a partial final buffer, and byte-for-byte equality; a
regular file descriptor exercises fallback detection. The complete integration
suite also covers the real `dump | dd` path and early downstream closure.

Before pipe resizing and huge-page hints were added, a synthetic 8 GiB
mostly-zero image streamed to `cat >/dev/null` measured 9.56 s median on the
base commit and 4.38 s median with the initial vmsplice path (three runs per
build after warm-up, alternating build order; about 2.18x on that host). This
measures stdout streaming rather than ADI decoding or disk input; it is
machine- and workload-specific, not a performance guarantee.

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
