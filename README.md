# adi2raw

**Turn an AOMEI Backupper `.adi` backup into a raw disk image on stdout**, so you
can pipe it straight into `dd` and write a disk on the fly — no intermediate
image file needed.

Two commands, no third-party crates, written entirely in safe Rust:

```
adi2raw info <file.adi>     describe the image
adi2raw dump <file.adi>     stream the raw disk image to stdout
```

Based on [adi-extract](https://github.com/l4red0/adi-extract) by Leszek Sołtys
(MIT licence); see [LICENSE](LICENSE). Not affiliated with AOMEI — `.adi` and
`.afi` are proprietary formats with no published specification.

---

## Build

Requires a Rust toolchain (the crate uses the 2021 edition). No third-party
crates and no system libraries.

```bash
cargo build --release
./target/release/adi2raw --help
```

Or install into `~/.cargo/bin`:

```bash
cargo install --path .
```

## Usage

### Inspect first

Example (abbreviated; output from the two-volume synthetic test image):

```console
$ adi2raw info test.adi
file:     test.adi
size:     14720 bytes (0.00 GiB)

[BIFH header]
  magic:     BIFH
  size:      64 (0x40)
  checksum:  0x0
  ...
[block index]
  records:   5
  crcs:      5 records carry a BRCrc32 checksum
  verified:  5 decoded blocks checked, 0 mismatches, 0 unchecked
  first off: 0x0
  last end:  0x3790

[layout]
  legacy volume runs

[volumes]
  v0 NTFS       lba 2048   sectors 4097   cluster 512   blocks 3  stored 1 KiB  label 'NTFS'
  v1 NTFS       lba 8192   sectors 8193   cluster 4096  blocks 2  stored 12 KiB label 'NTFS'

[raw image]
  disk:      16419 sectors
  size:      8406528 bytes (0.01 GiB)
  blocks in disk order: no (reorder buffer streaming)
```

`info` tells you the exact size of the stream, the volumes that will be
reconstructed, and whether blocks are already in disk order. It does not modify
anything.

### Standard records and split image sets

Real AOMEI images contain a **standard record stream**: a 0x201 volume index,
a 0x202 data-block index, 0x109 region geometry, 0x102 volume metadata and
0x105/0x106 compression/encryption modes. Each 16-byte record header carries
its own `BRCrc32`, and only CRC-valid records are trusted.

`adi2raw` scans for those records first. When it finds a complete volume
record set, it reads the real 0x20-byte VDB entries directly, so `RegNo` and
`BlockNo` are known rather than inferred. The 0x109 record gives the exact
bitmap length and cluster size; the 0x102 record gives the partition's
absolute start LBA, size, GPT type GUID, unique GUID and label, which are used
verbatim in the synthesised GPT. Blocks whose decoded bytes fail their VDB
`Crc32` are warned about and skipped.

`ImgOffset` in a VDB entry is a **logical image-set offset**, not a raw file
offset. Reads go through the member formula
`physical = logical - DataOffInSet + BIFH.size`, where `DataOffInSet` and
`DataLenInSet` come from the BIFT tail (`+0x628` / `+0x620`). For split backups,
pass the extra members as a colon-separated list:

```bash
ADI2RAW_MEMBERS="Backup1.adi:Backup2.adi" adi2raw dump Backup.adi | dd of=/dev/sdX bs=1M
```

`info` prints each member's logical range. Members must form a contiguous
logical range; a read outside every member fails loudly rather than seeking to
the wrong file offset. Set `ADI2RAW_LEGACY_ONLY=1` to force the older
signature-scan parser, which is also the automatic fallback when an image has
no CRC-valid record sets (older generations and synthetic images).

Standard-record blocks are bounded by their `0x109` region length. Short final
blocks, including a partial final cluster, are supported; padded blocks are
clipped to the region boundary. Other decoded geometry mismatches stop extraction
with an error instead of silently omitting the block.

### Block checksums

Each 0x20-byte VDB index entry ends with a `BRCrc32` over the block's
**decoded** bytes — CRC32C/Castagnoli with a zero seed and a final bitwise
inversion (not zlib's CRC32). `info` decodes the blocks and reports how many
checksums it could verify; `dump` checks every block again before writing it.
A mismatch produces a warning on stderr and that single block is skipped, so
corrupt data is never silently passed off as zeros. Records whose checksum
field is zero are treated as "no checksum" and reported as *unchecked*.

`verified: N decoded blocks checked, 0 mismatches` is the quickest objective
health check on a real `.adi`. If you see mismatches on an otherwise readable
image, please include the count and a few warnings in a bug report.

### Stream to a disk

```bash
adi2raw dump "System Backup.adi" \
  | dd of=/dev/sdX bs=1M iflag=fullblock status=progress conv=fsync
```

Diagnostics go to **stderr**; stdout carries only raw bytes. `dump` refuses to
write binary to a terminal, so a bare `adi2raw dump file.adi` is safe.

Other things you can do with the stream:

```bash
adi2raw dump backup.adi > disk.img               # plain file
adi2raw dump backup.adi | sha256sum             # hash it without storing it
adi2raw dump backup.adi | gzip > disk.img.gz    # compressed archive
```

A plain `> disk.img` redirect is **not sparse**: stdout is a byte stream with
no way to express holes, so the zero-filled gaps allocate real disk blocks. If
you want a sparse image file, punch the holes as you write it:

```bash
adi2raw dump backup.adi | cp --sparse=always /dev/stdin disk.img
# or, with GNU dd:
adi2raw dump backup.adi | dd of=disk.img bs=4K iflag=fullblock conv=sparse status=progress
```

Do **not** use `conv=sparse` when writing to a raw device — skipping zero
blocks would leave stale data on the target disk.

`raw` is accepted as an alias for `dump`.

---

## What comes out

The stream is **byte-identical to the `disk.img` written by
`adi-extract reconstruct`** (verified on several synthetic images).
Concretely:

* 512-byte sectors, total length `disk_sectors × 512`.
* A **synthesised protective MBR + GPT** at the front and a backup GPT at the
  end, built from the volumes found in the backup. Partition type GUIDs are
  guessed from the filesystem.
* Only the **used clusters** stored in the backup are written. Every gap is
  filled with zeros, which are streamed cheaply from a static zero buffer.
* It is **not** a byte-exact forensic clone: the original partition table,
  unused sectors and deleted/unallocated data are not preserved.

Run `info` first to see how large the stream will be — it can be much larger
than the `.adi` file, because zeros are expanded.

### Multi-partition images

AOMEI usually stores a whole multi-partition disk as **one** contiguous chain
of blocks. Splitting volumes at gaps in that chain (the approach used by the
original tool) finds only the first partition and drops every cluster past its
end. `adi2raw` instead scans the whole decompressed stream for volume boot
records. Each boot sector's `hidden_sectors` field gives that partition's
absolute LBA; when they all agree on a constant stream origin, every cluster
is placed at `stream offset + origin` and the GPT gets one entry per
partition. If the stream already contains a protective MBR/GPT at LBA 0, it is
kept rather than overwritten.

The scan is one extra full decompression pass. `info` and `dump` print what
they decided on stderr:

```console
adi2raw: boot sectors: 4
adi2raw:   LBA 2048 (byte 1048576) at stream 0 -> origin 1048576  NTFS 1025 sectors
  ...
adi2raw: layout: whole-disk stream (origin 1048576 bytes)
```

If the boot-sector origins disagree, it falls back to the old volume-run
mapping with a warning. Set `ADI2RAW_LEGACY_MAP=1` to force that fallback. If
a real image is still misplaced, include those lines plus `adi2raw info` in a
bug report.

### Why streaming needs extra work

stdout is strictly sequential, but blocks in an `.adi` may be stored out of
disk order, and the LZ4 decoder must read them in chain order (each block can
reference the previous 64 KiB of output). `adi2raw` plans every block's target
offset up front, then uses a bounded in-memory reorder window. For a normally
ordered image the window stays almost empty, so there is no staging file and no
large memory use.

The block numbers in a VDB entry actually describe the *next* block, so region
resolution is one global one-record shift across the whole index. An earlier
version split the chain at metadata gaps and invented a region number for each
run head; that turned an ordered index into a fake multi-gigabyte backward
jump. Chain gaps are normal in real images and no longer affect ordering.

If the window would exceed 256 MiB, `dump` switches to a **sparse temporary
file**: the remaining clusters are written at their disk offsets with seeks,
then the file is streamed to stdout in order and deleted. The output is
byte-identical to the pure in-memory path (this is covered by a test). Note
that in this mode stdout stays empty until the whole `.adi` has been decoded,
so a piped `dd` will not start writing immediately.

Three environment variables control the behaviour:

| Variable | Meaning |
| --- | --- |
| `ADI2RAW_MAX_PENDING_MB` | In-memory reorder cap before spilling (default 256). |
| `ADI2RAW_SPOOL_DIR` | Directory for the temporary file (default `$TMPDIR` / `/tmp`). |
| `ADI2RAW_NO_SPOOL=1` | Refuse the spool and report the old error instead. |

The spool is sparse on ext4/xfs/btrfs — only the clusters actually stored in
the backup take up disk space, not the whole apparent image size. Pick
`ADI2RAW_SPOOL_DIR` on a filesystem with enough free space; on some systems
`/tmp` is a RAM-backed tmpfs, and a filesystem without sparse-file support
would allocate the full apparent size.

Rust ignores `SIGPIPE` by default, so when a consumer closes the pipe early
(e.g. `head`) the next write fails with `EPIPE`. `adi2raw` treats that as a
clean stop instead of reporting an I/O error.

---

## No `unsafe`

There is **no `unsafe` code** in this crate and no `unsafe` dependency. All
binary parsing uses bounds-checked slice helpers (`get`, `from_le_bytes`),
buffering uses `BufWriter`, and the reorder window uses `BTreeMap`. The one
place `unsafe` is sometimes needed in a program like this is restoring default
`SIGPIPE` behaviour via `libc::signal`; this project handles
`io::ErrorKind::BrokenPipe` instead, so it was not needed.

If you specifically want traditional SIGPIPE semantics (process dies with
signal 13 / exit 141), that is the single change that would require an
`unsafe` FFI call or a small `libc` dependency.

---

## Debug diagnostics and verification

Use `--debug` to enable extended format-audit diagnostics on **stderr**:

```bash
adi2raw --debug info backup.adi
adi2raw --debug dump backup.adi > disk.img 2> debug.log
```

The flag can appear before or after the command. Use `--` to end option parsing
if a filename is literally `--debug`. Existing corruption/skip warnings and fatal
errors remain visible without the flag. Debug mode changes diagnostics only,
not the recovered bytes or exit status.

Extended diagnostics cover unknown referenced records, rejected record-set
candidates, missing or ambiguous metadata/modes, absent/unverified checksums,
image-set gaps/overlaps, and inferred geometry or partition metadata. They also
explain that `info` does not decode and verify all payload blocks. Correctly
bounded partial final blocks are supported, not a geometry warning.

A zero exit status is not proof of a complete or exact restore. Review recovery
warnings; do not use partial output left by a failed command. This is a
reverse-engineered format: diagnostics cover detected uncertainty, not unknown
semantics the parser cannot recognize. Arbitrary signature-like bytes in
compressed payloads are not treated as records, so rejected scan candidates
alone do not trigger diagnostics.

Validate the recovered layout and filesystem independently before restoring
valuable media. Decoded block checksums do not verify destination placement or
prove that a reconstructed GPT is identical to the original partition table.

## Limitations

Same constraints as the tool it is based on, plus streaming-specific ones:

* One **full** `.adi` disk image. No incremental/differential chains, split
  image sets, or password-protected/encrypted images.
* `.afi` file backups are a different container and are **not** supported.
* Volume geometry is inferred from NTFS/FAT boot sectors; BitLocker, exFAT and
  unknown filesystems are detected but not usefully mapped.
* The block index is found by scanning the payload for record signatures. This
  is a linear pass over the `.adi` — fine for a one-off conversion, but it is
  the dominant cost on very large backups.
* If blocks are wildly out of order, `dump` spills to a sparse temp file. Set
  `ADI2RAW_NO_SPOOL=1` to make that an error instead.
* Split image sets need their extra members supplied explicitly via
  `ADI2RAW_MEMBERS`; they are not auto-discovered by filename.
* Only compression mode 1 (AOMEI LZ4) and direct (uncompressed) blocks are
  supported; encryption mode 0 is required. Other 0x105/0x106 modes are
  rejected with a clear error instead of producing garbage.
* Per-block `BRCrc32` values are verified. BIFH/BIFT and standard-record CRCs
  are also checked and reported, but are not required to be valid (some older
  images carry none).

---

## Tests

```bash
./tests/run-tests.sh
```

The suite builds the binary, generates synthetic `.adi` files — including a
two-volume image with different cluster sizes, a four-partition image stored as
one contiguous chain, an image with a deliberately wrong block checksum, a
32 KiB-cluster image with a sparse one-byte bitmap, an ordered index with chain
gaps, an eight-block image stored in reverse disk order, a **real-format image**
with CRC-valid 0x201/0x202/0x102/0x105/0x106/0x109 records and a 0x20-byte VDB
table, and a **split image set** whose second stored block lives in a second
member file — validates the
GPT/MBR/NTFS structures in the output, checks marker bytes at their expected
disk offsets, exercises a broken pipe, and runs a real `dump | dd` pipeline.
The four-partition case is a regression test for volume discovery; the
reverse-order case checks that the sparse spool produces exactly the same bytes
as the in-memory path and cleans up after itself. Unit tests cover the CRC32C
vectors, the global region shift and the 32 KiB block layout.

To also compare against the reference implementation:

```bash
ADI_EXTRACT=/path/to/adi-extract ./tests/run-tests.sh
```

On the synthetic images, `dump` was verified byte-for-byte identical to
`adi-extract reconstruct`.

### Testing without a private backup

The full suite includes deterministic randomized and malformed-input tests:

* **Placement oracle:** 24 seeds vary cluster/block geometry, sparse bitmaps,
  unused bitmap bits, region bases and partial final clusters. Expected partition
  bytes are constructed directly from logical sector addresses, independently of
  the production parser/decoder. The writer reuses fixture framing/CRC helpers,
  so this is not an independent specification of the entire ADI format.
* **Metamorphic tests:** each model is encoded six ways: direct, literal-only
  compression, overlapping LZ4 matches, padded final blocks, regrouped VDB
  references, and split members. Variants also reorder entries/storage and
  relocate metadata. A member boundary falls inside stored block bytes. All six
  must produce identical whole-disk output as well as match the placement oracle.
* **Malformed-input smoke tests:** 128 deterministic cases cover truncation,
  framing corruption, CRC-repaired structural mutations and compressed payload
  corruption. POSIX subprocesses have 512 MiB address-space, three-second CPU,
  six-second wall-clock and 32 MiB output-file limits. Expected errors/skips are
  allowed; signals, panics and timeouts fail the tests.
* **Decoder smoke fuzzing:** 4,096 deterministic short inputs plus known
  overlapping matches and truncations. The C++ safety suite runs these under
  AddressSanitizer/UBSan; Rust runs them as unit tests.

These are bounded regression/smoke tests, not coverage-guided fuzzing or proof
that arbitrary hostile inputs cannot exhaust resources. A real AOMEI restore
comparison and independent filesystem checks remain necessary.

For a longer reproducible placement run:

```bash
python3 tests/test_properties.py ./target/release/adi2raw rust --seeds 200
```

### Coverage-guided fuzzing

Optional cargo-fuzz harnesses harden the record parsers, the LZ4 decoder and the whole
container path against malformed input. They are not part of the default test suite;
see [`tests/fuzz/README.md`](tests/fuzz/README.md) for prerequisites, targets and the
recorded campaign. Run them with:

```bash
sh tests/fuzz/run.sh 90
```

The 2026-10-28 campaign executed about 9.5 million cases under libFuzzer with
AddressSanitizer and found no crash, hang or sanitizer report. Fuzzing cannot validate
the format itself and does not replace a real AOMEI restore comparison.

### Offset-only debug trace

For the standard-record extraction path, `--debug` also emits `trace:` lines
showing VDB region/block identity, stored logical offsets, member ordinals and
physical read chunks, decoded size/checksum, bitmap and destination write ranges.
Trace lines contain no recovered payload bytes, labels, GUIDs or filenames.
They are not a substitute for the decoded checksum/skip diagnostics.

```bash
adi2raw --debug dump backup.adi > disk.img 2> debug.log
grep 'trace:' debug.log > offsets.trace.txt
```

Review before sharing: the complete debug log can contain filenames/labels,
and even an offset-only trace exposes disk geometry, sparse allocation and
checksums. Tracing is opt-in and does not change recovered bytes.

## Licence

MIT — see [LICENSE](LICENSE).
