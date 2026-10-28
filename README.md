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
  `ADI2RAW_NO_SPOOL=1` to make that an error instead. The block-index signature
  scan and the standard `0x201`/`0x202`/`0x109` record path are not parsed, so
  split image sets and images whose `ImgOffset` is not a raw file offset are not
  supported.
* Per-block `BRCrc32` values are verified. Header/footer CRC fields are parsed
  and displayed but not verified — there is no published checksum algorithm for
  the container.

---

## Tests

```bash
./tests/run-tests.sh
```

The suite builds the binary, generates synthetic `.adi` files — including a
two-volume image with different cluster sizes, a four-partition image stored as
one contiguous chain, an image with a deliberately wrong block checksum, a
32 KiB-cluster image with a sparse one-byte bitmap, an ordered index with chain
gaps, and an eight-block image stored in reverse disk order — validates the
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

## Licence

MIT — see [LICENSE](LICENSE).
