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
  crcs:      0 records carry a checksum
  first off: 0x0
  last end:  0x3790

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

### Why streaming needs extra work

stdout is strictly sequential, but blocks in an `.adi` may be stored out of
disk order. `adi2raw` plans every block's target offset up front, then uses a
bounded reorder window (capped at 256 MiB) to emit bytes in order. For a
normally ordered image the window stays almost empty, so there is no staging
file and no large memory use. If an image needs more reordering than the cap
allows, `dump` stops with an explicit error rather than emitting a corrupt
stream; use `adi-extract reconstruct` to build a file in that case.

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
* If blocks are wildly out of order, the 256 MiB reorder cap aborts the dump.
* Header/footer CRC fields are parsed and displayed but not verified — there is
  no published checksum algorithm for the container.

---

## Tests

```bash
./tests/run-tests.sh
```

The suite builds the binary, generates synthetic `.adi` files (including a
two-volume image with different cluster sizes, sparse bitmaps and out-of-order
blocks), validates the GPT/MBR/NTFS structures in the output, checks marker
bytes at their expected disk offsets, exercises a broken pipe, and runs a real
`dump | dd` pipeline.

To also compare against the reference implementation:

```bash
ADI_EXTRACT=/path/to/adi-extract ./tests/run-tests.sh
```

On the synthetic images, `dump` was verified byte-for-byte identical to
`adi-extract reconstruct`.

## Licence

MIT — see [LICENSE](LICENSE).
