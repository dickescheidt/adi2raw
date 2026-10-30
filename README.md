# adi2raw

Turn a complete AOMEI Backupper `.adi` disk backup into a raw disk image. The
image is written to stdout, so it can be saved to a file or streamed directly
to a disk.

## Install

Requires a Rust toolchain. Clone the repository and install it with Cargo:

```bash
git clone https://github.com/dickescheidt/adi2raw.git
cd adi2raw
cargo install --path .
```

Or build a standalone release binary:

```bash
cargo build --release
./target/release/adi2raw --help
```

## Use

Inspect the backup first, then write the raw image:

```bash
adi2raw info backup.adi
adi2raw dump backup.adi > disk.img
```

To stream directly to a device, double-check the destination: this overwrites
it completely.

```bash
adi2raw dump backup.adi | dd of=/dev/sdX bs=1M status=progress
```

Options go before the filename:

```bash
adi2raw dump --partition-table mbr backup.adi > disk-mbr.img
```

| Option | Description |
| --- | --- |
| `-p, --partition-table mbr\|gpt` | Choose a synthesized table; GPT is the default. |
| `--spool-dir DIR` | Choose where temporary reorder data is stored. The default is shown by `--help`. |
| `--max-pending-mb N` | Set the in-memory reorder limit before spooling (default: 256 MiB). |
| `--no-spool` | Fail rather than use a temporary file if the memory limit is exceeded. |
| `--no-vmsplice` | Disable the Linux pipe fast path. |
| `--no-huge-pages` | Disable the default best-effort huge-page hint for Linux pipe buffers. |
| `--busy-loop` | Opt into spinning on a full Linux pipe instead of blocking (uses more CPU). |
| `--full-scan` | Search the entire backup for metadata instead of trying the faster tail scan first. |
| `--debug` | Print additional diagnostics to stderr. |
| `-h, --help` | Show the complete option list. |

## Notes

- The default output uses a synthesized GPT. MBR output is also synthesized: it
  infers partition types and supports at most four primary partitions and disks
  up to 2 TiB. It does not include original boot code or active flags.
- This is a raw-disk restore, not file extraction. Use only complete,
  unencrypted, non-incremental `.adi` backups. Split image sets and `.afi` file
  backups are not supported.
- The result is not a byte-exact forensic copy. Review `info` and any recovery
  warnings before restoring valuable data.

## License

MIT. Based on [adi-extract](https://github.com/l4red0/adi-extract) by Leszek
Sołtys; see [LICENSE](LICENSE). Not affiliated with AOMEI.
