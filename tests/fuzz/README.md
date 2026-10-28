# Coverage-guided fuzzing (Rust)

Optional cargo-fuzz harnesses for parser, decoder and container hardening. They run
with libFuzzer and AddressSanitizer through nightly Rust; the normal build, `cargo
test` and `tests/run-tests.sh` do not depend on them.

| Target | Exercises |
|---|---|
| `codec` | `Lz4::decode` and `split_block` on arbitrary bytes, including reset/reuse |
| `records` | Each `0x201/0x202/0x102/0x105/0x106/0x109` parser, VDB entries and offset shifting, called directly |
| `image_file` | Whole constrained container: framing, record scan, standard image parse; record CRCs are repaired so fuzzing passes the checksum barrier |

Install once:

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz
```

Run with `sh tests/fuzz/run.sh [seconds-per-target]` (default 60). The runner builds an
isolated crate under the ignored `target/fuzz/` directory, seeds a corpus from
`seeds.py` (public synthetic models, no user data), and runs each target with the
committed dictionary, a 5 s per-input limit and a 768 MiB RSS cap.

The private byte parsers are compiled through a generated copy of `src/records.rs`
whose `//!`-documented module is preserved; production sources are not modified. The
`image_file` target repairs plausible record checksums so fuzzing can pass the CRC
barrier and reach deeper structural code, and it writes each case to a temporary file.

#### Recorded campaign

Seed `20261028`, cargo-fuzz/libFuzzer with AddressSanitizer on nightly Rust, 90 seconds
per target on x86-64 Linux, synthetic seeds from `tests/fuzz/seeds.py`:

| Target | Executions | Coverage units |
|---|---|---|
| `codec` | 459,554 | 84 |
| `records` | 8,889,572 | 106 |
| `image_file` | 195,327 | 590 |

9,544,453 executions in total, with no crash, hang or sanitizer report and no
artifact. Coverage units come from LLVM edge counters and are not comparable with the
C++ harness numbers.

#### Limitations

Fuzzing shows that these inputs do not crash, hang or trigger sanitizers. It cannot
show that the format interpretation is correct, and it is not a substitute for a real
AOMEI backup and restore comparison. Inputs are capped at 64 KiB and each campaign is
time-bounded; corpus and artifacts are deliberately not committed.
