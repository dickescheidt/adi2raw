#!/bin/sh
# Bounded coverage-guided fuzzing with cargo-fuzz/libFuzzer + ASan.
# Optional: this is not part of `cargo test` or tests/run-tests.sh.
# Requires a nightly toolchain and `cargo install cargo-fuzz`.
set -eu
seconds=${1:-60}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
if ! command -v cargo-fuzz >/dev/null 2>&1; then
    echo "cargo-fuzz not found: cargo install cargo-fuzz" >&2
    exit 1
fi
python3 tests/fuzz/prepare.py
cargo +nightly fuzz build --fuzz-dir target/fuzz
host=$(rustc +nightly -vV | sed -n 's/^host: //p')
bin="target/fuzz/target/$host/release"
for target in codec records image_file; do
    echo "== $target (${seconds}s per target)"
    max_len=4096
    [ "$target" = image_file ] && max_len=65536
    env ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
        "$bin/$target" "target/fuzz/corpus/$target" -dict=tests/fuzz/adi.dict \
        -max_total_time="$seconds" -max_len="$max_len" -timeout=5 \
        -rss_limit_mb=768 -artifact_prefix=target/fuzz/artifacts/
done
