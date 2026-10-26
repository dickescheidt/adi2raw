#!/usr/bin/env bash
# Self-contained test suite. Optional: set ADI_EXTRACT=/path/to/adi-extract to
# also compare byte-for-byte against the original C++ tool.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo build --release
BIN="$PWD/target/release/adi2raw"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 tests/make_test_adi.py "$TMP/simple.adi" simple
python3 tests/make_test_adi.py "$TMP/multi.adi" multi

echo "== info =="
"$BIN" info "$TMP/simple.adi" | grep -q "blocks in disk order: yes"
"$BIN" info "$TMP/multi.adi" | grep -q "blocks in disk order: no"
echo "info: OK"

echo "== dump =="
# simple: one NTFS volume, cluster 512, second region holds 0xC3 filler.
"$BIN" dump "$TMP/simple.adi" > "$TMP/simple.img" 2> "$TMP/simple.err"
python3 tests/check_raw.py "$TMP/simple.img" 3163648 1310720=c3

# multi: two volumes (512/4096 clusters), sparse units and out-of-order regions.
"$BIN" dump "$TMP/multi.adi" > "$TMP/multi.img" 2> "$TMP/multi.err"
python3 tests/check_raw.py "$TMP/multi.img" 8406528 \
    1574400=11 1310720=22 4214784=33 4464640=44

grep -q . "$TMP/simple.err" && echo "diagnostics go to stderr: OK"
echo "dump: OK"

echo "== stdout is clean binary =="
size=$(wc -c < "$TMP/simple.img")
[[ "$size" -eq 3163648 ]] && echo "stdout bytes: OK"

echo "== broken pipe =="
set +e
"$BIN" dump "$TMP/multi.adi" 2>/dev/null | head -c 1024 > /dev/null
pipe=("${PIPESTATUS[@]}")
set -e
[[ "${pipe[0]}" -eq 0 ]] || { echo "broken pipe exited ${pipe[0]}"; exit 1; }
echo "broken pipe: OK"

echo "== real dd pipeline =="
"$BIN" dump "$TMP/multi.adi" 2>/dev/null \
  | dd of="$TMP/dd.img" bs=1M iflag=fullblock status=none
cmp "$TMP/multi.img" "$TMP/dd.img"
echo "dump | dd: OK"

if [[ -n "${ADI_EXTRACT:-}" && -x "$ADI_EXTRACT" ]]; then
    echo "== reference comparison (C++ adi-extract) =="
    for kind in simple multi; do
        "$ADI_EXTRACT" reconstruct "$TMP/$kind.adi" "$TMP/cpp-$kind.img" > /dev/null 2>&1
        rm -f "$TMP/$kind.adi.index"
        cmp "$TMP/cpp-$kind.img" "$TMP/$kind.img"
        echo "$kind: byte-identical to C++ output"
    done
else
    echo "tip: ADI_EXTRACT=/path/to/adi-extract $0 also compares against the C++ tool"
fi

echo "ALL TESTS PASSED"
