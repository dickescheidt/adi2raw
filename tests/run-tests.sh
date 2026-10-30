#!/usr/bin/env bash
# Self-contained test suite. Optional: set ADI_EXTRACT=/path/to/adi-extract to
# also compare byte-for-byte against the original C++ tool.
set -euo pipefail

cd "$(dirname "$0")/.."
cargo test --quiet
cargo build --release
BIN="$PWD/target/release/adi2raw"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 tests/make_test_adi.py "$TMP/simple.adi" simple
python3 tests/make_test_adi.py "$TMP/multi.adi" multi
python3 tests/make_test_adi.py "$TMP/bigcluster.adi" bigcluster
python3 tests/make_test_adi.py "$TMP/badcrc.adi" simple-badcrc
python3 tests/make_multipart_adi.py "$TMP/multipart.adi"
python3 tests/make_out_of_order_adi.py "$TMP/ooo.adi"
python3 tests/make_gap_regions_adi.py "$TMP/gaps.adi"
python3 tests/make_standard_adi.py "$TMP/standard.adi" single
python3 tests/make_standard_adi.py "$TMP/split.adi" split

"$BIN" --help > "$TMP/help.txt"
grep -q -- "--max-pending-mb N" "$TMP/help.txt"
grep -q -- "--no-spool" "$TMP/help.txt"
grep -q -- "--full-scan" "$TMP/help.txt"
grep -q -- "default:" "$TMP/help.txt"

echo "== info =="
"$BIN" info "$TMP/simple.adi" | grep "blocks in disk order: yes" > /dev/null
"$BIN" info "$TMP/multi.adi" | grep "blocks in disk order: no" > /dev/null
"$BIN" info "$TMP/multipart.adi" | grep "whole-disk stream, origin 1048576 bytes" > /dev/null
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

echo "== multipart: 4 partitions in one block chain =="
"$BIN" dump "$TMP/multipart.adi" > "$TMP/multipart.img" 2> "$TMP/multipart.err"
grep -q "boot sectors: 4" "$TMP/multipart.err"
grep -q "layout: whole-disk stream" "$TMP/multipart.err"
python3 tests/check_multipart.py "$TMP/multipart.img" 4736512
echo "multipart: OK"

echo "== ordered index with chain gaps must stay ordered =="
"$BIN" info "$TMP/simple.adi" | grep "out-of-order steps: 0" > /dev/null
"$BIN" info "$TMP/gaps.adi" > "$TMP/gaps.info" 2> /dev/null
grep -q "index regions monotone: raw yes, after resolve_regions yes" "$TMP/gaps.info"
grep -q "estimated reorder need: 0 MiB" "$TMP/gaps.info"
echo "regions diagnostic: OK"

echo "== CRC32C (BRCrc32) on decoded blocks =="
"$BIN" info "$TMP/simple.adi" > "$TMP/crc.info"
grep -q "2 records carry a BRCrc32 checksum" "$TMP/crc.info"
grep -q "verified:  2 decoded blocks checked, 0 mismatches, 0 unchecked" "$TMP/crc.info"

# A deliberately wrong checksum must be reported, and only that block skipped.
"$BIN" info "$TMP/badcrc.adi" > "$TMP/badcrc.info" 2> /dev/null
grep -q "verified:  2 decoded blocks checked, 1 mismatches, 0 unchecked" "$TMP/badcrc.info"
"$BIN" dump "$TMP/badcrc.adi" > "$TMP/badcrc.img" 2> "$TMP/badcrc.err"
grep -q "CRC32C mismatch" "$TMP/badcrc.err"
grep -q "1 block(s) failed CRC32C verification" "$TMP/badcrc.err"
python3 tests/check_raw.py "$TMP/badcrc.img" 3163648 1310720=0
echo "crc32c: OK"

echo "== 32 KiB clusters with a 1-byte sparse bitmap =="
"$BIN" dump "$TMP/bigcluster.adi" > "$TMP/bigcluster.img" 2> "$TMP/bigcluster.err"
! grep -q "unrecognised layout" "$TMP/bigcluster.err"
python3 tests/check_bigcluster.py "$TMP/bigcluster.img" 3163648
echo "big clusters: OK"

echo "== out-of-order blocks: sparse spool fallback =="
# A large cap keeps everything in RAM; a 1 MiB cap forces the spool path.
"$BIN" dump --max-pending-mb 64 "$TMP/ooo.adi" > "$TMP/ooo-mem.img" 2> "$TMP/ooo-mem.err"
! grep -qi "spooling" "$TMP/ooo-mem.err"
"$BIN" dump --max-pending-mb 1 --spool-dir "$TMP" "$TMP/ooo.adi" > "$TMP/ooo-spool.img" 2> "$TMP/ooo-spool.err"
grep -q "spooling to" "$TMP/ooo-spool.err"
if "$BIN" dump --max-pending-mb 1 --no-spool "$TMP/ooo.adi" > /dev/null 2> "$TMP/no-spool.err"; then
    echo "--no-spool did not reject an out-of-order image"; exit 1
fi
grep -q "spooling disabled by --no-spool" "$TMP/no-spool.err"
cmp "$TMP/ooo-mem.img" "$TMP/ooo-spool.img"
python3 tests/check_out_of_order.py "$TMP/ooo-spool.img" 3163648
[[ -z "$(find "$TMP" -name '*.spool' -print -quit)" ]] || {
    echo "spool file was not cleaned up"; exit 1;
}
cp "$TMP/ooo-spool.img" "$TMP/ooo.img"     # for the C++ reference comparison
echo "spool fallback: OK"

echo "== stdout is clean binary =="
size=$(wc -c < "$TMP/simple.img")
[[ "$size" -eq 3163648 ]] && echo "stdout bytes: OK"

echo "== standard 0x201/0x202/0x109 records =="
"$BIN" info "$TMP/standard.adi" > "$TMP/standard.info" 2> "$TMP/standard.info.err"
grep -q "standard record path" "$TMP/standard.info.err"
grep -q "volume record sets: 1" "$TMP/standard.info"
grep -q "delta 0x65c" "$TMP/standard.info"
grep -q "8 clusters/block x 64 sectors/cluster x 512 B" "$TMP/standard.info"
grep -q "metadata: LBA 2048, 4096 sectors" "$TMP/standard.info"
grep -q "modes:      compress 1, encrypt 0" "$TMP/standard.info"
grep -q "BRCrc32 valid" "$TMP/standard.info"
"$BIN" dump "$TMP/standard.adi" > "$TMP/standard.img" 2> "$TMP/standard.err"
grep -q "2 decoded blocks checked, 0 mismatches" "$TMP/standard.err"
python3 tests/check_standard.py "$TMP/standard.img" 3163136
"$BIN" dump "$TMP/standard.adi" --partition-table mbr > "$TMP/standard-mbr.img" 2> "$TMP/standard-mbr.err"
"$BIN" dump "$TMP/standard.adi" --partition-table=gpt > "$TMP/standard-gpt.img" 2> "$TMP/standard-gpt.err"
"$BIN" dump "$TMP/multipart.adi" -p mbr > "$TMP/multipart-mbr.img" 2> "$TMP/multipart-mbr.err"
python3 tests/check_partition_tables.py "$TMP/standard-mbr.img" "$TMP/standard-gpt.img" "$TMP/standard.img" "$TMP/multipart-mbr.img"
if "$BIN" dump "$TMP/standard.adi" --partition-table invalid > /dev/null 2> "$TMP/invalid-pt.err"; then
    echo "invalid partition-table value was accepted"; exit 1
fi
grep -q "expected mbr or gpt" "$TMP/invalid-pt.err"
if "$BIN" dump --max-pending-mb invalid "$TMP/standard.adi" > /dev/null 2> "$TMP/invalid-pending.err"; then
    echo "invalid --max-pending-mb value was accepted"; exit 1
fi
grep -q "invalid --max-pending-mb value" "$TMP/invalid-pending.err"
if "$BIN" dump --no-spool --spool-dir "$TMP" "$TMP/standard.adi" > /dev/null 2> "$TMP/conflicting-spool.err"; then
    echo "--no-spool and --spool-dir were accepted together"; exit 1
fi
grep -q "cannot be combined" "$TMP/conflicting-spool.err"
echo "standard records: OK"

echo "== split image set without external-member interface =="
if "$BIN" dump "$TMP/split.adi" > /dev/null 2> "$TMP/missing.err"; then
    echo "split image set unexpectedly succeeded without all member files"; exit 1
fi
grep -q "not covered by any member" "$TMP/missing.err"
echo "split image set rejected clearly: OK"

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
    # The multipart comparison needs a C++ build with the whole-disk
    # boot-sector scan (the POSIX fork at dickescheidt/adi-extract).
    for kind in simple multi multipart bigcluster ooo standard; do
        src="$TMP/$kind.adi"
        "$ADI_EXTRACT" reconstruct "$src" "$TMP/cpp-$kind.img" > /dev/null 2>&1
        rm -f "$src.index"
        cmp "$TMP/cpp-$kind.img" "$TMP/$kind.img"
        echo "$kind: byte-identical to C++ output"
    done
else
    echo "tip: ADI_EXTRACT=/path/to/adi-extract $0 also compares against the C++ tool"
fi

echo "ALL TESTS PASSED"

python3 tests/test_boundary.py ./target/release/adi2raw rust

python3 tests/test_warnings.py ./target/release/adi2raw rust

python3 tests/test_properties.py ./target/release/adi2raw rust
python3 tests/test_malformed.py ./target/release/adi2raw rust
python3 tests/test_trace.py ./target/release/adi2raw rust
python3 tests/test_robustness.py ./target/release/adi2raw rust
python3 tests/test_scan_strategy.py ./target/release/adi2raw rust
python3 tests/test_fs_detect.py ./target/release/adi2raw rust
