#!/usr/bin/env python3
"""Generate isolated cargo-fuzz crate under target/fuzz; runtime CLI stays dependency-free."""
from pathlib import Path
import json
from seeds import seed_corpus
root = Path(__file__).resolve().parents[2]
out = root / 'target' / 'fuzz'
(out / 'fuzz_targets').mkdir(parents=True, exist_ok=True)
seed_corpus(out / 'corpus')
(out / 'Cargo.toml').write_text('''[package]
name = "adi2raw-fuzz"
version = "0.0.0"
edition = "2021"
publish = false
[package.metadata]
cargo-fuzz = true
[dependencies]
libfuzzer-sys = "=0.4.13"
[profile.release]
overflow-checks = true
[workspace]
''' + ''.join(f'\n[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\ntest = false\ndoc = false\nbench = false\n' for name in ['codec','records','image_file']))
copy = (root / 'src' / 'records.rs').read_text() + '\n' + (root / 'tests/fuzz/rust_target.rs').read_text()
(out / 'fuzz_targets' / 'records_copy.rs').write_text(copy)
common = '''macro_rules! debug_warn { ($($arg:tt)*) => {{}}; }
'''
for name in ('adi', 'crc', 'lz4'):
    common += f'#[path = {json.dumps(str(root / "src" / (name + ".rs")))}] mod {name};\n'
common += 'mod records { include!("records_copy.rs"); }\n'
# A path module preserves the original module-level //! docs.
common = common.replace('mod records { include!("records_copy.rs"); }','#[path = "records_copy.rs"] mod records;')
for name, code in {
 'codec': '''let mut dec = lz4::Lz4::new();
 let _ = dec.decode(data);
 if !data.is_empty() { let at = data[0] as usize % data.len(); dec.reset(); let _ = dec.decode(&data[..at]); let _ = dec.decode(&data[at..]); }
 let _ = adi::split_block(data, data.len() as u32, 0);''',
 'records': 'records::fuzz_records(data);',
 'image_file': '''if data.len() > 65536 { return; }
 let mut bytes = data.to_vec();
 // Repair plausible referenced standard records to get past checksum barriers.
 for at in 0..bytes.len().saturating_sub(16) {
   let kind = adi::u32le(&bytes, at); let len = adi::u32le(&bytes, at + 4) as usize;
   if matches!(kind, 0x201 | 0x202 | 0x102 | 0x105 | 0x106 | 0x109) && (16..=4096).contains(&len) && len <= bytes.len() - at {
     bytes[at+8..at+12].fill(0); let crc = crc::br_crc32(&bytes[at..at+len]); bytes[at+8..at+12].copy_from_slice(&crc.to_le_bytes());
   }
 }
 let path = std::env::temp_dir().join(format!("adi-rust-fuzz-{}.adi", std::process::id()));
 std::fs::write(&path, &bytes).unwrap();
 if let Ok(mut image) = adi::Adi::open_with_members(&path, &[]) { let _ = records::parse_standard(&mut image); }
 let _ = std::fs::remove_file(path);'''
}.items():
    (out / 'fuzz_targets' / (name + '.rs')).write_text('#![no_main]\n#![allow(dead_code, unused_variables)]\n' + common + '\nlibfuzzer_sys::fuzz_target!(|data: &[u8]| {\n' + code + '\n});\n')
print(out)
