//! Synthesises the protective MBR + GPT written into the reconstructed image.

use crate::adi::{Volume, SECTOR};

const ESP: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
];
const MSR: [u8; 16] = [
    0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE,
];
const DATA: [u8; 16] = [
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
];
const RECOVERY: [u8; 16] = [
    0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC,
];

pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb88320u32 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut c = 0xffffffffu32;
    for &b in data {
        c = table[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffffffffu32
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

fn part_type(v: &Volume, last: bool) -> (&'static [u8; 16], &'static str) {
    if v.fs.starts_with("FAT") && v.lba <= 4096 {
        (&ESP, "EFI system partition")
    } else if v.fs.is_empty() || v.fs == "raw" {
        (&MSR, "Microsoft reserved partition")
    } else if last && v.sectors * SECTOR < (4u64 << 30) {
        (&RECOVERY, "Basic data partition")
    } else {
        (&DATA, "Basic data partition")
    }
}

fn entries(volumes: &[Volume]) -> Vec<u8> {
    let mut ents = vec![0u8; 128 * 128];
    let mut n = 0usize;
    for (i, v) in volumes.iter().enumerate() {
        if v.sectors == 0 || n >= 128 {
            continue;
        }
        let (fallback_guid, name) = part_type(v, i + 1 == volumes.len());
        let recovered_type = v.type_guid.iter().any(|&b| b != 0);
        let recovered_unique = v.unique_guid.iter().any(|&b| b != 0);
        let e = &mut ents[n * 128..(n + 1) * 128];
        e[0..16].copy_from_slice(if recovered_type {
            &v.type_guid
        } else {
            fallback_guid
        });
        if recovered_unique {
            e[16..32].copy_from_slice(&v.unique_guid);
        } else {
            e[16..32].copy_from_slice(if recovered_type {
                &v.type_guid
            } else {
                fallback_guid
            });
            e[16] = 0xa0u8.wrapping_add(n as u8);
            e[17] = 0x51u8.wrapping_add(n as u8);
        }
        put64(e, 32, v.lba);
        put64(e, 40, v.lba + v.sectors - 1);
        if v.part_name.is_empty() {
            for (k, ch) in name.bytes().take(35).enumerate() {
                e[56 + 2 * k] = ch;
            }
        } else {
            for (k, unit) in v.part_name.encode_utf16().take(36).enumerate() {
                e[56 + 2 * k..58 + 2 * k].copy_from_slice(&unit.to_le_bytes());
            }
        }
        n += 1;
    }
    ents
}

fn header(self_lba: u64, other_lba: u64, ent_lba: u64, last: u64, ents: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; SECTOR as usize];
    h[0..8].copy_from_slice(b"EFI PART");
    put32(&mut h, 8, 0x0001_0000);
    put32(&mut h, 12, 92);
    put64(&mut h, 24, self_lba);
    put64(&mut h, 32, other_lba);
    put64(&mut h, 40, 34);
    put64(&mut h, 48, last - 33);
    for i in 0..16 {
        h[56 + i] = 0x40 + i as u8;
    }
    put64(&mut h, 72, ent_lba);
    put32(&mut h, 80, 128);
    put32(&mut h, 84, 128);
    put32(&mut h, 88, crc32(ents));
    let hc = crc32(&h[..92]);
    put32(&mut h, 16, hc);
    h
}

/// Returns (prefix = LBAs 0..34, suffix = LBAs disk_sectors-33 .. disk_sectors).
pub fn build(disk_sectors: u64, volumes: &[Volume]) -> (Vec<u8>, Vec<u8>) {
    let last = disk_sectors - 1;
    let ents = entries(volumes);

    let mut prefix = vec![0u8; 34 * SECTOR as usize];
    let mbr = &mut prefix[0..SECTOR as usize];
    mbr[446..454].copy_from_slice(&[0x00, 0x02, 0x00, 0x00, 0xEE, 0xFF, 0xFF, 0xFF]);
    put32(mbr, 446 + 8, 1);
    put32(mbr, 446 + 12, std::cmp::min(last, 0xffff_ffff) as u32);
    mbr[510] = 0x55;
    mbr[511] = 0xaa;
    prefix[SECTOR as usize..2 * SECTOR as usize].copy_from_slice(&header(1, last, 2, last, &ents));
    prefix[2 * SECTOR as usize..34 * SECTOR as usize].copy_from_slice(&ents);

    let mut suffix = vec![0u8; 33 * SECTOR as usize];
    suffix[0..32 * SECTOR as usize].copy_from_slice(&ents);
    suffix[32 * SECTOR as usize..33 * SECTOR as usize].copy_from_slice(&header(
        last,
        1,
        last - 32,
        last,
        &ents,
    ));

    (prefix, suffix)
}

pub fn suffix_start(disk_sectors: u64) -> u64 {
    (disk_sectors - 33) * SECTOR
}
