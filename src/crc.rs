//! AOMEI's `Encrypt.dll!BRCrc32`: CRC32C (Castagnoli) with a zero seed and a
//! final bitwise inversion. This is *not* zlib's CRC32. Every 0x20-byte VDB
//! index entry stores one of these over its decoded `OldSize` bytes.
//!
//! The table is built 16 times over (slicing-by-16): one byte-at-a-time ran at
//! ~430 MB/s on a 2.6 GHz core, which made the whole dump CPU-bound because
//! every decoded byte is checksummed. Slicing-by-16 consumes 16 bytes per
//! iteration with 16 table lookups and runs at several GB/s.

const POLY: u32 = 0x82f6_3b78;

const fn make_tables() -> [[u32; 256]; 16] {
    let mut t = [[0u32; 256]; 16];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut s = 1;
    while s < 16 {
        let mut i = 0;
        while i < 256 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        s += 1;
    }
    t
}

static TABLES: [[u32; 256]; 16] = make_tables();

/// Update a running CRC with one 16-byte block. The first byte of the block is
/// folded into the low bits of the running value, so it uses the highest table;
/// the last byte uses table 0.
#[inline]
fn update16(mut crc: u32, chunk: &[u8]) -> u32 {
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&chunk[..8]);
    hi.copy_from_slice(&chunk[8..16]);
    let mix = (crc as u64) ^ u64::from_le_bytes(lo);
    let hi = u64::from_le_bytes(hi);
    let t = &TABLES;
    crc = t[15][(mix & 0xff) as usize]
        ^ t[14][((mix >> 8) & 0xff) as usize]
        ^ t[13][((mix >> 16) & 0xff) as usize]
        ^ t[12][((mix >> 24) & 0xff) as usize]
        ^ t[11][((mix >> 32) & 0xff) as usize]
        ^ t[10][((mix >> 40) & 0xff) as usize]
        ^ t[9][((mix >> 48) & 0xff) as usize]
        ^ t[8][((mix >> 56) & 0xff) as usize]
        ^ t[7][(hi & 0xff) as usize]
        ^ t[6][((hi >> 8) & 0xff) as usize]
        ^ t[5][((hi >> 16) & 0xff) as usize]
        ^ t[4][((hi >> 24) & 0xff) as usize]
        ^ t[3][((hi >> 32) & 0xff) as usize]
        ^ t[2][((hi >> 40) & 0xff) as usize]
        ^ t[1][((hi >> 48) & 0xff) as usize]
        ^ t[0][((hi >> 56) & 0xff) as usize];
    crc
}

/// CRC32C with zero seed and final inversion, as used by AOMEI Backupper.
pub fn br_crc32(data: &[u8]) -> u32 {
    let head = data.len() & !15;
    let (body, tail) = data.split_at(head);
    let mut crc = 0u32;
    let (blocks, _) = body.as_chunks::<16>();
    for chunk in blocks {
        crc = update16(crc, chunk);
    }
    for &b in tail {
        crc = (crc >> 8) ^ TABLES[0][((crc ^ b as u32) & 0xff) as usize];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::br_crc32;

    /// Straightforward bit-at-a-time CRC32C, the definition of the algorithm.
    fn bitwise(data: &[u8]) -> u32 {
        let mut crc = 0u32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82f6_3b78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn known_vectors() {
        // Cross-checked against the independent tdestro/adi2raw implementation.
        assert_eq!(br_crc32(b""), 0xffff_ffff);
        assert_eq!(br_crc32(b"123456789"), 0xa71c_05df);
        assert_eq!(br_crc32(b"AOMEI"), 0xeb00_0f91);
    }

    #[test]
    fn empty_is_all_ones() {
        assert_eq!(br_crc32(&[]), !0u32);
    }

    /// The sliced implementation must agree with the definition for every
    /// length, in particular around the 16-byte block and tail handling.
    #[test]
    fn matches_the_bitwise_definition_at_every_length() {
        let mut data = vec![0u8; 300];
        let mut x = 0x1234_5678u32;
        for b in data.iter_mut() {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *b = (x >> 16) as u8;
        }
        for n in 0..=data.len() {
            assert_eq!(br_crc32(&data[..n]), bitwise(&data[..n]), "length {n}");
        }
        // A long buffer exercises the multi-block path.
        let long: Vec<u8> = (0..100_003u32).map(|i| ((i * 31) >> 3) as u8).collect();
        assert_eq!(br_crc32(&long), bitwise(&long));
    }
}
