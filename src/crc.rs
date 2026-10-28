//! AOMEI's `Encrypt.dll!BRCrc32`: CRC32C (Castagnoli) with a zero seed and a
//! final bitwise inversion. This is *not* zlib's CRC32. Every 0x20-byte VDB
//! index entry stores one of these over its decoded `OldSize` bytes.

const POLY: u32 = 0x82f6_3b78;

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = make_table();

/// CRC32C with zero seed and final inversion, as used by AOMEI Backupper.
pub fn br_crc32(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ b as u32) & 0xff) as usize];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::br_crc32;

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
}
