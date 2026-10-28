//! Decoder for the LZ4-flavoured block codec used inside AOMEI `.adi` images.
//!
//! Blocks are decoded in file order; each block may reference up to 64 KiB of
//! the previous output as a back-reference window.

const HISTORY: usize = 64 * 1024;

#[derive(Default)]
pub struct Lz4 {
    /// Trailing 64 KiB of the previous output, followed by the current block.
    work: Vec<u8>,
}

impl Lz4 {
    pub fn new() -> Self {
        Self {
            work: Vec::with_capacity(HISTORY + 1024 * 1024),
        }
    }

    /// Reset the 64 KiB back-reference window (used at gaps in the block index).
    pub fn reset(&mut self) {
        self.work.clear();
    }

    /// Decode one compressed block and return just this block's output bytes.
    pub fn decode(&mut self, comp: &[u8]) -> Result<Vec<u8>, String> {
        let base = self.work.len();
        let mut ip = 0usize;

        while ip < comp.len() {
            let token = comp[ip];
            ip += 1;

            let mut lit = (token >> 4) as usize;
            if lit == 15 {
                loop {
                    let b = *comp.get(ip).ok_or("truncated literal length")?;
                    ip += 1;
                    lit += b as usize;
                    if b != 255 {
                        break;
                    }
                }
            }
            if lit != 0 {
                let src = comp.get(ip..ip + lit).ok_or("truncated literals")?;
                ip += lit;
                self.work.extend_from_slice(src);
            }

            // A block may end right after its literals, with no match to follow.
            if ip >= comp.len() {
                break;
            }

            let lo = *comp.get(ip).ok_or("truncated match offset")? as usize;
            let hi = *comp.get(ip + 1).ok_or("truncated match offset")? as usize;
            ip += 2;
            let off = lo | (hi << 8);
            if off == 0 || off > self.work.len() {
                return Err("match offset outside window".to_string());
            }

            let mut mlen = (token & 15) as usize;
            if mlen == 15 {
                loop {
                    let b = *comp.get(ip).ok_or("truncated match length")?;
                    ip += 1;
                    mlen += b as usize;
                    if b != 255 {
                        break;
                    }
                }
            }
            mlen += 4;

            // Overlapping copy: as `work` grows, `start + i` reads bytes that
            // were appended by earlier iterations of this same loop.
            let start = self.work.len() - off;
            for i in 0..mlen {
                let b = self.work[start + i];
                self.work.push(b);
            }
        }

        let decoded = self.work[base..].to_vec();
        if self.work.len() > HISTORY {
            let drop = self.work.len() - HISTORY;
            self.work.drain(..drop);
        }
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::Lz4;

    #[test]
    fn overlapping_matches_and_truncation() {
        let mut decoder = Lz4::new();
        assert_eq!(
            decoder.decode(&[0x1f, b'A', 1, 0, 0]).unwrap(),
            vec![b'A'; 20]
        );
        for bad in [
            &[0xf0][..],
            &[0x10, b'X', 0],
            &[0, 0, 0],
            &[0x1f, b'A', 1, 0],
        ] {
            decoder.reset();
            assert!(decoder.decode(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn bounded_deterministic_decoder_smoke_fuzz() {
        let mut state = 0x15a4e35u32;
        let mut decoder = Lz4::new();
        for case in 0..4096 {
            let mut input = vec![0; case % 129];
            for byte in &mut input {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (state >> 24) as u8;
            }
            decoder.reset();
            let _ = decoder.decode(&input); // errors are expected; panic is not
            decoder.reset();
            assert_eq!(decoder.decode(&[0x30, b'A', b'B', b'C']).unwrap(), b"ABC");
        }
    }
}
