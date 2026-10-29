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

    /// Decode one compressed block, refusing to produce more than `limit` bytes.
    ///
    /// A VDB entry states the decoded size (`OldSize`) before its data is read,
    /// but a single match-length extension byte encodes 255 output bytes. Without
    /// the ceiling a few hundred kilobytes of crafted input can request gigabytes
    /// of allocation, so the caller's declared size is enforced here.
    pub fn decode_limited(&mut self, comp: &[u8], limit: usize) -> Result<Vec<u8>, String> {
        let base = self.work.len();
        let mut ip = 0usize;
        let fits = |produced: usize, extra: usize| {
            produced
                .checked_add(extra)
                .is_some_and(|total| total <= limit)
        };

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
                if !fits(self.work.len() - base, lit) {
                    return Err(format!(
                        "decoded output exceeds the declared {} bytes",
                        limit
                    ));
                }
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
            if !fits(self.work.len() - base, mlen) {
                return Err(format!(
                    "decoded output exceeds the declared {} bytes",
                    limit
                ));
            }

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
            decoder
                .decode_limited(&[0x1f, b'A', 1, 0, 0], usize::MAX)
                .unwrap(),
            vec![b'A'; 20]
        );
        for bad in [
            &[0xf0][..],
            &[0x10, b'X', 0],
            &[0, 0, 0],
            &[0x1f, b'A', 1, 0],
        ] {
            decoder.reset();
            assert!(
                decoder.decode_limited(bad, usize::MAX).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn declared_size_caps_expansion() {
        // One literal, then a match extended by 200 length bytes: LZ4 would emit
        // ~51 KiB. With a 4 KiB ceiling the decoder must refuse instead.
        let mut bomb = vec![0x1f, b'A', 0x01, 0x00];
        bomb.extend(std::iter::repeat_n(0xff, 200));
        bomb.push(0x00);
        let mut decoder = Lz4::new();
        assert!(decoder.decode_limited(&bomb, usize::MAX).is_ok());
        decoder.reset();
        assert!(decoder.decode_limited(&bomb, 4096).is_err());
        decoder.reset();
        assert_eq!(decoder.decode_limited(b"\x30ABC", 3).unwrap(), b"ABC");
        decoder.reset();
        assert!(decoder.decode_limited(b"\x30ABC", 2).is_err());
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
            let _ = decoder.decode_limited(&input, 1 << 20); // errors are expected; panic is not
            decoder.reset();
            assert_eq!(
                decoder
                    .decode_limited(&[0x30, b'A', b'B', b'C'], 3)
                    .unwrap(),
                b"ABC"
            );
        }
    }
}
