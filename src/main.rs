//! adi2raw — two commands, no dependencies:
//!
//!   adi2raw info <file.adi>     describe the image
//!   adi2raw dump <file.adi>     write a raw disk image to stdout

mod adi;
mod gpt;
mod lz4;

use std::collections::BTreeMap;
use std::env;
use std::io::{self, BufWriter, ErrorKind, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use adi::{
    block_base, discover_map, scan_block_index, split_block, unit_present, Adi, BlockRec,
    SectorMap, Volume, REGION, SECTOR,
};
use lz4::Lz4;

/// Ceiling for out-of-order clusters held in memory while streaming.
const MAX_PENDING: usize = 256 * 1024 * 1024;
const ZERO_CHUNK: usize = 1024 * 1024;
static ZEROS: [u8; ZERO_CHUNK] = [0u8; ZERO_CHUNK];

// ---------------------------------------------------------------------------
// Ordered byte stream with a bounded reorder buffer
// ---------------------------------------------------------------------------

struct Streamer<W: Write> {
    out: W,
    pos: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    pub broken: bool,
    pub total: u64,
}

impl<W: Write> Streamer<W> {
    fn new(out: W) -> Self {
        Self {
            out,
            pos: 0,
            pending: BTreeMap::new(),
            broken: false,
            total: 0,
        }
    }

    fn raw(&mut self, data: &[u8]) -> Result<(), String> {
        if self.broken {
            return Ok(());
        }
        match self.out.write_all(data) {
            Ok(()) => {
                self.pos += data.len() as u64;
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                // Rust ignores SIGPIPE; a closed downstream (dd exiting early)
                // is not an error for us. No unsafe signal handling needed.
                self.broken = true;
                Ok(())
            }
            Err(e) => Err(format!("write failed at offset {}: {e}", self.pos)),
        }
    }

    fn zero_fill(&mut self, target: u64) -> Result<(), String> {
        if target < self.pos {
            return Err(format!(
                "out-of-order write at {target} after output reached {} — this image cannot be streamed safely",
                self.pos
            ));
        }
        while self.pos < target {
            let n = std::cmp::min((target - self.pos) as usize, ZERO_CHUNK);
            self.raw(&ZEROS[..n])?;
            if self.broken {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Queue a write. Later writes win where ranges overlap, matching the
    /// behaviour of seeking and overwriting in a sparse output file.
    fn add(&mut self, off: u64, data: Vec<u8>) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        let end = off
            .checked_add(data.len() as u64)
            .ok_or("write offset overflow")?;

        let before: Vec<u64> = self.pending.range(..off).map(|(&k, _)| k).collect();
        for k in before {
            let e = self.pending.get_mut(&k).unwrap();
            if k + e.len() as u64 > off {
                e.truncate((off - k) as usize);
                if e.is_empty() {
                    self.pending.remove(&k);
                }
            }
        }
        let inside: Vec<u64> = self.pending.range(off..end).map(|(&k, _)| k).collect();
        for k in inside {
            let e = self.pending.remove(&k).unwrap();
            let e_end = k + e.len() as u64;
            if e_end > end {
                let tail = e[(end - k) as usize..].to_vec();
                self.pending.insert(end, tail);
            }
        }
        self.pending.insert(off, data);

        let buffered: usize = self.pending.values().map(|v| v.len()).sum();
        if buffered > MAX_PENDING {
            return Err(format!(
                "image blocks are too far out of disk order to stream ({} MiB buffered); \
                 use adi-extract reconstruct to build a file instead",
                buffered / 1024 / 1024
            ));
        }
        Ok(())
    }

    /// Emit every queued write that no future block can still precede.
    fn flush_to(&mut self, limit: u64) -> Result<(), String> {
        while let Some(&key) = self.pending.keys().next() {
            let len = self.pending[&key].len() as u64;
            if key + len > limit {
                break;
            }
            let data = self.pending.remove(&key).unwrap();
            self.zero_fill(key)?;
            self.raw(&data)?;
            if self.broken {
                return Ok(());
            }
        }
        Ok(())
    }

    fn flush_all(&mut self) -> Result<(), String> {
        self.flush_to(u64::MAX)
    }

    fn finish(&mut self) -> Result<(), String> {
        self.total = self.pos;
        if self.broken {
            return Ok(());
        }
        match self.out.flush() {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                self.broken = true;
                Ok(())
            }
            Err(e) => Err(format!("flush failed: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

type Plan = Vec<(usize, usize, u64)>; // (volume index, block index, target base)

fn build_plan(map: &SectorMap, blocks: &[BlockRec]) -> Plan {
    let mut plan = Vec::with_capacity(blocks.len());
    for (vi, v) in map.volumes.iter().enumerate() {
        for (bi, b) in blocks.iter().enumerate().take(v.last + 1).skip(v.first) {
            plan.push((vi, bi, block_base(v, b)));
        }
    }
    plan
}

/// future_min[i] = lowest target offset any block after i may write to.
fn future_min(plan: &Plan) -> Vec<u64> {
    let mut out = vec![u64::MAX; plan.len()];
    let mut low = u64::MAX;
    for i in (0..plan.len()).rev() {
        out[i] = low;
        low = low.min(plan[i].2);
    }
    out
}

/// Turn one compressed block into coalesced (offset, bytes) writes.
fn block_writes(
    adi: &mut Adi,
    dec: &mut Lz4,
    vol: &Volume,
    b: &BlockRec,
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let comp = adi.read_at(adi.payload_offset() + b.off, b.csize as usize)?;
    let data = match dec.decode(&comp) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("adi2raw: warn: block at 0x{:x}: {e}", b.off);
            return Ok(Vec::new());
        }
    };
    if data.len() != b.usize as usize {
        eprintln!(
            "adi2raw: warn: block at 0x{:x} decoded to {} bytes, expected {}",
            b.off,
            data.len(),
            b.usize
        );
        return Ok(Vec::new());
    }
    let lay = match split_block(&data, b.usize, vol.cluster) {
        Some(l) => l,
        None => {
            eprintln!("adi2raw: warn: block at 0x{:x}: unrecognised layout", b.off);
            return Ok(Vec::new());
        }
    };
    let base = block_base(vol, b);
    let vol_end = (vol.lba + vol.sectors) * SECTOR;
    let units_max = (REGION / lay.cluster as u64) as u32;
    let mut slot = 0usize;
    let mut runs: Vec<(u64, usize, usize)> = Vec::new(); // dst, src offset, length

    for u in 0..units_max {
        if slot as u32 >= lay.units {
            break;
        }
        if !unit_present(&data, &lay, u) {
            continue;
        }
        let src = lay.hdr as usize + slot * lay.cluster as usize;
        let dst = base + u as u64 * lay.cluster as u64;
        slot += 1;
        if dst + lay.cluster as u64 > vol_end {
            continue;
        }
        let len = lay.cluster as usize;
        if let Some(last) = runs.last_mut() {
            if last.0 + last.2 as u64 == dst && last.1 + last.2 == src {
                last.2 += len;
                continue;
            }
        }
        runs.push((dst, src, len));
    }

    let mut out = Vec::with_capacity(runs.len());
    for (dst, src, len) in runs {
        if src + len > data.len() {
            return Err(format!(
                "block at 0x{:x}: cluster past end of decoded data",
                b.off
            ));
        }
        out.push((dst, data[src..src + len].to_vec()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn open_and_map(path: &Path) -> Result<(Adi, Vec<BlockRec>, SectorMap), String> {
    let mut adi = Adi::open(path)?;
    let blocks = scan_block_index(&mut adi)?;
    if blocks.is_empty() {
        return Err("no block index records found — unsupported or damaged image".into());
    }
    let map = discover_map(&mut adi, &blocks)?;
    if map.disk_sectors < 68 {
        return Err(format!(
            "implausible disk size: {} sectors",
            map.disk_sectors
        ));
    }
    Ok((adi, blocks, map))
}

fn cmd_info(path: &Path) -> Result<(), String> {
    let (adi, blocks, map) = open_and_map(path)?;
    adi.print_info();
    println!("\n[block index]");
    println!("  records:   {}", blocks.len());
    println!(
        "  crcs:      {} records carry a checksum",
        blocks.iter().filter(|b| b.crc != 0).count()
    );
    if let (Some(first), Some(last)) = (blocks.first(), blocks.last()) {
        println!("  first off: 0x{:x}", first.off);
        println!("  last end:  0x{:x}", last.end());
    }
    println!("\n[volumes]");
    for (i, v) in map.volumes.iter().enumerate() {
        println!(
            "  v{} {:<10} lba {:<12} sectors {:<12} cluster {:<6} blocks {} stored {} KiB label '{}'",
            i,
            v.fs,
            v.lba,
            v.sectors,
            v.cluster,
            v.last - v.first + 1,
            v.stored / 1024,
            v.label
        );
    }
    let disk_size = map.disk_sectors * SECTOR;
    println!("\n[raw image]");
    println!("  disk:      {} sectors", map.disk_sectors);
    println!(
        "  size:      {} bytes ({:.2} GiB)",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0
    );
    let plan = build_plan(&map, &blocks);
    let ordered = plan.windows(2).all(|w| w[1].2 >= w[0].2);
    println!(
        "  blocks in disk order: {} ({} streaming)",
        if ordered { "yes" } else { "no" },
        if ordered { "direct" } else { "reorder buffer" }
    );
    Ok(())
}

fn cmd_dump(path: &Path) -> Result<(), String> {
    if io::stdout().is_terminal() {
        return Err(
            "refusing to write a raw disk image to a terminal; redirect to a file or pipe to dd"
                .into(),
        );
    }

    let (mut adi, blocks, map) = open_and_map(path)?;
    let plan = build_plan(&map, &blocks);
    let fmin = future_min(&plan);
    let disk_size = map.disk_sectors * SECTOR;
    let (prefix, suffix) = gpt::build(map.disk_sectors, &map.volumes);
    let suffix_at = gpt::suffix_start(map.disk_sectors);

    eprintln!(
        "adi2raw: {} bytes ({:.2} GiB), {} volume(s), {} blocks -> stdout",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0,
        map.volumes.len(),
        blocks.len()
    );

    let stdout = io::stdout();
    let mut st = Streamer::new(BufWriter::with_capacity(1024 * 1024, stdout.lock()));
    st.add(0, prefix)?;
    st.add(suffix_at, suffix)?;

    let mut pi = 0usize;
    let mut dec = Lz4::new();
    'outer: for v in &map.volumes {
        // A gap in the compressed block chain starts a new LZ4 window.
        dec.reset();
        for b in blocks.iter().take(v.last + 1).skip(v.first) {
            let writes = block_writes(&mut adi, &mut dec, v, b)?;
            for (dst, bytes) in writes {
                st.add(dst, bytes)?;
            }
            st.flush_to(fmin[pi])?;
            pi += 1;
            if st.broken {
                break 'outer;
            }
        }
    }

    if !st.broken {
        st.flush_all()?;
        st.zero_fill(disk_size)?;
    }
    st.finish()?;

    if st.broken {
        eprintln!("adi2raw: output pipe closed early");
    } else if st.total != disk_size {
        return Err(format!(
            "internal error: wrote {} bytes, expected {}",
            st.total, disk_size
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn usage() -> String {
    format!(
        "adi2raw {} — stream an AOMEI Backupper .adi image as a raw disk image\n\n\
         Usage:\n  \
         adi2raw info <file.adi>     show header, block index and volume map\n  \
         adi2raw dump <file.adi>     write the raw disk image to stdout\n\n\
         Examples:\n  \
         adi2raw dump backup.adi | dd of=/dev/sdX bs=1M status=progress\n  \
         adi2raw dump backup.adi > disk.img\n  \
         adi2raw dump backup.adi | sha256sum\n\n\
         Diagnostics go to stderr; stdout carries only raw bytes.\n\
         Alias for dump: raw",
        env!("CARGO_PKG_VERSION")
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let result = match (args.get(1).map(String::as_str), args.len()) {
        (Some("-h" | "--help" | "help"), _) => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        (Some("-V" | "--version"), _) => {
            println!("adi2raw {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        (Some("info"), 3) => cmd_info(Path::new(&args[2])),
        (Some("dump" | "raw"), 3) => cmd_dump(Path::new(&args[2])),
        _ => {
            eprintln!("{}\n", usage());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("adi2raw: error: {e}");
            ExitCode::FAILURE
        }
    }
}
