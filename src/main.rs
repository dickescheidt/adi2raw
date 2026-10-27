//! adi2raw — two commands, no dependencies:
//!
//!   adi2raw info <file.adi>     describe the image
//!   adi2raw dump <file.adi>     write a raw disk image to stdout

mod adi;
mod gpt;
mod lz4;

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use adi::{
    block_base, discover_map, scan_block_index, split_block, unit_present, Adi, BlockRec,
    SectorMap, REGION, SECTOR,
};
use lz4::Lz4;

/// Ceiling for out-of-order clusters held in memory while streaming.
const MAX_PENDING: usize = 256 * 1024 * 1024;
const ZERO_CHUNK: usize = 1024 * 1024;
static ZEROS: [u8; ZERO_CHUNK] = [0u8; ZERO_CHUNK];

/// A sparse scratch file used when the .adi's block order diverges too far
/// from disk order to stream with a bounded in-memory reorder window.
/// Seeking past the end leaves a hole on ext4/xfs/btrfs, so only the clusters
/// actually stored in the backup consume disk space.
struct Spool {
    file: File,
    path: PathBuf,
}

impl Spool {
    fn create() -> Result<Self, String> {
        let dir = env::var_os("ADI2RAW_SPOOL_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("adi2raw-{}-{nonce}.spool", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("cannot create spool {}: {e}", path.display()))?;
        Ok(Self { file, path })
    }

    fn write_at(&mut self, off: u64, data: &[u8]) -> Result<(), String> {
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("spool seek {off}: {e}"))?;
        self.file
            .write_all(data)
            .map_err(|e| format!("spool write {off}: {e}"))?;
        Ok(())
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Ordered byte stream with a bounded reorder buffer
// ---------------------------------------------------------------------------

struct Streamer<W: Write> {
    out: W,
    pos: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    spool: Option<Spool>,
    max_pending: usize,
    pub broken: bool,
    pub total: u64,
}

impl<W: Write> Streamer<W> {
    fn new(out: W, max_pending: usize) -> Self {
        Self {
            out,
            pos: 0,
            pending: BTreeMap::new(),
            spool: None,
            max_pending,
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
        if let Some(spool) = self.spool.as_mut() {
            return spool.write_at(off, &data);
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
        if buffered > self.max_pending {
            if env::var_os("ADI2RAW_NO_SPOOL").is_some() {
                return Err(format!(
                    "image blocks are too far out of disk order to stream ({} MiB buffered); \
                     spooling disabled by ADI2RAW_NO_SPOOL",
                    buffered / 1024 / 1024
                ));
            }
            self.spill()?;
        }
        Ok(())
    }

    /// Switch from the in-memory reorder window to a sparse scratch file.
    /// Everything already emitted to stdout stays emitted; the spool only
    /// holds unflushed writes, all of which start at or after `self.pos`.
    fn spill(&mut self) -> Result<(), String> {
        let mut spool = Spool::create()?;
        eprintln!(
            "adi2raw: blocks are far out of disk order; spooling to {} \
             (set ADI2RAW_SPOOL_DIR to choose a location)",
            spool.path.display()
        );
        for (off, data) in &self.pending {
            spool.write_at(*off, data)?;
        }
        self.pending.clear();
        self.spool = Some(spool);
        Ok(())
    }

    /// Emit every queued write that no future block can still precede.
    fn flush_to(&mut self, limit: u64) -> Result<(), String> {
        if self.spool.is_some() {
            return Ok(());
        }
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

    /// Read the remaining range from the spool and emit it in order. Takes the
    /// spool out of `self` so the output writer can be borrowed independently.
    fn finish_spool(&mut self, disk_size: u64) -> Result<(), String> {
        let mut spool = self.spool.take().ok_or("spool disappeared")?;
        let spool_len = spool
            .file
            .metadata()
            .map_err(|e| format!("spool stat: {e}"))?
            .len();
        let readable_end = disk_size.min(spool_len);
        spool
            .file
            .seek(SeekFrom::Start(self.pos))
            .map_err(|e| format!("spool seek: {e}"))?;
        let mut buf = vec![0u8; 1024 * 1024];
        while self.pos < readable_end {
            let n = std::cmp::min((readable_end - self.pos) as usize, buf.len());
            spool
                .file
                .read_exact(&mut buf[..n])
                .map_err(|e| format!("spool read at {}: {e}", self.pos))?;
            self.raw(&buf[..n])?;
            if self.broken {
                return Ok(());
            }
        }
        self.zero_fill(disk_size)?;
        Ok(())
    }

    fn finish(&mut self, disk_size: u64) -> Result<(), String> {
        if !self.broken {
            if self.spool.is_some() {
                self.finish_spool(disk_size)?;
            } else {
                self.flush_all()?;
                self.zero_fill(disk_size)?;
            }
        }
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

struct PlanEntry {
    bi: usize,
    base: u64,
    cluster_hint: u32,
}
type Plan = Vec<PlanEntry>;

fn build_plan(map: &SectorMap, blocks: &[BlockRec]) -> Plan {
    let mut plan = Vec::with_capacity(blocks.len());
    if map.passthrough {
        for (bi, b) in blocks.iter().enumerate() {
            let base = map.origin + b.region as u64 * REGION;
            let lba = base / SECTOR;
            // Nearest preceding partition supplies the cluster size; needed
            // for the "all units present" blocks which carry no bitmap.
            let hint = map
                .volumes
                .iter()
                .rev()
                .find(|v| v.lba <= lba)
                .map(|v| v.cluster)
                .unwrap_or(0);
            plan.push(PlanEntry {
                bi,
                base,
                cluster_hint: hint,
            });
        }
    } else {
        for v in &map.volumes {
            for (bi, b) in blocks.iter().enumerate().take(v.last + 1).skip(v.first) {
                plan.push(PlanEntry {
                    bi,
                    base: block_base(v, b),
                    cluster_hint: v.cluster,
                });
            }
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
        low = low.min(plan[i].base);
    }
    out
}

/// Turn one compressed block into coalesced (offset, bytes) writes.
fn block_writes(
    adi: &mut Adi,
    dec: &mut Lz4,
    b: &BlockRec,
    base: u64,
    limit: u64,
    cluster_hint: u32,
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
    let lay = match split_block(&data, b.usize, cluster_hint) {
        Some(l) => l,
        None => {
            eprintln!("adi2raw: warn: block at 0x{:x}: unrecognised layout", b.off);
            return Ok(Vec::new());
        }
    };
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
        if dst + lay.cluster as u64 > limit {
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

/// Ordering statistics. These describe *our computed target offsets*, not
/// necessarily the physical order of blocks inside the .adi.
struct PlanStats {
    blocks: usize,
    runs: usize,
    raw_monotone: bool,
    resolved_monotone: bool,
    min_base: u64,
    max_base: u64,
    inversions: u64,
    max_back: u64,
    reorder_need: u64,
}

fn plan_stats(plan: &Plan, blocks: &[BlockRec]) -> PlanStats {
    let fmin = future_min(plan);
    let mut runs = 1usize;
    let mut inversions = 0u64;
    let mut min_base = u64::MAX;
    let mut max_base = 0u64;
    let mut max_back = 0u64;
    let mut reorder_need = 0u64;
    let mut high = 0u64;
    for (i, e) in plan.iter().enumerate() {
        if i > 0 {
            let prev = &plan[i - 1];
            if blocks[e.bi].off != blocks[prev.bi].end() {
                runs += 1;
            }
            if e.base < prev.base {
                inversions += 1;
            }
        }
        min_base = min_base.min(e.base);
        max_base = max_base.max(e.base);
        high = high.max(e.base);
        max_back = max_back.max(high.saturating_sub(e.base));
        reorder_need = reorder_need.max((high + REGION).saturating_sub(fmin[i]));
    }
    PlanStats {
        blocks: plan.len(),
        runs,
        raw_monotone: blocks
            .windows(2)
            .all(|w| w[1].raw_region >= w[0].raw_region),
        resolved_monotone: blocks.windows(2).all(|w| w[1].region >= w[0].region),
        min_base: if plan.is_empty() { 0 } else { min_base },
        max_base,
        inversions,
        max_back,
        reorder_need,
    }
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
    println!("\n[layout]");
    if map.passthrough {
        println!(
            "  whole-disk stream, origin {} bytes, {} partitions",
            map.origin,
            map.volumes.len()
        );
        println!(
            "  stored payload: {} KiB",
            blocks.iter().map(|b| b.usize as u64).sum::<u64>() / 1024
        );
    } else {
        println!("  legacy volume runs");
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
    let ps = plan_stats(&plan, &blocks);
    let ordered = ps.inversions == 0;
    println!("\n[plan]");
    println!("  blocks: {} in {} chain run(s)", ps.blocks, ps.runs);
    println!("  base range: {} .. {} bytes", ps.min_base, ps.max_base);
    println!(
        "  index regions monotone: raw {}, after resolve_regions {}",
        if ps.raw_monotone { "yes" } else { "no" },
        if ps.resolved_monotone { "yes" } else { "no" }
    );
    println!(
        "  out-of-order steps: {}, max backward jump: {} MiB",
        ps.inversions,
        ps.max_back / 1024 / 1024
    );
    println!(
        "  estimated reorder need: {} MiB",
        ps.reorder_need / 1024 / 1024
    );
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
    let (prefix, suffix) = if map.native_table {
        (Vec::new(), Vec::new())
    } else {
        gpt::build(map.disk_sectors, &map.volumes)
    };
    let suffix_at = gpt::suffix_start(map.disk_sectors);

    let ps = plan_stats(&plan, &blocks);
    eprintln!(
        "adi2raw: {} bytes ({:.2} GiB), {} volume(s), {} blocks -> stdout",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0,
        map.volumes.len(),
        blocks.len()
    );
    eprintln!(
        "adi2raw: plan: {} chain run(s), raw regions monotone {}, resolved {}, \
         {} out-of-order steps, est. reorder need {} MiB",
        ps.runs,
        if ps.raw_monotone { "yes" } else { "no" },
        if ps.resolved_monotone { "yes" } else { "no" },
        ps.inversions,
        ps.reorder_need / 1024 / 1024
    );

    let max_pending = env::var("ADI2RAW_MAX_PENDING_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|mb| mb.saturating_mul(1024 * 1024))
        .unwrap_or(MAX_PENDING);
    let stdout = io::stdout();
    let mut st = Streamer::new(
        BufWriter::with_capacity(1024 * 1024, stdout.lock()),
        max_pending,
    );
    st.add(0, prefix)?;
    st.add(suffix_at, suffix)?;

    let mut dec = Lz4::new();
    for (pi, entry) in plan.iter().enumerate() {
        let b = &blocks[entry.bi];
        // A gap in the compressed block chain starts a new LZ4 window.
        if entry.bi == 0 || blocks[entry.bi - 1].end() != b.off {
            dec.reset();
        }
        let writes = block_writes(
            &mut adi,
            &mut dec,
            b,
            entry.base,
            disk_size,
            entry.cluster_hint,
        )?;
        for (dst, bytes) in writes {
            st.add(dst, bytes)?;
        }
        st.flush_to(fmin[pi])?;
        if st.broken {
            break;
        }
    }

    st.finish(disk_size)?;

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
         Alias for dump: raw.\n\
         Set ADI2RAW_LEGACY_MAP=1 to force the old volume-run layout.\n\
         Out-of-order images spill to a sparse temp file; see ADI2RAW_SPOOL_DIR.",
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
