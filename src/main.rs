//! adi2raw — two commands, no dependencies:
//!
//!   adi2raw info <file.adi>     describe the image
//!   adi2raw dump <file.adi>     write a raw disk image to stdout

// Optional format-audit diagnostics. Operational corruption warnings remain unconditional.
static DEBUG_DIAGNOSTICS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
macro_rules! debug_warn {
    ($($arg:tt)*) => {
        if crate::DEBUG_DIAGNOSTICS.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}

mod adi;
mod crc;
mod gpt;
mod lz4;
mod records;

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
    crc_bad: &mut u64,
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let comp = adi.read_logical(b.off, b.csize as usize)?;
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
    if b.crc == 0 {
        debug_warn!(
            "adi2raw: warn: block at 0x{:x}: no decoded checksum; contents need verification",
            b.off
        );
    }
    if !b.crc_ok(&data) {
        *crc_bad += 1;
        eprintln!(
            "adi2raw: warn: block at 0x{:x}: CRC32C mismatch (got 0x{:08x}, expected 0x{:08x}) — skipped",
            b.off,
            crc::br_crc32(&data),
            b.crc
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
            debug_warn!("adi2raw: warn: block at 0x{:x}: cluster at output 0x{:x} exceeds volume boundary; skipped; output needs verification", b.off, dst);
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

/// Real 0x201/0x202/0x109 record path, or the legacy signature-scan fallback.
enum ImageMap {
    Standard(records::StandardImage),
    Legacy {
        blocks: Vec<BlockRec>,
        map: SectorMap,
    },
}

struct Opened {
    adi: Adi,
    kind: ImageMap,
}

fn open_image(path: &Path) -> Result<Opened, String> {
    let extra = records::extra_member_paths("ADI2RAW_MEMBERS");
    let mut adi = Adi::open_with_members(path, &extra)?;
    debug_warn!("adi2raw: warn: disk extent/layout is inferred and GPT may be reconstructed, not an exact original-disk restore; block checksums do not verify placement; verify layout and filesystem before use");
    if env::var_os("ADI2RAW_LEGACY_ONLY").is_none() {
        if let Some(std) = records::parse_standard(&mut adi)? {
            debug_warn!("adi2raw: warn: standard-path filesystem type display is inferred from volume labels, not verified filesystem contents");
            eprintln!(
                "adi2raw: standard record path: {} volume set(s), {} VDB entries, {} member(s)",
                std.sets.len(),
                std.blocks.len(),
                adi.image_set.info().len()
            );
            return Ok(Opened {
                adi,
                kind: ImageMap::Standard(std),
            });
        }
        eprintln!("adi2raw: no standard record sets; using legacy signature scan");
    } else {
        eprintln!("adi2raw: legacy signature scan forced by ADI2RAW_LEGACY_ONLY");
    }
    debug_warn!("adi2raw: warn: legacy signature scan uses inferred geometry and placement; output needs further verification");
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
    Ok(Opened {
        adi,
        kind: ImageMap::Legacy { blocks, map },
    })
}

fn standard_volumes(std: &records::StandardImage) -> Vec<Volume> {
    std.volumes
        .iter()
        .map(|v| Volume {
            first: 0,
            last: std.blocks.len().saturating_sub(1),
            fs: v.fs.clone(),
            label: v.label.clone(),
            cluster: v.cluster,
            data_base: 0,
            lba: v.lba,
            sectors: v.sectors,
            stored: 0,
            max_region: 0,
            type_guid: v.type_guid,
            unique_guid: v.unique_guid,
            part_name: v.part_name.clone(),
        })
        .collect()
}

/// Decode one VDB entry using its exact 0x109 geometry and image-set logical
/// offset. Returns coalesced (absolute disk offset, bytes) writes.
fn standard_writes(
    adi: &mut Adi,
    b: &records::StdBlock,
    limit: u64,
    compress: Option<u32>,
    encrypt: Option<u32>,
    counts: &mut (u64, u64), // (crc checked, crc bad)
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let comp = adi.read_logical(b.off, b.csize as usize)?;
    let data = if b.csize == b.usize {
        comp
    } else {
        if encrypt.unwrap_or(0) != 0 {
            return Err("encrypted images are not supported (0x106 mode != 0)".into());
        }
        if compress.is_some_and(|m| m != 0 && m != 1) {
            return Err(format!(
                "unsupported compression mode {} (0x105)",
                compress.unwrap_or(0)
            ));
        }
        if compress == Some(0) {
            debug_warn!("adi2raw: warn: block at 0x{:x}: compression mode 0 but unequal stored/decoded sizes; attempting LZ4; verify output", b.off);
        }
        Lz4::new()
            .decode(&comp)
            .map_err(|e| format!("block at 0x{:x}: {e}", b.off))?
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
    if b.crc != 0 {
        counts.0 += 1;
        if crc::br_crc32(&data) != b.crc {
            counts.1 += 1;
            eprintln!(
                "adi2raw: warn: block at 0x{:x}: BRCrc32 mismatch (got 0x{:08x}, expected 0x{:08x}) — skipped",
                b.off,
                crc::br_crc32(&data),
                b.crc
            );
            return Ok(Vec::new());
        }
    }

    let bmp = b.bitmap_len as usize;
    let cpb = b.clusters_per_block;
    let cluster = b.cluster as usize;
    if data.len() < bmp || cluster == 0 || cpb == 0 {
        debug_warn!("adi2raw: warn: block at 0x{:x}: invalid bitmap/geometry; skipped; output needs verification", b.off);
        return Ok(Vec::new());
    }
    let present = |u: u32| -> bool {
        let idx = (u >> 3) as usize;
        idx < bmp && data[idx] & (1u8 << (u & 7)) != 0
    };
    let bytes_at = |u: u32| -> usize {
        b.region_remaining
            .saturating_sub(u as u64 * cluster as u64)
            .min(cluster as u64) as usize
    };
    let pop = (0..cpb).filter(|&u| present(u)).count();
    let bounded = bmp
        + (0..cpb)
            .filter(|&u| present(u))
            .map(bytes_at)
            .sum::<usize>();
    let padded = data.len() == bmp + pop * cluster;
    if b.region_remaining == 0 || (!padded && data.len() != bounded) {
        return Err(format!(
            "block at 0x{:x}: decoded size {} does not match 0x109 geometry (bounded {}, padded {})",
            b.off, data.len(), bounded, bmp + pop * cluster
        ));
    }
    let mut runs: Vec<(u64, usize, usize)> = Vec::new();
    let mut src = bmp;
    for u in 0..cpb {
        if !present(u) {
            continue;
        }
        let len = bytes_at(u);
        let offset = src;
        src += if padded { cluster } else { len };
        let src = offset;
        let dst = b.base + u as u64 * b.cluster as u64;
        if len == 0 {
            continue;
        }
        if dst + len as u64 > limit {
            return Err(format!(
                "block at 0x{:x}: write exceeds output boundary",
                b.off
            ));
        }
        if let Some(last) = runs.last_mut() {
            if last.0 + last.2 as u64 == dst && last.1 + last.2 == src {
                last.2 += len;
                continue;
            }
        }
        runs.push((dst, src, len));
    }
    Ok(runs
        .into_iter()
        .map(|(dst, src, len)| (dst, data[src..src + len].to_vec()))
        .collect())
}

fn cmd_info(path: &Path) -> Result<(), String> {
    debug_warn!("adi2raw: warn: info does not verify all decoded block contents/checksums; use extraction diagnostics and independent filesystem checks");
    let opened = open_image(path)?;
    opened.adi.print_info();
    match &opened.kind {
        ImageMap::Standard(std) => standard_info(&opened.adi, std),
        ImageMap::Legacy { blocks, map } => legacy_info(&opened.adi, blocks, map),
    }
}

fn standard_info(_adi: &Adi, std: &records::StandardImage) -> Result<(), String> {
    println!("\n[standard records]");
    println!("  volume record sets: {}", std.sets.len());
    for (i, s) in std.sets.iter().enumerate() {
        println!(
            "  set {}: 0x201 @ 0x{:x}, 0x202 @ 0x{:x}, delta 0x{:x}, {} VDB entries",
            i, s.volume_index_off, s.data_block_index_off, s.delta, s.entry_count
        );
        for r in &s.regions {
            println!(
                "    region {}: LBA {} + {} sectors, {} clusters/block x {} sectors/cluster x {} B (0x109 @ 0x{:x})",
                r.reg_no,
                r.block_begin_sector,
                r.total_sectors,
                r.clusters_per_block,
                r.sectors_per_cluster,
                r.bytes_per_sector,
                r.off
            );
        }
        for m in &s.metadata {
            println!(
                "    metadata: LBA {}, {} sectors, {} B/sector, label '{}' '{}' (0x102 @ 0x{:x})",
                m.partition_start_sector,
                m.partition_total_sectors,
                m.bytes_per_sector,
                m.label,
                m.description,
                m.off
            );
        }
    }
    println!(
        "  modes:      compress {}, encrypt {}",
        std.compress_mode
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        std.encrypt_mode
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    println!(
        "  crcs:       {} blocks carry a BRCrc32 checksum",
        std.blocks.iter().filter(|b| b.crc != 0).count()
    );
    if std.skipped_regions != 0 {
        println!(
            "  skipped:    {} VDB entries with no matching region",
            std.skipped_regions
        );
    }
    println!("\n[volumes]");
    for (i, v) in std.volumes.iter().enumerate() {
        println!(
            "  v{} {:<10} lba {:<12} sectors {:<12} cluster {:<6} blocks {} label '{}'",
            i, v.fs, v.lba, v.sectors, v.cluster, v.blocks, v.label
        );
    }
    let disk_size = std.disk_sectors * SECTOR;
    println!("\n[raw image]");
    println!("  disk:      {} sectors", std.disk_sectors);
    println!(
        "  size:      {} bytes ({:.2} GiB)",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0
    );
    let bases: Vec<u64> = std.blocks.iter().map(|b| b.base).collect();
    let inversions = bases.windows(2).filter(|w| w[1] < w[0]).count();
    println!("\n[plan]");
    println!(
        "  blocks: {} in disk order: {}",
        bases.len(),
        if inversions == 0 { "yes" } else { "no" }
    );
    println!(
        "  base range: {} .. {} bytes",
        bases.first().copied().unwrap_or(0),
        bases.last().copied().unwrap_or(0)
    );
    Ok(())
}

fn legacy_info(_adi: &Adi, blocks: &[BlockRec], map: &SectorMap) -> Result<(), String> {
    println!("\n[block index]");
    println!("  records:   {}", blocks.len());
    let crcs = blocks.iter().filter(|b| b.crc != 0).count();
    println!("  crcs:      {} records carry a BRCrc32 checksum", crcs);
    if crcs != 0 {
        println!(
            "  verified:  {} decoded blocks checked, {} mismatches, {} unchecked",
            map.crc_checked,
            map.crc_bad,
            crcs.saturating_sub(map.crc_checked as usize)
        );
    }
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
            i, v.fs, v.lba, v.sectors, v.cluster, v.last - v.first + 1, v.stored / 1024, v.label
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
    let plan = build_plan(map, blocks);
    let ps = plan_stats(&plan, blocks);
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
    let opened = open_image(path)?;
    match opened.kind {
        ImageMap::Standard(std) => dump_standard(opened.adi, &std),
        ImageMap::Legacy { blocks, map } => dump_legacy(opened.adi, &blocks, &map),
    }
}

fn dump_standard(mut adi: Adi, std: &records::StandardImage) -> Result<(), String> {
    if std.encrypt_mode.is_some_and(|m| m != 0) {
        return Err("encrypted images are not supported (0x106 mode != 0)".into());
    }
    let disk_size = std.disk_sectors * SECTOR;
    let volumes = standard_volumes(std);
    let (prefix, suffix) = gpt::build(std.disk_sectors, &volumes);
    let suffix_at = gpt::suffix_start(std.disk_sectors);
    let plan: Plan = std
        .blocks
        .iter()
        .enumerate()
        .map(|(bi, b)| PlanEntry {
            bi,
            base: b.base,
            cluster_hint: b.cluster,
        })
        .collect();
    let fmin = future_min(&plan);
    eprintln!(
        "adi2raw: {} bytes ({:.2} GiB), {} volume(s), {} blocks -> stdout",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0,
        volumes.len(),
        std.blocks.len()
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
    let mut counts = (0u64, 0u64);
    for (i, b) in std.blocks.iter().enumerate() {
        let writes = standard_writes(
            &mut adi,
            b,
            disk_size,
            std.compress_mode,
            std.encrypt_mode,
            &mut counts,
        )?;
        for (dst, bytes) in writes {
            st.add(dst, bytes)?;
        }
        st.flush_to(fmin[i])?;
        if st.broken {
            break;
        }
    }
    st.finish(disk_size)?;
    eprintln!(
        "adi2raw: BRCrc32: {} decoded blocks checked, {} mismatches",
        counts.0, counts.1
    );
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

fn dump_legacy(mut adi: Adi, blocks: &[BlockRec], map: &SectorMap) -> Result<(), String> {
    let plan = build_plan(map, blocks);
    let fmin = future_min(&plan);
    let disk_size = map.disk_sectors * SECTOR;
    let (prefix, suffix) = if map.native_table {
        (Vec::new(), Vec::new())
    } else {
        gpt::build(map.disk_sectors, &map.volumes)
    };
    let suffix_at = gpt::suffix_start(map.disk_sectors);

    let ps = plan_stats(&plan, blocks);
    eprintln!(
        "adi2raw: {} bytes ({:.2} GiB), {} volume(s), {} blocks -> stdout",
        disk_size,
        disk_size as f64 / 1024.0 / 1024.0 / 1024.0,
        map.volumes.len(),
        blocks.len()
    );
    eprintln!(
        "adi2raw: plan: {} chain run(s), {} out-of-order steps, est. reorder need {} MiB",
        ps.runs,
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
    let mut crc_bad = 0u64;
    for (pi, entry) in plan.iter().enumerate() {
        let b = &blocks[entry.bi];
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
            &mut crc_bad,
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

    if crc_bad != 0 {
        eprintln!(
            "adi2raw: warn: {} block(s) failed CRC32C verification and were skipped",
            crc_bad
        );
    }
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
         --debug enables extended format-audit diagnostics on stderr.\n\
         Diagnostics go to stderr; stdout carries only raw bytes.\n\
         Alias for dump: raw.\n\
         Standard 0x201/0x202/0x109 records are used when present.\n\
         Split image sets: ADI2RAW_MEMBERS=member1.adi:member2.adi\n\
         Set ADI2RAW_LEGACY_ONLY=1 to force the signature-scan parser.\n\
         Set ADI2RAW_LEGACY_MAP=1 to force the old volume-run layout.\n\
         Out-of-order images spill to a sparse temp file; see ADI2RAW_SPOOL_DIR.",
        env!("CARGO_PKG_VERSION")
    )
}

fn main() -> ExitCode {
    let mut args = Vec::new();
    let mut options = true;
    for (i, arg) in env::args().enumerate() {
        if i != 0 && options && arg == "--" {
            options = false;
        } else if i != 0 && options && arg == "--debug" {
            DEBUG_DIAGNOSTICS.store(true, std::sync::atomic::Ordering::Relaxed);
        } else {
            args.push(arg);
        }
    }
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
