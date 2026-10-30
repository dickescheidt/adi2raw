//! adi2raw — two commands, no dependencies:
//!
//!   adi2raw info [options] <file.adi>     describe the image
//!   adi2raw dump [options] <file.adi>     write a raw disk image to stdout

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
#[cfg(target_os = "linux")]
mod linux_pipe;
mod lz4;
mod mbr;
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
    fn create(spool_dir: Option<&Path>) -> Result<Self, String> {
        let dir = spool_dir
            .map(Path::to_path_buf)
            .unwrap_or_else(env::temp_dir);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("adi2raw-{}-{nonce}.spool", std::process::id()));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        // The spool holds recovered partition data. Create it owner-only instead
        // of relying on the umask (0644 on a default system) in a shared /tmp.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
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

#[derive(Clone, Copy, Default)]
struct PipeOptions {
    no_vmsplice: bool,
    no_huge_pages: bool,
    busy_loop: bool,
}

struct Streamer<W: Write> {
    out: W,
    pos: u64,
    pending: BTreeMap<u64, Vec<u8>>,
    spool: Option<Spool>,
    max_pending: usize,
    spool_dir: Option<PathBuf>,
    no_spool: bool,
    pub broken: bool,
    pub total: u64,
    #[cfg(target_os = "linux")]
    vmsplice: Option<linux_pipe::VmspliceWriter>,
}

impl<W: Write> Streamer<W> {
    #[cfg(test)]
    fn new(out: W, max_pending: usize, spool_dir: Option<PathBuf>, no_spool: bool) -> Self {
        Self::new_with_fd(
            out,
            max_pending,
            spool_dir,
            no_spool,
            None,
            PipeOptions::default(),
        )
    }

    fn new_with_fd(
        out: W,
        max_pending: usize,
        spool_dir: Option<PathBuf>,
        no_spool: bool,
        output_fd: Option<i32>,
        pipe_options: PipeOptions,
    ) -> Self {
        #[cfg(target_os = "linux")]
        let vmsplice = if pipe_options.no_vmsplice {
            None
        } else {
            output_fd.and_then(|fd| {
                linux_pipe::VmspliceWriter::for_fd(
                    fd,
                    !pipe_options.no_huge_pages,
                    pipe_options.busy_loop,
                )
                .ok()
                .flatten()
            })
        };
        #[cfg(not(target_os = "linux"))]
        let _ = (output_fd, pipe_options);
        Self {
            out,
            pos: 0,
            pending: BTreeMap::new(),
            spool: None,
            max_pending,
            spool_dir,
            no_spool,
            broken: false,
            total: 0,
            #[cfg(target_os = "linux")]
            vmsplice,
        }
    }

    fn raw(&mut self, data: &[u8]) -> Result<(), String> {
        if self.broken {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        if let Some(fast) = self.vmsplice.as_mut() {
            return match fast.write_all(data) {
                Ok(()) => {
                    self.pos += data.len() as u64;
                    Ok(())
                }
                Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                    self.broken = true;
                    Ok(())
                }
                Err(e) => Err(format!("write failed at offset {}: {e}", self.pos)),
            };
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
        let mut tails: Vec<(u64, Vec<u8>)> = Vec::new();
        for k in before {
            let e = self.pending.get_mut(&k).unwrap();
            let e_end = k + e.len() as u64;
            if e_end <= off {
                continue;
            }
            // The new write covers [off, end). If the older range extends past
            // `end`, that remainder must survive: dropping it silently zeroes
            // recovered data, because `zero_fill` later treats the gap as a hole.
            if e_end > end {
                tails.push((end, e[(end - k) as usize..].to_vec()));
            }
            e.truncate((off - k) as usize);
            if e.is_empty() {
                self.pending.remove(&k);
            }
        }
        // Only fill holes: a queued write that already starts at `end` was
        // issued later and wins over the older tail.
        for (at, tail) in tails {
            self.pending.entry(at).or_insert(tail);
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
            if self.no_spool {
                return Err(format!(
                    "image blocks are too far out of disk order to stream ({} MiB buffered); \
                     spooling disabled by --no-spool",
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
        let mut spool = Spool::create(self.spool_dir.as_deref())?;
        eprintln!(
            "adi2raw: blocks are far out of disk order; spooling to {} \
             (use --spool-dir to choose a location)",
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
        #[cfg(target_os = "linux")]
        if let Some(fast) = self.vmsplice.as_mut() {
            match fast.flush() {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                    self.broken = true;
                    return Ok(());
                }
                Err(e) => return Err(format!("flush failed at offset {}: {e}", self.pos)),
            }
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
    let data = match dec.decode_limited(&comp, b.usize as usize) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "adi2raw: warn: block at 0x{:x}: LZ4 decode failed: {e} — skipped",
                b.off
            );
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

fn open_image(path: &Path, full_scan: bool) -> Result<Opened, String> {
    let mut adi = Adi::open_with_members(path, &[])?;
    debug_warn!("adi2raw: warn: disk extent/layout is inferred and GPT may be reconstructed, not an exact original-disk restore; block checksums do not verify placement; verify layout and filesystem before use");
    if let Some(std) = records::parse_standard(&mut adi, full_scan)? {
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
    debug_warn!("adi2raw: trace: vdb region={} block={} logical=0x{:x} stored={} expected={} output_base=0x{:x} region_remaining={}",
        b.reg_no, b.block_no, b.off, b.csize, b.usize, b.base, b.region_remaining);
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
        // A damaged block must not discard the whole image: warn and skip it,
        // exactly like the legacy path and the C++ implementation. The run
        // still fails if no block at all could be decoded (see dump_standard).
        match Lz4::new().decode_limited(&comp, b.usize as usize) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "adi2raw: warn: block at 0x{:x}: LZ4 decode failed: {e} — skipped",
                    b.off
                );
                return Ok(Vec::new());
            }
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

    if DEBUG_DIAGNOSTICS.load(std::sync::atomic::Ordering::Relaxed) {
        debug_warn!("adi2raw: trace: decoded logical=0x{:x} bytes={} crc_actual=0x{:08x} crc_expected=0x{:08x}",
            b.off, data.len(), crc::br_crc32(&data), b.crc);
    }
    let bmp = b.bitmap_len as usize;
    let cpb = b.clusters_per_block;
    let cluster = b.cluster as usize;
    if data.len() < bmp || cluster == 0 || cpb == 0 {
        debug_warn!("adi2raw: warn: block at 0x{:x}: invalid bitmap/geometry; skipped; output needs verification", b.off);
        return Ok(Vec::new());
    }
    debug_warn!(
        "adi2raw: trace: bitmap logical=0x{:x} bytes={:02x?} clusters={} cluster_bytes={}",
        b.off,
        &data[..bmp],
        cpb,
        cluster
    );
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
    for (dst, src, len) in &runs {
        debug_warn!(
            "adi2raw: trace: write logical=0x{:x} decoded_offset={} output=0x{:x} bytes={}",
            b.off,
            src,
            dst,
            len
        );
    }
    Ok(runs
        .into_iter()
        .map(|(dst, src, len)| (dst, data[src..src + len].to_vec()))
        .collect())
}

fn cmd_info(path: &Path, options: &Options) -> Result<(), String> {
    debug_warn!("adi2raw: warn: info verifies a sample of decoded blocks; use dump for a full check of every block");
    let mut opened = open_image(path, options.full_scan)?;
    opened.adi.print_info();
    match &opened.kind {
        ImageMap::Standard(std) => standard_info(&mut opened.adi, std),
        ImageMap::Legacy { blocks, map } => legacy_info(&opened.adi, blocks, map),
    }
}

/// Cluster size shown in the volume line. Regions may disagree: a real card had
/// 32 KiB clusters in one region and 4 KiB in the other, and printing just the
/// first region's value was misleading.
fn cluster_label(region_clusters: &[u32], fallback: u32) -> String {
    match region_clusters {
        [] => fallback.to_string(),
        [one] => one.to_string(),
        many => {
            let list: Vec<String> = many.iter().map(|c| c.to_string()).collect();
            format!("mixed ({})", list.join(", "))
        }
    }
}

/// How many blocks `info` decodes to verify BRCrc32; spread over the image.
const INFO_SAMPLE: usize = 16;

/// A recovery tool must say how much of the image it actually filled in: the
/// exit status cannot distinguish "every cluster was free" from "most of the
/// disk is a hole", and the difference decides whether the image is usable.
fn report_coverage(placed: u64, disk_size: u64) {
    let zero = disk_size.saturating_sub(placed);
    let pct = if disk_size == 0 {
        0.0
    } else {
        100.0 * placed as f64 / disk_size as f64
    };
    eprintln!(
        "adi2raw: data: {placed} bytes of block data placed, {zero} bytes left zero ({pct:.3}% of the {disk_size}-byte image)"
    );
}

fn sample_indices(n: usize, k: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    if n <= k {
        return (0..n).collect();
    }
    (0..k).map(|i| i * n / k).collect()
}

/// Decode one block without the diagnostics of the dump path.
fn decode_block_quiet(adi: &mut Adi, b: &records::StdBlock) -> Option<Vec<u8>> {
    let comp = adi.read_logical(b.off, b.csize as usize).ok()?;
    let data = if b.csize == b.usize {
        comp
    } else {
        Lz4::new().decode_limited(&comp, b.usize as usize).ok()?
    };
    if data.len() == b.usize as usize {
        Some(data)
    } else {
        None
    }
}

fn verify_sample(adi: &mut Adi, std: &records::StandardImage, sample: &[usize]) -> (u64, u64) {
    let mut checked = 0u64;
    let mut bad = 0u64;
    for &i in sample {
        let Some(b) = std.blocks.get(i) else { continue };
        if b.crc == 0 {
            continue;
        }
        let Some(data) = decode_block_quiet(adi, b) else {
            continue;
        };
        checked += 1;
        if crc::br_crc32(&data) != b.crc {
            bad += 1;
            eprintln!(
                "adi2raw: warn: block at 0x{:x}: BRCrc32 mismatch (got 0x{:08x}, expected 0x{:08x})",
                b.off,
                crc::br_crc32(&data),
                b.crc
            );
        }
    }
    (checked, bad)
}

fn standard_info(adi: &mut Adi, std: &records::StandardImage) -> Result<(), String> {
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
    let crcs = std.blocks.iter().filter(|b| b.crc != 0).count();
    println!("  crcs:       {crcs} blocks carry a BRCrc32 checksum");
    if crcs != 0 {
        // info used to print the checksum count without ever testing one. Decode
        // a bounded, evenly spread sample instead of the whole image: enough to
        // catch a systematic decoder or placement problem, cheap on a 1 TB set.
        let sample = sample_indices(std.blocks.len(), INFO_SAMPLE);
        let (checked, bad) = verify_sample(adi, std, &sample);
        println!(
            "  verified:  {} of {} decoded blocks checked, {} {}, {} unchecked (dump verifies every block)",
            checked,
            crcs,
            bad,
            if bad == 1 { "mismatch" } else { "mismatches" },
            (crcs as u64).saturating_sub(checked)
        );
    }
    if std.skipped_regions != 0 {
        println!(
            "  skipped:    {} VDB entries with no matching region",
            std.skipped_regions
        );
    }
    println!("\n[volumes]");
    for (i, v) in std.volumes.iter().enumerate() {
        let clusters = cluster_label(&v.region_clusters, v.cluster);
        println!(
            "  v{} {:<10} lba {:<12} sectors {:<12} cluster {:<16} blocks {} label '{}'",
            i,
            format!("{}{}", v.fs, if v.fs_detected { "" } else { "?" }),
            v.lba,
            v.sectors,
            clusters,
            v.blocks,
            v.label
        );
    }
    if std.volumes.iter().any(|v| !v.fs_detected) {
        println!(
            "  ('?' = filesystem guessed from the label; its boot sector was not recoverable)"
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PartitionTable {
    Mbr,
    Gpt,
}

struct Options {
    partition_table: Option<PartitionTable>,
    spool_dir: Option<PathBuf>,
    max_pending: Option<usize>,
    no_spool: bool,
    no_vmsplice: bool,
    no_huge_pages: bool,
    busy_loop: bool,
    full_scan: bool,
}

fn build_partition_table(
    style: PartitionTable,
    disk_sectors: u64,
    volumes: &[Volume],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    match style {
        PartitionTable::Gpt => Ok(gpt::build(disk_sectors, volumes)),
        PartitionTable::Mbr => Ok((mbr::build(disk_sectors, volumes)?, Vec::new())),
    }
}

fn cmd_dump(path: &Path, options: &Options) -> Result<(), String> {
    if io::stdout().is_terminal() {
        return Err(
            "refusing to write a raw disk image to a terminal; redirect to a file or pipe to dd"
                .into(),
        );
    }
    let opened = open_image(path, options.full_scan)?;
    let pipe_options = PipeOptions {
        no_vmsplice: options.no_vmsplice,
        no_huge_pages: options.no_huge_pages,
        busy_loop: options.busy_loop,
    };
    match opened.kind {
        ImageMap::Standard(std) => dump_standard(
            opened.adi,
            &std,
            options.partition_table.unwrap_or(PartitionTable::Gpt),
            options.spool_dir.clone(),
            options.max_pending.unwrap_or(MAX_PENDING),
            options.no_spool,
            pipe_options,
        ),
        ImageMap::Legacy { blocks, map } => {
            // Native tables are preserved; dump_legacy rejects an explicit
            // partition-table choice rather than silently replacing metadata.
            dump_legacy(
                opened.adi,
                &blocks,
                &map,
                options.partition_table,
                options.spool_dir.clone(),
                options.max_pending.unwrap_or(MAX_PENDING),
                options.no_spool,
                pipe_options,
            )
        }
    }
}

fn dump_standard(
    mut adi: Adi,
    std: &records::StandardImage,
    table: PartitionTable,
    spool_dir: Option<PathBuf>,
    max_pending: usize,
    no_spool: bool,
    pipe_options: PipeOptions,
) -> Result<(), String> {
    if std.encrypt_mode.is_some_and(|m| m != 0) {
        return Err("encrypted images are not supported (0x106 mode != 0)".into());
    }
    let disk_size = std.disk_sectors * SECTOR;
    let volumes = standard_volumes(std);
    let (prefix, suffix) = build_partition_table(table, std.disk_sectors, &volumes)?;
    let suffix_at = if table == PartitionTable::Gpt {
        gpt::suffix_start(std.disk_sectors)
    } else {
        0
    };
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
    let stdout = io::stdout();
    let lock = stdout.lock();
    #[cfg(target_os = "linux")]
    let output_fd = {
        use std::os::fd::AsRawFd;
        Some(lock.as_raw_fd())
    };
    #[cfg(not(target_os = "linux"))]
    let output_fd = None;
    let mut st = Streamer::new_with_fd(
        BufWriter::with_capacity(1024 * 1024, lock),
        max_pending,
        spool_dir,
        no_spool,
        output_fd,
        pipe_options,
    );
    st.add(0, prefix)?;
    st.add(suffix_at, suffix)?;
    let mut counts = (0u64, 0u64);
    let mut placed = 0u64;
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
            placed += bytes.len() as u64;
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
    // Match the C++ tool: a run that placed nothing is a failure, not a
    // zero-filled success. Partial recovery stays a success with warnings.
    if !st.broken && placed == 0 && !std.blocks.is_empty() {
        return Err(format!(
            "no VDB block could be decoded; nothing was recovered from {} block(s)",
            std.blocks.len()
        ));
    }
    if !st.broken {
        report_coverage(placed, disk_size);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn dump_legacy(
    mut adi: Adi,
    blocks: &[BlockRec],
    map: &SectorMap,
    requested_table: Option<PartitionTable>,
    spool_dir: Option<PathBuf>,
    max_pending: usize,
    no_spool: bool,
    pipe_options: PipeOptions,
) -> Result<(), String> {
    let plan = build_plan(map, blocks);
    let fmin = future_min(&plan);
    let disk_size = map.disk_sectors * SECTOR;
    if map.native_table && requested_table.is_some() {
        return Err(
            "this legacy image already contains a native partition table; --partition-table only selects a synthesized table and will not replace native metadata".into(),
        );
    }
    let (prefix, suffix, suffix_at) = if map.native_table {
        (Vec::new(), Vec::new(), 0)
    } else {
        let table = requested_table.unwrap_or(PartitionTable::Gpt);
        let (prefix, suffix) = build_partition_table(table, map.disk_sectors, &map.volumes)?;
        let suffix_at = if table == PartitionTable::Gpt {
            gpt::suffix_start(map.disk_sectors)
        } else {
            0
        };
        (prefix, suffix, suffix_at)
    };

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

    let stdout = io::stdout();
    let lock = stdout.lock();
    #[cfg(target_os = "linux")]
    let output_fd = {
        use std::os::fd::AsRawFd;
        Some(lock.as_raw_fd())
    };
    #[cfg(not(target_os = "linux"))]
    let output_fd = None;
    let mut st = Streamer::new_with_fd(
        BufWriter::with_capacity(1024 * 1024, lock),
        max_pending,
        spool_dir,
        no_spool,
        output_fd,
        pipe_options,
    );
    st.add(0, prefix)?;
    st.add(suffix_at, suffix)?;

    let mut dec = Lz4::new();
    let mut crc_bad = 0u64;
    let mut placed = 0u64;
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
            placed += bytes.len() as u64;
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
    if !st.broken && placed == 0 && !plan.is_empty() {
        return Err(format!(
            "no block could be decoded; nothing was recovered from {} block(s)",
            plan.len()
        ));
    }
    if !st.broken {
        report_coverage(placed, disk_size);
    }
    Ok(())
}

// ---------------------------------------------------------------------------

fn usage() -> String {
    format!(
        "adi2raw {} — convert an AOMEI .adi disk image to raw output\n\n\
         Usage:\n  \
         adi2raw info [options] <file.adi>\n  \
         adi2raw dump [options] <file.adi>\n\n\
         Options:\n  \
         -p, --partition-table mbr|gpt  Select the synthetic table (default: gpt)\n  \
         --spool-dir DIR                Temporary-file location (default: {})\n  \
         --max-pending-mb N             Memory buffer before spooling (default: 256)\n  \
         --no-spool                     Fail instead of using a temporary file\n  \
         --no-vmsplice                  Disable Linux pipe fast path\n  \
         --no-huge-pages                Disable default huge-page hint\n  \
         --busy-loop                    Opt into pipe-write spinning (higher CPU use)\n  \
         --full-scan                    Search the entire file for records\n  \
         --debug                        Show additional diagnostics\n  \
         -h, --help                     Show this help\n\n\
         Examples:\n  \
         adi2raw dump backup.adi > disk.img\n  \
         adi2raw dump backup.adi | dd of=/dev/sdX bs=1M status=progress",
        env!("CARGO_PKG_VERSION"),
        env::temp_dir().display()
    )
}

fn parse_partition_table(value: &str) -> Result<PartitionTable, String> {
    match value.to_ascii_lowercase().as_str() {
        "mbr" => Ok(PartitionTable::Mbr),
        "gpt" => Ok(PartitionTable::Gpt),
        _ => Err(format!(
            "invalid partition table {value:?}; expected mbr or gpt"
        )),
    }
}

fn parse_pending_limit(value: &str) -> Result<usize, String> {
    let mb = value.parse::<usize>().map_err(|_| {
        format!("invalid --max-pending-mb value {value:?}; expected a non-negative integer")
    })?;
    Ok(mb.saturating_mul(1024 * 1024))
}

fn main() -> ExitCode {
    let mut args = vec![env::args().next().unwrap_or_else(|| "adi2raw".into())];
    let mut options = Options {
        partition_table: None,
        spool_dir: None,
        max_pending: None,
        no_spool: false,
        no_vmsplice: false,
        no_huge_pages: false,
        busy_loop: false,
        full_scan: false,
    };
    let mut parse_error = None;
    let mut it = env::args().skip(1);
    let mut parsing_options = true;
    while let Some(arg) = it.next() {
        if parsing_options && arg == "--" {
            parsing_options = false;
        } else if parsing_options && arg == "--debug" {
            DEBUG_DIAGNOSTICS.store(true, std::sync::atomic::Ordering::Relaxed);
        } else if parsing_options && arg == "--full-scan" {
            options.full_scan = true;
        } else if parsing_options && arg == "--no-spool" {
            options.no_spool = true;
        } else if parsing_options && arg == "--no-vmsplice" {
            options.no_vmsplice = true;
        } else if parsing_options && arg == "--no-huge-pages" {
            options.no_huge_pages = true;
        } else if parsing_options && arg == "--busy-loop" {
            options.busy_loop = true;
        } else if parsing_options && (arg == "-p" || arg == "--partition-table") {
            match it.next() {
                Some(value) => match parse_partition_table(&value) {
                    Ok(style) => options.partition_table = Some(style),
                    Err(e) => parse_error = Some(e),
                },
                None => parse_error = Some(format!("{arg} requires mbr or gpt")),
            }
        } else if parsing_options && arg.starts_with("--partition-table=") {
            let value = arg.strip_prefix("--partition-table=").unwrap();
            match parse_partition_table(value) {
                Ok(style) => options.partition_table = Some(style),
                Err(e) => parse_error = Some(e),
            }
        } else if parsing_options && arg == "--spool-dir" {
            match it.next() {
                Some(dir) if !dir.starts_with('-') => options.spool_dir = Some(PathBuf::from(dir)),
                Some(_) => parse_error = Some("--spool-dir requires a directory".into()),
                None => parse_error = Some("--spool-dir requires a directory".into()),
            }
        } else if parsing_options && arg.starts_with("--spool-dir=") {
            let dir = arg.strip_prefix("--spool-dir=").unwrap();
            if dir.is_empty() {
                parse_error = Some("--spool-dir requires a directory".into());
            } else {
                options.spool_dir = Some(PathBuf::from(dir));
            }
        } else if parsing_options && arg == "--max-pending-mb" {
            match it.next() {
                Some(value) => match parse_pending_limit(&value) {
                    Ok(limit) => options.max_pending = Some(limit),
                    Err(e) => parse_error = Some(e),
                },
                None => parse_error = Some("--max-pending-mb requires a number".into()),
            }
        } else if parsing_options && arg.starts_with("--max-pending-mb=") {
            let value = arg.strip_prefix("--max-pending-mb=").unwrap();
            match parse_pending_limit(value) {
                Ok(limit) => options.max_pending = Some(limit),
                Err(e) => parse_error = Some(e),
            }
        } else {
            args.push(arg);
        }
    }
    if parse_error.is_none() && options.no_spool && options.spool_dir.is_some() {
        parse_error = Some("--no-spool cannot be combined with --spool-dir".into());
    }
    if let Some(e) = parse_error {
        eprintln!("adi2raw: error: {e}\n\n{}", usage());
        return ExitCode::from(2);
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
        (Some("info"), 3)
            if options.partition_table.is_none()
                && options.spool_dir.is_none()
                && options.max_pending.is_none()
                && !options.no_spool
                && !options.no_vmsplice
                && !options.no_huge_pages
                && !options.busy_loop =>
        {
            cmd_info(Path::new(&args[2]), &options)
        }
        (Some("info"), 3) => Err("partition-table and dump-only options only apply to dump".into()),
        (Some("dump"), 3) => cmd_dump(Path::new(&args[2]), &options),
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

#[cfg(test)]
mod tests {
    use super::{cluster_label, Streamer};

    #[test]
    fn cluster_label_reports_mixed_region_geometries() {
        assert_eq!(cluster_label(&[], 4096), "4096");
        assert_eq!(cluster_label(&[4096], 512), "4096");
        assert_eq!(cluster_label(&[4096, 32768], 4096), "mixed (4096, 32768)");
    }

    #[test]
    fn later_write_inside_pending_range_keeps_the_tail() {
        // The second write starts inside the first one and ends before it, which
        // used to drop the first write's 85-byte tail and zero-fill that range.
        let mut st = Streamer::new(Vec::new(), 1 << 20, None, false);
        st.add(0, vec![b'A'; 100]).unwrap();
        st.add(10, vec![b'B'; 5]).unwrap();
        st.finish(100).unwrap();
        assert_eq!(st.total, 100);
        assert_eq!(&st.out[..10], &[b'A'; 10]);
        assert_eq!(&st.out[10..15], b"BBBBB");
        assert_eq!(&st.out[15..], &[b'A'; 85]);
    }

    #[test]
    fn write_fully_inside_pending_range_splits_it() {
        let mut st = Streamer::new(Vec::new(), 1 << 20, None, false);
        st.add(0, vec![b'A'; 100]).unwrap();
        st.add(40, vec![b'B'; 20]).unwrap();
        st.finish(100).unwrap();
        assert_eq!(&st.out[..40], &[b'A'; 40]);
        assert_eq!(&st.out[40..60], &[b'B'; 20]);
        assert_eq!(&st.out[60..], &[b'A'; 40]);
    }

    #[test]
    fn a_queued_write_at_the_new_end_is_not_overwritten() {
        let mut st = Streamer::new(Vec::new(), 1 << 20, None, false);
        st.add(0, vec![b'A'; 100]).unwrap();
        st.add(200, vec![b'C'; 10]).unwrap();
        st.add(50, vec![b'B'; 150]).unwrap();
        st.finish(210).unwrap();
        assert_eq!(&st.out[..50], &[b'A'; 50]);
        assert_eq!(&st.out[50..200], &[b'B'; 150]);
        assert_eq!(&st.out[200..], &[b'C'; 10]);
    }
}
