//! Standard AOMEI record path: image-set members, 0x201/0x202/0x109/0x102
//! records and the real 0x20-byte VDB index entries.
//!
//! The legacy path in `adi.rs` finds VDB entries by signature-scanning a
//! 32-byte window that starts 12 bytes *into* a real entry, so it has to guess
//! region numbers. This module reads the real record stream instead: every
//! field is known, including the volume region geometry and the partition's
//! absolute LBA. If no CRC-valid record set exists (synthetic or older images)
//! callers fall back to the legacy scanner.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::adi::{parse_boot_sector, u32le, u64le, utf16le_z, Adi};
use crate::crc::br_crc32;
use crate::lz4::Lz4;

pub const TYPE_VOLUME_INDEX: u32 = 0x201;
pub const TYPE_DATABLOCK_INDEX: u32 = 0x202;
pub const TYPE_VOLUME_METADATA: u32 = 0x102;
pub const TYPE_COMPRESS: u32 = 0x105;
pub const TYPE_ENCRYPT: u32 = 0x106;
pub const TYPE_VOLUME_REGION: u32 = 0x109;

const STD_HDR: usize = 0x10;
const VDB_SIZE: usize = 0x20;
const MAX_RECORD: usize = 1 << 20;
const CHUNK: usize = 4 * 1024 * 1024;
const OVERLAP: usize = STD_HDR - 1;

#[derive(Clone, Copy, Debug)]
pub struct StdHeader {
    pub off: u64,
    pub rec_type: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct DataBlockRef {
    pub data_offset: u64,
    pub data_size: u32,
    pub entry_count: u32,
}

#[derive(Clone, Debug)]
pub struct DataBlockIndex {
    pub off: u64,
    pub entry_count: u32,
    pub refs: Vec<DataBlockRef>,
}

#[derive(Clone, Copy, Debug)]
pub struct DirEntry {
    pub rec_type: u32,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct DirectoryIndex {
    pub off: u64,
    pub entries: Vec<DirEntry>,
}

#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub off: u64,
    pub reg_no: u32,
    pub block_begin_sector: u64,
    pub total_sectors: u64,
    pub clusters_per_block: u32,
    pub sectors_per_cluster: u32,
    pub bytes_per_sector: u32,
}

impl Region {
    pub fn cluster(&self) -> u64 {
        self.sectors_per_cluster as u64 * self.bytes_per_sector as u64
    }
    pub fn sectors_per_region(&self) -> u64 {
        self.clusters_per_block as u64 * self.sectors_per_cluster as u64
    }
    pub fn bitmap_len(&self) -> u32 {
        self.clusters_per_block.div_ceil(8)
    }
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub off: u64,
    pub bytes_per_sector: u32,
    pub partition_start_sector: u64,
    pub partition_total_sectors: u64,
    pub label: String,
    pub description: String,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
}

#[derive(Clone, Copy, Debug)]
pub struct VdbEntry {
    pub reg_no: u32,
    pub block_no: u64,
    pub img_offset: u64,
    pub old_size: u32,
    pub new_size: u32,
    pub crc: u32,
}

#[derive(Clone, Debug)]
pub struct RecordSet {
    pub volume_index_off: u64,
    pub data_block_index_off: u64,
    pub delta: i64,
    pub entry_count: u32,
    pub regions: Vec<Region>,
    pub metadata: Vec<Metadata>,
    pub compress_mode: Option<u32>,
    pub encrypt_mode: Option<u32>,
    pub entries: Vec<VdbEntry>,
}

/// One decoded block with its exact placement and geometry.
#[derive(Clone, Copy, Debug)]
pub struct StdBlock {
    pub off: u64,
    pub reg_no: u32,
    pub block_no: u64,
    pub usize: u32,
    pub csize: u32,
    pub crc: u32,
    /// Absolute byte offset in the output disk image where this block's region
    /// starts. Includes the partition start LBA and the region's block base.
    pub base: u64,
    pub cluster: u32,
    pub bitmap_len: u32,
    pub clusters_per_block: u32,
    /// Bytes remaining in this region from the block start.
    pub region_remaining: u64,
}

#[derive(Clone, Debug)]
pub struct StdVolume {
    pub label: String,
    /// Filesystem name. Comes from the volume's own boot sector when that block
    /// is recoverable; otherwise from the label heuristic (see `fs_detected`).
    pub fs: String,
    /// True when `fs` was read from a boot sector rather than guessed.
    pub fs_detected: bool,
    /// Distinct cluster sizes across the volume's regions, ascending.
    pub region_clusters: Vec<u32>,
    pub lba: u64,
    pub sectors: u64,
    pub cluster: u32,
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub part_name: String,
    pub blocks: usize,
}

#[derive(Clone, Debug)]
pub struct StandardImage {
    pub sets: Vec<RecordSet>,
    pub blocks: Vec<StdBlock>,
    pub volumes: Vec<StdVolume>,
    pub disk_sectors: u64,
    pub compress_mode: Option<u32>,
    pub encrypt_mode: Option<u32>,
    pub skipped_regions: u64,
}

fn guid(raw: &[u8], o: usize) -> [u8; 16] {
    let mut g = [0u8; 16];
    if raw.len() >= o + 16 {
        g.copy_from_slice(&raw[o..o + 16]);
    }
    g
}

/// Read a CRC-valid standard record at a physical file offset.
fn load_record(adi: &mut Adi, off: u64) -> Option<(StdHeader, Vec<u8>)> {
    let h = adi.read_at(off, STD_HDR).ok()?;
    let rec_type = u32le(&h, 0);
    let size = u32le(&h, 4);
    if size < STD_HDR as u32 || size as usize > MAX_RECORD {
        return None;
    }
    let raw = adi.read_at(off, size as usize).ok()?;
    let mut check = raw.clone();
    check[8..12].copy_from_slice(&[0; 4]);
    if br_crc32(&check) != u32le(&h, 8) {
        return None;
    }
    Some((StdHeader { off, rec_type }, raw))
}

fn parse_data_block_index(h: StdHeader, raw: &[u8]) -> Option<DataBlockIndex> {
    if h.rec_type != TYPE_DATABLOCK_INDEX || raw.len() < 0x24 {
        return None;
    }
    let block_count = u32le(raw, 0x10) as usize;
    let entry_count = u32le(raw, 0x14);
    if u32le(raw, 0x18) != VDB_SIZE as u32 {
        return None;
    }
    let refs_start: usize = 0x24;
    let refs_end = refs_start.checked_add(block_count.checked_mul(0x10)?)?;
    if refs_end > raw.len() {
        return None;
    }
    let mut refs = Vec::with_capacity(block_count);
    let mut total = 0u64;
    for p in (refs_start..refs_end).step_by(0x10) {
        let r = DataBlockRef {
            data_offset: u64le(raw, p),
            data_size: u32le(raw, p + 8),
            entry_count: u32le(raw, p + 12),
        };
        total += r.entry_count as u64;
        refs.push(r);
    }
    if total > entry_count as u64 {
        return None;
    }
    Some(DataBlockIndex {
        off: h.off,
        entry_count,
        refs,
    })
}

fn parse_directory_index(h: StdHeader, raw: &[u8]) -> Option<DirectoryIndex> {
    if h.rec_type != TYPE_VOLUME_INDEX || raw.len() < 0x14 {
        return None;
    }
    let count = u32le(raw, 0x10) as usize;
    let end = 0x14usize.checked_add(count.checked_mul(0x10)?)?;
    if end > raw.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for p in (0x14..end).step_by(0x10) {
        entries.push(DirEntry {
            rec_type: u32le(raw, p),
            offset: u64le(raw, p + 8),
        });
    }
    Some(DirectoryIndex {
        off: h.off,
        entries,
    })
}

fn parse_region(h: StdHeader, raw: &[u8]) -> Option<Region> {
    if h.rec_type != TYPE_VOLUME_REGION || raw.len() < 0x30 {
        return None;
    }
    let v = |i: usize| u32le(raw, 0x10 + i * 4);
    let region = Region {
        off: h.off,
        reg_no: v(0),
        block_begin_sector: v(1) as u64 | ((v(2) as u64) << 32),
        total_sectors: v(3) as u64 | ((v(4) as u64) << 32),
        clusters_per_block: v(5),
        sectors_per_cluster: v(6),
        bytes_per_sector: v(7),
    };
    if region.clusters_per_block == 0
        || region.clusters_per_block > 4096
        || region.sectors_per_cluster == 0
        || region.bytes_per_sector < 512
        || region.bytes_per_sector > 4096
    {
        return None;
    }
    Some(region)
}

fn parse_metadata(h: StdHeader, raw: &[u8]) -> Option<Metadata> {
    if h.rec_type != TYPE_VOLUME_METADATA || raw.len() < 0x28 {
        return None;
    }
    Some(Metadata {
        off: h.off,
        bytes_per_sector: u32le(raw, 0x14),
        partition_start_sector: u64le(raw, 0x18),
        partition_total_sectors: u64le(raw, 0x20),
        label: utf16le_z(raw.get(0x34..0xb0).unwrap_or(&[])),
        description: utf16le_z(raw.get(0x12a..0x170).unwrap_or(&[])),
        type_guid: guid(raw, 0x172),
        unique_guid: guid(raw, 0x182),
    })
}

fn parse_mode(h: StdHeader, raw: &[u8]) -> Option<u32> {
    if !matches!(h.rec_type, TYPE_COMPRESS | TYPE_ENCRYPT) || raw.len() < 0x18 {
        return None;
    }
    Some(u32le(raw, 0x14))
}

fn parse_vdb(raw: &[u8], p: usize) -> Option<VdbEntry> {
    if p + VDB_SIZE > raw.len() {
        return None;
    }
    Some(VdbEntry {
        reg_no: u32le(raw, p),
        block_no: u64le(raw, p + 4),
        img_offset: u64le(raw, p + 0x0c),
        old_size: u32le(raw, p + 0x14),
        new_size: u32le(raw, p + 0x18),
        crc: u32le(raw, p + 0x1c),
    })
}

/// Scan the primary member's physical bytes for CRC-valid standard headers.
fn scan_headers(adi: &mut Adi) -> Result<Vec<StdHeader>, String> {
    let end = adi.file_size;
    let mut candidates: Vec<u64> = Vec::new();
    let mut at = 0u64;
    while at < end {
        let want = std::cmp::min((CHUNK + OVERLAP) as u64, end - at) as usize;
        if want <= OVERLAP {
            break;
        }
        let buf = adi.read_at(at, want)?;
        let limit = want - OVERLAP;
        for i in 0..limit {
            let t = u32le(&buf, i);
            if matches!(
                t,
                TYPE_VOLUME_INDEX
                    | TYPE_DATABLOCK_INDEX
                    | TYPE_VOLUME_METADATA
                    | TYPE_COMPRESS
                    | TYPE_ENCRYPT
                    | TYPE_VOLUME_REGION
            ) {
                candidates.push(at + i as u64);
            }
        }
        at += limit as u64;
    }
    let mut out = Vec::new();
    for off in candidates {
        if let Some((h, _)) = load_record(adi, off) {
            out.push(h);
        }
    }
    Ok(out)
}

/// Read VDB entries from a data-block reference using the record-set delta.
/// The table is stored at a *physical* offset (logical + delta), unlike stored
/// block payloads which are read through the image-set member translation.
fn read_vdb_table(adi: &mut Adi, r: &DataBlockRef, delta: i64) -> Result<Vec<VdbEntry>, String> {
    let phys = (r.data_offset as i128 + delta as i128) as u64;
    let want = std::cmp::min(
        r.data_size as usize,
        (r.entry_count as usize).saturating_mul(VDB_SIZE),
    );
    if want != r.entry_count as usize * VDB_SIZE || want & (VDB_SIZE - 1) != 0 {
        debug_warn!("adi2raw: warn: VDB reference at 0x{phys:x}: truncated/misaligned table length; entries may be skipped; verify completeness");
    }
    let raw = adi.read_at(phys, want)?;
    let mut out = Vec::new();
    for p in (0..want).step_by(VDB_SIZE) {
        if let Some(e) = parse_vdb(&raw, p) {
            out.push(e);
        }
    }
    Ok(out)
}

/// Resolve a physical file offset from a logical directory offset plus delta.
fn shifted(offset: u64, delta: i64) -> Option<u64> {
    let v = offset as i128 + delta as i128;
    (v >= 0 && v <= u64::MAX as i128).then_some(v as u64)
}

/// Discover CRC-valid volume record sets. This is the same relationship the
/// independent implementation uses: a 0x201's 0x202 directory entry points at
/// the *end* of the VDB table, and the matching 0x202 header fixes the delta.
fn find_record_sets(adi: &mut Adi) -> Result<Vec<RecordSet>, String> {
    let headers = scan_headers(adi)?;

    let mut data_blocks: Vec<DataBlockIndex> = Vec::new();
    for h in headers
        .iter()
        .filter(|h| h.rec_type == TYPE_DATABLOCK_INDEX)
    {
        if let Some((hh, raw)) = load_record(adi, h.off) {
            if let Some(idx) = parse_data_block_index(hh, &raw) {
                data_blocks.push(idx);
            } else {
                debug_warn!("adi2raw: warn: malformed CRC-valid 0x202 at 0x{:x}; ignored; verify completeness", h.off);
            }
        }
    }
    let mut by_payload_end: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, idx) in data_blocks.iter().enumerate() {
        for r in &idx.refs {
            by_payload_end
                .entry(r.data_offset.saturating_add(r.data_size as u64))
                .or_default()
                .push(i);
        }
    }

    let mut global_compress = None;
    let mut global_encrypt = None;
    for h in &headers {
        if h.rec_type != TYPE_COMPRESS && h.rec_type != TYPE_ENCRYPT {
            continue;
        }
        let Some((hh, raw)) = load_record(adi, h.off) else {
            continue;
        };
        let Some(mode) = parse_mode(hh, &raw) else {
            continue;
        };
        if h.rec_type == TYPE_COMPRESS && global_compress.is_none() {
            global_compress = Some(mode);
        }
        if h.rec_type == TYPE_ENCRYPT && global_encrypt.is_none() {
            global_encrypt = Some(mode);
        }
    }

    let mut sets = Vec::new();
    for h in headers.iter().filter(|h| h.rec_type == TYPE_VOLUME_INDEX) {
        let Some((hh, raw)) = load_record(adi, h.off) else {
            continue;
        };
        let Some(dir) = parse_directory_index(hh, &raw) else {
            debug_warn!(
                "adi2raw: warn: malformed CRC-valid 0x201 at 0x{:x}; ignored; verify completeness",
                h.off
            );
            continue;
        };
        let db_entries: Vec<DirEntry> = dir
            .entries
            .iter()
            .copied()
            .filter(|e| e.rec_type == TYPE_DATABLOCK_INDEX)
            .collect();
        if db_entries.len() != 1 {
            debug_warn!("adi2raw: warn: volume index at 0x{:x}: expected one 0x202 reference, found {}; skipped; output needs verification", h.off, db_entries.len());
            continue;
        }
        let Some(matches) = by_payload_end.get(&db_entries[0].offset) else {
            debug_warn!("adi2raw: warn: volume index at 0x{:x}: no matching 0x202; skipped; output needs verification", h.off);
            continue;
        };
        for &mi in matches {
            let dbi = &data_blocks[mi];
            let delta = dbi.off as i64 - db_entries[0].offset as i64;
            let mut regions = Vec::new();
            let mut metadata = Vec::new();
            let mut compress_mode = None;
            let mut encrypt_mode = None;
            let mut ok = true;
            for e in &dir.entries {
                if e.rec_type == TYPE_DATABLOCK_INDEX {
                    continue;
                }
                let Some(phys) = shifted(e.offset, delta) else {
                    ok = false;
                    break;
                };
                let Some((rh, rraw)) = load_record(adi, phys) else {
                    ok = false;
                    break;
                };
                if rh.rec_type != e.rec_type {
                    ok = false;
                    break;
                }
                match e.rec_type {
                    TYPE_VOLUME_REGION => match parse_region(rh, &rraw) {
                        Some(r) => regions.push(r),
                        None => {
                            ok = false;
                            break;
                        }
                    },
                    TYPE_VOLUME_METADATA => {
                        if let Some(m) = parse_metadata(rh, &rraw) {
                            metadata.push(m);
                        } else { debug_warn!("adi2raw: warn: malformed 0x102 at 0x{:x}; ignored; verify metadata", phys); }
                    }
                    TYPE_COMPRESS => {
                        compress_mode = parse_mode(rh, &rraw);
                        if compress_mode.is_none() { debug_warn!("adi2raw: warn: malformed 0x105 at 0x{:x}; mode unknown; verify output", phys); }
                    }
                    TYPE_ENCRYPT => {
                        encrypt_mode = parse_mode(rh, &rraw);
                        if encrypt_mode.is_none() { debug_warn!("adi2raw: warn: malformed 0x106 at 0x{:x}; mode unknown; verify output", phys); }
                    }
                    _ => debug_warn!("adi2raw: warn: unknown referenced record type 0x{:x} at 0x{:x}; ignored; output needs verification", e.rec_type, phys)
                }
            }
            if !ok || regions.is_empty() {
                debug_warn!("adi2raw: warn: volume index at 0x{:x}: invalid, unreadable or checksum-invalid referenced record, or missing regions; candidate skipped; output needs verification", h.off);
                continue;
            }
            let mut entries = Vec::new();
            for r in &dbi.refs {
                match read_vdb_table(adi, r, delta) {
                    Ok(mut v) => entries.append(&mut v),
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok || entries.is_empty() {
                debug_warn!("adi2raw: warn: volume index at 0x{:x}: invalid or empty VDB table; candidate skipped; output needs verification", h.off);
                continue;
            }
            if compress_mode.is_none() && global_compress.is_some()
                || encrypt_mode.is_none() && global_encrypt.is_some()
            {
                debug_warn!("adi2raw: warn: volume index at 0x{:x}: mode taken from an unassociated global record; verify applicability", h.off);
            }
            if entries.len() != dbi.entry_count as usize {
                debug_warn!("adi2raw: warn: volume index at 0x{:x}: VDB count differs from declared count/capacity; verify completeness", h.off);
            }
            sets.push(RecordSet {
                volume_index_off: dir.off,
                data_block_index_off: dbi.off,
                delta,
                entry_count: dbi.entry_count,
                regions,
                metadata,
                compress_mode: compress_mode.or(global_compress),
                encrypt_mode: encrypt_mode.or(global_encrypt),
                entries,
            });
        }
    }
    Ok(sets)
}

/// Last-resort guess used when the volume's boot sector cannot be read.
fn label_fs(label: &str) -> String {
    let upper = label.to_uppercase();
    if upper.contains("ESP") || upper.contains("EFI") {
        "FAT32".into()
    } else {
        "NTFS".into()
    }
}

/// Decode the block that stores the volume's first cluster and read its boot
/// sector. `None` when that block is absent, undecodable, or does not start with
/// a recognisable boot sector.
fn probe_volume_boot(adi: &mut Adi, blocks: &[StdBlock], volume_start: u64) -> Option<String> {
    let b = blocks
        .iter()
        .filter(|b| b.block_no == 0 && b.base == volume_start)
        .min_by_key(|b| b.off)?;
    if b.cluster == 0 || b.bitmap_len == 0 {
        return None;
    }
    let comp = adi.read_logical(b.off, b.csize as usize).ok()?;
    let data = if b.csize == b.usize {
        comp
    } else {
        Lz4::new().decode_limited(&comp, b.usize as usize).ok()?
    };
    if data.len() != b.usize as usize || data.len() < b.bitmap_len as usize + 512 {
        return None;
    }
    // Cluster 0 has to be present and is stored right after the bitmap.
    if data[0] & 1 == 0 {
        return None;
    }
    let bs = parse_boot_sector(&data[b.bitmap_len as usize..])?;
    if bs.fs.is_empty() {
        None
    } else {
        Some(bs.fs)
    }
}

/// Parse the standard record path. Returns `None` when the image has no
/// CRC-valid volume record sets (synthetic fixtures, older generations).
pub fn parse_standard(adi: &mut Adi) -> Result<Option<StandardImage>, String> {
    let sets = find_record_sets(adi)?;
    if sets.is_empty() {
        return Ok(None);
    }

    let mut blocks = Vec::new();
    let mut volumes = Vec::new();
    let mut skipped_regions = 0u64;
    let mut compress_mode = None;
    let mut encrypt_mode = None;

    for set in &sets {
        compress_mode = compress_mode.or(set.compress_mode);
        encrypt_mode = encrypt_mode.or(set.encrypt_mode);
        if set.compress_mode.is_some_and(|m| m > 1) || set.encrypt_mode.is_some_and(|m| m != 0) {
            debug_warn!("adi2raw: warn: unsupported compression/encryption mode; extraction is not verified/supported for this set");
        }
        let meta = set.metadata.first();
        if set.metadata.len() != 1 {
            debug_warn!("adi2raw: warn: volume index at 0x{:x}: {} metadata records; using first or default LBA 0/512-byte sectors; verify placement", set.volume_index_off, set.metadata.len());
        }
        if meta.is_some_and(|m| !(512..=4096).contains(&m.bytes_per_sector)) {
            debug_warn!(
                "adi2raw: warn: invalid metadata sector size; assuming 512 bytes; verify placement"
            );
        }
        if set.compress_mode.is_none() || set.encrypt_mode.is_none() {
            debug_warn!("adi2raw: warn: volume index at 0x{:x}: missing compression/encryption mode; assuming LZ4 for compressed blocks and no encryption; verify output", set.volume_index_off);
        }
        if compress_mode
            .zip(set.compress_mode)
            .is_some_and(|(a, b)| a != b)
            || encrypt_mode
                .zip(set.encrypt_mode)
                .is_some_and(|(a, b)| a != b)
        {
            debug_warn!("adi2raw: warn: conflicting volume modes; first mode retained; output needs verification");
        }
        let bps = meta
            .map(|m| m.bytes_per_sector)
            .filter(|&b| (512..=4096).contains(&b))
            .unwrap_or(512) as u64;
        if bps != 512 {
            debug_warn!("adi2raw: warn: non-512-byte metadata sectors with 512-byte output GPT addressing; layout needs further verification");
        }
        let part_start = meta.map(|m| m.partition_start_sector).unwrap_or(0);
        let part_sectors = meta.map(|m| m.partition_total_sectors).unwrap_or(0);
        let label = meta.map(|m| m.label.clone()).unwrap_or_default();
        let description = meta.map(|m| m.description.clone()).unwrap_or_default();
        let type_guid = meta.map(|m| m.type_guid).unwrap_or([0; 16]);
        let unique_guid = meta.map(|m| m.unique_guid).unwrap_or([0; 16]);
        if type_guid == [0; 16] || unique_guid == [0; 16] {
            debug_warn!("adi2raw: warn: missing partition GUIDs; GPT uses a label-inferred type and/or generated identity; verify partition metadata");
        }
        let region_end: u64 = set
            .regions
            .iter()
            .map(|r| r.block_begin_sector + r.total_sectors)
            .max()
            .unwrap_or(0);
        if part_sectors < region_end {
            debug_warn!("adi2raw: warn: partition length absent/shorter than region extent; expanding from region geometry; verify partition bounds");
        }
        let sectors = part_sectors.max(region_end).max(1);
        let cluster = set
            .regions
            .first()
            .map(|r| r.cluster() as u32)
            .unwrap_or(512);
        let mut count = 0usize;
        let set_block_start = blocks.len();
        let mut region_map: BTreeMap<u32, Region> = BTreeMap::new();
        for r in &set.regions {
            if region_map.insert(r.reg_no, *r).is_some() {
                debug_warn!(
                    "adi2raw: warn: duplicate region {}; last geometry retained; verify output",
                    r.reg_no
                );
            }
            if r.bytes_per_sector as u64 != bps {
                debug_warn!(
                    "adi2raw: warn: region {} and metadata sector sizes differ; verify placement",
                    r.reg_no
                );
            }
        }
        for e in &set.entries {
            let Some(r) = region_map.get(&e.reg_no) else {
                debug_warn!("adi2raw: warn: VDB entry at logical 0x{:x}, region {}: missing region or invalid sizes; skipped; output needs verification", e.img_offset, e.reg_no);
                skipped_regions += 1;
                continue;
            };
            if e.old_size < r.bitmap_len() || e.new_size == 0 {
                debug_warn!("adi2raw: warn: VDB entry at logical 0x{:x}, region {}: missing region or invalid sizes; skipped; output needs verification", e.img_offset, e.reg_no);
                skipped_regions += 1;
                continue;
            }
            let base = (part_start
                .saturating_add(r.block_begin_sector)
                .saturating_add(e.block_no.saturating_mul(r.sectors_per_region())))
            .saturating_mul(bps);
            blocks.push(StdBlock {
                off: e.img_offset,
                reg_no: e.reg_no,
                block_no: e.block_no,
                usize: e.old_size,
                csize: e.new_size,
                crc: e.crc,
                base,
                cluster: r.cluster() as u32,
                bitmap_len: r.bitmap_len(),
                clusters_per_block: r.clusters_per_block,
                region_remaining: r
                    .total_sectors
                    .saturating_sub(e.block_no.saturating_mul(r.sectors_per_region()))
                    .saturating_mul(bps),
            });
            count += 1;
        }
        let mut region_clusters: Vec<u32> =
            set.regions.iter().map(|r| r.cluster() as u32).collect();
        region_clusters.sort_unstable();
        region_clusters.dedup();
        // The volume's first cluster holds its boot sector, which names the real
        // filesystem. The label heuristic below is only a fallback: it labels any
        // volume NTFS unless the label says ESP/EFI, which is wrong for FAT cards.
        let detected = probe_volume_boot(adi, &blocks[set_block_start..], part_start * bps);
        let (fs, fs_detected) = match detected {
            Some(name) => (name, true),
            None => {
                debug_warn!(
                    "adi2raw: warn: volume at LBA {}: boot sector not recoverable; filesystem '{}' is inferred from the label; verify output",
                    part_start,
                    label_fs(&label)
                );
                (label_fs(&label), false)
            }
        };
        volumes.push(StdVolume {
            label: label.clone(),
            fs,
            fs_detected,
            region_clusters,
            lba: part_start,
            sectors,
            cluster,
            type_guid,
            unique_guid,
            part_name: if label.is_empty() { description } else { label },
            blocks: count,
        });
    }

    let unchecked = blocks.iter().filter(|b| b.crc == 0).count();
    if unchecked != 0 {
        debug_warn!("adi2raw: warn: {unchecked} VDB blocks have no decoded checksum; contents need verification");
    }
    if blocks.is_empty() {
        return Ok(None);
    }
    blocks.sort_by_key(|b| (b.base, b.off));
    let mut covered_end = 0;
    for b in &blocks {
        if b.base < covered_end {
            debug_warn!("adi2raw: warn: overlapping VDB block extents at output 0x{:x}; write precedence needs verification", b.base);
        }
        let span = b
            .region_remaining
            .min(b.clusters_per_block as u64 * b.cluster as u64);
        covered_end = covered_end.max(b.base.saturating_add(span));
    }
    let mut end_sectors = volumes
        .iter()
        .map(|v| v.lba.saturating_add(v.sectors))
        .max()
        .unwrap_or(0);
    for b in &blocks {
        let end = b
            .base
            .saturating_add(b.clusters_per_block as u64 * b.cluster as u64)
            .div_ceil(crate::adi::SECTOR);
        end_sectors = end_sectors.max(end);
    }
    let disk_sectors = end_sectors.saturating_add(34).max(68);

    Ok(Some(StandardImage {
        sets,
        blocks,
        volumes,
        disk_sectors,
        compress_mode,
        encrypt_mode,
        skipped_regions,
    }))
}

pub fn extra_member_paths(var: &str) -> Vec<PathBuf> {
    let Some(raw) = std::env::var_os(var) else {
        return Vec::new();
    };
    raw.to_string_lossy()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(rec_type: u32, body: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; body.len()];
        r[0..4].copy_from_slice(&rec_type.to_le_bytes());
        r[4..8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        r[8..12].copy_from_slice(&[0; 4]);
        r[12..16].copy_from_slice(&123u32.to_le_bytes());
        r[16..].copy_from_slice(&body[16..]);
        let crc = br_crc32(&r);
        r[8..12].copy_from_slice(&crc.to_le_bytes());
        r
    }

    #[test]
    fn standard_header_crc_is_crc32c_with_zeroed_field() {
        let r = record(TYPE_VOLUME_REGION, &[0u8; 0x30]);
        let mut check = r.clone();
        check[8..12].copy_from_slice(&[0; 4]);
        assert_eq!(br_crc32(&check), u32le(&r, 8));
        assert_eq!(u32le(&r, 12), 123);
    }

    #[test]
    fn region_layout_matches_real_sample_values() {
        // Real C: region: 8 clusters x 64 sectors x 512 bytes = 256 KiB.
        let mut body = [0u8; 0x30];
        let values: [u32; 8] = [0, 0, 0, 4096, 0, 8, 64, 512];
        for (i, v) in values.iter().enumerate() {
            body[0x10 + i * 4..0x14 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        let r = record(TYPE_VOLUME_REGION, &body);
        let h = StdHeader {
            off: 0,
            rec_type: TYPE_VOLUME_REGION,
        };
        let reg = parse_region(h, &r).unwrap();
        assert_eq!(reg.reg_no, 0);
        assert_eq!(reg.total_sectors, 4096);
        assert_eq!(reg.clusters_per_block, 8);
        assert_eq!(reg.sectors_per_cluster, 64);
        assert_eq!(reg.bytes_per_sector, 512);
        assert_eq!(reg.cluster(), 32768);
        assert_eq!(reg.bitmap_len(), 1);
        assert_eq!(reg.sectors_per_region(), 512);
    }

    #[test]
    fn vdb_entry_layout() {
        let mut raw = [0u8; 0x20];
        raw[0..4].copy_from_slice(&7u32.to_le_bytes());
        raw[4..12].copy_from_slice(&9u64.to_le_bytes());
        raw[0x0c..0x14].copy_from_slice(&0x1234u64.to_le_bytes());
        raw[0x14..0x18].copy_from_slice(&0x40001u32.to_le_bytes());
        raw[0x18..0x1c].copy_from_slice(&0x1000u32.to_le_bytes());
        raw[0x1c..0x20].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        let e = parse_vdb(&raw, 0).unwrap();
        assert_eq!((e.reg_no, e.block_no, e.img_offset), (7, 9, 0x1234));
        assert_eq!(
            (e.old_size, e.new_size, e.crc),
            (0x40001, 0x1000, 0xdeadbeef)
        );
    }
}
