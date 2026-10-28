//! Minimal reader for AOMEI Backupper `.adi` disk images.
//!
//! The format is proprietary and undocumented; this is a best-effort read of
//! the BIFH/BIFT framing, the signature-scanned block index, the LZ4-flavoured
//! blocks and the used-sector bitmaps.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::lz4::Lz4;

pub const REGION: u64 = 256 * 1024;
pub const SECTOR: u64 = 512;

type Result<T> = std::result::Result<T, String>;

fn u16le(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}
fn u32le(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}
fn u64le(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .unwrap_or(0)
}

fn utf16le_z(b: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let cp = u16::from_le_bytes([b[i], b[i + 1]]);
        i += 2;
        if cp == 0 {
            break;
        }
        out.push(char::from_u32(cp as u32).unwrap_or('?'));
    }
    out
}

fn guid_str(g: &[u8; 16]) -> String {
    format!(
        "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11],
        g[12], g[13], g[14], g[15]
    )
}

fn ascii(b: &[u8]) -> String {
    let mut s: String = b
        .iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                ' '
            }
        })
        .collect();
    while s.ends_with(' ') {
        s.pop();
    }
    s
}

// ---------------------------------------------------------------------------
// Container header / footer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Header {
    pub size: u32,
    pub checksum: u32,
    pub guid_a: [u8; 16],
    pub guid_b: [u8; 16],
    pub comment: String,
    pub filename: String,
}

#[derive(Clone)]
pub struct Footer {
    pub checksum: u32,
    pub size: u32,
    pub offset_a: u64,
    pub offset_b: u64,
    pub field_a: u32,
    pub field_b: u32,
    pub guid_a: [u8; 16],
    pub guid_b: [u8; 16],
    pub comment: String,
    pub filename: String,
}

pub struct Adi {
    file: File,
    pub path: String,
    pub file_size: u64,
    pub header: Header,
    pub footer: Footer,
}

impl Adi {
    pub fn open(path: &Path) -> Result<Self> {
        let mut file =
            File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        let file_size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| format!("seek: {e}"))?;
        if file_size < 32 {
            return Err("file too small to be an AOMEI .adi image".into());
        }

        let mut head16 = [0u8; 16];
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        file.read_exact(&mut head16).map_err(|e| e.to_string())?;
        if &head16[0..4] != b"BIFH" {
            return Err("not an AOMEI Backupper image (missing BIFH)".into());
        }
        let hsize = u32le(&head16, 4);
        let hchecksum = u32le(&head16, 8);
        if !(0x40..=1024 * 1024).contains(&hsize) || hsize as u64 > file_size {
            return Err(format!("implausible BIFH size {hsize}"));
        }
        let mut hdr = vec![0u8; hsize as usize];
        file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        file.read_exact(&mut hdr).map_err(|e| e.to_string())?;
        let mut guid_a = [0u8; 16];
        let mut guid_b = [0u8; 16];
        guid_a.copy_from_slice(&hdr[0x10..0x20]);
        guid_b.copy_from_slice(&hdr[0x20..0x30]);
        let comment = if hsize as usize > 0x44 {
            utf16le_z(&hdr[0x44..])
        } else {
            String::new()
        };
        let filename = if hsize as usize > 0x454 {
            utf16le_z(&hdr[0x454..])
        } else {
            String::new()
        };
        let header = Header {
            size: hsize,
            checksum: hchecksum,
            guid_a,
            guid_b,
            comment,
            filename,
        };

        let mut tail = [0u8; 16];
        file.seek(SeekFrom::Start(file_size - 16))
            .map_err(|e| e.to_string())?;
        file.read_exact(&mut tail).map_err(|e| e.to_string())?;
        if &tail[12..16] != b"BIFT" {
            return Err("missing BIFT footer (file truncated?)".into());
        }
        let mut fsize = u32le(&tail, 8);
        let checksum = u32le(&tail, 4);
        if fsize < 16 || fsize as u64 > file_size {
            fsize = 16;
        }
        let mut blob = vec![0u8; fsize as usize];
        file.seek(SeekFrom::Start(file_size - fsize as u64))
            .map_err(|e| e.to_string())?;
        file.read_exact(&mut blob).map_err(|e| e.to_string())?;
        let mut footer = Footer {
            checksum,
            size: fsize,
            offset_a: 0,
            offset_b: 0,
            field_a: 0,
            field_b: 0,
            guid_a: [0u8; 16],
            guid_b: [0u8; 16],
            comment: String::new(),
            filename: String::new(),
        };
        if blob.len() >= 92 {
            let e = blob.len() - 92;
            footer.offset_a = u64le(&blob, e);
            footer.offset_b = u64le(&blob, e + 8);
            footer.field_a = u32le(&blob, e + 24);
            footer.field_b = u32le(&blob, e + 28);
            footer.guid_b.copy_from_slice(&blob[e + 44..e + 60]);
            footer.guid_a.copy_from_slice(&blob[e + 60..e + 76]);
        }
        footer.filename = utf16le_z(&blob);
        if blob.len() > 0x410 {
            footer.comment = utf16le_z(&blob[0x410..]);
        }

        Ok(Self {
            file,
            path: path.display().to_string(),
            file_size,
            header,
            footer,
        })
    }

    pub fn payload_offset(&self) -> u64 {
        self.header.size as u64
    }

    pub fn payload_end(&self) -> u64 {
        if self.footer.size > 0 && (self.footer.size as u64) < self.file_size {
            self.file_size - self.footer.size as u64
        } else {
            self.file_size.saturating_sub(16)
        }
    }

    pub fn read_at(&mut self, off: u64, len: usize) -> Result<Vec<u8>> {
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("seek {off}: {e}"))?;
        let mut buf = vec![0u8; len];
        self.file
            .read_exact(&mut buf)
            .map_err(|e| format!("read {off}+{len}: {e}"))?;
        Ok(buf)
    }

    pub fn print_info(&self) {
        println!("file:     {}", self.path);
        println!(
            "size:     {} bytes ({:.2} GiB)",
            self.file_size,
            self.file_size as f64 / 1024.0 / 1024.0 / 1024.0
        );
        println!("\n[BIFH header]");
        println!("  magic:     BIFH");
        println!(
            "  size:      {} (0x{:x})",
            self.header.size, self.header.size
        );
        println!("  checksum:  0x{:x}", self.header.checksum);
        println!("  guid A:    {}", guid_str(&self.header.guid_a));
        println!("  guid B:    {}", guid_str(&self.header.guid_b));
        println!("  comment:   {}", self.header.comment);
        println!("  filename:  {}", self.header.filename);
        println!("  payload:   offset 0x{:x}", self.payload_offset());
        println!("\n[BIFT footer]");
        println!("  magic:     BIFT");
        println!(
            "  size:      {} (0x{:x})",
            self.footer.size, self.footer.size
        );
        println!("  checksum:  0x{:x}", self.footer.checksum);
        println!("  offset A:  0x{:x}", self.footer.offset_a);
        println!("  offset B:  0x{:x}", self.footer.offset_b);
        println!("  field A:   {}", self.footer.field_a);
        println!("  field B:   {}", self.footer.field_b);
        println!("  guid A:    {}", guid_str(&self.footer.guid_a));
        println!("  guid B:    {}", guid_str(&self.footer.guid_b));
        println!("  comment:   {}", self.footer.comment);
        println!("  filename:  {}", self.footer.filename);
    }
}

// ---------------------------------------------------------------------------
// Block index
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BlockRec {
    pub off: u64,
    pub usize: u32,
    pub csize: u32,
    pub crc: u32,
    pub stream: u32,
    /// Region after `resolve_regions()` rewrote it.
    pub region: u32,
    /// Region exactly as stored in the 32-byte index record (diagnostics).
    pub raw_region: u32,
}

impl BlockRec {
    pub fn end(&self) -> u64 {
        self.off + self.csize as u64
    }

    /// `crc` is `Encrypt.dll!BRCrc32` over the *decoded* `usize` bytes. A zero
    /// field means the writer left no checksum (our own fixtures do this); we
    /// cannot distinguish that from a real zero CRC, so skip those records.
    pub fn crc_ok(&self, data: &[u8]) -> bool {
        self.crc == 0 || crate::crc::br_crc32(data) == self.crc
    }
}

fn parse_rec(p: &[u8]) -> BlockRec {
    BlockRec {
        off: u64le(p, 0),
        usize: u32le(p, 8),
        csize: u32le(p, 12),
        crc: u32le(p, 16),
        stream: u32le(p, 20),
        region: u32le(p, 24),
        raw_region: u32le(p, 24),
    }
}

fn plausible(p: &[u8], span: u64) -> bool {
    if p.len() < 32 || u32le(p, 28) != 0 {
        return false;
    }
    let usize_ = u32le(p, 8);
    let csize = u32le(p, 12);
    if !(0x20..=(1 << 20)).contains(&usize_) {
        return false;
    }
    if !(0x10..=(16 << 20)).contains(&csize) {
        return false;
    }
    if u32le(p, 20) > 0xffff {
        return false;
    }
    u64le(p, 0) < span
}

/// Scan the payload for the 32-byte block-index records. Records are found by
/// signature, not by a fixed offset — the format has no reliable index pointer.
pub fn scan_block_index(adi: &mut Adi) -> Result<Vec<BlockRec>> {
    const CHUNK: usize = 4 * 1024 * 1024;
    const OVER: usize = 64;

    let start = adi.payload_offset();
    let end = adi.payload_end();
    if end <= start {
        return Ok(Vec::new());
    }
    let span = end - start;
    let mut found: BTreeMap<u64, BlockRec> = BTreeMap::new();
    let mut at = start;
    while at < end {
        let want = std::cmp::min((CHUNK + OVER) as u64, end - at) as usize;
        if want <= OVER {
            break;
        }
        let buf = adi.read_at(at, want)?;
        let limit = want - OVER;
        for i in 0..limit {
            let p = &buf[i..];
            if !plausible(p, span) {
                continue;
            }
            let q = &buf[i + 32..];
            if !plausible(q, span) {
                continue;
            }
            let a = parse_rec(p);
            let b = parse_rec(q);
            if a.end() != b.off {
                continue;
            }
            found.entry(a.off).or_insert(a);
            found.entry(b.off).or_insert(b);
        }
        at += limit as u64;
    }

    let mut out = Vec::new();
    let mut chain_end = 0u64;
    for (_, rec) in found {
        if rec.off < chain_end {
            continue;
        }
        chain_end = rec.end();
        out.push(rec);
    }
    resolve_regions(&mut out);
    Ok(out)
}

/// The 32-byte window we find by signature is a real VDB index entry read 12
/// bytes late: its `RegNo`/`BlockNo` fields describe the *next* block, not the
/// one at `off`. So block i's region/stream is the stored value from record
/// i-1, and the very first block has no predecessor.
///
/// The old code split the chain at gaps and then invented the "lowest free"
/// region number for every run head. On a real multi-volume image those heads
/// start at high block numbers, so inventing 0 made the resolved region list
/// jump backwards by gigabytes — which is what produced the bogus
/// "image blocks are too far out of disk order to stream" error. A single
/// global shift has no such discontinuity.
fn resolve_regions(blocks: &mut [BlockRec]) {
    let raw_stream: Vec<u32> = blocks.iter().map(|b| b.stream).collect();
    let raw_region: Vec<u32> = blocks.iter().map(|b| b.region).collect();
    for (i, b) in blocks.iter_mut().enumerate() {
        if i == 0 {
            b.stream = 0;
            b.region = 0;
        } else {
            b.stream = raw_stream[i - 1];
            b.region = raw_region[i - 1];
        }
    }
}

// ---------------------------------------------------------------------------
// Decoded block layout
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Layout {
    pub hdr: u32,
    pub cluster: u32,
    pub units: u32,
    /// `usize == 1 + REGION`: the bitmap is a single "all present" marker byte,
    /// not a real 1-byte bitmap. A genuine 1-byte bitmap (32 KiB clusters or a
    /// 0x109 `ClusPerBlock` of 8) must still be read bit by bit.
    pub all_present: bool,
}

/// A decompressed block is a used-sector bitmap followed by only the clusters
/// whose bits are set. `usize == 1 + REGION` is the "all present" shorthand.
pub fn split_block(data: &[u8], usize_: u32, hint: u32) -> Option<Layout> {
    if data.len() != usize_ as usize {
        return None;
    }
    if usize_ as u64 == 1 + REGION {
        let cluster = if hint != 0 { hint } else { 512 };
        return Some(Layout {
            hdr: 1,
            cluster,
            units: (REGION / cluster as u64) as u32,
            all_present: true,
        });
    }
    // Real images use 32 KiB clusters for sparse C: regions (2 MiB / 64
    // sectors per cluster). Cover the whole power-of-two range up to 64 KiB so
    // a 0x109 geometry hint of 32768 or 65536 is never silently dropped.
    for cluster in [512u32, 1024, 2048, 4096, 8192, 16384, 32768, 65536] {
        if hint != 0 && cluster != hint {
            continue;
        }
        let clusters_per_region = REGION / cluster as u64;
        let hdr = clusters_per_region.div_ceil(8) as usize;
        if hdr == 0 || hdr > data.len() {
            continue;
        }
        let mut pop: u32 = data[..hdr].iter().map(|b| b.count_ones()).sum();
        let spare_bits = (hdr as u64 * 8 - clusters_per_region).min(7);
        if spare_bits > 0 {
            let last = data[hdr - 1] & (0xffu8 >> spare_bits);
            pop = pop - data[hdr - 1].count_ones() + last.count_ones();
        }
        if usize_ == hdr as u32 + pop * cluster {
            return Some(Layout {
                hdr: hdr as u32,
                cluster,
                units: pop,
                all_present: false,
            });
        }
    }
    None
}

pub fn unit_present(data: &[u8], lay: &Layout, u: u32) -> bool {
    if lay.all_present {
        return true;
    }
    let idx = (u >> 3) as usize;
    data.get(idx)
        .map(|b| b & (1u8 << (u & 7)) != 0)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Boot sectors and volume map
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BootSector {
    pub fs: String,
    pub label: String,
    pub cluster: u32,
    pub hidden: u64,
    pub total_sectors: u64,
    pub data_start: u64,
}

pub fn parse_boot_sector(p: &[u8]) -> Option<BootSector> {
    if p.len() < 512 || (p[0] != 0xeb && p[0] != 0xe9) || u16le(p, 510) != 0xaa55 {
        return None;
    }
    let bps = u16le(p, 11) as u32;
    if ![512u32, 1024, 2048, 4096].contains(&bps) {
        return None;
    }
    let spc = p[13] as u32;
    if spc == 0 || spc > 128 || spc & (spc - 1) != 0 {
        return None;
    }
    let mut bs = BootSector {
        fs: String::new(),
        label: ascii(&p[3..11]),
        cluster: bps * spc,
        hidden: u32le(p, 28) as u64,
        total_sectors: 0,
        data_start: 0,
    };
    if &p[3..11] == b"NTFS    " {
        bs.fs = "NTFS".into();
        bs.total_sectors = u64le(p, 40);
        return Some(bs);
    }
    if &p[3..11] == b"-FVE-FS-" {
        bs.fs = "BitLocker".into();
        bs.total_sectors = u64le(p, 40);
        return Some(bs);
    }
    let reserved = u16le(p, 14) as u64;
    let fats = p[16] as u64;
    let root_entries = u16le(p, 17) as u64;
    let fat32 = u16le(p, 22) == 0;
    let fat_sectors = if fat32 {
        u32le(p, 36) as u64
    } else {
        u16le(p, 22) as u64
    };
    if reserved != 0 && fats != 0 && fat_sectors != 0 {
        bs.data_start = (reserved + fats * fat_sectors) * bps as u64 + root_entries * 32;
    }
    if fat32 && p.len() >= 90 && &p[82..90] == b"FAT32   " {
        bs.fs = "FAT32".into();
        bs.total_sectors = if u16le(p, 19) != 0 {
            u16le(p, 19) as u64
        } else {
            u32le(p, 32) as u64
        };
        bs.label = ascii(&p[71..82]);
        return Some(bs);
    }
    if p.len() >= 62
        && (&p[54..62] == b"FAT16   " || &p[54..62] == b"FAT12   " || &p[54..62] == b"FAT     ")
    {
        bs.fs = ascii(&p[54..62]);
        bs.total_sectors = if u16le(p, 19) != 0 {
            u16le(p, 19) as u64
        } else {
            u32le(p, 32) as u64
        };
        bs.label = ascii(&p[43..54]);
        return Some(bs);
    }
    if &p[3..11] == b"EXFAT   " {
        bs.fs = "exFAT".into();
        return Some(bs);
    }
    None
}

#[derive(Clone)]
pub struct Volume {
    pub first: usize,
    pub last: usize,
    pub fs: String,
    pub label: String,
    pub cluster: u32,
    pub data_base: u64,
    pub lba: u64,
    pub sectors: u64,
    pub stored: u64,
    pub max_region: u32,
}

// ---------------------------------------------------------------------------
// Whole-stream boot-sector scan
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BootHit {
    pub stream_off: u64,
    pub lba: u64,
    pub sectors: u64,
    pub cluster: u32,
    pub fs: String,
    pub label: String,
}

struct BootScan {
    hits: Vec<BootHit>,
    region0_has_mbr: bool,
    crc_checked: u64,
    crc_bad: u64,
}

/// AOMEI normally writes a multi-partition disk as one contiguous block chain.
/// Grouping volumes by gaps in that chain therefore finds only the first
/// partition. Walk the whole decompressed stream instead: every volume boot
/// record carries its own partition start in `hidden_sectors`.
fn scan_boot_sectors(adi: &mut Adi, blocks: &[BlockRec]) -> Result<BootScan> {
    let mut out = BootScan {
        hits: Vec::new(),
        region0_has_mbr: false,
        crc_checked: 0,
        crc_bad: 0,
    };
    let mut dec = Lz4::new();
    let mut seen = BTreeSet::new();
    for (i, b) in blocks.iter().enumerate() {
        if i == 0 || blocks[i - 1].end() != b.off {
            dec.reset();
        }
        let comp = adi.read_at(adi.payload_offset() + b.off, b.csize as usize)?;
        let data = match dec.decode(&comp) {
            Ok(d) if d.len() == b.usize as usize => d,
            _ => continue,
        };
        if b.crc != 0 {
            out.crc_checked += 1;
            if !b.crc_ok(&data) {
                out.crc_bad += 1;
                continue;
            }
        }
        let lay = match split_block(&data, b.usize, 0) {
            Some(l) if l.units != 0 && l.cluster >= 512 => l,
            _ => continue,
        };
        let mut slot = 0usize;
        for u in 0..(REGION / lay.cluster as u64) as u32 {
            if slot >= lay.units as usize || !unit_present(&data, &lay, u) {
                continue;
            }
            let src = lay.hdr as usize + slot * lay.cluster as usize;
            slot += 1;
            if src + lay.cluster as usize > data.len() {
                break;
            }
            let cd = &data[src..src + lay.cluster as usize];
            let stream_off = b.region as u64 * REGION + u as u64 * lay.cluster as u64;
            if b.region == 0
                && u == 0
                && cd[510] == 0x55
                && cd[511] == 0xAA
                && (cd.get(450) == Some(&0xEE)
                    || (cd.len() >= 1024 && &cd[512..520] == b"EFI PART"))
            {
                out.region0_has_mbr = true;
            }
            if let Some(bs) = parse_boot_sector(&cd[..512]) {
                if bs.hidden != 0 && seen.insert(bs.hidden) {
                    out.hits.push(BootHit {
                        stream_off,
                        lba: bs.hidden,
                        sectors: bs.total_sectors + if bs.fs == "NTFS" { 1 } else { 0 },
                        cluster: bs.cluster,
                        fs: bs.fs,
                        label: bs.label,
                    });
                }
            }
        }
    }
    out.hits.sort_by_key(|h| h.stream_off);
    Ok(out)
}

pub struct SectorMap {
    pub disk_sectors: u64,
    pub volumes: Vec<Volume>,
    /// Decompressed stream is a whole-disk coordinate space shifted by origin.
    pub passthrough: bool,
    pub origin: u64,
    /// The stream already carries an MBR/GPT at LBA 0; do not synthesise one.
    pub native_table: bool,
    /// Blocks whose VDB entry carried a CRC32C that was checked while mapping.
    pub crc_checked: u64,
    pub crc_bad: u64,
}

fn volume_ranges(blocks: &[BlockRec]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..blocks.len() {
        if i == 0 || blocks[i - 1].end() != blocks[i].off {
            out.push((i, i));
        } else {
            out.last_mut().unwrap().1 = i;
        }
    }
    out
}

/// Derive the volume map. Prefer a whole-stream boot-sector scan; fall back
/// to grouping index runs into volumes when the boot sectors disagree.
pub fn discover_map(adi: &mut Adi, blocks: &[BlockRec]) -> Result<SectorMap> {
    let max_region = blocks.iter().map(|b| b.region).max().unwrap_or(0);
    let stream_span = (max_region as u64 + 1) * REGION;
    let scan = scan_boot_sectors(adi, blocks)?;
    let force_legacy = std::env::var("ADI2RAW_LEGACY_MAP").is_ok();

    // A boot sector's hidden_sectors is its absolute LBA. If every boot sector
    // agrees on (LBA * 512 - stream offset), the decompressed stream is a
    // whole-disk coordinate space shifted by one constant.
    let delta = scan
        .hits
        .first()
        .map(|h| h.lba as i128 * SECTOR as i128 - h.stream_off as i128);
    let consistent = !force_legacy
        && delta.is_some_and(|d| {
            d >= 0
                && scan
                    .hits
                    .iter()
                    .all(|h| h.lba as i128 * SECTOR as i128 - h.stream_off as i128 == d)
        });

    eprintln!("adi2raw: boot sectors: {}", scan.hits.len());
    for h in &scan.hits {
        eprintln!(
            "adi2raw:   LBA {} (byte {}) at stream {} -> origin {}  {} {} sectors",
            h.lba,
            h.lba * SECTOR,
            h.stream_off,
            h.lba as i128 * SECTOR as i128 - h.stream_off as i128,
            if h.fs.is_empty() {
                "raw"
            } else {
                h.fs.as_str()
            },
            h.sectors
        );
    }

    if consistent {
        let origin = delta.unwrap_or(0) as u64;
        let native_table = origin == 0 && scan.region0_has_mbr;
        eprintln!(
            "adi2raw: layout: whole-disk stream (origin {origin} bytes){}",
            if native_table {
                ", native partition table preserved"
            } else {
                ""
            }
        );
        let mut by_lba = scan.hits.clone();
        by_lba.sort_by_key(|h| h.lba);
        let end_lba = (origin + stream_span).div_ceil(SECTOR);
        let mut volumes: Vec<Volume> = by_lba
            .iter()
            .map(|h| Volume {
                first: 0,
                last: blocks.len().saturating_sub(1),
                fs: h.fs.clone(),
                label: h.label.clone(),
                cluster: if h.cluster == 0 { 512 } else { h.cluster },
                data_base: 0,
                lba: h.lba,
                sectors: h.sectors,
                stored: 0,
                max_region,
            })
            .collect();
        for i in 0..volumes.len() {
            if volumes[i].sectors != 0 {
                continue;
            }
            let end = if i + 1 < volumes.len() {
                volumes[i + 1].lba
            } else {
                end_lba
            };
            if end > volumes[i].lba {
                volumes[i].sectors = end - volumes[i].lba;
            }
        }
        let volume_end = volumes.iter().map(|v| v.lba + v.sectors).max().unwrap_or(0);
        let disk_sectors = volume_end.max(end_lba) + 34;
        return Ok(SectorMap {
            disk_sectors,
            volumes,
            passthrough: true,
            origin,
            native_table,
            crc_checked: scan.crc_checked,
            crc_bad: scan.crc_bad,
        });
    }

    eprintln!(
        "adi2raw: layout: legacy volume runs{}",
        if force_legacy {
            " (forced by ADI2RAW_LEGACY_MAP)"
        } else if scan.hits.is_empty() {
            " (no boot sectors found)"
        } else {
            " (boot-sector origins disagree; falling back to index-run volumes)"
        }
    );

    // --- fallback: one volume per gap in the compressed block chain ---
    let mut volumes = Vec::new();
    for (first, last) in volume_ranges(blocks) {
        let mut v = Volume {
            first,
            last,
            fs: String::new(),
            label: String::new(),
            cluster: 0,
            data_base: 0,
            lba: 0,
            sectors: 0,
            stored: blocks[first..=last].iter().map(|b| b.usize as u64).sum(),
            max_region: blocks[first..=last]
                .iter()
                .map(|b| b.region)
                .max()
                .unwrap_or(0),
        };
        let mut dec = Lz4::new();
        let mut probe_cluster = 0u32;
        let stop = std::cmp::min(last + 1, first + 512);
        for b in &blocks[first..stop] {
            let comp = adi.read_at(adi.payload_offset() + b.off, b.csize as usize)?;
            let data = dec.decode(&comp).unwrap_or_default();
            if data.len() != b.usize as usize || !b.crc_ok(&data) {
                continue;
            }
            let lay = match split_block(&data, b.usize, probe_cluster) {
                Some(l) => l,
                None => continue,
            };
            if probe_cluster == 0 && lay.hdr != 1 {
                probe_cluster = lay.cluster;
            }
            if b.region != 0 || lay.units == 0 || !unit_present(&data, &lay, 0) {
                continue;
            }
            let off = lay.hdr as usize;
            let len = lay.cluster as usize;
            if data.len() < off + len {
                continue;
            }
            if let Some(bs) = parse_boot_sector(&data[off..off + len]) {
                v.fs = bs.fs.clone();
                v.label = bs.label;
                v.cluster = bs.cluster;
                v.data_base = if b.stream == 0 { 0 } else { bs.data_start };
                v.lba = bs.hidden;
                v.sectors = bs.total_sectors + if v.fs == "NTFS" { 1 } else { 0 };
                break;
            }
        }
        if v.fs.is_empty() {
            v.fs = "raw".into();
            v.cluster = if probe_cluster != 0 {
                probe_cluster
            } else {
                512
            };
        }
        volumes.push(v);
    }

    for i in 1..volumes.len() {
        if volumes[i].lba == 0 {
            volumes[i].lba = volumes[i - 1].lba + volumes[i - 1].sectors;
        }
    }
    for i in 0..volumes.len() {
        if volumes[i].sectors != 0 {
            continue;
        }
        let span = (volumes[i].max_region as u64 + 1) * REGION / SECTOR;
        volumes[i].sectors = span;
        if i + 1 < volumes.len() && volumes[i + 1].lba > volumes[i].lba {
            volumes[i].sectors = volumes[i + 1].lba - volumes[i].lba;
        }
    }
    let disk_sectors = volumes
        .iter()
        .map(|v| v.lba + v.sectors + 34)
        .max()
        .unwrap_or(0);
    Ok(SectorMap {
        disk_sectors,
        volumes,
        passthrough: false,
        origin: 0,
        native_table: false,
        crc_checked: scan.crc_checked,
        crc_bad: scan.crc_bad,
    })
}

/// Where a block's units land, mirroring `reconstruct_image()` in image.cpp.
pub fn block_base(vol: &Volume, b: &BlockRec) -> u64 {
    vol.lba * SECTOR + if b.stream == 0 { vol.data_base } else { 0 } + b.region as u64 * REGION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_regions_is_one_global_shift() {
        // Three chain runs of two blocks, raw regions strictly increasing.
        // The old "lowest free region at each run head" logic produced
        // [0, 100000, 0, 100002, 0, 100004] from this perfectly ordered index.
        let mut blocks: Vec<BlockRec> = (0..6)
            .map(|i| BlockRec {
                off: 4096 * i + (i / 2) * 128,
                usize: 4096,
                csize: 4096,
                crc: 0,
                stream: 0,
                region: 100_000 + i as u32,
                raw_region: 100_000 + i as u32,
            })
            .collect();
        resolve_regions(&mut blocks);
        assert_eq!(blocks[0].region, 0);
        for i in 1..blocks.len() {
            assert_eq!(blocks[i].region, 100_000 + (i - 1) as u32);
            assert!(blocks[i].region > blocks[i - 1].region);
        }
    }

    #[test]
    fn split_block_handles_32k_sparse_bitmap() {
        let mut data = vec![0x5Au8; 1 + 3 * 32768];
        data[0] = 0x49; // bits 0, 3, 6
        let lay = split_block(&data, data.len() as u32, 32768).unwrap();
        assert_eq!((lay.hdr, lay.cluster, lay.units), (1, 32768, 3));
        assert!(!lay.all_present);
        assert!(unit_present(&data, &lay, 0));
        assert!(!unit_present(&data, &lay, 1));
        assert!(unit_present(&data, &lay, 3));
        assert!(unit_present(&data, &lay, 6));
        assert!(!unit_present(&data, &lay, 7));

        // The all-present shorthand is a different case, not a real bitmap.
        let mut all = vec![0x11u8; 1 + REGION as usize];
        all[0] = 1;
        let lay = split_block(&all, all.len() as u32, 0).unwrap();
        assert!(lay.all_present);
        assert!(unit_present(&all, &lay, 7));
    }
}
