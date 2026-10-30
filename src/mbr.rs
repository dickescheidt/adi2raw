//! Synthesises a basic DOS/MBR partition table for raw output.
//!
//! The ADI standard records do not preserve the original 16-byte MBR entries,
//! so partition type codes are inferred from the recovered filesystem. This
//! writes no boot code or active/bootable flag.

use crate::adi::{Volume, SECTOR};

const PARTITION_TABLE_OFFSET: usize = 446;
const PARTITION_ENTRY_SIZE: usize = 16;
const PARTITION_COUNT: usize = 4;
const MBR_LIMIT_SECTORS: u64 = u32::MAX as u64 + 1;

fn partition_type(volume: &Volume) -> u8 {
    let fs = volume.fs.to_ascii_uppercase();
    let label = volume.label.to_ascii_uppercase();
    if fs.starts_with("FAT") && (label.contains("ESP") || label.contains("EFI")) {
        0xEF // EFI system partition
    } else if fs == "FAT12" {
        0x01
    } else if fs == "FAT16" {
        0x0E // FAT16 with LBA
    } else if fs.starts_with("FAT") {
        0x0C // FAT32 with LBA (also the fallback for generic FAT)
    } else {
        0x07 // NTFS/exFAT and generic Microsoft data fallback
    }
}

/// Create a 512-byte MBR sector. GPT-only metadata (disk signature, boot code,
/// active flags, and original MBR type bytes) is not available in standard ADI
/// records and is therefore left zero or inferred.
pub fn build(disk_sectors: u64, volumes: &[Volume]) -> Result<Vec<u8>, String> {
    if disk_sectors == 0 || disk_sectors > MBR_LIMIT_SECTORS {
        return Err(format!(
            "MBR output cannot address a {disk_sectors}-sector disk (limit is 2^32 512-byte sectors)"
        ));
    }

    let live: Vec<&Volume> = volumes.iter().filter(|v| v.sectors != 0).collect();
    if live.len() > PARTITION_COUNT {
        return Err(format!(
            "MBR supports at most four primary partitions; image has {} non-empty volumes",
            live.len()
        ));
    }

    let mut sector = vec![0u8; SECTOR as usize];
    for (i, volume) in live.into_iter().enumerate() {
        let end = volume
            .lba
            .checked_add(volume.sectors)
            .ok_or_else(|| format!("partition {i} LBA range overflows"))?;
        if volume.lba == 0 || end > MBR_LIMIT_SECTORS || end > disk_sectors {
            return Err(format!(
                "partition {i} at LBA {} for {} sectors is outside the disk or MBR addressable range",
                volume.lba, volume.sectors
            ));
        }
        let start = u32::try_from(volume.lba)
            .map_err(|_| format!("partition {i} start LBA does not fit MBR"))?;
        let count = u32::try_from(volume.sectors)
            .map_err(|_| format!("partition {i} size does not fit MBR"))?;

        let at = PARTITION_TABLE_OFFSET + i * PARTITION_ENTRY_SIZE;
        // CHS fields are saturated: LBA fields are authoritative on modern disks.
        sector[at] = 0; // not marked active; source active flags are unavailable
        sector[at + 1..at + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        sector[at + 4] = partition_type(volume);
        sector[at + 5..at + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        sector[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
        sector[at + 12..at + 16].copy_from_slice(&count.to_le_bytes());
    }

    sector[510..512].copy_from_slice(&[0x55, 0xAA]);
    Ok(sector)
}

#[cfg(test)]
mod tests {
    use super::build;
    use crate::adi::Volume;

    fn volume(lba: u64, sectors: u64, fs: &str, label: &str) -> Volume {
        Volume {
            first: 0,
            last: 0,
            fs: fs.into(),
            label: label.into(),
            cluster: 4096,
            data_base: 0,
            lba,
            sectors,
            stored: 0,
            max_region: 0,
            type_guid: [0; 16],
            unique_guid: [0; 16],
            part_name: String::new(),
        }
    }

    #[test]
    fn writes_partition_entry_and_signature() {
        let mbr = build(10_000, &[volume(2048, 4096, "NTFS", "DATA")]).unwrap();
        assert_eq!(&mbr[446..450], &[0, 0xFE, 0xFF, 0xFF]);
        assert_eq!(mbr[450], 0x07);
        assert_eq!(&mbr[451..454], &[0xFE, 0xFF, 0xFF]);
        assert_eq!(u32::from_le_bytes(mbr[454..458].try_into().unwrap()), 2048);
        assert_eq!(u32::from_le_bytes(mbr[458..462].try_into().unwrap()), 4096);
        assert_eq!(&mbr[510..512], &[0x55, 0xAA]);
    }

    #[test]
    fn infers_fat_esp_type() {
        let mbr = build(10_000, &[volume(2048, 4096, "FAT32", "EFI")]).unwrap();
        assert_eq!(mbr[450], 0xEF);
    }

    #[test]
    fn rejects_unrepresentable_layouts() {
        assert!(build(1u64 << 32, &[]).is_ok());
        assert!(build((1u64 << 32) + 1, &[]).is_err());
        assert!(build(10_000, &[volume(0, 100, "NTFS", "")]).is_err());
        assert!(build(10_000, &[volume(9_999, 2, "NTFS", "")]).is_err());
        assert!(build(
            10_000,
            &[
                volume(1, 100, "NTFS", "1"),
                volume(101, 100, "NTFS", "2"),
                volume(201, 100, "NTFS", "3"),
                volume(301, 100, "NTFS", "4"),
                volume(401, 100, "NTFS", "5"),
            ]
        )
        .is_err());
    }
}
