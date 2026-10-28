// Template: prepare.py appends these adapters to a generated, unmodified source copy.
// Private byte parsers are exercised without a checksum barrier. Production
// headers/file parsing are exercised separately with record CRC repair.
pub fn fuzz_records(data: &[u8]) {
    for kind in [TYPE_VOLUME_INDEX, TYPE_DATABLOCK_INDEX, TYPE_VOLUME_METADATA,
                 TYPE_COMPRESS, TYPE_ENCRYPT, TYPE_VOLUME_REGION] {
        let h = StdHeader { off: 0, rec_type: kind };
        let _ = parse_directory_index(h, data);
        let _ = parse_data_block_index(h, data);
        let _ = parse_metadata(h, data);
        let _ = parse_region(h, data);
        let _ = parse_mode(h, data);
    }
    let _ = parse_vdb(data, 0);
    if data.len() >= 16 {
        let off = u64le(data, 0);
        let delta = u64le(data, 8) as i64;
        let _ = shifted(off, delta);
    }
}
