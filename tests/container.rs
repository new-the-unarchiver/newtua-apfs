//! NXSB container-superblock decode validated against a REAL self-minted APFS
//! container (Tier 2). Field values are cross-checked against `diskutil info`
//! (container UUID, block size) and the documented `hdiutil` construction
//! (magic NXSB, 4096-byte blocks). See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::container::{NxSuperblock, NX_MAGIC};
use apfs_core::ApfsError;

const HEAD: &[u8] = include_bytes!("../../tests/data/apfs_nxsb_head.bin");
const BLOCK_SIZE: usize = 4096;

fn block(n: usize) -> &'static [u8] {
    &HEAD[n * BLOCK_SIZE..(n + 1) * BLOCK_SIZE]
}

#[test]
fn nxsb_magic_constant_is_nxsb_little_endian() {
    // 'BSXN' four-char code, "NXSB" in a hex dump, LE u32 0x4253584E.
    assert_eq!(NX_MAGIC, 0x4253_584E);
    assert_eq!(&NX_MAGIC.to_le_bytes(), b"NXSB");
}

#[test]
fn parse_decodes_real_container_geometry() {
    let nx = NxSuperblock::parse(block(0)).expect("parse NXSB block 0");
    // Verified from the raw bytes + cross-checked against diskutil info:
    assert_eq!(nx.block_size, 4096); // diskutil "Device Block Size: 4096"
    assert_eq!(nx.block_count, 32758);
    assert_eq!(nx.xid, 2);
    assert_eq!(nx.omap_oid, 343);
    assert_eq!(nx.fs_oids, vec![1026]); // max_file_systems == 1
                                        // Container UUID echoed verbatim by `diskutil info` as
                                        // 40115033-9523-4496-96A2-0EDADEECA565.
    assert_eq!(
        nx.uuid,
        [
            0x40, 0x11, 0x50, 0x33, 0x95, 0x23, 0x44, 0x96, 0x96, 0xa2, 0x0e, 0xda, 0xde, 0xec,
            0xa5, 0x65
        ]
    );
}

#[test]
fn parse_decodes_checkpoint_area_fields() {
    // The checkpoint descriptor/data areas drive the live-superblock walk.
    // Verified: desc base=1 blocks=8 (high bit clear => contiguous);
    // data base=9 blocks=304.
    let nx = NxSuperblock::parse(block(0)).expect("parse NXSB block 0");
    assert_eq!(nx.xp_desc_base, 1);
    assert_eq!(nx.xp_desc_blocks, 8);
    assert_eq!(nx.xp_data_base, 9);
    assert_eq!(nx.xp_data_blocks, 304);
    // The descriptor area is contiguous for a freshly minted container.
    assert!(!nx.xp_desc_is_tree());
}

#[test]
fn parse_rejects_bad_magic_loudly() {
    // Corrupt the magic; parse must fail loud (named error), never Ok(empty).
    let mut blk = block(0).to_vec();
    blk[32] ^= 0xff; // first byte of nx_magic
    match NxSuperblock::parse(&blk) {
        Err(ApfsError::NoValidSuperblock { last_magic, .. }) => {
            // The error must carry the actual offending magic value seen.
            assert_ne!(last_magic, NX_MAGIC);
        }
        other => panic!("expected NoValidSuperblock, got {other:?}"),
    }
}

#[test]
fn parse_rejects_bad_checksum_loudly() {
    // Flip a body byte: the Fletcher-64 check must reject (carrying both the
    // stored and computed checksums for the examiner).
    let mut blk = block(0).to_vec();
    blk[200] ^= 0xff;
    match NxSuperblock::parse(&blk) {
        Err(ApfsError::ChecksumMismatch {
            stored, computed, ..
        }) => assert_ne!(stored, computed),
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

#[test]
fn parse_rejects_short_block_without_panicking() {
    assert!(NxSuperblock::parse(&[0u8; 64]).is_err());
    assert!(NxSuperblock::parse(&[]).is_err());
}
