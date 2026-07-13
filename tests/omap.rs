//! Object-map header (`omap_phys_t`) parse, validated against the REAL
//! self-minted container chain (Tier 2). The carve starts at NXSB block 0 so a
//! physical block address maps directly to `paddr * block_size` in the fixture.
//! Cross-checked against the live NXSB (`nx_omap_oid = 343`) and the raw bytes.
//! See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::omap::ObjectMap;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

fn block(idx: usize) -> &'static [u8] {
    &CHAIN[idx * BLOCK_SIZE..(idx + 1) * BLOCK_SIZE]
}

#[test]
fn parse_container_omap_phys_header() {
    // The live NXSB names nx_omap_oid = 343; that block is an OMAP-typed
    // omap_phys_t whose B-tree root is om_tree_oid = 344 (verified independently
    // against the raw image and confirmed cksum-valid).
    let omap = ObjectMap::parse(block(343)).expect("parse omap_phys");
    assert_eq!(omap.tree_oid(), 344);
    // om_tree_type = 0x4000_0002 (storage-physical flag | OBJECT_TYPE_BTREE).
    assert_eq!(omap.tree_type() & 0xffff, 0x2);
    // om_flags = OMAP_MANUALLY_MANAGED (0x1) for a container omap.
    assert_eq!(omap.flags(), 0x1);
    assert_eq!(omap.snapshot_tree_oid(), 0);
}

#[test]
fn parse_rejects_non_omap_block() {
    // The APSB block (342) is not an omap — a wrong-type block must be rejected
    // loudly (carrying the offending type), never silently mis-parsed.
    assert!(ObjectMap::parse(block(342)).is_err());
}

#[test]
fn parse_rejects_short_block() {
    // A block too short to hold the omap_phys header fails, never panics.
    assert!(ObjectMap::parse(&[0u8; 16]).is_err());
}

#[test]
fn parse_rejects_checksum_mismatch() {
    // Corrupt one byte past the cksum field: Fletcher-64 must reject it
    // (checksum-before-trust), never read the corrupted fields.
    let mut blk = block(343).to_vec();
    blk[100] ^= 0xff;
    assert!(ObjectMap::parse(&blk).is_err());
}
