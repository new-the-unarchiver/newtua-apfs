//! End-to-end volume-superblock resolution: open the container, resolve the
//! container object map, walk the omap B-tree to turn each virtual `nx_fs_oid`
//! into the physical block address of its volume superblock (APSB), and confirm
//! the resolved block carries the APSB magic + a valid Fletcher-64 checksum.
//!
//! Validated against the REAL self-minted single-volume container chain
//! (`apfs_container_chain.bin`). Independent oracles (Apple `diskutil apfs
//! list`, libfsapfs `fsapfsinfo`) report exactly one volume; we resolve exactly
//! one APSB at paddr 342. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::ApfsContainer;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

/// APFS volume superblock magic `APFS_MAGIC` ('BSPA', "APSB", LE 0x42535041).
const APFS_MAGIC: u32 = 0x4253_5041;

#[test]
fn resolve_single_volume_superblock_address() {
    // nx_fs_oid = [1026] (a virtual oid). Resolving it through the container omap
    // (nx_omap_oid 343 -> tree 344) yields the APSB physical block 342.
    let mut container = ApfsContainer::open(Cursor::new(CHAIN)).expect("open container");
    let addrs = container
        .volume_superblock_addrs()
        .expect("resolve volume addrs");
    assert_eq!(addrs, vec![342]);
}

#[test]
fn resolved_block_carries_apsb_magic_and_valid_checksum() {
    // End-to-end proof: re-read the resolved block and confirm it is a real APSB
    // (magic + Fletcher-64), i.e. the omap/btree chain landed on the volume
    // superblock and not on an arbitrary block.
    let mut container = ApfsContainer::open(Cursor::new(CHAIN)).expect("open");
    let addrs = container.volume_superblock_addrs().expect("resolve");
    assert_eq!(addrs.len(), 1);

    let paddr = addrs[0] as usize;
    let block = &CHAIN[paddr * BLOCK_SIZE..(paddr + 1) * BLOCK_SIZE];
    // Magic at offset 32 (after obj_phys_t).
    let magic = u32::from_le_bytes(block[32..36].try_into().unwrap());
    assert_eq!(magic, APFS_MAGIC, "resolved block is not an APSB");
    // Fletcher-64 must validate (the stored o_cksum recomputes).
    let stored = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let computed = apfs_core::object::fletcher64_checksum(block);
    assert_eq!(stored, computed, "APSB checksum mismatch");
}

#[test]
fn resolve_is_consistent_across_calls() {
    // Resolution must be deterministic and side-effect-free on the reader.
    let mut container = ApfsContainer::open(Cursor::new(CHAIN)).expect("open");
    let a = container.volume_superblock_addrs().expect("first");
    let b = container.volume_superblock_addrs().expect("second");
    assert_eq!(a, b);
}
