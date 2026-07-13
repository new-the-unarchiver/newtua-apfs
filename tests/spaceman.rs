//! Space-manager allocation query (`is_block_free`) on the real self-minted
//! container `apfs_container_chain.bin` (Tier 2).
//!
//! **Derivable ground truth.** The fixture is a 32 758-block container carved so
//! that exactly the first 345 blocks (0..=344) hold live objects; the space
//! manager's own accounting agrees: its single chunk reports
//! `free_count = 32 413` (⇒ `32 758 − 32 413 = 345` allocated), and the
//! allocation bitmap's popcount is 345. So `is_block_free` must report **every
//! block 0..=344 as allocated** (known live objects: NXSB@0, spaceman@11,
//! reaper@12, CIB@331, bitmap@332, omap@343, APSB@342) and **every block ≥ 345
//! as free**. This is checked against the spaceman's own free-count, an oracle
//! independent of the bitmap read (a wrong bit polarity would flip the answers).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::spaceman::is_block_free;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;
/// The live space manager (`nx_spaceman_oid` 1024) resolves to block 11 via the
/// live checkpoint map (verified: the highest-xid NXSB's descriptor window).
const SPACEMAN_BLOCK: u64 = 11;

#[test]
fn allocated_blocks_report_not_free() {
    let mut r = Cursor::new(CHAIN);
    // Blocks holding known live objects must be marked allocated (not free).
    for b in [0u64, 11, 12, 331, 332, 342, 343, 344] {
        let free = is_block_free(&mut r, SPACEMAN_BLOCK, b, BLOCK_SIZE)
            .unwrap_or_else(|e| panic!("is_block_free({b}): {e:?}"));
        assert!(!free, "block {b} holds a live object, must be allocated");
    }
}

#[test]
fn free_blocks_report_free() {
    let mut r = Cursor::new(CHAIN);
    // Beyond the 345 carved blocks the container is empty space.
    for b in [345u64, 346, 1000, 30_000, 32_757] {
        let free = is_block_free(&mut r, SPACEMAN_BLOCK, b, BLOCK_SIZE)
            .unwrap_or_else(|e| panic!("is_block_free({b}): {e:?}"));
        assert!(free, "block {b} is past the carved data, must be free");
    }
}

#[test]
fn free_count_matches_spaceman_accounting() {
    // The number of allocated blocks counted via is_block_free over the whole
    // container must equal block_count - free_count = 345 (the spaceman's own
    // accounting), an oracle independent of how each bit is read.
    let mut r = Cursor::new(CHAIN);
    let block_count: u64 = 32_758;
    let mut allocated = 0u64;
    for b in 0..block_count {
        if !is_block_free(&mut r, SPACEMAN_BLOCK, b, BLOCK_SIZE).expect("is_block_free") {
            allocated += 1;
        }
    }
    assert_eq!(
        allocated, 345,
        "allocated-block count vs spaceman free_count"
    );
}
