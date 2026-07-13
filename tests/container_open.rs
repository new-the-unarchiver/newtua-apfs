//! End-to-end container open: read block 0, resolve the checkpoint ring to the
//! live superblock, expose its geometry. Validated against the REAL self-minted
//! container (Tier 2). See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::object::fletcher64_checksum;
use apfs_core::{ApfsContainer, ApfsError};

const HEAD: &[u8] = include_bytes!("../../tests/data/apfs_nxsb_head.bin");
const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");

/// `NX_INCOMPAT_FUSION` (Apple *APFS Reference*, `nx_incompatible_features`).
const NX_INCOMPAT_FUSION: u64 = 0x100;
/// `nx_incompatible_features` byte offset within `nx_superblock_t`.
const OFF_INCOMPAT: usize = 64;

/// Set the Fusion incompatible-feature bit in block 0's NXSB and re-stamp its
/// Fletcher-64 so the (now-Fusion) superblock still passes the checksum gate.
fn with_fusion_bit(image: &[u8]) -> Vec<u8> {
    let mut img = image.to_vec();
    let mut feats = u64::from_le_bytes(img[OFF_INCOMPAT..OFF_INCOMPAT + 8].try_into().unwrap());
    feats |= NX_INCOMPAT_FUSION;
    img[OFF_INCOMPAT..OFF_INCOMPAT + 8].copy_from_slice(&feats.to_le_bytes());
    // Re-stamp the checksum (first 8 bytes) over the modified block.
    let cks = fletcher64_checksum(&img[..4096]);
    img[0..8].copy_from_slice(&cks.to_le_bytes());
    img
}

#[test]
fn open_resolves_live_superblock_geometry() {
    let container = ApfsContainer::open(Cursor::new(HEAD)).expect("open container");
    let nx = container.superblock();
    // The live superblock (descriptor xid 2) — values cross-checked against
    // diskutil info (block size, UUID) and the raw bytes.
    assert_eq!(nx.block_size, 4096);
    assert_eq!(nx.block_count, 32758);
    assert_eq!(nx.xid, 2);
    assert_eq!(nx.omap_oid, 343);
    assert_eq!(nx.fs_oids, vec![1026]);
    assert_eq!(
        nx.uuid,
        [
            0x40, 0x11, 0x50, 0x33, 0x95, 0x23, 0x44, 0x96, 0x96, 0xa2, 0x0e, 0xda, 0xde, 0xec,
            0xa5, 0x65
        ]
    );
    // The checkpoint resolved the live superblock at descriptor block 4.
    assert_eq!(container.live_superblock_paddr(), 4);
}

#[test]
fn open_fails_loud_on_fusion_container() {
    // Fusion changes physical-address resolution; until tier-aware translation
    // lands, a Fusion container must be REJECTED at open, never silently
    // mis-read. Take the real container, set NX_INCOMPAT_FUSION (+ re-stamp the
    // checksum so it still parses), and require a loud UnsupportedFusion.
    let fusion = with_fusion_bit(HEAD);
    match ApfsContainer::open(Cursor::new(fusion)) {
        Err(ApfsError::UnsupportedFusion) => {}
        Err(other) => panic!("expected UnsupportedFusion, got {other:?}"),
        Ok(_) => panic!("expected UnsupportedFusion, but open() succeeded on a Fusion container"),
    }
}

#[test]
fn open_does_not_flag_real_non_fusion_container() {
    // Regression: the unmodified real container has no Fusion bit and must open.
    assert!(ApfsContainer::open(Cursor::new(HEAD)).is_ok());
}

#[test]
fn resolves_ephemeral_spaceman_and_reaper_paddrs() {
    // The live NXSB names the spaceman/reaper by ephemeral oid (1024/1025); the
    // checkpoint map resolves them to physical blocks 11/12 in this fixture.
    let container = ApfsContainer::open(Cursor::new(CHAIN)).expect("open container");
    assert_eq!(container.spaceman_paddr(), Some(11));
    assert_eq!(container.reaper_paddr(), Some(12));
    // The checkpoint mappings (needed to walk the reaper's ephemeral reap lists)
    // are exposed and include both ephemeral objects.
    let maps = container.checkpoint_mappings();
    assert!(maps.iter().any(|m| m.paddr == 11));
    assert!(maps.iter().any(|m| m.paddr == 12));
}

#[test]
fn open_fails_loud_on_garbage_source() {
    // No NXSB magic anywhere -> loud bootstrap failure, never Ok.
    let garbage = vec![0u8; 4096 * 2];
    assert!(ApfsContainer::open(Cursor::new(garbage)).is_err());
}

#[test]
fn open_fails_loud_on_truncated_source() {
    // Source shorter than one block -> bootstrap failure, not a panic.
    let tiny = vec![0u8; 16];
    assert!(ApfsContainer::open(Cursor::new(tiny)).is_err());
}
