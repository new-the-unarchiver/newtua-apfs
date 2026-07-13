//! Generic B-tree node header + table-of-contents + entry iteration, validated
//! against the REAL self-minted container omap B-tree (block 344, a single
//! root+leaf node with one fixed-size omap entry). Offsets verified verbatim
//! against the Apple `btree_node_phys_t` and the raw image. See
//! `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::btree::{self, BTreeSubtype};

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

fn block(idx: usize) -> &'static [u8] {
    &CHAIN[idx * BLOCK_SIZE..(idx + 1) * BLOCK_SIZE]
}

#[test]
fn parse_omap_root_node_header() {
    // Block 344 is the omap B-tree root: btn_flags = 0x7 (ROOT|LEAF|FIXED),
    // btn_level = 0 (leaf), btn_nkeys = 1. Verified against the raw image.
    let hdr = btree::parse_node_header(block(344)).expect("parse node header");
    assert_eq!(hdr.nkeys, 1);
    assert_eq!(hdr.level, 0);
    assert!(hdr.is_leaf());
    assert!(hdr.is_root());
    assert!(hdr.is_fixed_kv());
}

#[test]
fn iterate_omap_root_entries_fixed_layout() {
    // The single fixed-size entry maps omap_key(oid=1026, xid=2) ->
    // omap_val(flags=0, size=4096, paddr=342). Independently decoded from the
    // raw image; paddr 342 is the APSB block. Key = 16 B, value = 16 B.
    let entries = btree::node_entries(block(344), BTreeSubtype::Omap);
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.key.len(), 16);
    assert_eq!(e.value.len(), 16);

    let k_oid = u64::from_le_bytes(e.key[0..8].try_into().unwrap());
    let k_xid = u64::from_le_bytes(e.key[8..16].try_into().unwrap());
    assert_eq!(k_oid, 1026);
    assert_eq!(k_xid, 2);

    let v_paddr = u64::from_le_bytes(e.value[8..16].try_into().unwrap());
    assert_eq!(v_paddr, 342);
}

#[test]
fn parse_node_header_rejects_short_block() {
    // A block too short to hold the node header yields None, never panics.
    assert!(btree::parse_node_header(&[0u8; 16]).is_none());
}

#[test]
fn node_entries_on_garbage_is_empty_not_panic() {
    // A node header claiming a huge nkeys but with no backing data must yield
    // an empty (or bounded) entry list, never an out-of-bounds panic.
    let mut blk = vec![0u8; BLOCK_SIZE];
    // btn_nkeys @36 = u32::MAX (allocation-bomb attempt), fixed-kv flag set.
    blk[32..34].copy_from_slice(&0x4u16.to_le_bytes()); // btn_flags = FIXED
    blk[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
    let entries = btree::node_entries(&blk, BTreeSubtype::Omap);
    // No TOC content -> entries bounded by the node, never a panic.
    assert!(entries.len() < BLOCK_SIZE);
}
