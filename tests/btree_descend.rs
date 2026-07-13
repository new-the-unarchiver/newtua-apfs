//! B-tree root→leaf descent (`for_each_leaf_entry`): visits every leaf entry,
//! verifying each node's Fletcher-64 checksum and guarding against cyclic node
//! links. Validated against the REAL self-minted omap B-tree (block 344, a
//! single root+leaf node) and synthetic multi-level / cyclic nodes for the
//! defensive paths. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::btree::{self, BTreeSubtype};
use apfs_core::object::fletcher64_checksum;
use apfs_core::ApfsError;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;

#[test]
fn descend_real_omap_tree_visits_single_leaf_entry() {
    // The container omap B-tree root is at block (paddr) 344. Walking it visits
    // exactly one leaf entry: omap_key(oid=1026, xid=2) -> omap_val(paddr=342).
    let mut reader = Cursor::new(CHAIN);
    let mut seen: Vec<(u64, u64, u64)> = Vec::new();
    btree::for_each_leaf_entry(
        &mut reader,
        344,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |k, v| {
            let oid = u64::from_le_bytes(k[0..8].try_into().unwrap());
            let xid = u64::from_le_bytes(k[8..16].try_into().unwrap());
            let paddr = u64::from_le_bytes(v[8..16].try_into().unwrap());
            seen.push((oid, xid, paddr));
        },
    )
    .expect("walk omap tree");
    assert_eq!(seen, vec![(1026, 2, 342)]);
}

#[test]
fn descend_rejects_checksum_mismatch_node() {
    // Corrupt the omap root node's body so Fletcher-64 fails: the walk must
    // error (checksum-before-trust), never read the corrupted TOC.
    let mut img = CHAIN.to_vec();
    img[344 * BLOCK_SIZE + 100] ^= 0xff;
    let mut reader = Cursor::new(img);
    match btree::for_each_leaf_entry(
        &mut reader,
        344,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |_, _| {},
    ) {
        Err(ApfsError::ChecksumMismatch { .. }) => {}
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

// Flags (btn_flags @32): ROOT=0x1, LEAF=0x2, FIXED_KV=0x4.
const ROOT: u16 = 0x1;
const LEAF: u16 = 0x2;
const FIXED: u16 = 0x4;

/// Build one fixed-KV B-tree node block in the layout `node_entries` expects
/// (header at 32, `table_space` at 40, TOC at 56, keys after the TOC, values
/// packed backward from `val_base`). Recomputes the Fletcher-64 checksum so the
/// node passes the checksum-before-trust gate.
fn fixed_node(flags: u16, level: u16, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; BLOCK_SIZE];
    let nkeys = entries.len();
    node[32..34].copy_from_slice(&flags.to_le_bytes());
    node[34..36].copy_from_slice(&level.to_le_bytes());
    node[36..40].copy_from_slice(&(nkeys as u32).to_le_bytes());
    let toc_len = nkeys * 4; // fixed-KV TOC entry = 4 bytes
    node[40..42].copy_from_slice(&0u16.to_le_bytes()); // table_space off
    node[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes()); // table_space len
    let toc_start = 56;
    let key_area = toc_start + toc_len;
    let val_base = if flags & ROOT != 0 {
        BLOCK_SIZE - 40 // root: footer btree_info (40 B) sits at the end
    } else {
        BLOCK_SIZE
    };
    let mut koff = 0usize;
    let mut voff = 0usize; // cumulative offset back from val_base
    for (i, (key, val)) in entries.iter().enumerate() {
        voff += val.len();
        let e = toc_start + i * 4;
        node[e..e + 2].copy_from_slice(&(koff as u16).to_le_bytes());
        node[e + 2..e + 4].copy_from_slice(&(voff as u16).to_le_bytes());
        node[key_area + koff..key_area + koff + key.len()].copy_from_slice(key);
        node[val_base - voff..val_base - voff + val.len()].copy_from_slice(val);
        koff += key.len();
    }
    let cks = fletcher64_checksum(&node);
    node[0..8].copy_from_slice(&cks.to_le_bytes());
    node
}

fn omap_key(oid: u64, xid: u64) -> Vec<u8> {
    let mut k = oid.to_le_bytes().to_vec();
    k.extend_from_slice(&xid.to_le_bytes());
    k
}
fn omap_leaf_val(paddr: u64) -> Vec<u8> {
    // omap_val { ov_flags u32, ov_size u32, ov_paddr u64 @8 }
    let mut v = vec![0u8; 8];
    v.extend_from_slice(&paddr.to_le_bytes());
    v
}

#[test]
fn find_leaf_descends_to_the_correct_child_in_a_multilevel_tree() {
    // 3-node omap tree: a ROOT index node (block 0) over two leaves —
    // block 1 holds (oid 10, xid 1) -> paddr 111, block 2 holds (oid 20) -> 222.
    // find_leaf must follow the separator keys to the RIGHT leaf, reading one
    // root->leaf path (this is what makes omap.resolve a point lookup).
    let mut img = vec![0u8; BLOCK_SIZE * 3];
    let leaf1 = fixed_node(LEAF | FIXED, 0, &[(omap_key(10, 1), omap_leaf_val(111))]);
    let leaf2 = fixed_node(LEAF | FIXED, 0, &[(omap_key(20, 1), omap_leaf_val(222))]);
    // Index node: separator key i = smallest key of child i; branch value = child block#.
    let root = fixed_node(
        ROOT | FIXED,
        1,
        &[
            (omap_key(10, 1), 1u64.to_le_bytes().to_vec()),
            (omap_key(20, 1), 2u64.to_le_bytes().to_vec()),
        ],
    );
    img[0..BLOCK_SIZE].copy_from_slice(&root);
    img[BLOCK_SIZE..2 * BLOCK_SIZE].copy_from_slice(&leaf1);
    img[2 * BLOCK_SIZE..3 * BLOCK_SIZE].copy_from_slice(&leaf2);

    let probe = |target: (u64, u64)| {
        let mut reader = Cursor::new(img.clone());
        let mut seen: Vec<(u64, u64)> = Vec::new();
        btree::find_leaf(
            &mut reader,
            0,
            BLOCK_SIZE,
            BTreeSubtype::Omap,
            |k| {
                let oid = u64::from_le_bytes(k[0..8].try_into().unwrap());
                let xid = u64::from_le_bytes(k[8..16].try_into().unwrap());
                (oid, xid).cmp(&target)
            },
            &mut |k, v| {
                let oid = u64::from_le_bytes(k[0..8].try_into().unwrap());
                let paddr = u64::from_le_bytes(v[8..16].try_into().unwrap());
                seen.push((oid, paddr));
            },
        )
        .expect("find_leaf");
        seen
    };

    // (oid 20) must land on leaf 2, NOT scan leaf 1.
    assert_eq!(
        probe((20, 1)),
        vec![(20, 222)],
        "descended to the oid-20 leaf"
    );
    // (oid 10) lands on leaf 1.
    assert_eq!(
        probe((10, 1)),
        vec![(10, 111)],
        "descended to the oid-10 leaf"
    );
}

#[test]
fn descend_guards_against_self_cycle() {
    // A two-block image where an INDEX node at block 0 points its only child
    // back at itself: the cycle guard must fire (CycleGuard), never loop forever.
    let mut img = vec![0u8; BLOCK_SIZE * 2];
    // Build a non-leaf (index) node at block 0, fixed-KV, 1 entry whose value is
    // the 8-byte child block number 0 (itself).
    let node = &mut img[0..BLOCK_SIZE];
    // btn_flags @32 = ROOT | FIXED (no LEAF); btn_level @34 = 1; btn_nkeys @36 = 1
    node[32..34].copy_from_slice(&(0x1u16 | 0x4u16).to_le_bytes());
    node[34..36].copy_from_slice(&1u16.to_le_bytes());
    node[36..40].copy_from_slice(&1u32.to_le_bytes());
    // btn_table_space @40 (nloc off=0, len=4)
    node[40..42].copy_from_slice(&0u16.to_le_bytes());
    node[42..44].copy_from_slice(&4u16.to_le_bytes());
    // TOC entry @ btn_data(56): key_offs=0, value_offs=8 (8-byte child value).
    node[56..58].copy_from_slice(&0u16.to_le_bytes());
    node[58..60].copy_from_slice(&8u16.to_le_bytes());
    // key area starts at 56+0+4 = 60; omap_key (16 B) — content irrelevant.
    // value: val_base = block.len() - btree_info(40); value at val_base-8 = child#.
    let val_base = BLOCK_SIZE - 40;
    node[val_base - 8..val_base].copy_from_slice(&0u64.to_le_bytes()); // child = block 0
                                                                       // recompute the node checksum so it passes the cksum gate
    let cks = fletcher64_checksum(node);
    node[0..8].copy_from_slice(&cks.to_le_bytes());

    let mut reader = Cursor::new(img);
    match btree::for_each_leaf_entry(
        &mut reader,
        0,
        BLOCK_SIZE,
        BTreeSubtype::Omap,
        &mut |_, _| {},
    ) {
        Err(ApfsError::CycleGuard { .. }) => {}
        other => panic!("expected CycleGuard, got {other:?}"),
    }
}
