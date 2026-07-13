//! Directory record (`DIR_REC`) listing and **name→inode path navigation**,
//! validated against the REAL fs-tree fixture and the independent TSK `fls`/
//! `istat` oracle.
//!
//! Ground truth (TSK `fls -r` / `istat` + macOS `stat` on the same image — see
//! `docs/validation.md`): the known tree is
//!   /                inode 2  (root)
//!   /top.txt         inode 22  size 15
//!   /Dir1            inode 18
//!   /Dir1/Beth.txt   inode 20  size 38
//!   /Dir1/Sub        inode 19
//!   /Dir1/Sub/secret.bin  inode 21  size 26
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::{list_dir, lookup_child, open_path};
use apfs_core::volume::ApfsVolume;

const FSTREE: &[u8] = include_bytes!("../../tests/data/apfs_fstree.bin");
const BLOCK_SIZE: usize = 4096;
/// The APSB (volume superblock) sits at block 371 in the fixture.
const APSB_BLOCK: usize = 371;

/// `ROOT_DIR_INO_NUM` (Apple) — the inode number of a volume's root directory.
const ROOT_DIR_INO_NUM: u64 = 2;

fn volume() -> ApfsVolume {
    let block = &FSTREE[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse APSB")
}

#[test]
fn list_root_directory() {
    // Root (inode 2) contains top.txt(22), Dir1(18), and the system .fseventsd
    // (16). fls -r shows exactly these at the root.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let mut entries = list_dir(&mut r, &vol, ROOT_DIR_INO_NUM, BLOCK_SIZE).expect("list root");
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let named: Vec<(&str, u64)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.file_id))
        .collect();
    assert!(named.contains(&("top.txt", 22)), "got {named:?}");
    assert!(named.contains(&("Dir1", 18)), "got {named:?}");
    assert!(named.contains(&(".fseventsd", 16)), "got {named:?}");
}

#[test]
fn list_dir1_children() {
    // Dir1 (inode 18) contains Beth.txt(20) and Sub(19).
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let entries = list_dir(&mut r, &vol, 18, BLOCK_SIZE).expect("list Dir1");
    let named: Vec<(&str, u64)> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.file_id))
        .collect();
    assert!(named.contains(&("Beth.txt", 20)), "got {named:?}");
    assert!(named.contains(&("Sub", 19)), "got {named:?}");
    assert_eq!(entries.len(), 2);
}

#[test]
fn lookup_child_resolves_single_component() {
    // (parent=2, "Dir1") -> 18; (parent=18, "Beth.txt") -> 20.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert_eq!(
        lookup_child(&mut r, &vol, ROOT_DIR_INO_NUM, "Dir1", BLOCK_SIZE).unwrap(),
        Some(18)
    );
    assert_eq!(
        lookup_child(&mut r, &vol, 18, "Beth.txt", BLOCK_SIZE).unwrap(),
        Some(20)
    );
}

#[test]
fn lookup_child_missing_is_none() {
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert_eq!(
        lookup_child(&mut r, &vol, ROOT_DIR_INO_NUM, "nope", BLOCK_SIZE).unwrap(),
        None
    );
}

#[test]
fn open_path_resolves_top_level_file() {
    // /top.txt -> inode 22, size 15.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/top.txt", BLOCK_SIZE).expect("open /top.txt");
    assert_eq!(inode.oid, 22);
    assert_eq!(inode.size, Some(15));
    assert_eq!(inode.name.as_deref(), Some("top.txt"));
    assert_eq!(inode.parent_id, ROOT_DIR_INO_NUM);
}

#[test]
fn open_path_resolves_nested_file() {
    // /Dir1/Beth.txt -> inode 20, size 38, parent 18.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Beth.txt", BLOCK_SIZE).expect("open Beth");
    assert_eq!(inode.oid, 20);
    assert_eq!(inode.size, Some(38));
    assert_eq!(inode.parent_id, 18);
}

#[test]
fn open_path_resolves_deeply_nested_file() {
    // /Dir1/Sub/secret.bin -> inode 21, size 26, parent 19.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Sub/secret.bin", BLOCK_SIZE).expect("open secret");
    assert_eq!(inode.oid, 21);
    assert_eq!(inode.size, Some(26));
    assert_eq!(inode.parent_id, 19);
}

#[test]
fn open_path_root_returns_root_inode() {
    // "/" resolves to the root directory inode (2).
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/", BLOCK_SIZE).expect("open root");
    assert_eq!(inode.oid, ROOT_DIR_INO_NUM);
}

#[test]
fn open_path_missing_component_errors() {
    // A non-existent path component is a loud per-item miss, not a panic.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    assert!(open_path(&mut r, &vol, "/Dir1/missing.txt", BLOCK_SIZE).is_err());
    assert!(open_path(&mut r, &vol, "/nope/Beth.txt", BLOCK_SIZE).is_err());
}

#[test]
fn open_path_handles_trailing_and_double_slashes() {
    // Empty path components (from "//" or a trailing "/") are skipped, so these
    // resolve identically to the canonical form.
    let mut r = Cursor::new(FSTREE);
    let vol = volume();
    let a = open_path(&mut r, &vol, "/Dir1/", BLOCK_SIZE).expect("trailing slash");
    assert_eq!(a.oid, 18);
    let b = open_path(&mut r, &vol, "/Dir1//Sub", BLOCK_SIZE).expect("double slash");
    assert_eq!(b.oid, 19);
}

#[test]
fn fs_tree_node_checksum_mismatch_errors() {
    // Corrupt the fs-tree leaf node (block 365) body so its Fletcher-64 fails:
    // navigation must error (checksum-before-trust), never read the bad TOC.
    let mut img = FSTREE.to_vec();
    img[365 * BLOCK_SIZE + 200] ^= 0xff;
    let mut r = Cursor::new(img);
    let vol = volume();
    match list_dir(&mut r, &vol, ROOT_DIR_INO_NUM, BLOCK_SIZE) {
        Err(apfs_core::ApfsError::ChecksumMismatch { .. }) => {}
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

mod synthetic {
    //! A hand-built two-level *virtual* fs-tree exercises the index-node descent
    //! and the cycle guard with valid Fletcher-64 checksums (the real fixture's
    //! fs-tree is a single leaf, so these production paths need synthetic input).
    use super::{Cursor, BLOCK_SIZE};
    use apfs_core::object::fletcher64_checksum;

    const OMAP_TYPE: u16 = 0xb;

    fn put_u16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Seal an object: set `o_type` (low 16) and recompute its Fletcher-64.
    fn seal(block: &mut [u8], obj_type: u16) {
        put_u32(block, 24, u32::from(obj_type));
        let c = fletcher64_checksum(block);
        block[0..8].copy_from_slice(&c.to_le_bytes());
    }

    /// Write a fixed-KV omap node (root+leaf) mapping each (oid -> paddr) at xid 1.
    fn write_omap_tree(block: &mut [u8], maps: &[(u64, u64)]) {
        // btn_flags = ROOT|LEAF|FIXED (0x7); level 0; nkeys = maps.len().
        put_u16(block, 32, 0x7);
        put_u16(block, 34, 0);
        put_u32(block, 36, maps.len() as u32);
        // btn_table_space: off 0, len = nkeys*4.
        put_u16(block, 40, 0);
        put_u16(block, 42, (maps.len() * 4) as u16);
        let toc = 56;
        let key_area = toc + maps.len() * 4;
        let val_base = BLOCK_SIZE - 40; // root: reversed from btree_info
        for (i, &(oid, paddr)) in maps.iter().enumerate() {
            // TOC entry: key_offs (from key_area), value_offs (reversed).
            let koff = (i * 16) as u16;
            let voff = ((i + 1) * 16) as u16;
            put_u16(block, toc + i * 4, koff);
            put_u16(block, toc + i * 4 + 2, voff);
            // omap_key { ok_oid, ok_xid=1 }
            put_u64(block, key_area + i * 16, oid);
            put_u64(block, key_area + i * 16 + 8, 1);
            // omap_val { flags, size, paddr } at val_base - voff
            let vs = val_base - voff as usize;
            put_u32(block, vs, 0);
            put_u32(block, vs + 4, BLOCK_SIZE as u32);
            put_u64(block, vs + 8, paddr);
        }
        seal(block, OMAP_TYPE);
    }

    /// Write an `omap_phys` header whose `om_tree_oid` points at `tree_paddr`.
    fn write_omap_header(block: &mut [u8], tree_paddr: u64) {
        put_u64(block, 48, tree_paddr); // om_tree_oid
        seal(block, OMAP_TYPE);
    }

    /// Write a variable-KV fs-tree node. `level` 0 = leaf. Each entry is
    /// `(key_bytes, value_bytes)`.
    fn write_fs_node(block: &mut [u8], level: u16, entries: &[(Vec<u8>, Vec<u8>)], root: bool) {
        let mut flags = if level == 0 { 0x2 } else { 0x0 }; // LEAF
        if root {
            flags |= 0x1;
        }
        put_u16(block, 32, flags);
        put_u16(block, 34, level);
        put_u32(block, 36, entries.len() as u32);
        // Variable TOC: 8 bytes/entry.
        let toc_len = (entries.len() * 8) as u16;
        put_u16(block, 40, 0);
        put_u16(block, 42, toc_len);
        let toc = 56;
        let key_area = toc + entries.len() * 8;
        let val_base = if root { BLOCK_SIZE - 40 } else { BLOCK_SIZE };
        let mut koff = 0usize;
        let mut voff_acc = 0usize;
        for (i, (k, v)) in entries.iter().enumerate() {
            put_u16(block, toc + i * 8, koff as u16);
            put_u16(block, toc + i * 8 + 2, k.len() as u16);
            voff_acc += v.len();
            put_u16(block, toc + i * 8 + 4, voff_acc as u16);
            put_u16(block, toc + i * 8 + 6, v.len() as u16);
            block[key_area + koff..key_area + koff + k.len()].copy_from_slice(k);
            let vs = val_base - voff_acc;
            block[vs..vs + v.len()].copy_from_slice(v);
            koff += k.len();
        }
        // FSTREE object type 0xe.
        seal(block, 0xe);
    }

    /// A minimal `ApfsVolume`-shaped APSB block: only `omap_oid` + `root_tree_oid` +
    /// xid + name are needed for navigation; sealed as an FS object with "APSB".
    fn write_apsb(block: &mut [u8], omap_oid: u64, root_tree_oid: u64, xid: u64) {
        put_u64(block, 16, xid); // o_xid
        put_u32(block, 32, 0x4253_5041); // "APSB"
        put_u64(block, 128, omap_oid);
        put_u64(block, 136, root_tree_oid);
        // a name so ApfsVolume::parse succeeds
        block[704..707].copy_from_slice(b"SYN");
        seal(block, 0xd); // OBJECT_TYPE_FS
    }

    /// Build a 6-block image:
    ///   blk0 APSB, blk1 omap, blk2 omap-tree, blk3 fs index root,
    ///   blk4 fs leaf, blk5 spare. Returns the raw image bytes.
    fn build_index_image() -> Vec<u8> {
        let mut img = vec![0u8; BLOCK_SIZE * 6];
        // Virtual oids: root fs-tree node = 100 (index), child leaf = 101.
        // Layout: blk0 APSB, blk1 omap_phys header (om_tree_oid -> blk2),
        // blk2 omap tree (100 -> blk3, 101 -> blk4), blk3 index root, blk4 leaf.
        write_apsb(&mut img[0..BLOCK_SIZE], 1, 100, 1);
        write_omap_header(&mut img[BLOCK_SIZE..2 * BLOCK_SIZE], 2);
        write_omap_tree(
            &mut img[2 * BLOCK_SIZE..3 * BLOCK_SIZE],
            &[(100, 3), (101, 4)],
        );

        // Index root node (blk3, level 1): one entry whose value is child oid 101.
        let idx_key = (9u64 << 60).to_le_bytes().to_vec(); // any j_key
        let idx_val = 101u64.to_le_bytes().to_vec();
        write_fs_node(
            &mut img[3 * BLOCK_SIZE..4 * BLOCK_SIZE],
            1,
            &[(idx_key, idx_val)],
            true,
        );

        // Leaf node (blk4, level 0): one DIR_REC (parent 2, name "leaf", file 55).
        let mut k = Vec::new();
        k.extend_from_slice(&((9u64 << 60) | 2).to_le_bytes()); // DIR_REC, parent 2
        k.extend_from_slice(&5u32.to_le_bytes()); // hashed len 5 = "leaf\0"
        k.extend_from_slice(b"leaf\0");
        let mut v = Vec::new();
        v.extend_from_slice(&55u64.to_le_bytes()); // file_id
        v.extend_from_slice(&0u64.to_le_bytes()); // date_added
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        write_fs_node(
            &mut img[4 * BLOCK_SIZE..5 * BLOCK_SIZE],
            0,
            &[(k, v)],
            false,
        );
        img
    }

    #[test]
    fn descends_index_node_to_leaf() {
        // Walk a two-level virtual fs-tree: the index root resolves its child oid
        // through the omap and the leaf DIR_REC is found.
        use apfs_core::dir::{list_dir, lookup_child, ROOT_DIR_INO_NUM};
        use apfs_core::volume::ApfsVolume;
        let img = build_index_image();
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("parse synthetic APSB");
        let mut r = Cursor::new(img);
        let entries = list_dir(&mut r, &vol, ROOT_DIR_INO_NUM, BLOCK_SIZE).expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "leaf");
        assert_eq!(entries[0].file_id, 55);
        assert_eq!(
            lookup_child(&mut r, &vol, ROOT_DIR_INO_NUM, "leaf", BLOCK_SIZE).unwrap(),
            Some(55)
        );
    }

    #[test]
    fn cycle_guard_fires_on_self_referential_node() {
        // An index node whose only child oid maps back to itself must trip the
        // cycle guard rather than loop forever.
        use apfs_core::dir::{list_dir, ROOT_DIR_INO_NUM};
        use apfs_core::volume::ApfsVolume;
        let mut img = vec![0u8; BLOCK_SIZE * 4];
        write_apsb(&mut img[0..BLOCK_SIZE], 1, 100, 1);
        write_omap_header(&mut img[BLOCK_SIZE..2 * BLOCK_SIZE], 2);
        // omap maps node oid 100 -> blk3 (the index node).
        write_omap_tree(&mut img[2 * BLOCK_SIZE..3 * BLOCK_SIZE], &[(100, 3)]);
        // Index node (blk3) whose child value is 100 again (its own oid).
        let key = (9u64 << 60).to_le_bytes().to_vec();
        let val = 100u64.to_le_bytes().to_vec();
        write_fs_node(
            &mut img[3 * BLOCK_SIZE..4 * BLOCK_SIZE],
            1,
            &[(key, val)],
            true,
        );
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("parse APSB");
        let mut r = Cursor::new(img);
        match list_dir(&mut r, &vol, ROOT_DIR_INO_NUM, BLOCK_SIZE) {
            Err(apfs_core::ApfsError::CycleGuard { .. }) => {}
            other => panic!("expected CycleGuard, got {other:?}"),
        }
    }
}
