//! Inode value parsing (`j_inode_val_t`), validated against the REAL fs-tree
//! fixture and the independent TSK `istat` oracle.
//!
//! The on-disk inode-value field offsets were derived empirically from the
//! fixture and **cross-checked against TSK `istat`** (timestamps, mode, uid/gid,
//! nchildren) — see `tests/data/README.md` and `docs/validation.md`. The
//! authoritative offsets: parent@0, private@8, create@16, mod@24, change@32,
//! access@40, `internal_flags`@48, nchildren/nlink@56, `bsd_flags`@68, owner@72,
//! gid@76, mode@80, xfields@92.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::fsrecord::{decode_jkey, RecordType};
use apfs_core::inode::{ns_to_datetime, Inode};

const FSTREE: &[u8] = include_bytes!("../../tests/data/apfs_fstree.bin");
const BLOCK_SIZE: usize = 4096;
/// The fs-tree leaf node is a single block at paddr 365 (verified via the chain).
const FSTREE_NODE: usize = 365;

fn u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Pull the raw value bytes of the INODE record for `oid` straight from the
/// fs-tree leaf node (independent of the crate's own tree walker — an
/// independent code path, so the assertion is not self-referential).
fn inode_value(oid: u64) -> Vec<u8> {
    let node = &FSTREE[FSTREE_NODE * BLOCK_SIZE..(FSTREE_NODE + 1) * BLOCK_SIZE];
    let nkeys = u32(node, 36) as usize;
    let toc_start = 56 + u16(node, 40) as usize;
    let key_area = toc_start + u16(node, 42) as usize;
    let val_base = node.len() - 40; // root node: values reversed from btree_info
    for i in 0..nkeys {
        let e = toc_start + i * 8;
        let koff = u16(node, e) as usize;
        let klen = u16(node, e + 2) as usize;
        let voff = u16(node, e + 4) as usize;
        let vlen = u16(node, e + 6) as usize;
        let key = &node[key_area + koff..key_area + koff + klen];
        let (k_oid, ty) = decode_jkey(u64(key, 0));
        if ty == Some(RecordType::Inode) && k_oid == oid {
            return node[val_base - voff..val_base - voff + vlen].to_vec();
        }
    }
    panic!("inode {oid} not found in fs-tree node");
}

#[test]
fn parse_beth_txt_inode_metadata() {
    // inode 20 = /Dir1/Beth.txt. Ground truth from TSK istat: parent 18, size
    // 38, mode 0100644, uid/gid 99/99, nlink 1.
    let v = inode_value(20);
    let inode = Inode::parse(20, &v).expect("parse inode");
    assert_eq!(inode.oid, 20);
    assert_eq!(inode.parent_id, 18);
    assert_eq!(inode.name.as_deref(), Some("Beth.txt"));
    assert_eq!(inode.size, Some(38));
    assert_eq!(inode.mode, 0o100_644);
    assert_eq!(inode.uid, 99);
    assert_eq!(inode.gid, 99);
    assert_eq!(inode.nlink_or_nchildren, 1);
}

#[test]
fn parse_root_dir_inode_metadata() {
    // inode 2 = root dir. TSK istat: mode 0040755, uid/gid 501/20, children 3.
    let v = inode_value(2);
    let inode = Inode::parse(2, &v).expect("parse root inode");
    assert_eq!(inode.mode, 0o040_755);
    assert_eq!(inode.uid, 501);
    assert_eq!(inode.gid, 20);
    assert_eq!(inode.nlink_or_nchildren, 3);
    // The root has no INO_EXT_TYPE_NAME / DSTREAM xfield.
    assert_eq!(inode.size, None);
}

#[test]
fn parse_inode_timestamps_match_istat() {
    // inode 20 (Beth.txt) timestamps in ns since 1970, verbatim from the image,
    // each cross-checked against TSK istat (see docs/validation.md):
    //   Created  = 1782060082608648902
    //   Modified = 1782060082608686902
    //   Accessed = 1782060082733745215
    let v = inode_value(20);
    let inode = Inode::parse(20, &v).expect("parse inode");
    assert_eq!(inode.create_time, 1_782_060_082_608_648_902);
    assert_eq!(inode.mod_time, 1_782_060_082_608_686_902);
    assert_eq!(inode.change_time, 1_782_060_082_608_686_902);
    assert_eq!(inode.access_time, 1_782_060_082_733_745_215);
}

#[test]
fn created_datetime_round_trips() {
    let v = inode_value(20);
    let inode = Inode::parse(20, &v).expect("parse inode");
    let dt = inode.created().expect("create time -> datetime");
    // 1782060082 s = 2026-06-21 (UTC). Check the year/epoch-seconds.
    assert_eq!(dt.timestamp(), 1_782_060_082);
    assert_eq!(dt.timestamp_subsec_nanos(), 608_648_902);
}

#[test]
fn ns_to_datetime_zero_is_epoch() {
    // Zero is a contextual lead, not a sentinel; it still maps to the epoch.
    let dt = ns_to_datetime(0).expect("epoch");
    assert_eq!(dt.timestamp(), 0);
}

#[test]
fn ns_to_datetime_handles_huge_value() {
    // u64::MAX ns is ~year 2554 — within chrono's range, so it decodes rather
    // than panicking. The point is graceful handling of an extreme value.
    let dt = ns_to_datetime(u64::MAX).expect("u64::MAX ns is representable");
    assert!(dt.timestamp() > 0);
}

#[test]
fn inode_datetime_accessors_round_trip() {
    // Exercise modified/changed/accessed alongside created; each must convert the
    // stored ns to a UTC datetime whose seconds match the raw field.
    let v = inode_value(20);
    let inode = Inode::parse(20, &v).expect("parse inode");
    assert_eq!(
        inode.modified().unwrap().timestamp_subsec_nanos(),
        608_686_902
    );
    assert_eq!(
        inode.changed().unwrap().timestamp_subsec_nanos(),
        608_686_902
    );
    assert_eq!(
        inode.accessed().unwrap().timestamp_subsec_nanos(),
        733_745_215
    );
}

#[test]
fn parse_inode_with_unknown_xfield_is_ignored() {
    // An inode value whose xfields carry only an unrecognized type must parse
    // (the unknown field is skipped, name/size stay None).
    let mut v = vec![0u8; 92];
    // xf_blob: 1 ext, used 8; descriptor type=99 (unknown), size=8; 8-byte value.
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&8u16.to_le_bytes());
    v.push(99);
    v.push(0);
    v.extend_from_slice(&8u16.to_le_bytes());
    v.extend_from_slice(&[0u8; 8]);
    let inode = Inode::parse(7, &v).expect("parse inode with unknown xfield");
    assert_eq!(inode.name, None);
    assert_eq!(inode.size, None);
}

#[test]
fn parse_short_inode_value_is_bounded() {
    // A truncated inode value must not panic; fields beyond the buffer read 0.
    let inode = Inode::parse(99, &[0u8; 8]).expect("parse short value");
    assert_eq!(inode.oid, 99);
    assert_eq!(inode.parent_id, 0);
    assert_eq!(inode.name, None);
}
