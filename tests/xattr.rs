//! Extended-attribute listing and symlink-target resolution, validated against
//! the REAL `apfs_content.bin` fixture and the macOS `xattr -l` / `readlink`
//! oracles.
//!
//! Ground truth (macOS `xattr -l` / `readlink` before detach — see
//! `tests/data/README.md`):
//!   /plain.txt        inode 18  xattrs: com.example.tag="forensic-marker-P4",
//!                                       user.note="second custom attr"
//!   /compressed.txt   inode 23  xattrs: com.apple.decmpfs (embedded header,
//!                                       type 8), com.apple.ResourceFork (stream)
//!   `/symlink_to_beth`  inode 29  com.apple.fs.symlink -> "Dir1/Beth.txt"
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::open_path;
use apfs_core::volume::ApfsVolume;
use apfs_core::xattr::{
    get_xattr, list_xattrs, symlink_target, XattrValue, XATTR_NAME_DECMPFS,
    XATTR_NAME_RESOURCE_FORK,
};

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
const APSB_BLOCK: usize = 438;

fn volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn inode_oid(path: &str) -> u64 {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    open_path(&mut r, &vol, path, BLOCK_SIZE)
        .unwrap_or_else(|_| panic!("open {path}"))
        .oid
}

#[test]
fn lists_custom_xattrs_matching_xattr_l() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let xattrs = list_xattrs(&mut r, &vol, oid, BLOCK_SIZE).expect("list xattrs");
    let named: Vec<(&str, &[u8])> = xattrs
        .iter()
        .map(|x| {
            let bytes: &[u8] = match &x.value {
                XattrValue::Embedded(b) => b,
                _ => &[],
            };
            (x.name.as_str(), bytes)
        })
        .collect();
    assert!(
        named.contains(&("com.example.tag", b"forensic-marker-P4".as_slice())),
        "got {named:?}"
    );
    assert!(
        named.contains(&("user.note", b"second custom attr".as_slice())),
        "got {named:?}"
    );
}

#[test]
fn get_xattr_returns_embedded_value() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let v = get_xattr(&mut r, &vol, oid, "com.example.tag", BLOCK_SIZE)
        .expect("get_xattr")
        .expect("present");
    match v {
        XattrValue::Embedded(b) => assert_eq!(b, b"forensic-marker-P4"),
        other => panic!("expected embedded, got {other:?}"),
    }
}

#[test]
fn get_xattr_absent_is_none() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    assert!(get_xattr(&mut r, &vol, oid, "no.such.attr", BLOCK_SIZE)
        .expect("get_xattr")
        .is_none());
}

#[test]
fn compressed_file_carries_decmpfs_and_resource_fork() {
    let oid = inode_oid("/compressed.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    // decmpfs is an embedded 16-byte header: magic 'cmpf', type 8, usize 180000.
    let decmpfs = get_xattr(&mut r, &vol, oid, XATTR_NAME_DECMPFS, BLOCK_SIZE)
        .expect("get decmpfs")
        .expect("decmpfs present");
    match decmpfs {
        XattrValue::Embedded(b) => {
            assert_eq!(&b[0..4], &0x636d_7066u32.to_le_bytes(), "magic 'cmpf'");
            assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 8, "type 8");
            assert_eq!(
                u64::from_le_bytes(b[8..16].try_into().unwrap()),
                180_000,
                "uncompressed_size"
            );
        }
        other => panic!("decmpfs should be embedded, got {other:?}"),
    }
    // ResourceFork is a STREAM xattr (the bulk compressed payload).
    let fork = get_xattr(&mut r, &vol, oid, XATTR_NAME_RESOURCE_FORK, BLOCK_SIZE)
        .expect("get fork")
        .expect("fork present");
    match fork {
        XattrValue::Stream { dstream_oid, size } => {
            assert_eq!(dstream_oid, 24, "resource-fork dstream id");
            assert_eq!(size, 1526, "resource-fork compressed size");
        }
        other => panic!("ResourceFork should be a stream, got {other:?}"),
    }
}

#[test]
fn resource_fork_reads_back_the_stream_bytes() {
    let oid = inode_oid("/compressed.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let fork = apfs_core::xattr::resource_fork(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("read fork")
        .expect("fork present");
    assert_eq!(fork.len(), 1526, "resource-fork size from the dstream");
    // The chunked LZVN fork header: little-endian headerSize 16, then end-offsets.
    assert_eq!(u32::from_le_bytes(fork[0..4].try_into().unwrap()), 16);
}

#[test]
fn resolves_symlink_target_matching_readlink() {
    let oid = inode_oid("/symlink_to_beth");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let target = symlink_target(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("symlink_target")
        .expect("is a symlink");
    assert_eq!(target, "Dir1/Beth.txt", "must match readlink");
}

#[test]
fn non_symlink_has_no_symlink_target() {
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    assert!(symlink_target(&mut r, &vol, oid, BLOCK_SIZE)
        .expect("symlink_target")
        .is_none());
}

#[test]
fn file_without_resource_fork_yields_none() {
    // plain.txt has custom xattrs but no com.apple.ResourceFork.
    let oid = inode_oid("/plain.txt");
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    assert!(
        apfs_core::xattr::resource_fork(&mut r, &vol, oid, BLOCK_SIZE)
            .expect("resource_fork")
            .is_none()
    );
}

/// Synthetic single-leaf fs-tree exercising the xattr paths the real macOS
/// corpus does not produce: an *embedded* (rather than stream) ResourceFork, and
/// a malformed zero-length-name XATTR key that must be skipped.
mod synthetic {
    use super::{Cursor, BLOCK_SIZE};
    use apfs_core::object::fletcher64_checksum;
    use apfs_core::volume::ApfsVolume;
    use apfs_core::xattr::{list_xattrs, resource_fork, XattrValue};

    fn put_u16(b: &mut [u8], o: usize, v: u16) {
        b[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(b: &mut [u8], o: usize, v: u64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn seal(block: &mut [u8], obj_type: u16) {
        put_u32(block, 24, u32::from(obj_type));
        let c = fletcher64_checksum(block);
        block[0..8].copy_from_slice(&c.to_le_bytes());
    }
    fn jkey(ty: u64, oid: u64) -> u64 {
        (ty << 60) | oid
    }

    fn write_omap_tree(block: &mut [u8], maps: &[(u64, u64)]) {
        put_u16(block, 32, 0x7);
        put_u32(block, 36, maps.len() as u32);
        put_u16(block, 42, (maps.len() * 4) as u16);
        let toc = 56;
        let key_area = toc + maps.len() * 4;
        let val_base = BLOCK_SIZE - 40;
        for (i, &(oid, paddr)) in maps.iter().enumerate() {
            let voff = ((i + 1) * 16) as u16;
            put_u16(block, toc + i * 4, (i * 16) as u16);
            put_u16(block, toc + i * 4 + 2, voff);
            put_u64(block, key_area + i * 16, oid);
            put_u64(block, key_area + i * 16 + 8, 1);
            let vs = val_base - voff as usize;
            put_u32(block, vs + 4, BLOCK_SIZE as u32);
            put_u64(block, vs + 8, paddr);
        }
        seal(block, 0xb);
    }
    fn write_omap_header(block: &mut [u8], tree_paddr: u64) {
        put_u64(block, 48, tree_paddr);
        seal(block, 0xb);
    }
    fn write_fs_leaf(block: &mut [u8], entries: &[(Vec<u8>, Vec<u8>)]) {
        put_u16(block, 32, 0x3);
        put_u32(block, 36, entries.len() as u32);
        put_u16(block, 42, (entries.len() * 8) as u16);
        let toc = 56;
        let key_area = toc + entries.len() * 8;
        let val_base = BLOCK_SIZE - 40;
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
        seal(block, 0xe);
    }
    fn write_apsb(block: &mut [u8]) {
        put_u64(block, 16, 1);
        put_u32(block, 32, 0x4253_5041);
        put_u64(block, 128, 1); // omap_oid
        put_u64(block, 136, 100); // root_tree_oid (virtual)
        block[704..707].copy_from_slice(b"SYN");
        seal(block, 0xd);
    }
    fn build(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut img = vec![0u8; BLOCK_SIZE * 4];
        write_apsb(&mut img[0..BLOCK_SIZE]);
        write_omap_header(&mut img[BLOCK_SIZE..2 * BLOCK_SIZE], 2);
        write_omap_tree(&mut img[2 * BLOCK_SIZE..3 * BLOCK_SIZE], &[(100, 3)]);
        write_fs_leaf(&mut img[3 * BLOCK_SIZE..4 * BLOCK_SIZE], records);
        img
    }

    /// An XATTR record: `name` (with NUL) in the key, embedded `data` in the value.
    fn embedded_xattr(oid: u64, name: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = jkey(4, oid).to_le_bytes().to_vec();
        key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        key.extend_from_slice(name);
        let mut val = 0x0002u16.to_le_bytes().to_vec(); // EMBEDDED
        val.extend_from_slice(&(data.len() as u16).to_le_bytes());
        val.extend_from_slice(data);
        (key, val)
    }

    #[test]
    fn resource_fork_embedded_is_returned_inline() {
        // A small resource fork can be embedded directly in the xattr.
        let oid = 60u64;
        let fork_bytes = b"embedded resource fork payload";
        let rec = embedded_xattr(oid, b"com.apple.ResourceFork\0", fork_bytes);
        let img = build(&[rec]);
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("apsb");
        let mut r = Cursor::new(img);
        let fork = resource_fork(&mut r, &vol, oid, BLOCK_SIZE)
            .expect("resource_fork")
            .expect("present");
        assert_eq!(fork, fork_bytes);
    }

    #[test]
    fn zero_length_name_xattr_is_skipped() {
        // A malformed XATTR key claiming name_len 0 decodes to no name and is
        // dropped, leaving only the valid attribute.
        let oid = 60u64;
        let mut bad_key = jkey(4, oid).to_le_bytes().to_vec();
        bad_key.extend_from_slice(&0u16.to_le_bytes()); // name_len = 0
        let bad_val = {
            let mut v = 0x0002u16.to_le_bytes().to_vec();
            v.extend_from_slice(&0u16.to_le_bytes());
            v
        };
        let good = embedded_xattr(oid, b"user.ok\0", b"value");
        let img = build(&[(bad_key, bad_val), good]);
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("apsb");
        let mut r = Cursor::new(img);
        let xattrs = list_xattrs(&mut r, &vol, oid, BLOCK_SIZE).expect("list");
        assert_eq!(xattrs.len(), 1, "malformed-name record skipped");
        assert_eq!(xattrs[0].name, "user.ok");
        match &xattrs[0].value {
            XattrValue::Embedded(b) => assert_eq!(b, b"value"),
            other => panic!("expected embedded, got {other:?}"),
        }
    }
}
