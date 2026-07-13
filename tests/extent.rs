//! File-extent assembly + sparse-hole handling, validated against the REAL
//! `apfs_content.bin` fixture and the macOS `cp`/`cat` SHA-256 oracle.
//!
//! Ground truth (macOS `shasum -a 256` of each file before detach — see
//! `docs/validation.md` / `tests/data/README.md`):
//!   /plain.txt        inode 18  35 B    sha256 289af0a0…  (single extent, phys 347)
//!   /sparse.bin       inode 22  69632 B sha256 fe0fc4fa…  (HOLE phys 0 + tail phys 371)
//!   /Dir1/Beth.txt    inode 28  33 B    sha256 ee7c2682…  (single extent, phys 400)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::open_path;
use apfs_core::extent::read_data;
use apfs_core::volume::ApfsVolume;
use sha2::{Digest, Sha256};

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB, xid 14) sits at block 438 in the fixture.
const APSB_BLOCK: usize = 438;

fn volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[test]
fn reads_plain_file_byte_identical() {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/plain.txt", BLOCK_SIZE).expect("open plain.txt");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read plain.txt");
    assert_eq!(bytes.len(), 35);
    assert_eq!(
        &bytes, b"APFS P4 plain file. Hello extents.\n",
        "plain content must match"
    );
    assert_eq!(
        sha256_hex(&bytes),
        "289af0a0b21ede77675f1173c65cc2388d3b26570dbaaa7f2506444e05abf86b",
        "plain.txt SHA-256 must match macOS cp"
    );
}

#[test]
fn reads_sparse_file_with_hole_byte_identical() {
    // sparse.bin is 69632 logical bytes: a 64 KiB hole (phys 0) then a 4 KiB
    // tail extent at logical offset 65536. The hole must read back as zeroes and
    // the tail truncated to the DSTREAM size.
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/sparse.bin", BLOCK_SIZE).expect("open sparse.bin");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read sparse.bin");
    assert_eq!(bytes.len(), 69632, "logical size honoured");
    // The hole region [0, 65536) is all zero.
    assert!(
        bytes[..65536].iter().all(|&b| b == 0),
        "sparse hole must be zero-filled"
    );
    // The tail [65536, 69632) is real data (non-zero somewhere).
    assert!(
        bytes[65536..].iter().any(|&b| b != 0),
        "sparse tail carries data"
    );
    assert_eq!(
        sha256_hex(&bytes),
        "fe0fc4fa9e8465dd74086a9e37d21d1a69c0f4d08cf6b9abbb288886d4cc822a",
        "sparse.bin SHA-256 must match macOS cp"
    );
}

#[test]
fn reads_nested_file_byte_identical() {
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/Dir1/Beth.txt", BLOCK_SIZE).expect("open Beth.txt");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read Beth.txt");
    assert_eq!(bytes.len(), 33);
    assert_eq!(
        sha256_hex(&bytes),
        "ee7c26829909d9c7ea1bcb444908fff35c1254f3c51894bd49b8b175becfeb96",
        "Beth.txt SHA-256 must match macOS cp"
    );
}

#[test]
fn list_extents_reports_hole_and_tail() {
    // The lower-level extent list surfaces the raw records, including the
    // sparse hole (phys_block_num 0).
    use apfs_core::extent::list_extents;
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/sparse.bin", BLOCK_SIZE).expect("open sparse.bin");
    let extents = list_extents(&mut r, &vol, inode.private_id, BLOCK_SIZE).expect("list extents");
    // Two extents: a 64 KiB hole at offset 0, a 4 KiB tail at 65536.
    assert_eq!(extents.len(), 2, "got {extents:?}");
    let hole = extents.iter().find(|e| e.logical_offset == 0).unwrap();
    assert_eq!(hole.phys_block_num, 0, "first extent is a hole");
    assert_eq!(hole.len, 65536);
    let tail = extents.iter().find(|e| e.logical_offset == 65536).unwrap();
    assert_ne!(tail.phys_block_num, 0, "tail is backed by a physical block");
    assert_eq!(tail.len, 4096);
}

/// Synthetic single-leaf virtual fs-tree, used to drive the defensive guards and
/// the inline-compressed `read_data` path that the real macOS corpus does not
/// exercise (`ditto` chose a resource-fork file, and a real image never carries a
/// 16-gibibyte `DSTREAM` size or a near-overflow physical block). All objects
/// carry valid Fletcher-64 checksums so the reader trusts them.
mod synthetic {
    use super::{Cursor, BLOCK_SIZE};
    use apfs_core::extent::{read_data, read_stream};
    use apfs_core::object::fletcher64_checksum;
    use apfs_core::volume::ApfsVolume;

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
        put_u16(block, 32, 0x7); // ROOT|LEAF|FIXED
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
        put_u16(block, 32, 0x3); // ROOT|LEAF
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
    fn write_apsb(block: &mut [u8], omap_oid: u64, root_tree_oid: u64) {
        put_u64(block, 16, 1); // o_xid
        put_u32(block, 32, 0x4253_5041); // APSB
        put_u64(block, 128, omap_oid);
        put_u64(block, 136, root_tree_oid);
        block[704..707].copy_from_slice(b"SYN");
        seal(block, 0xd);
    }

    /// Build a 5-block image: blk0 APSB, blk1 omap header, blk2 omap tree
    /// (oid 100 -> blk3 fs leaf), blk3 fs leaf with `records`, blk4 spare data.
    fn build(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut img = vec![0u8; BLOCK_SIZE * 5];
        write_apsb(&mut img[0..BLOCK_SIZE], 1, 100);
        write_omap_header(&mut img[BLOCK_SIZE..2 * BLOCK_SIZE], 2);
        write_omap_tree(&mut img[2 * BLOCK_SIZE..3 * BLOCK_SIZE], &[(100, 3)]);
        write_fs_leaf(&mut img[3 * BLOCK_SIZE..4 * BLOCK_SIZE], records);
        img
    }

    /// A `j_inode_val_t` whose only xfield is a DSTREAM giving `size`.
    fn inode_value_with_size(size: u64) -> Vec<u8> {
        let mut v = vec![0u8; 92]; // fixed prefix
                                   // xf_blob: num_exts 1, used_data 8, one descriptor (DSTREAM type 8, size 8).
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&[8u8, 0]); // x_type=DSTREAM, x_flags
        v.extend_from_slice(&8u16.to_le_bytes()); // x_size
        v.extend_from_slice(&size.to_le_bytes()); // DSTREAM used_size
        v
    }

    fn file_extent(oid: u64, logical: u64, len: u64, phys: u64) -> (Vec<u8>, Vec<u8>) {
        let mut key = jkey(8, oid).to_le_bytes().to_vec();
        key.extend_from_slice(&logical.to_le_bytes());
        let mut val = (len & 0x00ff_ffff_ffff_ffff).to_le_bytes().to_vec();
        val.extend_from_slice(&phys.to_le_bytes());
        val.extend_from_slice(&0u64.to_le_bytes()); // crypto_id
        (key, val)
    }

    #[test]
    fn read_stream_rejects_oversize_dstream() {
        // A DSTREAM size beyond the 16 GiB cap is an allocation-bomb lead: refuse.
        let img = build(&[]);
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("apsb");
        let mut r = Cursor::new(img);
        let huge = (1u64 << 34) + 1;
        match read_stream(&mut r, &vol, 50, huge, BLOCK_SIZE) {
            Err(apfs_core::ApfsError::FieldOutOfRange { field: "size", .. }) => {}
            other => panic!("expected FieldOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn read_stream_rejects_overflowing_phys_block() {
        // A physical block number whose byte offset overflows u64 is a hostile
        // record: refuse rather than wrap the seek.
        let inode_oid = 50u64;
        let ext = file_extent(inode_oid, 0, BLOCK_SIZE as u64, u64::MAX);
        let img = build(&[ext]);
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("apsb");
        let mut r = Cursor::new(img);
        match read_stream(&mut r, &vol, inode_oid, BLOCK_SIZE as u64, BLOCK_SIZE) {
            Err(apfs_core::ApfsError::FieldOutOfRange {
                field: "phys_block_num",
                ..
            }) => {}
            other => panic!("expected phys overflow, got {other:?}"),
        }
    }

    #[test]
    fn read_data_decodes_inline_compressed_end_to_end() {
        // An inline type-1 (uncompressed) decmpfs file drives read_data's
        // compressed branch through read_compressed's no-resource-fork path.
        let inode_oid = 50u64;
        let content = b"inline decmpfs content via read_data";
        // inode record (size is ignored for a compressed file).
        let inode_rec = (
            jkey(3, inode_oid).to_le_bytes().to_vec(),
            inode_value_with_size(0),
        );
        // decmpfs xattr (embedded, type 1, the content verbatim).
        let mut xattr_key = jkey(4, inode_oid).to_le_bytes().to_vec();
        let name = b"com.apple.decmpfs\0";
        xattr_key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        xattr_key.extend_from_slice(name);
        let mut hdr = 0x636d_7066u32.to_le_bytes().to_vec(); // cmpf
        hdr.extend_from_slice(&1u32.to_le_bytes()); // type 1
        hdr.extend_from_slice(&(content.len() as u64).to_le_bytes());
        hdr.extend_from_slice(content);
        let mut xattr_val = 0x0002u16.to_le_bytes().to_vec(); // EMBEDDED
        xattr_val.extend_from_slice(&(hdr.len() as u16).to_le_bytes());
        xattr_val.extend_from_slice(&hdr);
        let img = build(&[inode_rec, (xattr_key, xattr_val)]);
        let vol = ApfsVolume::parse(&img[0..BLOCK_SIZE]).expect("apsb");
        let mut r = Cursor::new(img);
        let inode =
            apfs_core::dir::load_inode(&mut r, &vol, inode_oid, BLOCK_SIZE).expect("load inode");
        let out = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("read inline compressed");
        assert_eq!(out, content);
    }
}
