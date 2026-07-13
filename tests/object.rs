//! Object-header (`obj_phys_t`) + APFS Fletcher-64 validation against a REAL
//! superblock carved from a self-minted APFS container (Tier 2: real Apple
//! `hdiutil` output, ground truth derivable from the documented construction +
//! recomputable Fletcher-64; see `tests/data/README.md`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::object::{fletcher64_checksum, ObjPhys, OBJ_PHYS_LEN};

/// Repo-root `tests/data/` reached from `core/tests/` (two levels up).
const HEAD: &[u8] = include_bytes!("../../tests/data/apfs_nxsb_head.bin");

const BLOCK_SIZE: usize = 4096;

fn block(n: usize) -> &'static [u8] {
    &HEAD[n * BLOCK_SIZE..(n + 1) * BLOCK_SIZE]
}

#[test]
fn obj_phys_header_decodes_real_nxsb_block0() {
    // Block 0 is a copy of the live container superblock (an NX_SUPERBLOCK
    // object). Values verified independently from the raw bytes:
    //   o_cksum  = 0x2d03fdf65e3db5e6
    //   o_oid    = 1, o_xid = 2
    //   o_type   = 0x80000001 (PHYSICAL storage flag | NX_SUPERBLOCK 0x1)
    //   o_subtype= 0x0
    let h = ObjPhys::parse(block(0)).expect("parse block 0 header");
    assert_eq!(h.cksum, 0x2d03_fdf6_5e3d_b5e6);
    assert_eq!(h.oid, 1);
    assert_eq!(h.xid, 2);
    assert_eq!(h.obj_type_raw, 0x8000_0001);
    assert_eq!(h.subtype, 0x0);
    // type after masking off the storage/flag bits == NX_SUPERBLOCK (0x1)
    assert_eq!(h.obj_type(), 0x1);
}

#[test]
fn obj_phys_parse_rejects_short_slice() {
    // A buffer shorter than the 32-byte header must not panic; returns None.
    assert!(ObjPhys::parse(&[0u8; OBJ_PHYS_LEN - 1]).is_none());
    assert!(ObjPhys::parse(&[]).is_none());
}

#[test]
fn fletcher64_recomputes_real_stored_checksum_block0() {
    // The binding validation: the recomputed APFS Fletcher-64 over the object
    // (with the 8-byte o_cksum field zeroed) must equal the checksum Apple's
    // own implementation stored. NOT a synthetic round-trip.
    let blk = block(0);
    let stored = u64::from_le_bytes(blk[0..8].try_into().unwrap());
    assert_eq!(stored, 0x2d03_fdf6_5e3d_b5e6);
    assert_eq!(fletcher64_checksum(blk), stored);
}

#[test]
fn fletcher64_validates_every_real_object_in_the_descriptor_ring() {
    // Every non-empty object block carved from the real image must verify:
    // its recomputed Fletcher-64 equals its stored o_cksum. This exercises
    // NXSB copies, checkpoint maps, spaceman, reaper, and btree objects.
    let mut checked = 0;
    for n in 0..HEAD.len() / BLOCK_SIZE {
        let blk = block(n);
        let stored = u64::from_le_bytes(blk[0..8].try_into().unwrap());
        let oid = u64::from_le_bytes(blk[8..16].try_into().unwrap());
        if stored == 0 && oid == 0 {
            continue; // empty/unallocated block
        }
        assert_eq!(
            fletcher64_checksum(blk),
            stored,
            "block {n} checksum mismatch"
        );
        checked += 1;
    }
    // The 17-block head holds the NXSB copies + descriptor ring + data head.
    assert!(checked >= 10, "expected >=10 real objects, got {checked}");
}

#[test]
fn fletcher64_detects_a_corrupted_object() {
    // Flip a byte in the object body: the recomputed checksum must diverge
    // from the stored one (the basis of APFS-OBJECT-CKSUM-MISMATCH).
    let mut blk = block(0).to_vec();
    let stored = u64::from_le_bytes(blk[0..8].try_into().unwrap());
    blk[100] ^= 0xff;
    assert_ne!(fletcher64_checksum(&blk), stored);
}

#[test]
fn fletcher64_does_not_panic_on_unaligned_or_short_input() {
    // Fuzz-style robustness: any length (incl. not a multiple of 4) is safe.
    for len in [0usize, 1, 3, 7, 31, 33, 4095, 4097] {
        let _ = fletcher64_checksum(&vec![0xABu8; len]);
    }
}
