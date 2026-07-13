//! Snapshot metadata + name trees and the point-in-time volume view, validated
//! against real, Apple-authored APFS images.
//!
//! Two corpora drive this test:
//!
//!   * **`apfs_content.bin`** (the P4 fixture, NO snapshots): a real Apple-minted
//!     container whose volume APSB (block 438) carries an **empty** snap-metadata
//!     tree (block 340, `o_subtype` 0x10 SNAPMETATREE, `btn_nkeys` 0). It proves
//!     the tree is *located* and walked correctly on real data and yields zero
//!     snapshots (Tier-2: real Apple structure, ground truth = the documented
//!     empty tree). No `todo!`, no synthetic snap-meta tree.
//!
//!   * **`APFS_P5_FIXTURE`** (env-gated, a container *with* snapshots and a file
//!     whose content changes between snapshots): validates the populated
//!     snap-metadata list (names, xids, create-times) against `diskutil apfs
//!     listSnapshots` / `fsapfsinfo`, the snap-name to xid resolution, and the
//!     **point-in-time read** (v1 bytes at snapshot 1's frozen APSB vs v2 at the
//!     live APSB). Skips cleanly when the fixture is absent, like an oracle
//!     binary (the snapshot-with-changing-file image needs the macOS snapshot
//!     entitlement to mint — see `docs/validation.md` / `tests/data/README.md`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::snapshot::{list_snapshots, mount_snapshot, resolve_snapshot_xid};
use apfs_core::volume::ApfsVolume;

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB) sits at block 438 in the P4 fixture.
const APSB_BLOCK: usize = 438;

fn p4_volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

#[test]
fn real_unsnapshotted_volume_lists_zero_snapshots() {
    // The P4 fixture has no snapshots: its snap-metadata tree (a real
    // Apple-authored physical btree at block 340, o_subtype 0x10) has
    // btn_nkeys == 0. The walk must locate it, verify its Fletcher-64 checksum,
    // and return an empty list — never a todo!/panic, never a bootstrap error.
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let snaps = list_snapshots(&mut r, &vol, BLOCK_SIZE).expect("list snapshots");
    assert!(
        snaps.is_empty(),
        "P4 fixture has no snapshots; got {snaps:?}"
    );
}

#[test]
fn real_volume_exposes_snap_meta_tree_oid() {
    // The snap-metadata tree is located by a *physical* block number in the APSB
    // (apfs_snap_meta_tree_oid @152). For the P4 fixture that is block 340.
    let vol = p4_volume();
    assert_eq!(vol.snap_meta_tree_oid(), 340);
}

#[test]
fn real_unsnapshotted_volume_resolves_no_name() {
    // The empty snap-meta tree has no SNAP_NAME records, so resolving any name
    // returns None (a clean per-item miss, walked over real Apple structure —
    // never a bootstrap error, never a panic).
    let mut r = Cursor::new(CONTENT);
    let vol = p4_volume();
    let xid = resolve_snapshot_xid(&mut r, &vol, "nonexistent", BLOCK_SIZE)
        .expect("resolve snapshot name");
    assert_eq!(xid, None, "no snapshot named 'nonexistent' exists");
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A `Read + Seek` view of a partition embedded at `base` bytes within a larger
/// image — e.g. the APFS container partition inside a whole GPT disk image (a
/// Tart VM `disk.img`). Logical offset 0 maps to `base`, so an unmodified
/// `ApfsContainer::open` (which seeks `Start(0)`) lands on the container. Only
/// `Start`/`Current` seeks are exercised by the reader; `End` is unsupported
/// because the partition length is not tracked.
struct PartitionView<R> {
    inner: R,
    base: u64,
}

impl<R: std::io::Seek> PartitionView<R> {
    fn new(mut inner: R, base: u64) -> std::io::Result<Self> {
        inner.seek(std::io::SeekFrom::Start(base))?;
        Ok(Self { inner, base })
    }
}

impl<R: std::io::Read> std::io::Read for PartitionView<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: std::io::Seek> std::io::Seek for PartitionView<R> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom;
        let abs = match pos {
            SeekFrom::Start(o) => self.inner.seek(SeekFrom::Start(self.base + o))?,
            SeekFrom::Current(d) => self.inner.seek(SeekFrom::Current(d))?,
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "End-relative seek unsupported on a partition view",
                ))
            }
        };
        Ok(abs.saturating_sub(self.base))
    }
}

fn read_block<R: std::io::Read + std::io::Seek>(r: &mut R, block: u64, bs: usize) -> Vec<u8> {
    use std::io::SeekFrom;
    r.seek(SeekFrom::Start(block * bs as u64))
        .expect("seek block");
    let mut buf = vec![0u8; bs];
    r.read_exact(&mut buf).expect("read block");
    buf
}

/// Env-gated populated-fixture validation (Tier-2, real Apple-minted snapshots).
///
/// `APFS_P5_FIXTURE` points at an APFS image carrying ≥2 snapshots and a file
/// whose content differs between a snapshot and the live volume. The image may
/// be a raw container partition *or* a whole GPT disk (e.g. a Tart VM
/// `disk.img`): `APFS_P5_PART_OFFSET` gives the container partition's byte
/// offset (default 0), and the image is opened as a seekable `File` through a
/// [`PartitionView`] rather than slurped, so a multi-GB disk works without
/// reading it into memory. The live volume's APSB is *derived* from the
/// container object map (`volume_superblock_addrs`), and the Data volume is
/// picked as the one carrying the snapshots — no per-image block numbers are
/// hard-coded. `APFS_P5_FILE` (default `/changing.txt`) is the changing file's
/// path within that volume. The test reads it at the earliest snapshot (v1) vs
/// the live volume (v2) and asserts each matches the macOS-written SHA-256
/// (`APFS_P5_V1_SHA256` / `APFS_P5_V2_SHA256`). Skips cleanly when the fixture
/// env var is unset — see `docs/validation.md` / `tests/data/README.md`.
#[test]
fn populated_fixture_point_in_time_read() {
    let Ok(path) = std::env::var("APFS_P5_FIXTURE") else {
        eprintln!("APFS_P5_FIXTURE unset; skipping populated point-in-time test");
        return;
    };
    let part_offset: u64 = std::env::var("APFS_P5_PART_OFFSET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let file = std::env::var("APFS_P5_FILE").unwrap_or_else(|_| "/changing.txt".to_string());

    let f = std::fs::File::open(&path).expect("open APFS_P5_FIXTURE");
    let mut r = PartitionView::new(f, part_offset).expect("seek to container partition");

    let mut container = apfs_core::ApfsContainer::open(&mut r).expect("open container");
    // Derive every volume's APSB block from the container omap (not hard-coded),
    // then pick the Data volume as the one carrying the snapshots (the sealed
    // System volume and the others have none).
    let apsb_addrs = container
        .volume_superblock_addrs()
        .expect("resolve volume APSB addrs");
    drop(container); // release the &mut borrow on `r`

    let mut best: Option<(ApfsVolume, Vec<apfs_core::snapshot::Snapshot>)> = None;
    for &paddr in &apsb_addrs {
        let block = read_block(&mut r, paddr, BLOCK_SIZE);
        let Ok(vol) = ApfsVolume::parse(&block) else {
            continue;
        };
        let snaps = list_snapshots(&mut r, &vol, BLOCK_SIZE).unwrap_or_default();
        if best.as_ref().is_none_or(|(_, b)| snaps.len() > b.len()) {
            best = Some((vol, snaps));
        }
    }
    let (live, snaps) = best.expect("fixture must expose at least one volume");
    assert!(
        snaps.len() >= 2,
        "expected >=2 snapshots in the populated fixture, got {}",
        snaps.len()
    );
    // snap-name resolution must round-trip every snapshot's name back to its xid.
    for s in &snaps {
        let resolved =
            resolve_snapshot_xid(&mut r, &live, &s.name, BLOCK_SIZE).expect("resolve name");
        assert_eq!(resolved, Some(s.xid), "snap-name {} -> xid", s.name);
    }

    // Point-in-time: read the changing file at the EARLIEST snapshot (v1) vs live (v2).
    use apfs_core::dir::open_path;
    use apfs_core::extent::read_data;
    let snap_v1 = snaps.iter().min_by_key(|s| s.xid).expect("snapshot");
    let snap_vol =
        mount_snapshot(&mut r, &live, snap_v1, BLOCK_SIZE).expect("mount earliest snapshot");
    let v1_inode = open_path(&mut r, &snap_vol, &file, BLOCK_SIZE).expect("open v1 file");
    let v1 = read_data(&mut r, &snap_vol, &v1_inode, BLOCK_SIZE).expect("read v1");
    let live_inode = open_path(&mut r, &live, &file, BLOCK_SIZE).expect("open live file");
    let v2 = read_data(&mut r, &live, &live_inode, BLOCK_SIZE).expect("read v2");

    let v1_sha = std::env::var("APFS_P5_V1_SHA256").expect("APFS_P5_V1_SHA256 must be set");
    let v2_sha = std::env::var("APFS_P5_V2_SHA256").expect("APFS_P5_V2_SHA256 must be set");
    assert_eq!(sha256_hex(&v1), v1_sha, "snapshot file = v1 bytes");
    assert_eq!(sha256_hex(&v2), v2_sha, "live file = v2 bytes");
    assert_ne!(
        v1, v2,
        "v1 and v2 must differ (content changed across snapshot)"
    );
}
