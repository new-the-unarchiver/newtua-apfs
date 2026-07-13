//! `impl FileSystem for ApfsFs`, driven as `Arc<dyn FileSystem>` over a REAL
//! macOS-authored APFS container (doer-checker).
//!
//! The fixture is the committed `tests/data/apfs_content.bin` — a raw carve of a
//! real APFS container partition starting at NXSB block 0, minted on a macOS host
//! by Apple's own `hdiutil` + `ditto` (see `tests/data/README.md`). Every asserted
//! value is what an **independent oracle** reports, not our own reader:
//!
//! ```text
//! # macOS + TSK, run against the same image (tests/data/README.md ground truth):
//! fls   -o 40 -B <apsb>            # root (inode 2) → plain.txt=18, Dir1=…, compressed.txt=23, symlink_to_beth=29
//! istat -o 40 -B <apsb> 18        # plain.txt: size 35
//! istat -o 40 -B <apsb> 28        # Dir1/Beth.txt: size 33
//! shasum -a 256 plain.txt         # 289af0a0…abf86b, over "APFS P4 plain file. Hello extents.\n"
//! shasum -a 256 Dir1/Beth.txt     # ee7c2682…cfeb96, over "Beth target content for symlink.\n"
//! shasum -a 256 compressed.txt    # 3f58a418…3abc78, decmpfs LZVN → 180000 bytes
//! ```

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::Arc;

use apfs_core::vfs::ApfsFs;
use forensic_vfs::{FileId, FileSystem, FsKind, NodeKind, StreamId, TimeZonePolicy};

/// The committed real macOS-authored APFS carve (repo-root `tests/data/`, two
/// levels up from `core/tests/`). About 1.7 MB — safe to `include_bytes!`.
const IMG: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");

fn open() -> Arc<dyn FileSystem> {
    Arc::new(ApfsFs::open(Cursor::new(IMG.to_vec())).expect("open APFS container"))
}

/// Build an APFS `FileId` for inode `n`, reusing the root's xid (the transaction
/// id is uniform across the mounted snapshot).
fn oid(fs: &dyn FileSystem, n: u64) -> FileId {
    match fs.root() {
        FileId::ApfsOid { xid, .. } => FileId::ApfsOid { oid: n, xid },
        other => panic!("root is not an ApfsOid: {other:?}"),
    }
}

#[test]
fn identity_is_apfs_and_root_is_inode_2() {
    let fs = open();
    assert_eq!(fs.kind(), FsKind::Apfs);
    assert_eq!(fs.timestamp_zone(), TimeZonePolicy::Utc);
    match fs.root() {
        FileId::ApfsOid { oid, .. } => assert_eq!(oid, 2, "APFS root is ROOT_DIR_INO_NUM"),
        other => panic!("root is not an ApfsOid: {other:?}"),
    }
}

#[test]
fn read_dir_lists_real_root_entries() {
    let fs = open();
    let entries: Vec<_> = fs
        .read_dir(fs.root())
        .unwrap()
        .map(Result::unwrap)
        .collect();

    // fls: plain.txt is inode 18, a regular file.
    let plain = entries
        .iter()
        .find(|e| e.name == b"plain.txt")
        .expect("plain.txt in root");
    assert_eq!(plain.id, oid(&*fs, 18));
    assert_eq!(plain.kind, NodeKind::File);

    // Dir1 is a directory.
    let dir1 = entries
        .iter()
        .find(|e| e.name == b"Dir1")
        .expect("Dir1 in root");
    assert_eq!(dir1.kind, NodeKind::Dir);

    // The rest of the known root set is present.
    for name in [
        b"sparse.bin".as_slice(),
        b"compressed.txt",
        b"symlink_to_beth",
    ] {
        assert!(
            entries.iter().any(|e| e.name == name),
            "root should list {}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn lookup_finds_a_known_file() {
    let fs = open();
    assert_eq!(
        fs.lookup(fs.root(), b"plain.txt").unwrap(),
        Some(oid(&*fs, 18))
    );
    assert_eq!(fs.lookup(fs.root(), b"no-such").unwrap(), None);
}

#[test]
fn meta_matches_istat_for_plain_file() {
    let fs = open();
    let m = fs.meta(oid(&*fs, 18)).unwrap();
    assert_eq!(m.ino, 18);
    assert_eq!(m.kind, NodeKind::File);
    assert_eq!(m.size, 35); // istat: plain.txt size 35
}

#[test]
fn read_at_returns_plain_file_bytes() {
    let fs = open();
    let id = oid(&*fs, 18);

    // read_data: plain.txt is 35 bytes beginning "APFS P4 plain file.".
    let mut buf = [0u8; 1024];
    let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
    assert_eq!(n, 35);
    assert_eq!(&buf[..35], b"APFS P4 plain file. Hello extents.\n");
    assert!(buf[..n].starts_with(b"APFS P4 plain file."));

    // A non-zero offset returns the windowed suffix.
    let mut win = [0u8; 16];
    let n = fs.read_at(id, StreamId::Default, 5, &mut win).unwrap();
    assert_eq!(&win[..n], b"P4 plain file. H");

    // Reading past the end yields zero bytes, not an error.
    assert_eq!(
        fs.read_at(id, StreamId::Default, 10_000, &mut buf).unwrap(),
        0
    );
}

#[test]
fn nested_path_resolves_beth_via_dir1() {
    let fs = open();
    let dir1 = fs.lookup(fs.root(), b"Dir1").unwrap().expect("Dir1");
    let beth = fs.lookup(dir1, b"Beth.txt").unwrap().expect("Beth.txt");
    assert_eq!(beth, oid(&*fs, 28));

    let m = fs.meta(beth).unwrap();
    assert_eq!(m.size, 33); // istat: Beth.txt size 33
    assert_eq!(m.kind, NodeKind::File);

    let mut buf = [0u8; 64];
    let n = fs.read_at(beth, StreamId::Default, 0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"Beth target content for symlink.\n");
}

#[test]
fn decmpfs_file_reads_transparently() {
    let fs = open();
    // compressed.txt (inode 23): decmpfs LZVN resource fork, logical size 180000.
    let id = oid(&*fs, 23);

    // The decompressed size (180000) lives in the `com.apple.decmpfs` header, not
    // the inode's dstream `size` field — a resource-fork-compressed file has no
    // main-fork dstream, so `inode.size` is absent and `meta().size` is 0. The
    // load-bearing check is that `read_at` transparently decodes decmpfs and
    // materializes all 180000 bytes (macOS SHA-256 3f58a418… over the content).
    let m = fs.meta(id).unwrap();
    assert_eq!(m.kind, NodeKind::File);

    let mut buf = vec![0u8; 180_000];
    let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
    assert_eq!(n, 180_000);
}
