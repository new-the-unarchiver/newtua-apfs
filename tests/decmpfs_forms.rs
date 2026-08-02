//! Both storage forms of the `com.apple.decmpfs` xattr, on a REAL macOS-minted
//! image, validated against the macOS `shasum -a 256` oracle.
//!
//! APFS keeps an xattr value inline (`XATTR_DATA_EMBEDDED`, flags `0x2`) only
//! while it fits in the fs-tree record; past a couple of hundred bytes it moves
//! the value into a data stream (`XATTR_DATA_STREAM`, flags `0x1`). Both forms
//! occur on an ordinary volume, so a reader that handles only the embedded one
//! returns **zero bytes and no error** for every larger file — which is exactly
//! the bug this fixture pins. `apfs_decmpfs.bin` carries all four files
//! compressed the same way (decmpfs type 3, zlib in the xattr) and differing
//! only in that storage form:
//!
//! | file | xattr form | flags | xattr len | logical size |
//! |---|---|---|---:|---:|
//! | `/hello.txt` | embedded | `0x2` | 32 | 15 |
//! | `/привет.txt` | embedded | `0x2` | 39 | 22 |
//! | `/big.txt` | stream (dstream 22) | `0x1` | 226 | 65529 |
//! | `/nested/deep/tiny.bin` | stream (dstream 23) | `0x1` | 273 | 256 |
//!
//! Ground truth: the SHA-256 column below is macOS's own read of each file
//! (`shasum -a 256` on the mounted volume), and `afsctool -v` independently
//! reports "ZLIB in decmpfs xattr (3)" plus the same "uncompressed file size
//! reported in compressed header" for each. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::dir::open_path;
use apfs_core::extent::{data_size, read_data};
use apfs_core::volume::ApfsVolume;
use apfs_core::xattr::{decmpfs_header, get_xattr, XattrValue, XATTR_NAME_DECMPFS};
use sha2::{Digest, Sha256};

const IMAGE: &[u8] = include_bytes!("data/apfs_decmpfs.bin");
const BLOCK_SIZE: usize = 4096;
/// The live volume superblock (APSB) sits at block 199 in the carve.
const APSB_BLOCK: usize = 199;

/// One compressed file: what macOS reports for it, and how APFS stored its
/// `com.apple.decmpfs` xattr.
struct Case {
    path: &'static str,
    inode: u64,
    /// Logical size — what macOS shows and what a read must return.
    size: u64,
    /// macOS `shasum -a 256` of the file's content.
    sha256: &'static str,
    /// `j_xattr_val_t.flags` of the decmpfs xattr (`0x2` embedded, `0x1` stream).
    xattr_flags: u16,
    /// Length of the decmpfs xattr value (header + inline zlib payload).
    xattr_len: usize,
}

const CASES: &[Case] = &[
    Case {
        path: "/hello.txt",
        inode: 21,
        size: 15,
        sha256: "d8bfbcfd8b1bce61f3abbd65de37d13f354e2c73c7a6d5f362353317c2ffce42",
        xattr_flags: 0x2,
        xattr_len: 32,
    },
    Case {
        path: "/привет.txt",
        inode: 17,
        size: 22,
        sha256: "f509c862e2613c56f3b322e4b080e013ece8259a549ffd81113a335b67a840ca",
        xattr_flags: 0x2,
        xattr_len: 39,
    },
    Case {
        path: "/big.txt",
        inode: 16,
        size: 65529,
        sha256: "df1515a6fad9ce2f8141ff97f1e14ca7873ca48e50a95185efd64a55df216bec",
        xattr_flags: 0x1,
        xattr_len: 226,
    },
    Case {
        path: "/nested/deep/tiny.bin",
        inode: 20,
        size: 256,
        sha256: "1455fb514dcd6af818919b765a99cbebf7d91d7994341cc1d4f350ecc65e0a36",
        xattr_flags: 0x1,
        xattr_len: 273,
    },
];

fn volume() -> ApfsVolume {
    let block = &IMAGE[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
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
fn every_compressed_file_reads_byte_identical_to_macos() {
    let mut r = Cursor::new(IMAGE);
    let vol = volume();
    for c in CASES {
        let inode = open_path(&mut r, &vol, c.path, BLOCK_SIZE).expect(c.path);
        assert_eq!(inode.oid, c.inode, "{} inode", c.path);
        let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect(c.path);
        // Length first: the defect this pins returned Ok(vec![]) — a silent
        // empty file, which only a content check catches.
        assert_eq!(bytes.len() as u64, c.size, "{} decoded length", c.path);
        assert_eq!(
            sha256_hex(&bytes),
            c.sha256,
            "{} content must match the macOS shasum oracle",
            c.path
        );
    }
}

#[test]
fn the_fixture_really_carries_both_xattr_storage_forms() {
    // If APFS ever embedded all four values, the test above would pass without
    // exercising the stream path at all — so assert the fixture's own premise.
    let mut r = Cursor::new(IMAGE);
    let vol = volume();
    let mut embedded = 0;
    let mut streamed = 0;
    for c in CASES {
        let value = get_xattr(&mut r, &vol, c.inode, XATTR_NAME_DECMPFS, BLOCK_SIZE)
            .expect("get decmpfs xattr")
            .unwrap_or_else(|| panic!("{} has no decmpfs xattr", c.path));
        match (&value, c.xattr_flags) {
            (XattrValue::Embedded(bytes), 0x2) => {
                assert_eq!(bytes.len(), c.xattr_len, "{} embedded length", c.path);
                embedded += 1;
            }
            (XattrValue::Stream { size, .. }, 0x1) => {
                assert_eq!(*size as usize, c.xattr_len, "{} stream length", c.path);
                streamed += 1;
            }
            other => panic!("{} unexpected xattr form {other:?}", c.path),
        }
    }
    assert_eq!(embedded, 2, "embedded-form decmpfs xattrs");
    assert_eq!(streamed, 2, "stream-form decmpfs xattrs");
}

#[test]
fn stream_form_decmpfs_header_is_read_whole() {
    // The header of a stream-backed value must come back complete — magic and
    // all — not as the `None` that silently made the file read empty.
    let mut r = Cursor::new(IMAGE);
    let vol = volume();
    for c in CASES {
        let header = decmpfs_header(&mut r, &vol, c.inode, BLOCK_SIZE)
            .expect("decmpfs header")
            .unwrap_or_else(|| panic!("{} decmpfs header missing", c.path));
        assert_eq!(header.len(), c.xattr_len, "{} header+payload", c.path);
        assert_eq!(&header[..4], b"fpmc", "{} decmpfs magic", c.path);
        // All four are type 3 (zlib, payload inline in the xattr).
        assert_eq!(header[4], 3, "{} compression type", c.path);
    }
}

#[test]
fn data_size_reports_the_logical_size_the_inode_does_not_have() {
    // A transparently-compressed file has no data stream, so its inode carries
    // no DSTREAM xfield: `inode.size` is 0 for all four. The real size is only
    // in the decmpfs header.
    let mut r = Cursor::new(IMAGE);
    let vol = volume();
    for c in CASES {
        let inode = open_path(&mut r, &vol, c.path, BLOCK_SIZE).expect(c.path);
        assert_eq!(
            inode.size,
            Some(0),
            "{}: a compressed file has no dstream size",
            c.path
        );
        let size = data_size(&mut r, &vol, &inode, BLOCK_SIZE).expect("data_size");
        assert_eq!(size, c.size, "{} logical size", c.path);
        // And it is exactly what a read produces.
        let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect(c.path);
        assert_eq!(size, bytes.len() as u64, "{} size vs read", c.path);
    }
}

#[test]
fn data_size_of_an_uncompressed_file_is_the_inode_size() {
    // The other fixture's plain 35-byte file: no decmpfs xattr, so `data_size`
    // must fall through to the inode's own DSTREAM size.
    const CONTENT: &[u8] = include_bytes!("data/apfs_content.bin");
    let mut r = Cursor::new(CONTENT);
    let vol = ApfsVolume::parse(&CONTENT[438 * BLOCK_SIZE..439 * BLOCK_SIZE]).expect("APSB");
    let inode = open_path(&mut r, &vol, "/plain.txt", BLOCK_SIZE).expect("open plain.txt");
    assert_eq!(inode.size, Some(35));
    assert_eq!(
        data_size(&mut r, &vol, &inode, BLOCK_SIZE).expect("data_size"),
        35
    );
}
