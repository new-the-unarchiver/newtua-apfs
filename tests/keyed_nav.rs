//! Keyed fs-tree navigation prunes the walk to the target object id.
//!
//! The committed fixtures have **single-leaf** fs-trees, so index-node pruning
//! cannot be exercised on them — this test uses the real, multi-level macOS
//! fs-tree inside the env-gated P5 disk image (`APFS_P5_FIXTURE`). It asserts two
//! things on that real Apple-authored tree:
//!
//!   1. **Correctness** — `open_path` + `read_data` over the keyed navigation
//!      still reads the live `changing.txt` bytes that macOS wrote
//!      (`APFS_P5_V2_SHA256`), i.e. pruning never skips a covering subtree.
//!   2. **Pruning** — resolving that path touches far fewer distinct blocks than
//!      a full fs-tree walk would, proving the walk descends one root→leaf path
//!      per lookup instead of visiting every node.
//!
//! Skips cleanly when the fixture is absent (like the snapshot populated test).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};

use apfs_core::dir::open_path;
use apfs_core::extent::read_data;
use apfs_core::volume::ApfsVolume;

const BLOCK_SIZE: usize = 4096;

/// A `Read + Seek` view of a partition embedded at `base` bytes that also records
/// the distinct block indices touched, so a test can prove a walk is pruned.
struct CountingPartitionReader<R> {
    inner: R,
    base: u64,
    pos: u64,
    blocks: HashSet<u64>,
}

impl<R: Seek> CountingPartitionReader<R> {
    fn new(mut inner: R, base: u64) -> std::io::Result<Self> {
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self {
            inner,
            base,
            pos: base,
            blocks: HashSet::new(),
        })
    }
    fn distinct_blocks(&self) -> usize {
        self.blocks.len()
    }
    fn reset_count(&mut self) {
        self.blocks.clear();
    }
}

impl<R: Read> Read for CountingPartitionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.blocks.insert(self.pos / BLOCK_SIZE as u64);
        let n = self.inner.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Seek> Seek for CountingPartitionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let abs = match pos {
            SeekFrom::Start(o) => self.inner.seek(SeekFrom::Start(self.base + o))?,
            SeekFrom::Current(d) => self.inner.seek(SeekFrom::Current(d))?,
            SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "End-relative seek unsupported",
                ))
            }
        };
        self.pos = abs;
        Ok(abs.saturating_sub(self.base))
    }
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn read_block(r: &mut (impl Read + Seek), block: u64) -> Vec<u8> {
    r.seek(SeekFrom::Start(block * BLOCK_SIZE as u64)).unwrap();
    let mut buf = vec![0u8; BLOCK_SIZE];
    r.read_exact(&mut buf).unwrap();
    buf
}

/// Pick the live Data volume (the one carrying snapshots) from the container.
fn data_volume(r: &mut (impl Read + Seek)) -> ApfsVolume {
    use apfs_core::snapshot::list_snapshots;
    let mut container = apfs_core::ApfsContainer::open(&mut *r).expect("open container");
    let addrs = container
        .volume_superblock_addrs()
        .expect("volume APSB addrs");
    drop(container);
    let mut best: Option<(ApfsVolume, usize)> = None;
    for paddr in addrs {
        let block = read_block(r, paddr);
        let Ok(vol) = ApfsVolume::parse(&block) else {
            continue;
        };
        let n = list_snapshots(&mut *r, &vol, BLOCK_SIZE).map_or(0, |s| s.len());
        if best.as_ref().is_none_or(|(_, b)| n > *b) {
            best = Some((vol, n));
        }
    }
    best.expect("a volume").0
}

#[test]
fn keyed_navigation_prunes_real_fs_tree() {
    let Ok(path) = std::env::var("APFS_P5_FIXTURE") else {
        eprintln!("APFS_P5_FIXTURE unset; skipping keyed-navigation pruning test");
        return;
    };
    let part_offset: u64 = std::env::var("APFS_P5_PART_OFFSET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let file = std::env::var("APFS_P5_FILE").unwrap_or_else(|_| "/changing.txt".to_string());
    let v2_sha = std::env::var("APFS_P5_V2_SHA256").expect("APFS_P5_V2_SHA256 must be set");

    let f = std::fs::File::open(&path).expect("open APFS_P5_FIXTURE");
    let mut r = CountingPartitionReader::new(f, part_offset).expect("seek partition");

    let live = data_volume(&mut r);

    // Correctness: the keyed navigation resolves the file on the real multi-level
    // tree and reads exactly the bytes macOS wrote (the independent oracle).
    r.reset_count();
    let inode = open_path(&mut r, &live, &file, BLOCK_SIZE).expect("open live file");
    let data = read_data(&mut r, &live, &inode, BLOCK_SIZE).expect("read live file");
    assert_eq!(
        sha256_hex(&data),
        v2_sha,
        "keyed nav reads the live v2 bytes"
    );

    // Pruning: resolving the path + reading the file touched only a keyed-descent
    // number of distinct blocks. A full fs-tree walk per path component would
    // touch every fs-tree node (thousands on a real macOS Data volume); a pruned
    // walk reads ~tree-height nodes per lookup. 3000 sits well between the two.
    let touched = r.distinct_blocks();
    eprintln!("keyed open_path+read_data touched {touched} distinct blocks");
    assert!(
        touched < 3000,
        "expected a pruned (keyed) walk to touch < 3000 blocks, touched {touched}"
    );
}
