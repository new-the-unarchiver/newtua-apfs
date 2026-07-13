//! `impl FileSystem for ApfsFs` — the forensic-vfs adapter (behind the `vfs`
//! feature).
//!
//! [`ApfsFs`] serves every read through a shared `&self` over a `Mutex`-guarded
//! source, so one mounted handle backs N workers. This module maps that reader
//! onto the [`forensic_vfs::FileSystem`] contract: APFS nodes are addressed by
//! [`FileId::ApfsOid`] (inode oid + the mounted volume's xid), directory and run
//! enumerations are owned `Send` streams, and every fallible apfs-core call is
//! translated to a typed [`VfsError`] — never an `unwrap`/panic (Paranoid
//! Gatekeeper).
//!
//! The adapter is pure wiring over the apfs-core free functions (`dir::list_dir`,
//! `dir::lookup_child`, `dir::load_inode`, `extent::read_data`,
//! `extent::list_extents`); it introduces no new parsing.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use forensic_vfs::{
    Allocation, ByteRun, DirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta,
    MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo, SectorSizes,
    SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::dir::{self, ROOT_DIR_INO_NUM};
use crate::extent;
use crate::inode::Inode;
use crate::volume::ApfsVolume;
use crate::{ApfsContainer, ApfsError, Result};

/// `S_IFMT` mask isolating the file-type bits of a Unix `mode`.
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

/// DT_ type mask: the low 4 bits of a `j_drec_val_t.flags` hold the entry type.
const DT_MASK: u16 = 0x0F;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;

/// An APFS volume mounted as a [`FileSystem`].
///
/// One handle serves N workers: every read locks the interior `Mutex` for the
/// duration of a single apfs-core call and releases it, so `&self` methods are
/// shareable across threads.
pub struct ApfsFs<R: Read + Seek> {
    reader: Mutex<R>,
    volume: ApfsVolume,
    block_size: usize,
    /// The mounted volume's transaction id, stamped into every [`FileId`] so a
    /// reused oid at a different xid is never confused with this snapshot.
    root_xid: u64,
}

impl<R: Read + Seek> ApfsFs<R> {
    /// Open the first volume of an APFS container as a mountable filesystem.
    ///
    /// Walks the container to its live NXSB, resolves the first volume superblock
    /// (APSB), parses it, and stashes the reader behind a `Mutex`.
    ///
    /// # Errors
    /// [`ApfsError::NoValidSuperblock`] (no volume present is surfaced as a
    /// bootstrap-class error), the container-open errors of
    /// [`ApfsContainer::open`], or [`ApfsError::Io`] on a read/seek failure.
    pub fn open(reader: R) -> Result<Self> {
        let (reader, volume, block_size) = Self::open_first_volume(reader)?;
        let root_xid = volume.xid();
        Ok(Self {
            reader: Mutex::new(reader),
            volume,
            block_size,
            root_xid,
        })
    }

    /// Open the container, resolve the first volume's live superblock (APSB), and
    /// return the reader together with the parsed live volume and the container
    /// block size. Shared bootstrap for [`ApfsFs::open`], [`ApfsFs::open_snapshot`],
    /// and [`ApfsFs::snapshots`].
    ///
    /// # Errors
    /// As [`ApfsFs::open`].
    fn open_first_volume(reader: R) -> Result<(R, ApfsVolume, usize)> {
        let mut container = ApfsContainer::open(reader)?;
        let block_size = container.superblock().block_size as usize;
        let addrs = container.volume_superblock_addrs()?;
        // No volume is a bootstrap failure, not an empty mount (fail loud).
        let vaddr = *addrs.first().ok_or(ApfsError::NoValidSuperblock {
            checked: 0,
            last_magic: 0,
        })?;

        let mut reader = container.into_reader();
        let offset = vaddr.saturating_mul(block_size as u64);
        reader.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; block_size];
        reader.read_exact(&mut buf)?;
        let volume = ApfsVolume::parse(&buf)?;
        Ok((reader, volume, block_size))
    }

    /// Open the first volume as it stood at transaction `xid` — the point-in-time
    /// view for the `[H]` state-history cohort.
    ///
    /// The live volume *is* the state at its own xid (the newest point in the
    /// timeline), so `xid == live.xid()` mounts the live volume directly. Any
    /// earlier `xid` must name a retained snapshot: its frozen APSB is read via
    /// [`crate::snapshot::mount_snapshot`] (which grafts the live omap so the
    /// existing navigation reads the volume exactly as it stood at snapshot time).
    /// Every subsequent read reflects the snapshot, not the live volume.
    ///
    /// # Errors
    /// [`ApfsError::SnapshotNotFound`] if `xid` names neither the live volume nor
    /// a retained snapshot; otherwise the errors of [`ApfsFs::open`],
    /// [`crate::snapshot::list_snapshots`], and [`crate::snapshot::mount_snapshot`].
    pub fn open_snapshot(reader: R, xid: u64) -> Result<Self> {
        let (mut reader, live, block_size) = Self::open_first_volume(reader)?;
        if xid == live.xid() {
            return Ok(Self {
                reader: Mutex::new(reader),
                volume: live,
                block_size,
                root_xid: xid,
            });
        }
        let snaps = crate::snapshot::list_snapshots(&mut reader, &live, block_size)?;
        let snapshot = snaps
            .iter()
            .find(|s| s.xid == xid)
            .ok_or(ApfsError::SnapshotNotFound { xid })?;
        let volume = crate::snapshot::mount_snapshot(&mut reader, &live, snapshot, block_size)?;
        Ok(Self {
            reader: Mutex::new(reader),
            volume,
            block_size,
            root_xid: xid,
        })
    }

    /// Enumerate the first volume's snapshots (sorted by xid), so a caller can list
    /// the temporal cohort without re-implementing the container/volume open.
    /// Returns an empty vector for an unsnapshotted volume.
    ///
    /// # Errors
    /// The bootstrap errors of [`ApfsFs::open`] and the tree-walk errors of
    /// [`crate::snapshot::list_snapshots`].
    pub fn snapshots(reader: R) -> Result<Vec<crate::snapshot::Snapshot>> {
        let (mut reader, volume, block_size) = Self::open_first_volume(reader)?;
        crate::snapshot::list_snapshots(&mut reader, &volume, block_size)
    }
}

/// The inode oid carried by a [`FileId`]. Only APFS oids address this filesystem;
/// any other identity domain is a caller error, surfaced loud.
fn oid_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::ApfsOid { oid, .. } => Ok(oid),
        other => Err(VfsError::Unsupported {
            layer: "apfs file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Only the default data stream is addressable; a named stream id is refused loud
/// rather than silently read as the default.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "apfs stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate an apfs-core error into the VFS error type, keeping I/O distinct
/// from a structural decode failure (a per-node miss maps to `Decode`, carrying
/// the original message).
fn map_err(e: ApfsError) -> VfsError {
    match e {
        ApfsError::Io(source) => VfsError::Io {
            op: "apfs read",
            source,
        },
        other => VfsError::Decode {
            layer: "apfs",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// A poisoned interior lock is a hard, named failure — never an `unwrap`.
fn poisoned() -> VfsError {
    VfsError::Bootstrap {
        stage: "apfs reader lock",
        detail: "interior reader mutex poisoned".to_string(),
    }
}

/// Map a `j_drec_val_t.flags` DT_ type to a [`NodeKind`].
fn dt_to_kind(flags: u16) -> NodeKind {
    match flags & DT_MASK {
        DT_DIR => NodeKind::Dir,
        DT_REG => NodeKind::File,
        DT_LNK => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

/// Map an inode `mode`'s `S_IFMT` bits to a [`NodeKind`].
fn mode_to_kind(mode: u16) -> NodeKind {
    match mode & S_IFMT {
        S_IFDIR => NodeKind::Dir,
        S_IFREG => NodeKind::File,
        S_IFLNK => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

/// Assemble the unified [`FsMeta`] from an APFS inode.
fn build_meta(inode: &Inode) -> FsMeta {
    let ts = |ns: u64| TimeStamp {
        unix_nanos: i128::from(ns),
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Nanos,
    };
    FsMeta {
        ino: inode.oid,
        kind: mode_to_kind(inode.mode),
        allocated: Allocation::Allocated,
        size: inode.size.unwrap_or(0),
        nlink: inode.nlink_or_nchildren.max(0) as u32,
        uid: Some(inode.uid),
        gid: Some(inode.gid),
        mode: Some(u32::from(inode.mode)),
        times: MacbTimes {
            born: Some(ts(inode.create_time)),
            modified: Some(ts(inode.mod_time)),
            changed: Some(ts(inode.change_time)),
            accessed: Some(ts(inode.access_time)),
        },
        streams: Vec::new(),
        residency: ResidencyKind::NonResident,
        link_target: None,
    }
}

impl<R: Read + Seek + Send> FileSystem for ApfsFs<R> {
    fn kind(&self) -> FsKind {
        FsKind::Apfs
    }

    fn root(&self) -> FileId {
        FileId::ApfsOid {
            oid: ROOT_DIR_INO_NUM,
            xid: self.root_xid,
        }
    }

    fn sector_sizes(&self) -> SectorSizes {
        let bs = self.block_size as u32;
        SectorSizes {
            logical: bs,
            physical: bs,
            cluster_or_block: bs,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let parent = oid_of(ino)?;
        let xid = self.root_xid;
        let mut guard = self.reader.lock().map_err(|_| poisoned())?;
        let entries =
            dir::list_dir(&mut *guard, &self.volume, parent, self.block_size).map_err(map_err)?;
        let out: Vec<VfsResult<DirEntry>> = entries
            .into_iter()
            .map(|e| {
                Ok(DirEntry {
                    kind: dt_to_kind(e.flags),
                    name: e.name.into_bytes(),
                    id: FileId::ApfsOid {
                        oid: e.file_id,
                        xid,
                    },
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let node = oid_of(ino)?;
        require_default_stream(stream)?;
        let bs = self.block_size;
        let mut guard = self.reader.lock().map_err(|_| poisoned())?;
        let inode = dir::load_inode(&mut *guard, &self.volume, node, bs).map_err(map_err)?;
        // The main-fork stream oid is the inode's `private_id` (what `read_data`
        // uses internally).
        let exts = extent::list_extents(&mut *guard, &self.volume, inode.private_id, bs)
            .map_err(map_err)?;
        let out: Vec<VfsResult<RunInfo>> = exts
            .into_iter()
            .map(|x| {
                let sparse = x.phys_block_num == 0;
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset: x.phys_block_num.saturating_mul(bs as u64),
                        len: x.len,
                        flags: RunFlags {
                            sparse,
                            ..RunFlags::default()
                        },
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let parent = oid_of(parent)?;
        let xid = self.root_xid;
        // APFS names are UTF-8; a non-UTF-8 query cannot match any on-disk name.
        let Ok(name) = std::str::from_utf8(name) else {
            return Ok(None);
        };
        let mut guard = self.reader.lock().map_err(|_| poisoned())?;
        let found = dir::lookup_child(&mut *guard, &self.volume, parent, name, self.block_size)
            .map_err(map_err)?;
        Ok(found.map(|oid| FileId::ApfsOid { oid, xid }))
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let node = oid_of(ino)?;
        let mut guard = self.reader.lock().map_err(|_| poisoned())?;
        let inode =
            dir::load_inode(&mut *guard, &self.volume, node, self.block_size).map_err(map_err)?;
        Ok(build_meta(&inode))
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let node = oid_of(ino)?;
        require_default_stream(stream)?;
        let bs = self.block_size;
        let mut guard = self.reader.lock().map_err(|_| poisoned())?;
        let inode = dir::load_inode(&mut *guard, &self.volume, node, bs).map_err(map_err)?;
        // `read_data` decodes decmpfs transparently. It materializes the whole
        // stream; the window slice below caps what is copied back to the caller.
        let data = extent::read_data(&mut *guard, &self.volume, &inode, bs).map_err(map_err)?;
        let start = usize::try_from(off).unwrap_or(usize::MAX);
        if start >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - start);
        // `start < data.len()` and `n <= data.len() - start`, so the range is in
        // bounds; `n <= buf.len()` bounds the destination.
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), data.get(start..start + n)) {
            dst.copy_from_slice(src);
            return Ok(n);
        }
        Ok(0) // cov:unreachable: n <= buf.len() and start+n <= data.len() by construction
    }

    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // APFS symlink targets live in the `com.apple.fs.symlink` embedded xattr;
        // resolving them is a follow-up. A node with none reads as an empty target.
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Deleted-record carving is a follow-up; the default surface is an empty
        // stream, not a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    //! Snapshot-aware mounting over the committed P4 fixture (`apfs_content.bin`,
    //! ZERO snapshots — a real Apple-minted container). These exercise the
    //! `vfs`-feature snapshot seam only; the populated (with-snapshots) path is
    //! validated by the env-gated point-in-time test in `core/tests/snapshot.rs`.
    use super::*;
    use std::io::Cursor;

    const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");

    /// The live volume's transaction id — the newest point in the timeline.
    fn live_xid() -> u64 {
        ApfsFs::open(Cursor::new(CONTENT))
            .expect("open live apfs")
            .root_xid
    }

    #[test]
    fn p4_fixture_lists_zero_snapshots() {
        // The P4 fixture's snap-metadata tree is empty; enumeration returns [].
        let snaps = ApfsFs::snapshots(Cursor::new(CONTENT)).expect("list snapshots");
        assert!(
            snaps.is_empty(),
            "P4 fixture has no snapshots; got {snaps:?}"
        );
    }

    #[test]
    fn open_snapshot_at_live_xid_reads_plain_txt() {
        // Mounting at the live volume's own xid is the live state — /plain.txt is
        // readable, proving open_snapshot wires a mountable FileSystem.
        let fs = ApfsFs::open_snapshot(Cursor::new(CONTENT), live_xid())
            .expect("mount live-xid snapshot");
        let root = fs.root();
        let found = fs
            .lookup(root, b"plain.txt")
            .expect("lookup plain.txt")
            .expect("plain.txt present at root");
        let mut buf = [0u8; 64];
        let n = fs
            .read_at(found, StreamId::Default, 0, &mut buf)
            .expect("read plain.txt");
        assert!(n > 0, "plain.txt should have content");
    }

    #[test]
    fn open_snapshot_unknown_xid_fails_loud() {
        // A xid that is neither the live volume's nor any retained snapshot's is a
        // loud, named failure carrying the offending value — never a silent mount.
        let bogus = live_xid().wrapping_add(0xDEAD_BEEF);
        match ApfsFs::open_snapshot(Cursor::new(CONTENT), bogus) {
            Err(ApfsError::SnapshotNotFound { xid }) => assert_eq!(xid, bogus),
            Err(other) => panic!("expected SnapshotNotFound({bogus}); got {other:?}"),
            Ok(_) => panic!("expected SnapshotNotFound({bogus}); got a mounted fs"),
        }
    }
}
