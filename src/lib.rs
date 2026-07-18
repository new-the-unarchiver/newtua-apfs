//! `apfs-core` — a pure-Rust, from-scratch, panic-free reader for the Apple File
//! System (APFS).
//!
//! APFS is a copy-on-write, transactional, object-oriented filesystem. Every
//! on-disk object carries a 32-byte [`object::ObjPhys`] header with a Fletcher-64
//! checksum, an object identifier (`oid`), and a transaction identifier (`xid`).
//! Navigation is two-staged compared to NTFS: the **object map** ([`omap`])
//! resolves a *virtual* oid at a given xid to a physical block address, and the
//! **checkpoint ring** ([`checkpoint`]) locates the live container superblock.
//!
//! ```text
//! container (NXSB) → checkpoint ring → live nx_superblock (highest valid xid)
//!   → container omap → volume superblock (APSB) per volume
//!      → volume omap → root fs-tree (FSTREE)
//!         → j_key lookup: name → DIR_REC → INODE → DSTREAM_ID
//!            → FILE_EXTENT records → blocks → bytes → (decmpfs?) → content
//! ```
//!
//! This is the APFS analogue of NTFS `name → inode → runs → bytes`. The reader
//! exposes this over any [`std::io::Read`] + [`std::io::Seek`] source and never
//! panics on malformed input (Paranoid Gatekeeper: bounds-checked reads,
//! range-checked length/offset/count fields, capped allocations, cycle-guarded
//! tree walks).
//!
//! Forensic format constants (magics, object-type codes, the decmpfs type map)
//! live in the KNOWLEDGE leaf [`forensicnomicon`]; this crate holds the parsing
//! *algorithms*, not the constant tables.
//!
//! # Scaffold notice
//!
//! Implements phases P1–P8 of `docs/plans/2026-06-21-apfs-forensic-design.md`:
//! container open + checkpoint, object map / B-tree, volume superblock, inode /
//! directory navigation, file extents + decmpfs + xattrs, snapshots + point-in-
//! time view, the space manager (allocation bitmap) + reaper, and keybag /
//! sealed-volume metadata parsing. Full Fusion address translation is the one
//! remaining gap (rejected loudly at open until a Fusion fixture exists).
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod bytes;
mod decmpfs;

pub mod btree;
pub mod checkpoint;
pub mod compression;
pub mod container;
pub mod dir;
pub mod encryption;
pub mod extent;
pub mod fsrecord;
pub mod fusion;
pub mod inode;
pub mod object;
pub mod omap;
pub mod reaper;
pub mod sealed;
pub mod snapshot;
pub mod spaceman;
#[cfg(feature = "vfs")]
pub mod vfs;
pub mod volume;
pub mod xattr;

use std::io::{Read, Seek};

/// Errors surfaced by the reader. Bootstrap failures (no valid superblock, omap
/// unresolvable) are **loud, named** variants — never silently absorbed into an
/// empty result (fleet fail-loud-on-bootstrap rule).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApfsError {
    /// Underlying I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// No valid container superblock (NXSB) found in the checkpoint ring — a
    /// bootstrap failure, carries what was seen so the examiner can diagnose.
    #[error(
        "no valid NXSB superblock found (checked {checked} checkpoint slots; last magic seen: {last_magic:#010x})"
    )]
    NoValidSuperblock { checked: usize, last_magic: u32 },
    /// Object Fletcher-64 checksum did not validate.
    #[error(
        "object checksum mismatch at block {block}: stored {stored:#018x}, computed {computed:#018x}"
    )]
    ChecksumMismatch {
        block: u64,
        stored: u64,
        computed: u64,
    },
    /// An object map could not resolve a virtual oid at the requested xid.
    #[error("omap could not resolve virtual oid {oid:#x} at xid {xid}")]
    OmapUnresolved { oid: u64, xid: u64 },
    /// A block did not carry the expected object type — a short block, a
    /// wrong-typed object, or corruption. Carries the offending raw `o_type`
    /// (fleet "show the unrecognized value" rule).
    #[error(
        "unexpected object type in {structure}: expected {expected:#06x}, found {found:#010x}"
    )]
    UnexpectedObjectType {
        structure: &'static str,
        expected: u32,
        found: u32,
    },
    /// A Fusion container was encountered but Fusion address translation is not
    /// yet supported — fail loud rather than mis-read physical addresses.
    #[error(
        "unsupported Fusion container (tier-2 device present); Fusion addressing not yet implemented"
    )]
    UnsupportedFusion,
    /// The space manager uses chunk-info **address** blocks (`sm_cab_count > 0`),
    /// the multi-TB CAB indirection tier, which is not yet implemented — fail
    /// loud rather than mis-resolve an allocation chunk. Carries the count.
    #[error(
        "unsupported space-manager CAB tier (sm_cab_count = {count}); only inline CIB layout is implemented"
    )]
    UnsupportedSpacemanCab { count: u64 },
    /// A length/offset/count field from the image exceeded a sanity cap
    /// (allocation-bomb / corruption defense). Carries the offending value.
    #[error("structural field out of range in {structure}: {field} = {value} (cap {cap})")]
    FieldOutOfRange {
        structure: &'static str,
        field: &'static str,
        value: u64,
        cap: u64,
    },
    /// A tree walk exceeded the cycle-guard depth (malicious/cyclic oid graph).
    #[error("tree walk exceeded depth cap {cap} (possible cyclic object graph)")]
    CycleGuard { cap: usize },
    /// The checkpoint descriptor or data area is stored as a B-tree (high bit of
    /// `nx_xp_{desc,data}_blocks` set), which needs B-tree resolution not yet
    /// implemented — fail loud rather than mis-read a tree oid as a base address.
    #[error("checkpoint {area} area is tree-backed; B-tree resolution not yet implemented")]
    CheckpointTreeUnsupported { area: &'static str },
    /// A snapshot mount was requested for a transaction id that names neither the
    /// live volume nor any retained snapshot — fail loud with the offending xid
    /// rather than silently mounting the wrong (or live) state.
    #[error("no snapshot with transaction id {xid} (and it is not the live volume's xid)")]
    SnapshotNotFound { xid: u64 },
    /// A transparently-compressed file's `com.apple.decmpfs` payload could not be
    /// decoded — a named codec/format failure (unknown/unsupported compression
    /// type, malformed header, codec rejection, or a length mismatch). The reader
    /// **refuses** rather than returning plausible-but-wrong bytes (fail-loud:
    /// fabricating file content in a forensic tool is the worst failure).
    #[error("decmpfs decode failure: {0}")]
    Decmpfs(&'static str),
}

/// Result alias for the crate.
pub type Result<T> = std::result::Result<T, ApfsError>;

/// An open APFS container, the entry point for navigation.
///
/// Opening walks the checkpoint ring to the **live** [`container::NxSuperblock`]
/// (highest valid xid, checksum + magic validated before trust), resolves the
/// container object map, and enumerates volumes.
pub struct ApfsContainer<R: Read + Seek> {
    reader: R,
    /// The live container superblock (highest valid xid in the checkpoint ring),
    /// magic + Fletcher-64 validated before it was trusted.
    superblock: container::NxSuperblock,
    /// Block address of the live superblock within the checkpoint descriptor area.
    live_superblock_paddr: u64,
    /// Ephemeral oid → paddr mappings from the live checkpoint map (resolve the
    /// spaceman, reaper, and reap-list ephemeral objects).
    checkpoint_mappings: Vec<checkpoint::CheckpointMapping>,
}

impl<R: Read + Seek> ApfsContainer<R> {
    /// Open a container from a `Read + Seek` source, validating the bootstrap.
    ///
    /// Reads block zero (a copy of the container superblock; Apple "Mounting an
    /// APFS Partition" step 1), validates its magic + Fletcher-64, walks the
    /// checkpoint descriptor ring to the live superblock (highest valid xid),
    /// and re-reads that superblock as the live container state.
    ///
    /// # Errors
    /// [`ApfsError::NoValidSuperblock`] if block zero is malformed or the
    /// checkpoint ring holds no cksum-valid, correctly-magicked NXSB;
    /// [`ApfsError::CheckpointTreeUnsupported`] for a tree-backed descriptor
    /// area (phase P2); [`ApfsError::Io`] on a read/seek failure.
    pub fn open(mut reader: R) -> Result<Self> {
        // Read block zero. Block size is not yet known, so read the minimum APFS
        // block — block zero's geometry fields all sit within the first 4 KiB.
        let mut block0 = vec![0u8; container::NX_MINIMUM_BLOCK_SIZE as usize];
        reader.seek(std::io::SeekFrom::Start(0))?;
        match reader.read_exact(&mut block0) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(ApfsError::NoValidSuperblock {
                    checked: 0,
                    last_magic: 0,
                });
            }
            Err(e) => return Err(e.into()),
        }

        // Parse + validate the block-zero bootstrap superblock (magic + cksum).
        let bootstrap = container::NxSuperblock::parse(&block0)?;

        // Fail loud on a Fusion container BEFORE trusting any addressing: the
        // `nx_incompatible_features` Fusion bit means physical-address resolution
        // is tier-aware, which this reader does not yet implement. Detect it on
        // the bootstrap (the flag is set at container creation and invariant
        // across checkpoints) and reject rather than silently mis-read.
        if fusion::is_fusion(&bootstrap) {
            return Err(ApfsError::UnsupportedFusion);
        }

        // Walk the checkpoint ring to the live superblock.
        let live = checkpoint::resolve_live_checkpoint(&mut reader, &bootstrap)?;

        // Re-read the chosen superblock as the authoritative live state.
        let block_size = bootstrap.block_size as usize;
        let mut buf = vec![0u8; block_size];
        let offset = live.superblock_paddr.saturating_mul(block_size as u64);
        reader.seek(std::io::SeekFrom::Start(offset))?;
        reader.read_exact(&mut buf)?;
        let superblock = container::NxSuperblock::parse(&buf)?;

        Ok(Self {
            reader,
            superblock,
            live_superblock_paddr: live.superblock_paddr,
            checkpoint_mappings: live.mappings,
        })
    }

    /// The live checkpoint-map mappings (ephemeral oid → paddr). Pass these to
    /// [`reaper::pending_objects`] to walk the reaper's ephemeral reap lists.
    #[must_use]
    pub fn checkpoint_mappings(&self) -> &[checkpoint::CheckpointMapping] {
        &self.checkpoint_mappings
    }

    /// Physical block of the live space manager (`nx_spaceman_oid` resolved
    /// through the checkpoint map), or `None` if it is not mapped. Feed it to
    /// [`spaceman::is_block_free`].
    #[must_use]
    pub fn spaceman_paddr(&self) -> Option<u64> {
        self.resolve_ephemeral(self.superblock.spaceman_oid)
    }

    /// Physical block of the live reaper (`nx_reaper_oid` resolved through the
    /// checkpoint map), or `None` if it is not mapped. Feed it to
    /// [`reaper::pending_objects`].
    #[must_use]
    pub fn reaper_paddr(&self) -> Option<u64> {
        self.resolve_ephemeral(self.superblock.reaper_oid)
    }

    /// Resolve an ephemeral oid to its physical block via the checkpoint map.
    fn resolve_ephemeral(&self, oid: u64) -> Option<u64> {
        self.checkpoint_mappings
            .iter()
            .find(|m| m.oid == oid)
            .map(|m| m.paddr)
    }

    /// The live container superblock resolved from the checkpoint ring.
    #[must_use]
    pub fn superblock(&self) -> &container::NxSuperblock {
        &self.superblock
    }

    /// Block address of the live superblock within the checkpoint descriptor area.
    #[must_use]
    pub fn live_superblock_paddr(&self) -> u64 {
        self.live_superblock_paddr
    }

    /// Resolve the physical block address of each volume superblock (APSB).
    ///
    /// The live NXSB names its volumes by *virtual* oid (`nx_fs_oid[]`). Each is
    /// resolved through the **container object map** (`nx_omap_oid`, a physical
    /// omap object whose B-tree is stored physically) at the container's
    /// transaction id, yielding the physical block address of that volume's
    /// `apfs_superblock_t`. These paddrs feed volume parsing (phase P3).
    ///
    /// Resolution is deterministic and leaves the reader position arbitrary (it
    /// seeks as it walks), so callers should not assume a cursor position after.
    ///
    /// # Errors
    /// [`ApfsError::FieldOutOfRange`] if `nx_block_size` is outside the spec
    /// range; [`ApfsError::UnexpectedObjectType`] if `nx_omap_oid` does not point
    /// at an omap object; [`ApfsError::OmapUnresolved`] if a `nx_fs_oid` has no
    /// mapping; [`ApfsError::ChecksumMismatch`] / [`ApfsError::CycleGuard`] /
    /// [`ApfsError::Io`] on a structurally invalid omap or a read failure.
    pub fn volume_superblock_addrs(&mut self) -> Result<Vec<u64>> {
        let block_size = self.superblock.block_size;
        if !(container::NX_MINIMUM_BLOCK_SIZE..=container::NX_MAXIMUM_BLOCK_SIZE)
            .contains(&block_size)
        {
            return Err(ApfsError::FieldOutOfRange {
                structure: "nx_superblock",
                field: "nx_block_size",
                value: u64::from(block_size),
                cap: u64::from(container::NX_MAXIMUM_BLOCK_SIZE),
            });
        }
        let block_size = block_size as usize;

        // Read the container omap_phys block (nx_omap_oid is a physical oid, so
        // it is also the omap object's block address).
        let mut buf = vec![0u8; block_size];
        let omap_off = self.superblock.omap_oid.saturating_mul(block_size as u64);
        self.reader.seek(std::io::SeekFrom::Start(omap_off))?;
        self.reader.read_exact(&mut buf)?;
        let omap = omap::ObjectMap::parse(&buf)?;

        // Resolve each virtual fs_oid through the omap at the container xid.
        let xid = self.superblock.xid;
        let mut addrs = Vec::with_capacity(self.superblock.fs_oids.len());
        for &fs_oid in &self.superblock.fs_oids {
            let entry = omap.resolve(&mut self.reader, fs_oid, xid, block_size)?;
            addrs.push(entry.paddr);
        }
        Ok(addrs)
    }

    /// Consume the container, returning the underlying reader.
    #[must_use]
    pub fn into_reader(self) -> R {
        self.reader
    }
}
