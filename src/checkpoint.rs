//! Checkpoint descriptor + data ring, and resolution of the **live** container
//! superblock.
//!
//! APFS writes superblocks transactionally into a ring of checkpoint blocks. To
//! find the current container state (Apple *APFS Reference*, "Mounting an APFS
//! container"): scan the checkpoint **descriptor area** for the
//! `nx_superblock_t` with the **highest `xid` that also has a valid Fletcher-64
//! checksum**, then read the checkpoint **map** (`checkpoint_map_phys_t`, type
//! `OBJECT_TYPE_CHECKPOINT_MAP 0xc`) to resolve the ephemeral oids it references
//! (spaceman, reaper) to physical addresses.
//!
//! Non-latest checkpoints reference superseded objects — this is normal
//! copy-on-write history, and is a **recovery opportunity** (the analyzer reads
//! it as residue, never as an anomaly).

use crate::container::NX_MAXIMUM_BLOCK_SIZE;
use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};

/// Object type code `OBJECT_TYPE_NX_SUPERBLOCK` (Apple): `o_type & 0xffff == 1`.
const OBJECT_TYPE_NX_SUPERBLOCK: u16 = 0x1;
/// Object type code `OBJECT_TYPE_CHECKPOINT_MAP` (Apple): `o_type & 0xffff == 0xc`.
const OBJECT_TYPE_CHECKPOINT_MAP: u16 = 0xc;

/// `checkpoint_map_phys_t` field offsets after the 32-byte `obj_phys_t cpm_o`.
const CPM_COUNT_OFF: usize = 36; // cpm_count u32
const CPM_MAP_OFF: usize = 40; // cpm_map[] start
/// One `checkpoint_mapping_t` is 40 bytes: `cpm_type`/`cpm_subtype`/`cpm_size`/
/// `cpm_pad` (4×u32) + `cpm_fs_oid`/`cpm_oid`/`cpm_paddr` (3×u64).
const CHECKPOINT_MAPPING_LEN: usize = 40;
/// Sanity cap on `cpm_count` — a single map block can hold at most
/// `(block_size - 40) / 40` mappings; cap well above that to reject corruption
/// without rejecting any legal block.
const MAX_CPM_COUNT: u32 = 4096;

/// One `checkpoint_mapping_t` entry (ephemeral oid → paddr at a type/subtype).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CheckpointMapping {
    pub oid: u64,
    pub paddr: u64,
    pub obj_type: u32,
    pub subtype: u32,
}

/// Resolution of the live superblock from the checkpoint ring.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LiveCheckpoint {
    /// Block address of the chosen (highest-valid-xid) NXSB.
    pub superblock_paddr: u64,
    /// Its transaction id.
    pub xid: u64,
    /// Ephemeral oid → paddr mappings from the checkpoint map.
    pub mappings: Vec<CheckpointMapping>,
}

/// Scan the descriptor area and return the live checkpoint.
///
/// # Errors
/// [`crate::ApfsError::NoValidSuperblock`] if no cksum-valid NXSB exists in the
/// ring — a loud bootstrap failure, never an empty `Ok`.
pub fn resolve_live_checkpoint<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    bootstrap: &crate::container::NxSuperblock,
) -> crate::Result<LiveCheckpoint> {
    // A tree-backed descriptor area needs B-tree resolution (phase P2). Reject
    // it loudly so a tree oid is never mis-read as a contiguous base address.
    if bootstrap.xp_desc_is_tree() {
        return Err(crate::ApfsError::CheckpointTreeUnsupported { area: "descriptor" });
    }

    // Trust the block size only within the spec range (a corrupt value would
    // drive every seek to the wrong place / size an over-large buffer).
    let block_size = bootstrap.block_size;
    if !(crate::container::NX_MINIMUM_BLOCK_SIZE..=NX_MAXIMUM_BLOCK_SIZE).contains(&block_size) {
        return Err(crate::ApfsError::FieldOutOfRange {
            structure: "nx_superblock",
            field: "nx_block_size",
            value: u64::from(block_size),
            cap: u64::from(NX_MAXIMUM_BLOCK_SIZE),
        });
    }
    let block_size = block_size as usize;
    let mut buf = vec![0u8; block_size];

    // Apple "Mounting an APFS Partition": read the contiguous descriptor area
    // and choose the cksum-valid NX_SUPERBLOCK with the largest xid.
    let desc_base = bootstrap.xp_desc_base;
    let desc_blocks = bootstrap.xp_desc_blocks;

    let mut best: Option<(u64, u64)> = None; // (xid, paddr)
    let mut checked = 0usize;
    let mut last_magic = 0u32;

    for i in 0..u64::from(desc_blocks) {
        let paddr = desc_base + i;
        if !read_block(reader, paddr, block_size, &mut buf)? {
            continue; // cov:unreachable: descriptor blocks lie within the image
        }
        checked += 1;
        let Some(hdr) = ObjPhys::parse(&buf) else {
            continue; // cov:unreachable: buf is block_size >= header length
        };
        if hdr.obj_type() != OBJECT_TYPE_NX_SUPERBLOCK {
            continue;
        }
        let magic = crate::bytes::le_u32(&buf, 32);
        last_magic = magic;
        if magic != crate::container::NX_MAGIC {
            continue; // cov:unreachable: an NX_SUPERBLOCK-typed block carries NX_MAGIC
        }
        if fletcher64_stored(&buf) != fletcher64_checksum(&buf) {
            continue;
        }
        if best.is_none_or(|(bx, _)| hdr.xid > bx) {
            best = Some((hdr.xid, paddr));
        }
    }

    let Some((xid, superblock_paddr)) = best else {
        return Err(crate::ApfsError::NoValidSuperblock {
            checked,
            last_magic,
        });
    };

    // Collect the ephemeral oid→paddr mappings from the checkpoint-map blocks in
    // the descriptor ring that belong to the live checkpoint (same xid).
    let mut mappings = Vec::new();
    for i in 0..u64::from(desc_blocks) {
        let paddr = desc_base + i;
        if !read_block(reader, paddr, block_size, &mut buf)? {
            continue; // cov:unreachable: descriptor blocks lie within the image
        }
        let Some(hdr) = ObjPhys::parse(&buf) else {
            continue; // cov:unreachable: buf is block_size >= header length
        };
        if hdr.obj_type() != OBJECT_TYPE_CHECKPOINT_MAP || hdr.xid != xid {
            continue;
        }
        if fletcher64_stored(&buf) != fletcher64_checksum(&buf) {
            continue; // cov:unreachable: real map blocks carry a valid cksum
        }
        let count = crate::bytes::le_u32(&buf, CPM_COUNT_OFF).min(MAX_CPM_COUNT);
        for m in 0..count as usize {
            let off = CPM_MAP_OFF + m * CHECKPOINT_MAPPING_LEN;
            mappings.push(CheckpointMapping {
                obj_type: crate::bytes::le_u32(&buf, off),
                subtype: crate::bytes::le_u32(&buf, off + 4),
                oid: crate::bytes::le_u64(&buf, off + 24),
                paddr: crate::bytes::le_u64(&buf, off + 32),
            });
        }
    }

    Ok(LiveCheckpoint {
        superblock_paddr,
        xid,
        mappings,
    })
}

/// Seek to `paddr * block_size` and fill `buf`. Returns `false` (not an error)
/// if the block lies past the end of the source — a descriptor index can point
/// past a truncated image, which is a per-block miss, not a bootstrap failure.
fn read_block<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    paddr: u64,
    block_size: usize,
    buf: &mut [u8],
) -> crate::Result<bool> {
    let Some(offset) = paddr.checked_mul(block_size as u64) else {
        return Ok(false); // cov:unreachable: descriptor paddr*bs cannot overflow u64
    };
    reader.seek(std::io::SeekFrom::Start(offset))?;
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}
