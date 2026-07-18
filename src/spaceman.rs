//! Space manager (`spaceman_phys_t`, type `OBJECT_TYPE_SPACEMAN 0x5`) and
//! allocation bitmaps.
//!
//! The space manager tracks which container blocks are allocated. It references
//! chunk-info blocks (`chunk_info_block_t`, type `SPACEMAN_CIB 0x7`) and
//! chunk-info-address blocks (`cib_addr_block_t`, type `SPACEMAN_CAB 0x6`) that
//! point at allocation bitmaps (`SPACEMAN_BITMAP 0x8`), plus free queues
//! (`SPACEMAN_FREE_QUEUE 0x9`) of blocks pending release. The forensic value is
//! the "is this physical block currently free?" predicate — input to
//! deleted-extent carve-candidate reasoning (a free bitmap is necessary but
//! **not** sufficient for recoverability; see the analyzer).

use std::io::{Read, Seek};

use crate::bytes::{le_u32, le_u64};

// `spaceman_phys_t` field offsets (after the 32-byte obj_phys header).
const SM_BLOCKS_PER_CHUNK: usize = 36; // u32 (== 8 * sm_block_size)
const SM_CHUNKS_PER_CIB: usize = 40; // u32
const SM_DEV0: usize = 48; // spaceman_device_t sm_dev[0] (main device)
                           // `spaceman_device_t` field offsets (relative to the device base).
const DEV_BLOCK_COUNT: usize = 0; // u64
const DEV_CHUNK_COUNT: usize = 8; // u64
const DEV_CIB_COUNT: usize = 16; // u32
const DEV_CAB_COUNT: usize = 20; // u32
const DEV_ADDR_OFFSET: usize = 32; // u32 — byte offset within the spaceman block
                                   // `chunk_info_block_t` (CIB) offsets.
const CIB_CHUNK_INFO_COUNT: usize = 36; // u32
const CIB_CHUNK_INFO: usize = 40; // chunk_info_t[]
const CHUNK_INFO_LEN: usize = 32;
// `chunk_info_t` field offsets.
const CI_BITMAP_ADDR: usize = 24; // u64 — SPACEMAN_BITMAP paddr, or 0 if all-free

/// Read a block at `paddr` and verify its Fletcher-64 before trusting it (a
/// checksummed `obj_phys` object: spaceman, CIB, reaper, reap list).
pub(crate) fn read_obj_block<R: Read + Seek>(
    reader: &mut R,
    paddr: u64,
    block_size: usize,
) -> crate::Result<Vec<u8>> {
    let mut buf = vec![0u8; block_size];
    let offset = paddr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;
    let stored = crate::object::fletcher64_stored(&buf);
    let computed = crate::object::fletcher64_checksum(&buf);
    if stored != computed {
        return Err(crate::ApfsError::ChecksumMismatch {
            block: le_u64(&buf, 8),
            stored,
            computed,
        });
    }
    Ok(buf)
}

/// Query whether a physical block is currently marked **free** in the space
/// manager's allocation bitmaps.
///
/// Resolves `block` to its chunk, follows the main device's inline chunk-info
/// (CIB) address array to the owning `chunk_info_t`, and reads the bit for the
/// block in that chunk's `SPACEMAN_BITMAP`. Per the APFS format, a **set** bit
/// means *allocated*, a **clear** bit means *free* (apfsck:
/// `free = total − popcount(bitmap)`); a `ci_bitmap_addr` of 0 means the whole
/// chunk is free. The bitmap block is raw (no `obj_phys` header / checksum); the
/// spaceman and CIB blocks are checksum-verified before use.
///
/// `spaceman_paddr` is the live space manager's physical block (resolve it from
/// the container's checkpoint map via [`crate::ApfsContainer::spaceman_paddr`]).
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if `block` is past the device, or a
/// chunk/CIB index is inconsistent; [`crate::ApfsError::UnsupportedSpacemanCab`]
/// for the multi-TB CAB tier (`sm_cab_count > 0`), not yet implemented;
/// [`crate::ApfsError::ChecksumMismatch`] on a bad spaceman/CIB checksum;
/// [`crate::ApfsError::Io`] on a read/seek failure.
pub fn is_block_free<R: Read + Seek>(
    reader: &mut R,
    spaceman_paddr: u64,
    block: u64,
    block_size: usize,
) -> crate::Result<bool> {
    let sm = read_obj_block(reader, spaceman_paddr, block_size)?;

    let blocks_per_chunk = u64::from(le_u32(&sm, SM_BLOCKS_PER_CHUNK));
    let chunks_per_cib = u64::from(le_u32(&sm, SM_CHUNKS_PER_CIB));
    let block_count = le_u64(&sm, SM_DEV0 + DEV_BLOCK_COUNT);
    let chunk_count = le_u64(&sm, SM_DEV0 + DEV_CHUNK_COUNT);
    let cib_count = u64::from(le_u32(&sm, SM_DEV0 + DEV_CIB_COUNT));
    let cab_count = u64::from(le_u32(&sm, SM_DEV0 + DEV_CAB_COUNT));
    let addr_offset = le_u32(&sm, SM_DEV0 + DEV_ADDR_OFFSET) as usize;

    let range = |field, value, cap| crate::ApfsError::FieldOutOfRange {
        structure: "spaceman_phys",
        field,
        value,
        cap,
    };
    if blocks_per_chunk == 0 || chunks_per_cib == 0 {
        return Err(range("sm_blocks_per_chunk/sm_chunks_per_cib", 0, 1));
    }
    if block >= block_count {
        return Err(range("block", block, block_count));
    }
    // The CAB indirection tier (sm_cab_count > 0) is multi-TB-container only and
    // not yet implemented — fail loud rather than mis-resolve a chunk.
    if cab_count != 0 {
        return Err(crate::ApfsError::UnsupportedSpacemanCab { count: cab_count });
    }

    let chunk_index = block / blocks_per_chunk;
    if chunk_index >= chunk_count {
        return Err(range("chunk_index", chunk_index, chunk_count));
    }
    let cib_idx = chunk_index / chunks_per_cib;
    let within_cib = (chunk_index % chunks_per_cib) as usize;
    if cib_idx >= cib_count {
        return Err(range("cib_index", cib_idx, cib_count));
    }

    // Inline CIB address array (u64 paddrs) at `addr_offset` within the spaceman.
    let cib_paddr = le_u64(&sm, addr_offset + cib_idx as usize * 8);
    let cib = read_obj_block(reader, cib_paddr, block_size)?;

    let ci_count = le_u32(&cib, CIB_CHUNK_INFO_COUNT) as usize;
    if within_cib >= ci_count {
        return Err(range(
            "chunk_info_index",
            within_cib as u64,
            ci_count as u64,
        ));
    }
    let ci_off = CIB_CHUNK_INFO + within_cib * CHUNK_INFO_LEN;
    let bitmap_addr = le_u64(&cib, ci_off + CI_BITMAP_ADDR);

    // A zero bitmap address means the whole chunk is free (no bitmap allocated).
    if bitmap_addr == 0 {
        return Ok(true);
    }

    // The bitmap is a raw block (one bit per block, LSB-first), no obj_phys header.
    let mut bitmap = vec![0u8; block_size];
    let offset = bitmap_addr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut bitmap)?;

    let bit = (block % blocks_per_chunk) as usize;
    let allocated = bitmap
        .get(bit / 8)
        .is_some_and(|byte| byte & (1u8 << (bit % 8)) != 0);
    Ok(!allocated)
}
