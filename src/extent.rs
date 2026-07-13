//! File extents (`APFS_TYPE_FILE_EXTENT 8`, value `j_file_extent_val_t`) and
//! file byte assembly.
//!
//! A file's content is described by a data stream (the inode's `private_id`,
//! also surfaced as the `INO_EXT_TYPE_DSTREAM` xfield giving the logical `size`)
//! plus a series of `FILE_EXTENT` records keyed by `(private_id, FILE_EXTENT,
//! logical_offset)`. Each `j_file_extent_val_t { u64 len_and_flags; u64
//! phys_block_num; u64 crypto_id }` (Apple *APFS Reference*) carries the extent
//! length (`len_and_flags & J_FILE_EXTENT_LEN_MASK 0x00ffffffffffffff`, a
//! multiple of the block size) and the starting physical block. A
//! `phys_block_num` of 0 is a **sparse hole** — it reads back as zeroes.
//!
//! [`read_data`] assembles extents in logical order into plaintext bytes,
//! truncating to the inode's DSTREAM `size`; if the inode carries a
//! `com.apple.decmpfs` xattr, [`crate::compression`] is applied transparently
//! over the decmpfs payload (inline xattr or `com.apple.ResourceFork` stream)
//! instead of the regular extent stream.

use std::io::{Read, Seek};

use crate::dir::for_each_fs_record_for_oid;
use crate::fsrecord::{decode_jkey, RecordType};
use crate::inode::Inode;
use crate::volume::ApfsVolume;

/// Mask for the extent length within `len_and_flags` (`J_FILE_EXTENT_LEN_MASK`).
pub const J_FILE_EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

// j_file_extent_key_t: the logical offset is the second u64 of the key, after
// the 8-byte j_key header.
const OFF_FEXT_KEY_LOGICAL: usize = 8;
// j_file_extent_val_t field offsets.
const OFF_FEXT_LEN_AND_FLAGS: usize = 0;
const OFF_FEXT_PHYS_BLOCK: usize = 8;

/// Hard cap on assembled file size (allocation-bomb defense). A single image we
/// would read in memory cannot legitimately exceed this; a DSTREAM `size` or an
/// extent run beyond it is rejected loudly rather than allocated.
const MAX_FILE_BYTES: u64 = 1 << 34; // 16 GiB

/// One file extent (a `j_file_extent_val_t` plus its logical offset).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FileExtent {
    /// Logical offset within the file (from the record key).
    pub logical_offset: u64,
    /// Length in bytes (`len_and_flags & J_FILE_EXTENT_LEN_MASK`).
    pub len: u64,
    /// Starting physical block (0 = sparse hole).
    pub phys_block_num: u64,
}

/// List the `FILE_EXTENT` records of a data stream (`stream_oid`, an inode's
/// `private_id` for the main fork or a resource-fork dstream id), sorted by
/// logical offset.
///
/// A `phys_block_num` of 0 is preserved as a sparse hole; callers zero-fill it.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::ChecksumMismatch`]
/// / [`crate::ApfsError::CycleGuard`] / [`crate::ApfsError::Io`] on a
/// structurally invalid omap/fs-tree or a read failure.
pub fn list_extents<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    stream_oid: u64,
    block_size: usize,
) -> crate::Result<Vec<FileExtent>> {
    let mut out = Vec::new();
    for_each_fs_record_for_oid(reader, volume, block_size, stream_oid, &mut |key, value| {
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::FileExtent) || oid != stream_oid {
            return;
        }
        let logical_offset = crate::bytes::le_u64(key, OFF_FEXT_KEY_LOGICAL);
        let len = crate::bytes::le_u64(value, OFF_FEXT_LEN_AND_FLAGS) & J_FILE_EXTENT_LEN_MASK;
        let phys_block_num = crate::bytes::le_u64(value, OFF_FEXT_PHYS_BLOCK);
        out.push(FileExtent {
            logical_offset,
            len,
            phys_block_num,
        });
    })?;
    out.sort_by_key(|e| e.logical_offset);
    Ok(out)
}

/// Assemble the raw extent stream of `stream_oid` into a byte buffer, zero-filling
/// sparse holes, then truncate/zero-extend to exactly `logical_size` bytes.
///
/// This is the *physical* read: it does not apply decmpfs. [`read_data`] uses it
/// for an ordinary file and to fetch a decmpfs resource-fork stream.
///
/// # Errors
/// [`crate::ApfsError::FieldOutOfRange`] if `logical_size` or an extent block
/// number exceeds the sanity caps / the image, plus the structural errors of
/// [`list_extents`].
pub fn read_stream<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    stream_oid: u64,
    logical_size: u64,
    block_size: usize,
) -> crate::Result<Vec<u8>> {
    if logical_size > MAX_FILE_BYTES {
        return Err(crate::ApfsError::FieldOutOfRange {
            structure: "j_dstream",
            field: "size",
            value: logical_size,
            cap: MAX_FILE_BYTES,
        });
    }
    let extents = list_extents(reader, volume, stream_oid, block_size)?;

    let size = logical_size as usize;
    let mut out = vec![0u8; size];
    for ext in &extents {
        // Only fill within the logical size; extents past EOF (alloced tail) are
        // ignored, holes leave the pre-zeroed region untouched.
        let start = ext.logical_offset as usize;
        if start >= size || ext.phys_block_num == 0 {
            continue;
        }
        let avail = size - start;
        let copy_len = (ext.len as usize).min(avail);
        // Range-check the physical span against the image before reading.
        let byte_off = ext.phys_block_num.checked_mul(block_size as u64).ok_or(
            crate::ApfsError::FieldOutOfRange {
                structure: "j_file_extent",
                field: "phys_block_num",
                value: ext.phys_block_num,
                cap: u64::MAX / block_size as u64,
            },
        )?;
        reader.seek(std::io::SeekFrom::Start(byte_off))?;
        reader.read_exact(&mut out[start..start + copy_len])?;
    }
    Ok(out)
}

/// Assemble a file's full byte content, applying transparent decmpfs compression
/// when the inode carries a `com.apple.decmpfs` xattr.
///
/// For an ordinary file, the data stream (`inode.private_id`) is read extent by
/// extent (sparse holes zero-filled) and truncated to the inode's logical
/// `size`. For a transparently-compressed file, the decmpfs payload (inline in
/// the xattr or in the `com.apple.ResourceFork` stream) is decoded via
/// [`crate::compression`] — never the raw extent bytes.
///
/// # Errors
/// [`crate::ApfsError::Decmpfs`] if a decmpfs file's payload cannot be decoded
/// (a named codec/format error — never fabricated bytes); the structural errors
/// of [`read_stream`] otherwise.
pub fn read_data<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode: &Inode,
    block_size: usize,
) -> crate::Result<Vec<u8>> {
    // A compressed file is identified by a `com.apple.decmpfs` xattr.
    if let Some(header) = crate::xattr::decmpfs_header(reader, volume, inode.oid, block_size)? {
        return crate::compression::read_compressed(reader, volume, inode, &header, block_size);
    }

    let size = inode.size.unwrap_or(0);
    read_stream(reader, volume, inode.private_id, size, block_size)
}
