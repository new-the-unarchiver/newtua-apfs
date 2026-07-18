//! Extended attributes (`APFS_TYPE_XATTR 4`, value `j_xattr_val_t`) and symlink
//! targets.
//!
//! An xattr key is `j_xattr_key_t { j_key; u16 name_len; u8 name[] }` (the
//! `name_len` includes the trailing NUL). The value is `j_xattr_val_t { u16
//! flags; u16 xdata_len; u8 xdata[] }` (Apple *APFS Reference*). The `flags`
//! word selects where the data lives:
//!
//! - **`XATTR_DATA_EMBEDDED` (0x0002)** — `xdata` holds the attribute value
//!   inline.
//! - **`XATTR_DATA_STREAM` (0x0001)** — `xdata` holds a `j_xattr_dstream_t`
//!   (`u64 xattr_obj_id` = the dstream id, then a `j_dstream_t { u64 size; … }`);
//!   the value bytes are the extents keyed by that dstream id.
//!
//! Forensically important named xattrs:
//! - `com.apple.decmpfs` — transparent-compression header ([`crate::compression`]).
//! - `com.apple.ResourceFork` — resource fork (non-embedded compressed payload),
//!   stored as a stream xattr.
//! - `com.apple.fs.symlink` — a symlink's target path, stored **embedded** in the
//!   xattr value (verified against the real fixture: flags `0x6` =
//!   `EMBEDDED | 0x4`, value `"Dir1/Beth.txt\0"`).

use std::io::{Read, Seek};

use crate::dir::for_each_fs_record_for_oid;
use crate::fsrecord::{decode_jkey, RecordType};
use crate::volume::ApfsVolume;

/// `XATTR_DATA_STREAM` flag (the value is in a referenced data stream).
pub const XATTR_DATA_STREAM: u16 = 0x0001;
/// `XATTR_DATA_EMBEDDED` flag (the value is inline in the record).
pub const XATTR_DATA_EMBEDDED: u16 = 0x0002;

/// The `com.apple.decmpfs` xattr name (transparent compression header).
pub const XATTR_NAME_DECMPFS: &str = "com.apple.decmpfs";
/// The `com.apple.ResourceFork` xattr name (resource fork / compressed payload).
pub const XATTR_NAME_RESOURCE_FORK: &str = "com.apple.ResourceFork";
/// The `com.apple.fs.symlink` xattr name (symlink target path).
pub const XATTR_NAME_SYMLINK: &str = "com.apple.fs.symlink";

// j_xattr_key_t: name_len u16 follows the 8-byte j_key; name follows at @10.
const OFF_XATTR_KEY_NAME_LEN: usize = 8;
const OFF_XATTR_KEY_NAME: usize = 10;
// j_xattr_val_t: flags u16 @0, xdata_len u16 @2, xdata @4.
const OFF_XATTR_VAL_FLAGS: usize = 0;
const OFF_XATTR_VAL_XDATA_LEN: usize = 2;
const OFF_XATTR_VAL_XDATA: usize = 4;
// j_xattr_dstream_t (the embedded value of a XATTR_DATA_STREAM xattr):
//   u64 xattr_obj_id; then j_dstream_t { u64 size; … }.
const OFF_XDSTREAM_OBJ_ID: usize = 0;
const OFF_XDSTREAM_SIZE: usize = 8;

/// Where an xattr's value lives.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum XattrValue {
    /// The value is stored inline in the record.
    Embedded(Vec<u8>),
    /// The value is stored in a data stream: `(dstream_oid, logical_size)`. The
    /// bytes are the `FILE_EXTENT` records keyed by `dstream_oid`
    /// ([`crate::extent::read_stream`]).
    Stream { dstream_oid: u64, size: u64 },
}

/// A parsed extended attribute.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Xattr {
    /// The attribute name (e.g. `com.apple.decmpfs`).
    pub name: String,
    /// The raw `j_xattr_val_t.flags` word.
    pub flags: u16,
    /// The attribute value (embedded bytes or a stream reference).
    pub value: XattrValue,
}

/// Decode a single `XATTR` (key, value) record, or `None` if the key has no
/// decodable name (a malformed/hostile record is skipped, never panics).
fn parse_xattr(key: &[u8], value: &[u8]) -> Option<Xattr> {
    let name_len = crate::bytes::le_u16(key, OFF_XATTR_KEY_NAME_LEN) as usize;
    if name_len == 0 {
        return None;
    }
    let name_bytes = key.get(OFF_XATTR_KEY_NAME..OFF_XATTR_KEY_NAME + name_len)?;
    let name = decode_cstr(name_bytes);

    let flags = crate::bytes::le_u16(value, OFF_XATTR_VAL_FLAGS);
    let xdata_len = crate::bytes::le_u16(value, OFF_XATTR_VAL_XDATA_LEN) as usize;
    let xdata = value
        .get(OFF_XATTR_VAL_XDATA..OFF_XATTR_VAL_XDATA + xdata_len)
        .unwrap_or(&[]);

    let xvalue = if flags & XATTR_DATA_STREAM != 0 {
        XattrValue::Stream {
            dstream_oid: crate::bytes::le_u64(xdata, OFF_XDSTREAM_OBJ_ID),
            size: crate::bytes::le_u64(xdata, OFF_XDSTREAM_SIZE),
        }
    } else {
        XattrValue::Embedded(xdata.to_vec())
    };
    Some(Xattr {
        name,
        flags,
        value: xvalue,
    })
}

/// List all extended attributes of the inode `inode_oid`, scanning the volume
/// fs-tree for `XATTR` records whose key oid is the inode.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::ChecksumMismatch`]
/// / [`crate::ApfsError::CycleGuard`] / [`crate::ApfsError::Io`] on a
/// structurally invalid omap/fs-tree or a read failure.
pub fn list_xattrs<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode_oid: u64,
    block_size: usize,
) -> crate::Result<Vec<Xattr>> {
    let mut out = Vec::new();
    for_each_fs_record_for_oid(reader, volume, block_size, inode_oid, &mut |key, value| {
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::Xattr) || oid != inode_oid {
            return;
        }
        if let Some(x) = parse_xattr(key, value) {
            out.push(x);
        }
    })?;
    Ok(out)
}

/// Fetch a named xattr's value for an inode, or `None` if absent.
///
/// # Errors
/// As [`list_xattrs`].
pub fn get_xattr<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode_oid: u64,
    name: &str,
    block_size: usize,
) -> crate::Result<Option<XattrValue>> {
    let xattrs = list_xattrs(reader, volume, inode_oid, block_size)?;
    Ok(xattrs.into_iter().find(|x| x.name == name).map(|x| x.value))
}

/// Return the raw `com.apple.decmpfs` header bytes for an inode, if it is a
/// transparently-compressed file. The decmpfs header is always embedded in the
/// xattr (the bulk payload, when large, lives in the resource fork — see
/// [`resource_fork`]).
///
/// # Errors
/// As [`list_xattrs`].
pub fn decmpfs_header<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode_oid: u64,
    block_size: usize,
) -> crate::Result<Option<Vec<u8>>> {
    match get_xattr(reader, volume, inode_oid, XATTR_NAME_DECMPFS, block_size)? {
        // The decmpfs xattr is embedded; an unexpected stream form yields its
        // (empty) embedded bytes, which the decoder then rejects loudly.
        Some(XattrValue::Embedded(bytes)) => Ok(Some(bytes)),
        Some(XattrValue::Stream { .. }) | None => Ok(None),
    }
}

/// Read the inode's `com.apple.ResourceFork` value as bytes, if present.
///
/// The resource fork holds a non-embedded decmpfs payload. It is normally a
/// stream xattr (`XATTR_DATA_STREAM`) whose dstream is read through the extent
/// machinery; a small fork may be embedded.
///
/// # Errors
/// As [`list_xattrs`], plus the structural errors of
/// [`crate::extent::read_stream`] when the fork is stream-backed.
pub fn resource_fork<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode_oid: u64,
    block_size: usize,
) -> crate::Result<Option<Vec<u8>>> {
    match get_xattr(
        reader,
        volume,
        inode_oid,
        XATTR_NAME_RESOURCE_FORK,
        block_size,
    )? {
        Some(XattrValue::Embedded(bytes)) => Ok(Some(bytes)),
        Some(XattrValue::Stream { dstream_oid, size }) => {
            let bytes = crate::extent::read_stream(reader, volume, dstream_oid, size, block_size)?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

/// Resolve a symlink's target path. APFS stores it in the `com.apple.fs.symlink`
/// xattr value (embedded), as a NUL-terminated UTF-8 path. `None` if the inode is
/// not a symlink (no such xattr).
///
/// # Errors
/// As [`list_xattrs`].
pub fn symlink_target<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode_oid: u64,
    block_size: usize,
) -> crate::Result<Option<String>> {
    match get_xattr(reader, volume, inode_oid, XATTR_NAME_SYMLINK, block_size)? {
        Some(XattrValue::Embedded(bytes)) => Ok(Some(decode_cstr(&bytes))),
        // A stream-backed symlink target is not a form macOS produces; surface
        // None rather than guess (the caller can still list the raw xattr).
        Some(XattrValue::Stream { .. }) | None => Ok(None),
    }
}

/// Decode a NUL-terminated UTF-8 byte string. Bytes after the first NUL are
/// dropped; invalid UTF-8 is replaced (never panics).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
