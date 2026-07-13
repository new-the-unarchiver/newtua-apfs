//! Inode records (`APFS_TYPE_INODE 3`, value `j_inode_val_t`).
//!
//! Apple *APFS Reference*, `j_inode_val_t`: `parent_id`, `private_id` (the
//! data-stream object id), four timestamps, `internal_flags`, a
//! `nchildren`/`nlink` union, ownership/mode, then extended fields (xfields).
//! **Timestamps are 64-bit nanoseconds since 1970-01-01 00:00 UTC** (disregarding
//! leap seconds); zero is a contextual lead, not a spec-defined "unset" sentinel.
//! The filename lives in an `INO_EXT_TYPE_NAME 4` xfield; the data-stream
//! attribute (carrying the logical file size) in an `INO_EXT_TYPE_DSTREAM 8`
//! xfield.
//!
//! On-disk field offsets within the value (verified empirically against the real
//! self-minted fixture and cross-checked against TSK `istat` — timestamps, mode,
//! uid/gid, nchildren — see `docs/validation.md`):
//!
//! | off | size | field                          |
//! |-----|------|--------------------------------|
//! | 0   | 8    | `parent_id`                    |
//! | 8   | 8    | `private_id` (data-stream oid) |
//! | 16  | 8    | `create_time`                  |
//! | 24  | 8    | `mod_time`                     |
//! | 32  | 8    | `change_time`                  |
//! | 40  | 8    | `access_time`                  |
//! | 48  | 8    | `internal_flags`               |
//! | 56  | 4    | `nchildren` / `nlink` (union)  |
//! | 68  | 4    | `bsd_flags`                    |
//! | 72  | 4    | `owner` (uid)                  |
//! | 76  | 4    | `group` (gid)                  |
//! | 80  | 2    | `mode`                         |
//! | 92  | …    | extended fields (`xf_blob`)    |
//!
//! The fixed prefix differs from the libfsapfs asciidoc table (which inserts a
//! phantom 8-byte gap, placing access@48 / flags@56 / mode@86); the real on-disk
//! layout above reconciles exactly with the TSK oracle.

use chrono::{DateTime, Utc};

use crate::fsrecord::parse_xfields;

// `j_inode_val_t` fixed-field offsets (verified vs the fixture + TSK istat).
const OFF_PARENT_ID: usize = 0;
const OFF_PRIVATE_ID: usize = 8;
const OFF_CREATE_TIME: usize = 16;
const OFF_MOD_TIME: usize = 24;
const OFF_CHANGE_TIME: usize = 32;
const OFF_ACCESS_TIME: usize = 40;
const OFF_INTERNAL_FLAGS: usize = 48;
const OFF_NCHILDREN: usize = 56;
const OFF_BSD_FLAGS: usize = 68;
const OFF_OWNER: usize = 72;
const OFF_GROUP: usize = 76;
const OFF_MODE: usize = 80;
/// Extended fields begin after the 92-byte fixed inode prefix.
const OFF_XFIELDS: usize = 92;

/// Inode extended-field type `INO_EXT_TYPE_NAME` (filename, UTF-8 + NUL).
const INO_EXT_TYPE_NAME: u8 = 4;
/// Inode extended-field type `INO_EXT_TYPE_DSTREAM` (data-stream attribute).
const INO_EXT_TYPE_DSTREAM: u8 = 8;

/// Nanoseconds per second — APFS timestamps are ns since the Unix epoch.
const NS_PER_SEC: i64 = 1_000_000_000;

/// A parsed inode.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Inode {
    /// File-system object id of this inode (the `j_key` oid).
    pub oid: u64,
    /// `parent_id` — the inode of the containing directory.
    pub parent_id: u64,
    /// `private_id` — the data-stream object id (file extents are keyed by it).
    pub private_id: u64,
    /// `create_time` (ns since 1970-01-01 UTC).
    pub create_time: u64,
    /// `mod_time` (ns since 1970-01-01 UTC).
    pub mod_time: u64,
    /// `change_time` (ns since 1970-01-01 UTC).
    pub change_time: u64,
    /// `access_time` (ns since 1970-01-01 UTC).
    pub access_time: u64,
    /// `internal_flags` (e.g. `INODE_WAS_CLONED`, `INODE_NO_RSRC_FORK`).
    pub internal_flags: u64,
    /// `nchildren` (directories) or `nlink` (files) — the same union field.
    pub nlink_or_nchildren: i32,
    /// `bsd_flags` — BSD file entry flags.
    pub bsd_flags: u32,
    /// `owner` — owner user id (uid).
    pub uid: u32,
    /// `group` — group id (gid).
    pub gid: u32,
    /// `mode` — POSIX file mode (type bits + permissions).
    pub mode: u16,
    /// Filename from the `INO_EXT_TYPE_NAME` xfield, if present.
    pub name: Option<String>,
    /// Logical file size (the data-stream `used_size`) from the
    /// `INO_EXT_TYPE_DSTREAM` xfield, if present (directories have none).
    pub size: Option<u64>,
}

impl Inode {
    /// Parse a `j_inode_val_t` value (+ xfields) for `oid`. Bounds-checked: a
    /// truncated value reads missing fields as 0 rather than panicking.
    ///
    /// # Errors
    /// Never fails for a well-formed slice today; the `Result` is reserved for
    /// future stricter validation (kept for API stability).
    pub fn parse(oid: u64, value: &[u8]) -> crate::Result<Self> {
        let mut name = None;
        let mut size = None;
        if value.len() > OFF_XFIELDS {
            for (x_type, data) in parse_xfields(&value[OFF_XFIELDS..]) {
                match x_type {
                    INO_EXT_TYPE_NAME => name = Some(decode_cstr(data)),
                    // The data-stream attribute's first u64 is `used_size`, the
                    // logical file size.
                    INO_EXT_TYPE_DSTREAM => size = Some(crate::bytes::le_u64(data, 0)),
                    _ => {}
                }
            }
        }

        Ok(Self {
            oid,
            parent_id: crate::bytes::le_u64(value, OFF_PARENT_ID),
            private_id: crate::bytes::le_u64(value, OFF_PRIVATE_ID),
            create_time: crate::bytes::le_u64(value, OFF_CREATE_TIME),
            mod_time: crate::bytes::le_u64(value, OFF_MOD_TIME),
            change_time: crate::bytes::le_u64(value, OFF_CHANGE_TIME),
            access_time: crate::bytes::le_u64(value, OFF_ACCESS_TIME),
            internal_flags: crate::bytes::le_u64(value, OFF_INTERNAL_FLAGS),
            #[allow(clippy::cast_possible_wrap)]
            nlink_or_nchildren: crate::bytes::le_u32(value, OFF_NCHILDREN) as i32,
            bsd_flags: crate::bytes::le_u32(value, OFF_BSD_FLAGS),
            uid: crate::bytes::le_u32(value, OFF_OWNER),
            gid: crate::bytes::le_u32(value, OFF_GROUP),
            mode: crate::bytes::le_u16(value, OFF_MODE),
            name,
            size,
        })
    }

    /// `create_time` as a UTC datetime.
    #[must_use]
    pub fn created(&self) -> Option<DateTime<Utc>> {
        ns_to_datetime(self.create_time)
    }

    /// `mod_time` as a UTC datetime.
    #[must_use]
    pub fn modified(&self) -> Option<DateTime<Utc>> {
        ns_to_datetime(self.mod_time)
    }

    /// `change_time` as a UTC datetime.
    #[must_use]
    pub fn changed(&self) -> Option<DateTime<Utc>> {
        ns_to_datetime(self.change_time)
    }

    /// `access_time` as a UTC datetime.
    #[must_use]
    pub fn accessed(&self) -> Option<DateTime<Utc>> {
        ns_to_datetime(self.access_time)
    }
}

/// Convert APFS nanoseconds-since-epoch to a UTC datetime (range-checked).
/// `None` for a value beyond the representable range (never panics).
#[must_use]
pub fn ns_to_datetime(ns: u64) -> Option<DateTime<Utc>> {
    // Split into whole seconds + sub-second nanos, both non-negative.
    #[allow(clippy::cast_possible_wrap)]
    let secs = (ns / NS_PER_SEC as u64) as i64;
    #[allow(clippy::cast_possible_truncation)]
    let nanos = (ns % NS_PER_SEC as u64) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Decode a NUL-terminated UTF-8 byte string (the xfield filename form). Bytes
/// after the first NUL are dropped; invalid UTF-8 is replaced (never panics).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
