//! File-system record keys (`j_key_t`) and record-type dispatch.
//!
//! Every file-system record's key begins with `j_key_t { u64 obj_id_and_type }`
//! (Apple *APFS Reference*). The top 4 bits are the record type
//! (`OBJ_TYPE_SHIFT 60`, `OBJ_TYPE_MASK 0xf000000000000000`); the low 60 bits
//! are the object id (`OBJ_ID_MASK 0x0fffffffffffffff`).
//!
//! Record types (`j_obj_types`, verbatim numeric values from Apple):
//! `SNAP_METADATA 1`, `EXTENT 2`, `INODE 3`, `XATTR 4`, `SIBLING_LINK 5`,
//! `DSTREAM_ID 6`, `CRYPTO_STATE 7`, `FILE_EXTENT 8`, `DIR_REC 9`,
//! `DIR_STATS 10`, `SNAP_NAME 11`, `SIBLING_MAP 12`, `FILE_INFO 13`.
//!
//! Variable records carry extended fields (xfields) after the fixed value: an
//! `xf_blob { u16 xf_num_exts; u16 xf_used_data; u8 xf_data[] }`. `xf_data`
//! begins with `xf_num_exts` 4-byte descriptors (`x_field_t { u8 x_type;
//! u8 x_flags; u16 x_size }`), followed by the field value data — each value is
//! **8-byte aligned** (Apple). Common fields: `INO_EXT_TYPE_NAME 4` (filename),
//! `INO_EXT_TYPE_DSTREAM 8` (data-stream attribute → file size),
//! `INO_EXT_TYPE_DOCUMENT_ID 3`. Layout verified verbatim against the Apple
//! reference + libfsapfs format spec.

/// APFS file-system record types (`j_obj_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordType {
    SnapMetadata = 1,
    Extent = 2,
    Inode = 3,
    Xattr = 4,
    SiblingLink = 5,
    DstreamId = 6,
    CryptoState = 7,
    FileExtent = 8,
    DirRec = 9,
    DirStats = 10,
    SnapName = 11,
    SiblingMap = 12,
    FileInfo = 13,
}

impl RecordType {
    /// Map a 4-bit `j_obj_types` value to a [`RecordType`]; `None` for an
    /// undefined type code (0, 14, 15).
    #[must_use]
    pub fn from_u4(value: u8) -> Option<Self> {
        Some(match value {
            1 => RecordType::SnapMetadata,
            2 => RecordType::Extent,
            3 => RecordType::Inode,
            4 => RecordType::Xattr,
            5 => RecordType::SiblingLink,
            6 => RecordType::DstreamId,
            7 => RecordType::CryptoState,
            8 => RecordType::FileExtent,
            9 => RecordType::DirRec,
            10 => RecordType::DirStats,
            11 => RecordType::SnapName,
            12 => RecordType::SiblingMap,
            13 => RecordType::FileInfo,
            _ => return None,
        })
    }
}

/// Top-4-bit type shift in `j_key.obj_id_and_type`.
pub const OBJ_TYPE_SHIFT: u64 = 60;
/// Low-60-bit object-id mask.
pub const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;

/// Decode a `j_key_t.obj_id_and_type` into `(object_id, record_type)`.
///
/// The object id is always returned (even for an undefined type) so a caller
/// reporting an unrecognized record still has the offending oid (fleet "show the
/// value" rule).
#[must_use]
pub fn decode_jkey(obj_id_and_type: u64) -> (u64, Option<RecordType>) {
    let oid = obj_id_and_type & OBJ_ID_MASK;
    #[allow(clippy::cast_possible_truncation)]
    let ty = ((obj_id_and_type >> OBJ_TYPE_SHIFT) & 0xf) as u8;
    (oid, RecordType::from_u4(ty))
}

// xf_blob header field offsets.
const OFF_XF_NUM_EXTS: usize = 0;
const OFF_XF_USED_DATA: usize = 2;
/// First `x_field_t` descriptor begins after the 4-byte `xf_blob` header.
const XF_DESC_OFF: usize = 4;
/// `x_field_t` descriptor length (`x_type` u8, `x_flags` u8, `x_size` u16).
const XF_DESC_LEN: usize = 4;

/// Hard cap on `xf_num_exts` — an inode/drec value cannot hold more than a few
/// hundred extended fields; cap well above any legal value to reject an
/// allocation-bomb count without rejecting a legal blob.
const MAX_XF_NUM_EXTS: usize = 4096;

/// Walk an `xf_blob` extended-field area, returning `(x_type, value_bytes)` per
/// field (bounds-checked, never panics).
///
/// Each value slice is 8-byte aligned within `xf_data` per the Apple spec; an
/// out-of-bounds descriptor or value (a hostile/short blob) ends the walk early,
/// yielding only the fields that fully fit.
#[must_use]
pub fn parse_xfields(data: &[u8]) -> Vec<(u8, &[u8])> {
    if data.len() < XF_DESC_OFF {
        return Vec::new();
    }
    let num = crate::bytes::le_u16(data, OFF_XF_NUM_EXTS) as usize;
    let _used = crate::bytes::le_u16(data, OFF_XF_USED_DATA);
    let num = num.min(MAX_XF_NUM_EXTS);

    // The descriptor table is `num` 4-byte entries; value data follows it.
    let Some(desc_end) = num
        .checked_mul(XF_DESC_LEN)
        .and_then(|t| t.checked_add(XF_DESC_OFF))
    else {
        return Vec::new(); // cov:unreachable: num capped at MAX_XF_NUM_EXTS
    };
    // If the descriptor table itself does not fit, there are no decodable fields.
    if desc_end > data.len() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(num);
    let mut value_off = desc_end;
    for i in 0..num {
        let d = XF_DESC_OFF + i * XF_DESC_LEN;
        let x_type = data[d]; // d < desc_end <= data.len(), in bounds
        let x_size = crate::bytes::le_u16(data, d + 2) as usize;

        // The value slice [value_off, value_off + x_size) must lie within the
        // blob; a hostile size ends the walk rather than over-reading.
        let Some(end) = value_off.checked_add(x_size) else {
            break; // cov:unreachable: u16 size + usize off cannot overflow usize
        };
        let Some(value) = data.get(value_off..end) else {
            break;
        };
        out.push((x_type, value));

        // Advance to the next 8-byte-aligned value boundary.
        let aligned = (x_size + 7) & !7;
        let Some(next) = value_off.checked_add(aligned) else {
            break; // cov:unreachable: aligned size cannot overflow a valid blob
        };
        value_off = next;
    }
    out
}
