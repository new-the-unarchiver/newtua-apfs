//! Object header (`obj_phys_t`) parsing and Fletcher-64 checksum verification.
//!
//! Every APFS on-disk object begins with a 32-byte header
//! (Apple *APFS Reference*, `obj_phys_t`; `MAX_CKSUM_SIZE = 8`):
//!
//! | off | size | field        |
//! |-----|------|--------------|
//! | 0   | 8    | `o_cksum`    | Fletcher-64 checksum |
//! | 8   | 8    | `o_oid`      | object identifier    |
//! | 16  | 8    | `o_xid`      | transaction id       |
//! | 24  | 4    | `o_type`     | type + storage flags |
//! | 28  | 4    | `o_subtype`  | subtype              |
//!
//! `o_type & OBJECT_TYPE_MASK (0x0000ffff)` selects the object type;
//! `OBJ_STORAGETYPE_MASK (0xc0000000)` carries physical/ephemeral/virtual flags.
//!
//! Object-type constants (complete, from Apple): `INVALID 0x0`, `NX_SUPERBLOCK
//! 0x1`, `BTREE 0x2`, `BTREE_NODE 0x3`, `SPACEMAN 0x5`, …, `OMAP 0xb`,
//! `CHECKPOINT_MAP 0xc`, `FS 0xd`, `FSTREE 0xe`, …, `INTEGRITY_META 0x1e`,
//! `FEXT_TREE 0x1f`, plus the keybag 4CC object types. The authoritative table
//! lives in [`forensicnomicon`]; this module decodes against it.

/// Size in bytes of the `obj_phys_t` header.
pub const OBJ_PHYS_LEN: usize = 32;

/// Read the stored Fletcher-64 checksum (`o_cksum`, the first 8 bytes of an
/// object). Bounds-checked: `0` if the block is shorter than 8 bytes.
#[must_use]
pub fn fletcher64_stored(block: &[u8]) -> u64 {
    crate::bytes::le_u64(block, 0)
}

/// A parsed object header.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ObjPhys {
    /// Stored Fletcher-64 checksum (`o_cksum`).
    pub cksum: u64,
    /// Object identifier (`o_oid`) — for a physical object, its block address.
    pub oid: u64,
    /// Transaction identifier (`o_xid`).
    pub xid: u64,
    /// Raw `o_type` (type + storage/flag bits).
    pub obj_type_raw: u32,
    /// `o_subtype`.
    pub subtype: u32,
}

impl ObjPhys {
    /// Parse a header from the start of `block`. Bounds-checked; returns `None`
    /// if the slice is too short (never panics).
    ///
    /// Layout (Apple `obj_phys_t`, little-endian on disk): `o_cksum[8]` @0,
    /// `o_oid` u64 @8, `o_xid` u64 @16, `o_type` u32 @24, `o_subtype` u32 @28.
    #[must_use]
    pub fn parse(block: &[u8]) -> Option<Self> {
        if block.len() < OBJ_PHYS_LEN {
            return None;
        }
        Some(Self {
            cksum: crate::bytes::le_u64(block, 0),
            oid: crate::bytes::le_u64(block, 8),
            xid: crate::bytes::le_u64(block, 16),
            obj_type_raw: crate::bytes::le_u32(block, 24),
            subtype: crate::bytes::le_u32(block, 28),
        })
    }

    /// The object type after masking off storage/flag bits
    /// (`o_type & OBJECT_TYPE_MASK`).
    #[must_use]
    pub fn obj_type(&self) -> u16 {
        (self.obj_type_raw & 0x0000_ffff) as u16
    }
}

/// Compute the APFS Fletcher-64 object checksum over `block`, treating the first
/// 8 bytes (the stored `o_cksum`) as zero.
///
/// Apple specifies Fletcher-64; the exact modular arithmetic is taken from the
/// libfsapfs reverse-engineered spec and **must be validated against real APFS
/// object test vectors + apfsck** before being trusted (a wrong implementation
/// would make every block fail verification).
#[must_use]
pub fn fletcher64_checksum(block: &[u8]) -> u64 {
    // APFS Fletcher-64 (Apple names the algorithm; the modular steps follow the
    // libfsapfs formulation and are validated against a real Apple-stored
    // o_cksum in core/tests/object.rs):
    //   - iterate the object as 32-bit little-endian words,
    //   - treat the 8-byte o_cksum field (the first two words) as zero,
    //   - accumulate two running sums modulo 0xffffffff,
    //   - fold into the lower then upper 32 bits.
    const MOD: u64 = 0xffff_ffff;
    let mut sum_lo: u64 = 0;
    let mut sum_hi: u64 = 0;

    // chunks_exact yields only whole 4-byte words; a trailing partial word
    // (malformed/odd-length input) is ignored — never indexed, never panics.
    for (i, word) in block.chunks_exact(4).enumerate() {
        // word is exactly 4 bytes from chunks_exact, so the conversion is total.
        let v = if i < 2 {
            0 // the o_cksum field is excluded from its own checksum
        } else {
            u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        };
        sum_lo = (sum_lo + v) % MOD;
        sum_hi = (sum_hi + sum_lo) % MOD;
    }

    let check_lo = MOD - ((sum_lo + sum_hi) % MOD);
    let check_hi = MOD - ((sum_lo + check_lo) % MOD);
    (check_hi << 32) | check_lo
}
