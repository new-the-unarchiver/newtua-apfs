//! Sealed / signed system volume: integrity metadata and file-info records —
//! **parse + accessors only** (hash recomputation + seal validation live in the
//! analyzer, `apfs-forensic::sealed`).
//!
//! On a sealed volume (macOS Signed System Volume), an
//! `integrity_meta_phys_t` object (type `OBJECT_TYPE_INTEGRITY_META 0x1e`)
//! anchors a Merkle tree over the volume's content. Apple *APFS Reference*,
//! `integrity_meta_phys_t`: `im_version`, `im_flags`, `im_hash_type`
//! (`apfs_hash_type_t`, e.g. SHA-256), `im_root_hash_offset`, **`im_broken_xid`**
//! (non-zero ⇒ the seal was broken at that transaction), `im_reserved[9]`.
//! Per-file hashes live in `APFS_TYPE_FILE_INFO 13` records (`j_file_info_val_t`)
//! and a file-extent tree (`fext_tree_key_t`/`fext_tree_val_t`, type
//! `OBJECT_TYPE_FEXT_TREE 0x1f`).
//!
//! This module decodes those structures and exposes accessors (root hash, hash
//! type, `im_broken_xid`, per-file hashes). It does **not** recompute or compare
//! hashes — that is a forensic judgment (and the exact canonicalization is the
//! least-documented, highest-FP-risk area), so it lives in the analyzer and is
//! validated only against a real SSV image + apfsck.

/// Parsed integrity metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IntegrityMeta {
    pub version: u32,
    pub flags: u32,
    pub hash_type: u32,
    /// Non-zero ⇒ the seal is recorded as broken at this transaction id.
    pub broken_xid: u64,
}

// `integrity_meta_phys_t` field offsets (after the 32-byte obj_phys header).
const OFF_IM_VERSION: usize = 32; // u32
const OFF_IM_FLAGS: usize = 36; // u32
const OFF_IM_HASH_TYPE: usize = 40; // u32 (apfs_hash_type_t)
const OFF_IM_BROKEN_XID: usize = 48; // xid_t (u64)
const INTEGRITY_META_MIN_LEN: usize = OFF_IM_BROKEN_XID + 8;

impl IntegrityMeta {
    /// Parse an `integrity_meta_phys_t` (parse only — no hash recomputation,
    /// which is a forensic judgment in `apfs-forensic::sealed`).
    ///
    /// # Errors
    /// [`crate::ApfsError::ChecksumMismatch`] on a Fletcher-64 failure (checksum-
    /// before-trust); [`crate::ApfsError::FieldOutOfRange`] if the block is too
    /// short to hold the structure.
    pub fn parse(block: &[u8]) -> crate::Result<Self> {
        if block.len() < INTEGRITY_META_MIN_LEN {
            return Err(crate::ApfsError::FieldOutOfRange {
                structure: "integrity_meta_phys",
                field: "block.len",
                value: block.len() as u64,
                cap: INTEGRITY_META_MIN_LEN as u64,
            });
        }
        let stored = crate::object::fletcher64_stored(block);
        let computed = crate::object::fletcher64_checksum(block);
        if stored != computed {
            return Err(crate::ApfsError::ChecksumMismatch {
                block: crate::bytes::le_u64(block, 8),
                stored,
                computed,
            });
        }
        Ok(Self {
            version: crate::bytes::le_u32(block, OFF_IM_VERSION),
            flags: crate::bytes::le_u32(block, OFF_IM_FLAGS),
            hash_type: crate::bytes::le_u32(block, OFF_IM_HASH_TYPE),
            broken_xid: crate::bytes::le_u64(block, OFF_IM_BROKEN_XID),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a checksum-valid `integrity_meta_phys_t` block: fields after the
    /// 32-byte `obj_phys` header — `im_version`@32, `im_flags`@36, `im_hash_type`@40,
    /// `im_root_hash_offset`@44, `im_broken_xid`@48 (u64).
    fn integrity_block(version: u32, flags: u32, hash_type: u32, broken_xid: u64) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[32..36].copy_from_slice(&version.to_le_bytes());
        b[36..40].copy_from_slice(&flags.to_le_bytes());
        b[40..44].copy_from_slice(&hash_type.to_le_bytes());
        b[48..56].copy_from_slice(&broken_xid.to_le_bytes());
        let cks = crate::object::fletcher64_checksum(&b);
        b[0..8].copy_from_slice(&cks.to_le_bytes());
        b
    }

    #[test]
    fn parses_fields_including_broken_xid() {
        // im_hash_type 1 = SHA-256 (APFS_HASH_SHA256); seal broken at xid 42.
        let block = integrity_block(1, 0, 1, 42);
        let im = IntegrityMeta::parse(&block).expect("parse integrity_meta");
        assert_eq!(im.version, 1);
        assert_eq!(im.hash_type, 1);
        assert_eq!(im.broken_xid, 42);
    }

    #[test]
    fn unbroken_seal_has_zero_broken_xid() {
        let block = integrity_block(1, 0, 1, 0);
        let im = IntegrityMeta::parse(&block).expect("parse");
        assert_eq!(im.broken_xid, 0);
    }

    #[test]
    fn rejects_corrupted_block() {
        // A bad Fletcher-64 must fail loud (checksum-before-trust), never parse.
        let mut block = integrity_block(1, 0, 1, 0);
        block[100] ^= 0xff;
        assert!(IntegrityMeta::parse(&block).is_err());
    }
}
