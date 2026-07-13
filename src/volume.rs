//! Volume superblock (`apfs_superblock_t`, magic `APFS_MAGIC = 'BSPA'` →
//! "APSB" → LE `0x42535041`) and per-volume navigation roots.
//!
//! Each volume's APSB (Apple *APFS Reference*, `apfs_superblock_t`) carries the
//! volume's own object map (`apfs_omap_oid`), the file-system tree root
//! (`apfs_root_tree_oid`, a virtual oid resolved through the volume omap), the
//! extent-reference tree (`apfs_extentref_tree_oid`), the snapshot-metadata tree
//! (`apfs_snap_meta_tree_oid`), the volume role/flags, `apfs_volname`, and
//! `apfs_fs_index`.
//!
//! Field offsets (little-endian on disk), after the 32-byte `obj_phys_t` header
//! — verified verbatim against libfsapfs `fsapfs_volume_superblock` and the raw
//! self-minted fixture:
//!
//! | off | size | field                                |
//! |-----|------|--------------------------------------|
//! | 32  | 4    | `apfs_magic` ("APSB")                |
//! | 36  | 4    | `apfs_fs_index`                      |
//! | 40  | 8    | `apfs_features` (compatible)         |
//! | 48  | 8    | `apfs_readonly_compatible_features`  |
//! | 56  | 8    | `apfs_incompatible_features`         |
//! | 116 | 4    | `apfs_root_tree_type`                |
//! | 128 | 8    | `apfs_omap_oid` (volume omap block)  |
//! | 136 | 8    | `apfs_root_tree_oid` (virtual)       |
//! | 144 | 8    | `apfs_extentref_tree_oid`            |
//! | 152 | 8    | `apfs_snap_meta_tree_oid`            |
//! | 240 | 16   | `apfs_vol_uuid`                      |
//! | 256 | 8    | `apfs_fs_flags`                      |
//! | 704 | 256  | `apfs_volname[APFS_VOLNAME_LEN]`     |

use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};

/// Volume superblock magic `APFS_MAGIC` ('BSPA', "APSB" in a hex dump).
pub const APFS_MAGIC: u32 = 0x4253_5041;

/// Object type code `OBJECT_TYPE_FS 0xd` — the APSB object type (low 16 bits of
/// `o_type`).
const OBJECT_TYPE_FS: u16 = 0xd;

// `apfs_superblock_t` field offsets after the 32-byte `obj_phys_t` header.
const OFF_MAGIC: usize = 32;
const OFF_FS_INDEX: usize = 36;
const OFF_FEATURES: usize = 40;
const OFF_RO_COMPAT_FEATURES: usize = 48;
const OFF_INCOMPAT_FEATURES: usize = 56;
const OFF_ROOT_TREE_TYPE: usize = 116;
const OFF_OMAP_OID: usize = 128;
const OFF_ROOT_TREE_OID: usize = 136;
const OFF_EXTENTREF_TREE_OID: usize = 144;
const OFF_SNAP_META_TREE_OID: usize = 152;
const OFF_VOL_UUID: usize = 240;
const OFF_FS_FLAGS: usize = 256;
const OFF_VOLNAME: usize = 704;

/// `APFS_VOLNAME_LEN` (Apple) — the fixed `apfs_volname` field size in bytes.
const VOLNAME_LEN: usize = 256;

/// Minimum readable APSB length: header through the volume name field.
const APSB_MIN_LEN: usize = OFF_VOLNAME + VOLNAME_LEN;

/// A parsed volume superblock (subset; `#[non_exhaustive]` for additive growth).
///
/// The fs-tree navigation entry points ([`Self::root_tree_oid`] /
/// [`Self::omap_oid`]) are consumed by [`crate::dir`] for name→inode path
/// resolution.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ApfsVolume {
    oid: u64,
    xid: u64,
    fs_index: u32,
    features: u64,
    readonly_compatible_features: u64,
    incompatible_features: u64,
    root_tree_type: u32,
    omap_oid: u64,
    root_tree_oid: u64,
    extentref_tree_oid: u64,
    snap_meta_tree_oid: u64,
    uuid: [u8; 16],
    fs_flags: u64,
    name: String,
}

impl ApfsVolume {
    /// Parse and validate an APSB block (magic-by-type + signature + Fletcher-64
    /// checksum) before trusting any field.
    ///
    /// # Errors
    /// [`crate::ApfsError::UnexpectedObjectType`] on a short block, a non-FS
    /// object type, or a wrong `apfs_magic` signature (carrying the offending
    /// value); [`crate::ApfsError::ChecksumMismatch`] on a Fletcher-64 failure.
    pub fn parse(block: &[u8]) -> crate::Result<Self> {
        if block.len() < APSB_MIN_LEN {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "apfs_superblock",
                expected: APFS_MAGIC,
                found: 0,
            });
        }
        // Object-type gate: the block must be an FS (volume superblock) object.
        let Some(hdr) = ObjPhys::parse(block) else {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "apfs_superblock",
                expected: APFS_MAGIC,
                found: 0,
            }); // cov:unreachable: len checked >= APSB_MIN_LEN > OBJ_PHYS_LEN
        };
        if hdr.obj_type() != OBJECT_TYPE_FS {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "apfs_superblock",
                expected: u32::from(OBJECT_TYPE_FS),
                found: hdr.obj_type_raw,
            });
        }

        // Signature gate: apfs_magic == "APSB".
        let magic = crate::bytes::le_u32(block, OFF_MAGIC);
        if magic != APFS_MAGIC {
            return Err(crate::ApfsError::UnexpectedObjectType {
                structure: "apfs_superblock",
                expected: APFS_MAGIC,
                found: magic,
            });
        }

        // Checksum gate before trusting the tree oids.
        let stored = fletcher64_stored(block);
        let computed = fletcher64_checksum(block);
        if stored != computed {
            return Err(crate::ApfsError::ChecksumMismatch {
                block: hdr.oid,
                stored,
                computed,
            });
        }

        // Volume name: a NUL-terminated UTF-8 string within the 256-byte field.
        let name = decode_volname(block, OFF_VOLNAME, VOLNAME_LEN);

        Ok(Self {
            oid: hdr.oid,
            xid: hdr.xid,
            fs_index: crate::bytes::le_u32(block, OFF_FS_INDEX),
            features: crate::bytes::le_u64(block, OFF_FEATURES),
            readonly_compatible_features: crate::bytes::le_u64(block, OFF_RO_COMPAT_FEATURES),
            incompatible_features: crate::bytes::le_u64(block, OFF_INCOMPAT_FEATURES),
            root_tree_type: crate::bytes::le_u32(block, OFF_ROOT_TREE_TYPE),
            omap_oid: crate::bytes::le_u64(block, OFF_OMAP_OID),
            root_tree_oid: crate::bytes::le_u64(block, OFF_ROOT_TREE_OID),
            extentref_tree_oid: crate::bytes::le_u64(block, OFF_EXTENTREF_TREE_OID),
            snap_meta_tree_oid: crate::bytes::le_u64(block, OFF_SNAP_META_TREE_OID),
            uuid: crate::bytes::arr::<16>(block, OFF_VOL_UUID),
            fs_flags: crate::bytes::le_u64(block, OFF_FS_FLAGS),
            name,
        })
    }

    /// The volume superblock object id (`nx_o.o_oid`).
    #[must_use]
    pub fn oid(&self) -> u64 {
        self.oid
    }

    /// The transaction id of this volume superblock (`nx_o.o_xid`). Used as the
    /// xid for resolving virtual fs-tree oids through the volume omap.
    #[must_use]
    pub fn xid(&self) -> u64 {
        self.xid
    }

    /// `apfs_fs_index` — this volume's index within the container's `nx_fs_oid[]`.
    #[must_use]
    pub fn fs_index(&self) -> u32 {
        self.fs_index
    }

    /// `apfs_features` — compatible feature flags.
    #[must_use]
    pub fn features(&self) -> u64 {
        self.features
    }

    /// `apfs_readonly_compatible_features` — read-only-compatible feature flags.
    #[must_use]
    pub fn readonly_compatible_features(&self) -> u64 {
        self.readonly_compatible_features
    }

    /// `apfs_incompatible_features` — incompatible feature flags (the
    /// case-insensitivity / normalization bits affect directory-name matching).
    #[must_use]
    pub fn incompatible_features(&self) -> u64 {
        self.incompatible_features
    }

    /// `apfs_root_tree_type` — the storage-flag + object-type word of the
    /// file-system root tree (the root tree is virtual, so its high bits carry
    /// the virtual storage flag).
    #[must_use]
    pub fn root_tree_type(&self) -> u32 {
        self.root_tree_type
    }

    /// `apfs_omap_oid` — the block address of this volume's object map
    /// (`omap_phys_t`, a physical object). The fs-tree's virtual oids resolve
    /// through this omap.
    #[must_use]
    pub fn omap_oid(&self) -> u64 {
        self.omap_oid
    }

    /// Return this volume superblock with its `omap_oid` replaced.
    ///
    /// A *snapshot's* frozen `apfs_superblock_t` carries `apfs_omap_oid == 0`:
    /// snapshots have no object map of their own and are read through the
    /// **live** volume's omap, resolved at the snapshot's `xid` (the omap B-tree
    /// retains historical `(oid, xid) → paddr` mappings that snapshots pin). A
    /// point-in-time view therefore keeps the frozen superblock's `root_tree_oid`
    /// and `xid` but borrows the live volume's omap. See
    /// [`crate::snapshot::mount_snapshot`].
    #[must_use]
    pub fn with_omap_oid(mut self, omap_oid: u64) -> Self {
        self.omap_oid = omap_oid;
        self
    }

    /// `apfs_root_tree_oid` — the **virtual** oid of the file-system tree root
    /// (`FSTREE`). Resolve it through the volume omap ([`Self::omap_oid`]) at
    /// [`Self::xid`] to get the root node's physical block address.
    #[must_use]
    pub fn root_tree_oid(&self) -> u64 {
        self.root_tree_oid
    }

    /// `apfs_extentref_tree_oid` — the extent-reference tree oid.
    #[must_use]
    pub fn extentref_tree_oid(&self) -> u64 {
        self.extentref_tree_oid
    }

    /// `apfs_snap_meta_tree_oid` — the snapshot-metadata tree oid.
    #[must_use]
    pub fn snap_meta_tree_oid(&self) -> u64 {
        self.snap_meta_tree_oid
    }

    /// `apfs_vol_uuid` — the volume UUID.
    #[must_use]
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// `apfs_fs_flags` — volume flags (e.g. encryption state bits).
    #[must_use]
    pub fn fs_flags(&self) -> u64 {
        self.fs_flags
    }

    /// The volume name (`apfs_volname`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Decode a fixed-width, NUL-terminated UTF-8 volume name field. Bytes after the
/// first NUL (or the whole field if there is none) are dropped; invalid UTF-8 is
/// replaced (never panics).
fn decode_volname(block: &[u8], offset: usize, len: usize) -> String {
    let Some(field) = block.get(offset..offset + len) else {
        return String::new(); // cov:unreachable: caller checks block.len() >= APSB_MIN_LEN
    };
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}
