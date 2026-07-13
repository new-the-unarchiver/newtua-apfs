//! Container superblock (`nx_superblock_t`, magic `NX_MAGIC = 'BSXN'` →
//! "NXSB" → LE `0x4253584E`) and container geometry.
//!
//! The NXSB (Apple *APFS Reference*, `nx_superblock_t`) names the block size
//! (`nx_block_size`, default 4096, max 65536), block count, feature/incompatible
//! flags, container UUID, the spaceman/omap/reaper oids, the checkpoint
//! descriptor + data areas (`nx_xp_desc_base/len`, `nx_xp_data_base/len`), and
//! the volume oids (`nx_fs_oid[]`). Block 0 holds *a* copy, but the **live**
//! superblock is found via the checkpoint ring ([`crate::checkpoint`]).
//!
//! The EFI jumpstart (`nx_efi_jumpstart`, magic `NX_EFI_JUMPSTART_MAGIC =
//! 'RDSJ'` → "JSDR") locates the bootable EFI driver, parsed here for
//! completeness.

/// Container superblock magic `NX_MAGIC` ('BSXN', "NXSB" in a hex dump).
pub const NX_MAGIC: u32 = 0x4253_584E;

/// Smallest / default / largest block size and minimum container size (Apple).
/// `NX_INCOMPAT_FUSION` — the `nx_incompatible_features` bit set on a Fusion
/// (SSD+HDD) container (Apple *APFS Reference*). A reader that does not implement
/// tier-aware address translation must reject such a container rather than
/// mis-read physical addresses (see [`crate::fusion`]).
pub const NX_INCOMPAT_FUSION: u64 = 0x100;

pub const NX_MINIMUM_BLOCK_SIZE: u32 = 4096;
pub const NX_DEFAULT_BLOCK_SIZE: u32 = 4096;
pub const NX_MAXIMUM_BLOCK_SIZE: u32 = 65536;
pub const NX_MINIMUM_CONTAINER_SIZE: u64 = 1_048_576;

/// `NX_MAX_FILE_SYSTEMS` (Apple) — the hard cap on volumes per container, used
/// as the sanity bound on `nx_max_file_systems` (allocation-bomb defense).
pub const NX_MAX_FILE_SYSTEMS: u32 = 100;

/// The high bit of `nx_xp_{desc,data}_blocks` is a flag (Apple): when set, the
/// corresponding checkpoint area is stored as a B-tree rather than contiguously.
const XP_BLOCKS_TREE_FLAG: u32 = 0x8000_0000;

// Verified field offsets within `nx_superblock_t` (little-endian on disk),
// after the 32-byte `obj_phys_t nx_o` header (Apple *APFS Reference*):
const OFF_MAGIC: usize = 32; // nx_magic           u32
const OFF_BLOCK_SIZE: usize = 36; // nx_block_size  u32
const OFF_BLOCK_COUNT: usize = 40; // nx_block_count u64
const OFF_INCOMPAT_FEATURES: usize = 64; // nx_incompatible_features u64
const OFF_UUID: usize = 72; // nx_uuid            uuid_t (16)
const OFF_SPACEMAN_OID: usize = 152; // nx_spaceman_oid oid (u64, ephemeral)
const OFF_REAPER_OID: usize = 168; // nx_reaper_oid    oid (u64, ephemeral)
const OFF_XP_DESC_BLOCKS: usize = 104; // nx_xp_desc_blocks u32
const OFF_XP_DATA_BLOCKS: usize = 108; // nx_xp_data_blocks u32
const OFF_XP_DESC_BASE: usize = 112; // nx_xp_desc_base paddr (u64)
const OFF_XP_DATA_BASE: usize = 120; // nx_xp_data_base paddr (u64)
const OFF_OMAP_OID: usize = 160; // nx_omap_oid     oid (u64)
const OFF_MAX_FILE_SYSTEMS: usize = 180; // nx_max_file_systems u32
const OFF_FS_OID: usize = 184; // nx_fs_oid[NX_MAX_FILE_SYSTEMS] oid[] (u64 each)

/// A parsed container superblock (subset; `#[non_exhaustive]` for additive growth).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NxSuperblock {
    /// Transaction id of this superblock (`nx_o.o_xid`).
    pub xid: u64,
    /// Container UUID (`nx_uuid`).
    pub uuid: [u8; 16],
    /// `nx_block_size` — the authoritative block size (never assumed).
    pub block_size: u32,
    /// `nx_block_count`.
    pub block_count: u64,
    /// `nx_incompatible_features` — feature bits a reader must understand to
    /// mount safely (e.g. [`NX_INCOMPAT_FUSION`]); an unrecognised bit means the
    /// image cannot be read correctly.
    pub incompatible_features: u64,
    /// Checkpoint descriptor-area base (`nx_xp_desc_base`) — a block address
    /// when contiguous, or a B-tree oid when [`Self::xp_desc_is_tree`].
    pub xp_desc_base: u64,
    /// Checkpoint descriptor-area length in blocks (`nx_xp_desc_blocks`, flag
    /// bit already masked off).
    pub xp_desc_blocks: u32,
    /// Checkpoint data-area base (`nx_xp_data_base`).
    pub xp_data_base: u64,
    /// Checkpoint data-area length in blocks (`nx_xp_data_blocks`, flag bit masked).
    pub xp_data_blocks: u32,
    /// Container object-map oid (`nx_omap_oid`).
    pub omap_oid: u64,
    /// Space-manager ephemeral oid (`nx_spaceman_oid`) — resolve to a paddr via
    /// the checkpoint map.
    pub spaceman_oid: u64,
    /// Reaper ephemeral oid (`nx_reaper_oid`) — resolve to a paddr via the
    /// checkpoint map.
    pub reaper_oid: u64,
    /// Volume oids (`nx_fs_oid[]`), one per APSB volume (trailing zeros trimmed).
    pub fs_oids: Vec<u64>,
    /// Whether the descriptor area is a B-tree (high bit of `nx_xp_desc_blocks`).
    desc_is_tree: bool,
    /// Whether the data area is a B-tree (high bit of `nx_xp_data_blocks`).
    data_is_tree: bool,
}

impl NxSuperblock {
    /// Parse and validate an NXSB from a block (checks magic + checksum).
    ///
    /// # Errors
    /// [`crate::ApfsError::NoValidSuperblock`] on a short block or bad magic
    /// (carrying the offending magic value);
    /// [`crate::ApfsError::ChecksumMismatch`] on a Fletcher-64 failure
    /// (carrying both the stored and computed checksums).
    pub fn parse(block: &[u8]) -> crate::Result<Self> {
        // A block too short to hold even the magic field has no readable
        // superblock — surface that as a loud bootstrap failure, not Ok(empty).
        if block.len() < OFF_MAGIC + 4 {
            return Err(crate::ApfsError::NoValidSuperblock {
                checked: 1,
                last_magic: 0,
            });
        }

        // 1. Magic gate (Apple mounting step 3): nx_magic == NX_MAGIC.
        let magic = crate::bytes::le_u32(block, OFF_MAGIC);
        if magic != NX_MAGIC {
            return Err(crate::ApfsError::NoValidSuperblock {
                checked: 1,
                last_magic: magic,
            });
        }

        // 2. Checksum gate (Apple mounting step 2): verify Fletcher-64 before
        //    trusting any geometry field.
        let stored = crate::object::fletcher64_stored(block);
        let computed = crate::object::fletcher64_checksum(block);
        if stored != computed {
            let oid = crate::bytes::le_u64(block, 8);
            return Err(crate::ApfsError::ChecksumMismatch {
                block: oid,
                stored,
                computed,
            });
        }

        // 3. Geometry — only now are the fields trustworthy.
        let xid = crate::bytes::le_u64(block, 16);
        let uuid = crate::bytes::arr::<16>(block, OFF_UUID);
        let block_size = crate::bytes::le_u32(block, OFF_BLOCK_SIZE);
        let block_count = crate::bytes::le_u64(block, OFF_BLOCK_COUNT);
        let incompatible_features = crate::bytes::le_u64(block, OFF_INCOMPAT_FEATURES);

        let desc_blocks_raw = crate::bytes::le_u32(block, OFF_XP_DESC_BLOCKS);
        let data_blocks_raw = crate::bytes::le_u32(block, OFF_XP_DATA_BLOCKS);
        let desc_is_tree = desc_blocks_raw & XP_BLOCKS_TREE_FLAG != 0;
        let data_is_tree = data_blocks_raw & XP_BLOCKS_TREE_FLAG != 0;

        let omap_oid = crate::bytes::le_u64(block, OFF_OMAP_OID);
        let spaceman_oid = crate::bytes::le_u64(block, OFF_SPACEMAN_OID);
        let reaper_oid = crate::bytes::le_u64(block, OFF_REAPER_OID);

        // Cap nx_max_file_systems before reading the fs_oid array (Apple bounds
        // it at NX_MAX_FILE_SYSTEMS; a larger value is corruption — clamp to the
        // spec maximum so a hostile image can't drive an over-read loop).
        let max_fs = crate::bytes::le_u32(block, OFF_MAX_FILE_SYSTEMS).min(NX_MAX_FILE_SYSTEMS);
        let mut fs_oids = Vec::new();
        for i in 0..max_fs as usize {
            let oid = crate::bytes::le_u64(block, OFF_FS_OID + i * 8);
            if oid != 0 {
                fs_oids.push(oid);
            }
        }

        Ok(Self {
            xid,
            uuid,
            block_size,
            block_count,
            incompatible_features,
            xp_desc_base: crate::bytes::le_u64(block, OFF_XP_DESC_BASE),
            xp_desc_blocks: desc_blocks_raw & !XP_BLOCKS_TREE_FLAG,
            xp_data_base: crate::bytes::le_u64(block, OFF_XP_DATA_BASE),
            xp_data_blocks: data_blocks_raw & !XP_BLOCKS_TREE_FLAG,
            omap_oid,
            spaceman_oid,
            reaper_oid,
            fs_oids,
            desc_is_tree,
            data_is_tree,
        })
    }

    /// Whether the checkpoint descriptor area is stored as a B-tree (high bit of
    /// `nx_xp_desc_blocks` set) rather than a contiguous run. A contiguous area
    /// can be walked directly; a tree-backed one needs B-tree resolution (P2).
    #[must_use]
    pub fn xp_desc_is_tree(&self) -> bool {
        self.desc_is_tree
    }

    /// Whether the checkpoint data area is stored as a B-tree.
    #[must_use]
    pub fn xp_data_is_tree(&self) -> bool {
        self.data_is_tree
    }
}
