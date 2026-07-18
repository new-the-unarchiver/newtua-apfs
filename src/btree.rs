//! Generic B-tree node walker (`btree_node_phys_t`, types `OBJECT_TYPE_BTREE
//! 0x2` / `OBJECT_TYPE_BTREE_NODE 0x3`).
//!
//! Every APFS index (omap, fs-tree, snapshot-metadata tree, extent-reference
//! tree, fext-tree) is a B-tree built from `btree_node_phys_t` blocks. The node
//! header (Apple *APFS Reference*, after the 32-byte `obj_phys_t`):
//!
//! | off | size | field            |
//! |-----|------|------------------|
//! | 32  | 2    | `btn_flags`      |
//! | 34  | 2    | `btn_level` (0 = leaf) |
//! | 36  | 4    | `btn_nkeys`      |
//! | 40  | 4    | `btn_table_space`  (`nloc_t`: u16 off, u16 len) |
//! | 44  | 4    | `btn_free_space`   (`nloc_t`) |
//! | 48  | 4    | `btn_key_free_list`(`nloc_t`) |
//! | 52  | 4    | `btn_val_free_list`(`nloc_t`) |
//! | 56  | …    | `btn_data[]`     |
//!
//! `btn_table_space.off` is relative to the start of `btn_data` (offset 56) and
//! locates the table-of-contents (TOC). For **fixed-size** nodes
//! (`BTNODE_FIXED_KV_SIZE` in `btn_flags`) a TOC entry is 4 bytes
//! (`key_offs u16`, `value_offs u16`); for **variable-size** nodes it is 8 bytes
//! (`key_offs`, `key_len`, `value_offs`, `value_len`, all u16).
//!
//! In a TOC entry, `key_offs` is relative to the **end of the TOC** (start of the
//! key area) and `value_offs` is a **reversed** offset relative to the start of
//! the B-tree footer (`btree_info_t`, 40 bytes) on a root node, or the end of the
//! node on a non-root node. Offsets are verified verbatim against the Apple
//! reference and the libfsapfs format spec.
//!
//! Walks are cycle-guarded and allocation-capped (`btn_nkeys` and every TOC
//! offset are range-checked against the node before use — a hostile image's TOC
//! is a classic out-of-bounds vector).

/// `btn_flags` bit: node uses fixed-size key/value entries (`BTNODE_FIXED_KV_SIZE`).
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
/// `btn_flags` bit: node is the B-tree root (`BTNODE_ROOT`).
const BTNODE_ROOT: u16 = 0x1;
/// `btn_flags` bit: node is a leaf (`BTNODE_LEAF`).
const BTNODE_LEAF: u16 = 0x2;

// Node-header field offsets after the 32-byte `obj_phys_t`.
const OFF_BTN_FLAGS: usize = 32;
const OFF_BTN_LEVEL: usize = 34;
const OFF_BTN_NKEYS: usize = 36;
const OFF_BTN_TABLE_SPACE: usize = 40;
/// `btn_data[]` begins immediately after the four `nloc_t` regions.
const BTN_DATA_OFF: usize = 56;
/// Minimum readable node-header length.
const BTREE_NODE_MIN_LEN: usize = BTN_DATA_OFF;

/// `btree_info_t` footer size (root node only).
const BTREE_INFO_LEN: usize = 40;

/// Fixed-size TOC entry length (`kvoff_t`): `key_offs`, `value_offs` (u16 each).
const TOC_FIXED_LEN: usize = 4;
/// Variable-size TOC entry length (`kvloc_t`): adds `key_len`, `value_len`.
const TOC_VAR_LEN: usize = 8;

/// Hard cap on `btn_nkeys` — a 4 `KiB` node cannot hold more than ~1000 entries;
/// cap well above any legal node to reject an allocation-bomb `btn_nkeys`
/// without rejecting a legal node.
const MAX_BTN_NKEYS: u32 = 1 << 20;

/// The B-tree subtype, which fixes the key/value sizes of a **fixed-size** node.
///
/// APFS B-trees are typed by `o_subtype`. For fixed-KV trees the per-entry sizes
/// are not stored in the TOC, so the subtype supplies them. (Variable-KV trees
/// carry the lengths in the TOC and ignore these.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BTreeSubtype {
    /// Object map (`OBJECT_TYPE_OMAP`): `omap_key_t` (16) → `omap_val_t` (16) at
    /// a leaf; a branch value is an 8-byte child block number. A **fixed-KV**
    /// tree, so the per-entry sizes below are consulted.
    Omap,
    /// File-system tree (`FSTREE`): `j_key`-keyed records of varying length. A
    /// **variable-KV** tree — the TOC carries the per-entry key/value sizes, so
    /// the fixed sizes below are *not* consulted for leaves; for an index node a
    /// branch value is an 8-byte child object id (virtual, resolved through the
    /// volume omap by the caller).
    FsTree,
}

impl BTreeSubtype {
    /// Fixed key length for a **leaf** entry of this subtype (fixed-KV trees only;
    /// variable-KV trees read the length from the TOC and ignore this).
    pub(crate) const fn fixed_key_len(self) -> usize {
        match self {
            BTreeSubtype::Omap => 16,  // omap_key_t { ok_oid u64, ok_xid u64 }
            BTreeSubtype::FsTree => 0, // variable-KV: TOC carries the length
        }
    }

    /// Fixed value length for a **leaf** entry of this subtype (fixed-KV only).
    pub(crate) const fn fixed_leaf_val_len(self) -> usize {
        match self {
            BTreeSubtype::Omap => 16,  // omap_val_t { ov_flags, ov_size, ov_paddr }
            BTreeSubtype::FsTree => 0, // variable-KV: TOC carries the length
        }
    }

    /// Fixed value length for a **branch** (index) entry: an 8-byte child oid
    /// (block number for a physical tree, virtual oid for the fs-tree).
    pub(crate) const fn fixed_branch_val_len(self) -> usize {
        match self {
            BTreeSubtype::Omap | BTreeSubtype::FsTree => 8,
        }
    }
}

/// A parsed B-tree node header.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BTreeNodeHeader {
    /// `btn_flags`.
    pub flags: u16,
    /// `btn_level` (0 = leaf).
    pub level: u16,
    /// `btn_nkeys`.
    pub nkeys: u32,
}

impl BTreeNodeHeader {
    /// Whether this node is a leaf (`BTNODE_LEAF` set, or `btn_level == 0`).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.flags & BTNODE_LEAF != 0 || self.level == 0
    }

    /// Whether this node is the B-tree root (`BTNODE_ROOT`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.flags & BTNODE_ROOT != 0
    }

    /// Whether entries are fixed-size (`BTNODE_FIXED_KV_SIZE`).
    #[must_use]
    pub fn is_fixed_kv(&self) -> bool {
        self.flags & BTNODE_FIXED_KV_SIZE != 0
    }
}

/// A key/value pair yielded by a node walk (borrowed from the node buffer).
pub struct Entry<'a> {
    /// The raw key bytes.
    pub key: &'a [u8],
    /// The raw value bytes.
    pub value: &'a [u8],
}

/// Parse a node header (bounds-checked). `None` if the block is too short to hold
/// the header (never panics).
#[must_use]
pub fn parse_node_header(block: &[u8]) -> Option<BTreeNodeHeader> {
    if block.len() < BTREE_NODE_MIN_LEN {
        return None;
    }
    Some(BTreeNodeHeader {
        flags: crate::bytes::le_u16(block, OFF_BTN_FLAGS),
        level: crate::bytes::le_u16(block, OFF_BTN_LEVEL),
        nkeys: crate::bytes::le_u32(block, OFF_BTN_NKEYS),
    })
}

/// Iterate the (key, value) entries of a single node, handling both fixed and
/// variable KV layouts. Returns an empty vector on a malformed node (a short
/// block, an out-of-bounds TOC, or an entry whose key/value slice would run past
/// the node) — never panics, never reads out of bounds.
///
/// `subtype` supplies the fixed key/value sizes for a fixed-KV node; variable-KV
/// nodes read the sizes from the TOC and ignore it.
#[must_use]
pub fn node_entries(block: &[u8], subtype: BTreeSubtype) -> Vec<Entry<'_>> {
    let Some(hdr) = parse_node_header(block) else {
        return Vec::new(); // cov:unreachable: callers pass full-size node blocks
    };
    let nkeys = hdr.nkeys.min(MAX_BTN_NKEYS) as usize;
    if nkeys == 0 {
        return Vec::new();
    }

    // The TOC begins at btn_data + btn_table_space.off; the key area begins right
    // after the TOC (btn_table_space.len bytes long).
    let toc_off = crate::bytes::le_u16(block, OFF_BTN_TABLE_SPACE) as usize;
    let toc_len = crate::bytes::le_u16(block, OFF_BTN_TABLE_SPACE + 2) as usize;
    let toc_start = BTN_DATA_OFF + toc_off; // u16 off + 56 cannot overflow usize
    let key_area = toc_start + toc_len; // u16 sums cannot overflow usize

    // Value offsets are reversed from the start of the footer on a root node, or
    // the end of the node otherwise.
    let val_base = if hdr.is_root() {
        block.len().saturating_sub(BTREE_INFO_LEN)
    } else {
        block.len()
    };

    let fixed = hdr.is_fixed_kv();
    let entry_len = if fixed { TOC_FIXED_LEN } else { TOC_VAR_LEN };
    let key_len = subtype.fixed_key_len();
    let val_len = if hdr.is_leaf() {
        subtype.fixed_leaf_val_len()
    } else {
        subtype.fixed_branch_val_len()
    };

    let mut out = Vec::with_capacity(nkeys);
    for i in 0..nkeys {
        let e = toc_start + i * entry_len; // bounded by MAX_BTN_NKEYS * 8
                                           // A TOC entry must lie within the key area (before the keys begin) and
                                           // within the node.
        if e + entry_len > key_area || e + entry_len > block.len() {
            break;
        }
        // TOC layout (verified vs Apple reference + libfsapfs):
        //   fixed (4 B):    key_offs u16 @0, value_offs u16 @2
        //   variable (8 B): key_offs u16 @0, key_len u16 @2,
        //                   value_offs u16 @4, value_len u16 @6
        let koff = crate::bytes::le_u16(block, e) as usize;
        let (voff, this_key_len, this_val_len) = if fixed {
            (
                crate::bytes::le_u16(block, e + 2) as usize,
                key_len,
                val_len,
            )
        } else {
            (
                crate::bytes::le_u16(block, e + 4) as usize,
                crate::bytes::le_u16(block, e + 2) as usize,
                crate::bytes::le_u16(block, e + 6) as usize,
            )
        };

        // Key slice: [key_area + koff, +len); value slice: val_base - voff
        // growing backward by this_val_len. Every bound is checked against the
        // node; a hostile offset yields a skipped entry, never an OOB read.
        let kstart = key_area + koff; // u16 sums cannot overflow usize
        let kend = kstart + this_key_len;
        let Some(vstart) = val_base.checked_sub(voff) else {
            continue;
        };
        let vend = vstart + this_val_len;

        let (Some(key), Some(value)) = (block.get(kstart..kend), block.get(vstart..vend)) else {
            continue;
        };
        out.push(Entry { key, value });
    }
    out
}

/// Depth cap on a root→leaf descent (cyclic-oid / malformed-tree guard).
const MAX_BTREE_DEPTH: usize = 64;

/// Walk a physically-stored B-tree from its root block, invoking `visit` for
/// every **leaf** (key, value) entry. Index nodes are descended by their child
/// block numbers; each node's Fletcher-64 checksum is verified before its TOC is
/// trusted, the descent depth is capped (`MAX_BTREE_DEPTH`), and a visited-set
/// guards against revisiting a block (cyclic-oid defense). The container omap
/// tree is stored physically, so `root_paddr` and every child block number are
/// direct block addresses.
///
/// # Errors
/// [`crate::ApfsError::ChecksumMismatch`] for a node whose checksum fails;
/// [`crate::ApfsError::CycleGuard`] on a cycle or an over-deep tree;
/// [`crate::ApfsError::Io`] on a read/seek failure.
pub fn for_each_leaf_entry<R, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: usize,
    subtype: BTreeSubtype,
    visit: &mut F,
) -> crate::Result<()>
where
    R: std::io::Read + std::io::Seek,
    F: FnMut(&[u8], &[u8]),
{
    let mut visited = std::collections::HashSet::new();
    descend(
        reader,
        root_paddr,
        block_size,
        subtype,
        0,
        &mut visited,
        visit,
    )
}

/// Read a block and verify its Fletcher-64 checksum before returning it.
/// `Ok(None)` only for the (unreachable) `paddr * block_size` overflow — the
/// caller treats it as a clean skip, mirroring the full-walk descent.
fn read_verified_node<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    paddr: u64,
    block_size: usize,
) -> crate::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; block_size];
    let Some(offset) = paddr.checked_mul(block_size as u64) else {
        return Ok(None); // cov:unreachable: in-image paddr*bs cannot overflow u64
    };
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;

    // Checksum-before-trust: never read a node's TOC until its cksum validates.
    let stored = crate::object::fletcher64_stored(&buf);
    let computed = crate::object::fletcher64_checksum(&buf);
    if stored != computed {
        let block = crate::object::ObjPhys::parse(&buf).map_or(paddr, |h| h.oid);
        return Err(crate::ApfsError::ChecksumMismatch {
            block,
            stored,
            computed,
        });
    }
    Ok(Some(buf))
}

/// Descend a physically-stored B-tree to the single leaf whose key range covers
/// the search target, invoking `visit` on that leaf's entries. `cmp(entry_key)`
/// returns how an entry's key orders against the target. At each index node the
/// descent follows the last child whose separator key is ≤ the target (standard
/// B-tree point lookup); the caller's `visit` filters the landing leaf. Same
/// checksum / depth-cap / visited-set guards as [`for_each_leaf_entry`].
///
/// This is the keyed counterpart to [`for_each_leaf_entry`] — it reads one
/// root→leaf path instead of every node, for hot point lookups like
/// [`crate::omap::ObjectMap::resolve`]. The B-tree must be physically stored
/// (children are direct block numbers), like the omap tree.
///
/// # Errors
/// [`crate::ApfsError::ChecksumMismatch`] for a node whose checksum fails;
/// [`crate::ApfsError::CycleGuard`] on a cycle or an over-deep tree;
/// [`crate::ApfsError::Io`] on a read/seek failure.
pub fn find_leaf<R, C, F>(
    reader: &mut R,
    root_paddr: u64,
    block_size: usize,
    subtype: BTreeSubtype,
    cmp: C,
    visit: &mut F,
) -> crate::Result<()>
where
    R: std::io::Read + std::io::Seek,
    C: Fn(&[u8]) -> std::cmp::Ordering,
    F: FnMut(&[u8], &[u8]),
{
    let mut visited = std::collections::HashSet::new();
    let mut paddr = root_paddr;
    for _ in 0..MAX_BTREE_DEPTH {
        // A block visited twice is a cycle — reject rather than loop forever.
        if !visited.insert(paddr) {
            return Err(crate::ApfsError::CycleGuard {
                cap: MAX_BTREE_DEPTH,
            });
        }
        let Some(buf) = read_verified_node(reader, paddr, block_size)? else {
            return Ok(()); // cov:unreachable: in-image paddr*bs cannot overflow u64
        };
        let Some(hdr) = parse_node_header(&buf) else {
            return Ok(()); // cov:unreachable: buf is block_size >= node header length
        };

        if hdr.is_leaf() {
            for e in node_entries(&buf, subtype) {
                visit(e.key, e.value);
            }
            return Ok(());
        }

        // Index node: separator key i is the smallest key of child i's subtree, so
        // the child covering the target is the last one whose key is ≤ the target
        // (or the first child if the target precedes every separator).
        let entries = node_entries(&buf, subtype);
        let Some(first) = entries.first() else {
            return Ok(()); // cov:unreachable: a non-leaf node has ≥1 child
        };
        let mut child = crate::bytes::le_u64(first.value, 0);
        for e in &entries {
            if cmp(e.key) == std::cmp::Ordering::Greater {
                break;
            }
            child = crate::bytes::le_u64(e.value, 0);
        }
        paddr = child;
    }
    Err(crate::ApfsError::CycleGuard {
        cap: MAX_BTREE_DEPTH,
    })
}

fn descend<R, F>(
    reader: &mut R,
    paddr: u64,
    block_size: usize,
    subtype: BTreeSubtype,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: std::io::Read + std::io::Seek,
    F: FnMut(&[u8], &[u8]),
{
    if depth >= MAX_BTREE_DEPTH {
        return Err(crate::ApfsError::CycleGuard {
            cap: MAX_BTREE_DEPTH,
        });
    }
    // A block visited twice is a cycle — reject rather than loop forever.
    if !visited.insert(paddr) {
        return Err(crate::ApfsError::CycleGuard {
            cap: MAX_BTREE_DEPTH,
        });
    }

    let Some(buf) = read_verified_node(reader, paddr, block_size)? else {
        return Ok(()); // cov:unreachable: in-image paddr*bs cannot overflow u64
    };

    let Some(hdr) = parse_node_header(&buf) else {
        return Ok(()); // cov:unreachable: buf is block_size >= node header length
    };

    if hdr.is_leaf() {
        for e in node_entries(&buf, subtype) {
            visit(e.key, e.value);
        }
        return Ok(());
    }

    // Index node: each value is an 8-byte child block number; descend each.
    let children: Vec<u64> = node_entries(&buf, subtype)
        .iter()
        .map(|e| crate::bytes::le_u64(e.value, 0))
        .collect();
    for child in children {
        descend(
            reader,
            child,
            block_size,
            subtype,
            depth + 1,
            visited,
            visit,
        )?;
    }
    Ok(())
}
