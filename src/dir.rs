//! Directory records (`APFS_TYPE_DIR_REC 9`) and name→inode navigation.
//!
//! A directory entry's key is `j_drec_key_t` (parent oid + name) or, on
//! case-insensitive/normalization-aware volumes, `j_drec_hashed_key_t` (parent
//! oid + a packed name-length/hash word + name). After the 8-byte `j_key`
//! header:
//!
//! - **unhashed** (`j_drec_key_t`): `name_len` u16 @8 (incl. the NUL), name @10.
//! - **hashed** (`j_drec_hashed_key_t`): `name_len_and_hash` u32 @8
//!   (`J_DREC_LEN_MASK 0x000003ff` = name length incl. NUL,
//!   `J_DREC_HASH_SHIFT 10` for the 22-bit hash), name @12.
//!
//! The value `j_drec_val_t { u64 file_id; u64 date_added; u16 flags; xfields }`
//! gives the target inode (`file_id`) and the time the entry was added
//! (`date_added`). Layout verified verbatim against the Apple reference +
//! libfsapfs format spec.
//!
//! **Navigation** resolves a path component by scanning the volume fs-tree for
//! the `DIR_REC` whose key oid is the parent inode and whose name matches the
//! requested component, returning the child inode (`file_id`); full-path
//! resolution descends from `ROOT_DIR_INO_NUM` (2). The fs-tree is *virtual* —
//! its node oids resolve through the volume object map at the volume's xid.

use std::io::{Read, Seek};

use crate::btree::{self, BTreeSubtype};
use crate::fsrecord::{decode_jkey, RecordType};
use crate::inode::Inode;
use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};
use crate::omap::ObjectMap;
use crate::volume::ApfsVolume;

/// `ROOT_DIR_INO_NUM` (Apple) — the inode number of a volume's root directory.
pub const ROOT_DIR_INO_NUM: u64 = 2;

/// `j_drec_hashed_key_t` name-length mask (low 10 bits of `name_len_and_hash`).
const J_DREC_LEN_MASK: u32 = 0x0000_03ff;

// j_drec_val_t value field offsets.
const OFF_DREC_FILE_ID: usize = 0;
const OFF_DREC_DATE_ADDED: usize = 8;
const OFF_DREC_FLAGS: usize = 16;

/// Depth cap on a path descent / fs-tree walk (cyclic-oid guard).
const MAX_FSTREE_DEPTH: usize = 64;

/// A directory entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name (the directory-record key's name string).
    pub name: String,
    /// `file_id` — the target inode number.
    pub file_id: u64,
    /// `date_added` — when the entry was added (ns since 1970, distinct from the
    /// inode's own timestamps; not updated on an in-place rename).
    pub date_added: u64,
    /// Directory-entry flags (`j_drec_val_t.flags`).
    pub flags: u16,
}

/// Decode a `DIR_REC` key's name. The key begins with the 8-byte `j_key` header;
/// the name layout depends on whether the volume uses hashed keys. The hashed
/// form is detected structurally: its 4-byte `name_len_and_hash` low-10-bit
/// length plus a name at offset 12 must fit the key; otherwise the unhashed
/// (u16 length @8, name @10) form is used. Returns `None` if neither form's
/// length fits the key slice (never panics, never over-reads).
fn decode_drec_name(key: &[u8]) -> Option<String> {
    // Hashed key: name_len_and_hash u32 @8, name @12.
    let hashed_len = (crate::bytes::le_u32(key, 8) & J_DREC_LEN_MASK) as usize;
    if hashed_len > 0 {
        if let Some(name) = key.get(12..12 + hashed_len) {
            return Some(decode_cstr(name));
        }
    }
    // Unhashed key: name_len u16 @8, name @10.
    let unhashed_len = crate::bytes::le_u16(key, 8) as usize;
    if unhashed_len > 0 {
        if let Some(name) = key.get(10..10 + unhashed_len) {
            return Some(decode_cstr(name));
        }
    }
    None
}

/// Parse a `DIR_REC` (key, value) pair into a [`DirEntry`]. `None` if the name
/// cannot be decoded from the key (a malformed record is skipped, not fatal).
fn parse_dir_entry(key: &[u8], value: &[u8]) -> Option<DirEntry> {
    let name = decode_drec_name(key)?;
    Some(DirEntry {
        name,
        file_id: crate::bytes::le_u64(value, OFF_DREC_FILE_ID),
        date_added: crate::bytes::le_u64(value, OFF_DREC_DATE_ADDED),
        flags: crate::bytes::le_u16(value, OFF_DREC_FLAGS),
    })
}

/// Walk the volume fs-tree (a *virtual* B-tree resolved through the volume omap)
/// keyed to a single object id: visit only the records whose `j_key` object id is
/// `target_oid`, descending one root→leaf path per node level instead of the
/// whole tree. The fs-tree is sorted by object id first, so all records for one
/// object id occupy a contiguous key range; at each index node only the children
/// whose key range can cover `target_oid` are descended (see
/// [`child_may_contain_oid`]). Each node's Fletcher-64 checksum is verified
/// before its TOC is trusted, the descent depth is capped, and a visited-set
/// guards against cyclic node oids. The `visit` callback still sees the landing
/// leaves' entries and must filter precisely (a leaf may also hold neighbours).
///
/// `pub(crate)` so every navigation entry point shares it — `lookup_child`,
/// `load_inode`, `list_dir`, [`crate::extent::list_extents`],
/// [`crate::xattr::list_xattrs`] — since each filters by a single object id,
/// without duplicating the omap-resolution + checksum/cycle-guard walk.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::ChecksumMismatch`]
/// / [`crate::ApfsError::CycleGuard`] / [`crate::ApfsError::Io`] on a
/// structurally invalid omap/fs-tree or a read failure.
pub(crate) fn for_each_fs_record_for_oid<R, F>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    target_oid: u64,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    walk_fs_tree(reader, volume, block_size, Some(target_oid), visit)
}

fn walk_fs_tree<R, F>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    target_oid: Option<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    // Read the volume omap header (a physical object at apfs_omap_oid).
    let mut buf = vec![0u8; block_size];
    let omap_off = volume.omap_oid().saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(omap_off))?;
    reader.read_exact(&mut buf)?;
    let omap = ObjectMap::parse(&buf)?;

    let xid = volume.xid();
    let mut visited = std::collections::HashSet::new();
    descend_virtual(
        reader,
        &omap,
        volume.root_tree_oid(),
        xid,
        block_size,
        0,
        target_oid,
        &mut visited,
        visit,
    )
}

/// Whether an index-node child whose subtree covers keys `[sep, next_sep)` can
/// contain a record with object id `target`. `next_sep` is the next separator's
/// object id, or `None` for the last child (its subtree extends upward without
/// bound). Records for one object id form a contiguous key range, so the child
/// is relevant iff its low bound is ≤ `target` and its high bound is ≥ `target`.
///
/// The `next_sep == target` boundary **must** descend: a separator is the first
/// *full* key of the next child, so a record `(target, low_type)` smaller than
/// that separator can still live at the end of *this* child.
fn child_may_contain_oid(sep_oid: u64, next_sep_oid: Option<u64>, target: u64) -> bool {
    sep_oid <= target && next_sep_oid.is_none_or(|next| next >= target)
}

#[allow(clippy::too_many_arguments)]
fn descend_virtual<R, F>(
    reader: &mut R,
    omap: &ObjectMap,
    node_oid: u64,
    xid: u64,
    block_size: usize,
    depth: usize,
    target_oid: Option<u64>,
    visited: &mut std::collections::HashSet<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    let cycle = || crate::ApfsError::CycleGuard {
        cap: MAX_FSTREE_DEPTH,
    };
    // The visited-set guard below dominates — any cycle repeats a node oid
    // (tripping it) before a legal tree reaches depth 64; this depth cap is
    // defense-in-depth against a pathological deep acyclic tree.
    if depth >= MAX_FSTREE_DEPTH {
        return Err(cycle()); // cov:unreachable: visited-set guard dominates any realizable cycle
    }
    if !visited.insert(node_oid) {
        return Err(cycle());
    }

    // Resolve this node's virtual oid to a physical block via the omap.
    let entry = omap.resolve(reader, node_oid, xid, block_size)?;

    let mut buf = vec![0u8; block_size];
    let offset = entry.paddr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;

    // Checksum-before-trust.
    let stored = fletcher64_stored(&buf);
    let computed = fletcher64_checksum(&buf);
    if stored != computed {
        let block = ObjPhys::parse(&buf).map_or(entry.paddr, |h| h.oid);
        return Err(crate::ApfsError::ChecksumMismatch {
            block,
            stored,
            computed,
        });
    }

    let Some(hdr) = btree::parse_node_header(&buf) else {
        return Ok(()); // cov:unreachable: buf is block_size >= node header length
    };

    if hdr.is_leaf() {
        for e in btree::node_entries(&buf, BTreeSubtype::FsTree) {
            visit(e.key, e.value);
        }
        return Ok(());
    }

    // Index node: each value is an 8-byte child *virtual* oid. For a keyed walk,
    // descend only the children whose key range can cover `target_oid`; a full
    // walk (target_oid == None) descends every child.
    let entries = btree::node_entries(&buf, BTreeSubtype::FsTree);
    for i in 0..entries.len() {
        if let Some(target) = target_oid {
            let (sep_oid, _) = decode_jkey(crate::bytes::le_u64(entries[i].key, 0));
            let next_sep_oid = entries
                .get(i + 1)
                .map(|e| decode_jkey(crate::bytes::le_u64(e.key, 0)).0);
            if !child_may_contain_oid(sep_oid, next_sep_oid, target) {
                continue;
            }
        }
        let child = crate::bytes::le_u64(entries[i].value, 0);
        descend_virtual(
            reader,
            omap,
            child,
            xid,
            block_size,
            depth + 1,
            target_oid,
            visited,
            visit,
        )?;
    }
    Ok(())
}

/// List the directory entries whose parent is `parent_oid`, scanning the volume
/// fs-tree for `DIR_REC` records.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::ChecksumMismatch`]
/// / [`crate::ApfsError::CycleGuard`] / [`crate::ApfsError::Io`] on a
/// structurally invalid omap/fs-tree or a read failure.
pub fn list_dir<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    parent_oid: u64,
    block_size: usize,
) -> crate::Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for_each_fs_record_for_oid(reader, volume, block_size, parent_oid, &mut |key, value| {
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::DirRec) || oid != parent_oid {
            return;
        }
        // Skip a malformed DIR_REC rather than fail the whole listing.
        let Some(entry) = parse_dir_entry(key, value) else {
            return; // cov:unreachable: valid DIR_REC keys always decode a name
        };
        out.push(entry);
    })?;
    Ok(out)
}

/// Resolve a single path component: look up the `DIR_REC` `(parent_oid, name)` in
/// the fs-tree and return the child inode number, or `None` if absent.
///
/// # Errors
/// As [`list_dir`].
pub fn lookup_child<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    parent_oid: u64,
    name: &str,
    block_size: usize,
) -> crate::Result<Option<u64>> {
    let mut found = None;
    for_each_fs_record_for_oid(reader, volume, block_size, parent_oid, &mut |key, value| {
        if found.is_some() {
            return;
        }
        let (oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::DirRec) || oid != parent_oid {
            return;
        }
        // A DIR_REC whose name cannot be decoded is a malformed/hostile record;
        // skip it rather than fail the whole listing (defensive — real images
        // always decode, so the skip arm is unreachable on valid data).
        let Some(entry) = parse_dir_entry(key, value) else {
            return; // cov:unreachable: valid DIR_REC keys always decode a name
        };
        if entry.name == name {
            found = Some(entry.file_id);
        }
    })?;
    Ok(found)
}

/// Load the inode (`INODE` record) for `oid` from the volume fs-tree.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] if the inode record is not present (a
/// loud per-item miss), plus the structural errors of [`list_dir`].
pub fn load_inode<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    oid: u64,
    block_size: usize,
) -> crate::Result<Inode> {
    let mut value: Option<Vec<u8>> = None;
    for_each_fs_record_for_oid(reader, volume, block_size, oid, &mut |key, val| {
        if value.is_some() {
            return;
        }
        let (k_oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty == Some(RecordType::Inode) && k_oid == oid {
            value = Some(val.to_vec());
        }
    })?;
    let value = value.ok_or(crate::ApfsError::OmapUnresolved {
        oid,
        xid: volume.xid(),
    })?;
    Inode::parse(oid, &value)
}

/// Resolve a `/`-separated path to an [`Inode`] by descending the fs-tree from
/// the root directory (`ROOT_DIR_INO_NUM`). Empty components (from a leading,
/// trailing, or doubled `/`) are skipped; `"/"` resolves to the root inode.
///
/// # Errors
/// [`crate::ApfsError::OmapUnresolved`] if any path component is not found or the
/// final inode record is absent (a loud per-item miss), plus the structural
/// errors of [`list_dir`].
pub fn open_path<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    path: &str,
    block_size: usize,
) -> crate::Result<Inode> {
    let mut current = ROOT_DIR_INO_NUM;
    for component in path.split('/').filter(|c| !c.is_empty()) {
        match lookup_child(reader, volume, current, component, block_size)? {
            Some(child) => current = child,
            None => {
                return Err(crate::ApfsError::OmapUnresolved {
                    oid: current,
                    xid: volume.xid(),
                });
            }
        }
    }
    load_inode(reader, volume, current, block_size)
}

/// Decode a NUL-terminated UTF-8 byte string. Bytes after the first NUL are
/// dropped; invalid UTF-8 is replaced (never panics).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `j_key` header word from a 4-bit type and a 60-bit oid.
    fn jkey(ty: u64, oid: u64) -> [u8; 8] {
        ((ty << 60) | oid).to_le_bytes()
    }

    #[test]
    fn decode_hashed_drec_name() {
        // 8-byte j_key header (DIR_REC, parent 2), then name_len_and_hash u32 with
        // low-10-bit length = 5 ("abcd\0"), then the name at offset 12.
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        key.extend_from_slice(&5u32.to_le_bytes()); // len=5 in low 10 bits, hash 0
        key.extend_from_slice(b"abcd\0");
        assert_eq!(decode_drec_name(&key).as_deref(), Some("abcd"));
    }

    #[test]
    fn child_pruning_selects_only_covering_subtrees() {
        // Index node with separators [oid 0, oid 10, oid 20]; child i covers
        // [sep_i, sep_{i+1}). Records for one oid form a contiguous key range.
        // target oid 15 lives only under child[1] (covers [10, 20)).
        assert!(
            !child_may_contain_oid(0, Some(10), 15),
            "child [0,10) excludes 15"
        );
        assert!(
            child_may_contain_oid(10, Some(20), 15),
            "child [10,20) covers 15"
        );
        assert!(
            !child_may_contain_oid(20, None, 15),
            "child [20,inf) excludes 15"
        );

        // Boundary spill: a separator is the next child's FIRST FULL key, so a
        // record (target, low_type) below it can sit at the END of THIS child.
        // Hence next_sep == target MUST still descend.
        assert!(
            child_may_contain_oid(5, Some(10), 10),
            "next_sep == target must descend (record may trail in this child)"
        );
        // sep == target obviously descends; last child always covers the high side.
        assert!(child_may_contain_oid(10, Some(20), 10));
        assert!(child_may_contain_oid(5, None, 999));
        // Entirely below the target prunes.
        assert!(!child_may_contain_oid(0, Some(5), 10));
    }

    // Real-data cross-check: on the Apple-authored fs-tree, the KEYED walk must
    // visit exactly the records the FULL (unpruned) walk visits when filtered to
    // the same object id. The full walk — the same descent with no pruning, whose
    // results are independently validated against `fls`/`istat` by the dir/inode
    // integration tests — is the oracle, so this proves the keyed pruning never
    // drops a covering record.
    const FSTREE: &[u8] = include_bytes!("../../tests/data/apfs_fstree.bin");
    const FSTREE_BLOCK_SIZE: usize = 4096;
    const FSTREE_APSB_BLOCK: usize = 371;

    fn fstree_volume() -> ApfsVolume {
        let b = &FSTREE
            [FSTREE_APSB_BLOCK * FSTREE_BLOCK_SIZE..(FSTREE_APSB_BLOCK + 1) * FSTREE_BLOCK_SIZE];
        ApfsVolume::parse(b).expect("parse APSB")
    }

    fn keys_for_oid_full(oid: u64) -> Vec<Vec<u8>> {
        use std::io::Cursor;
        let mut r = Cursor::new(FSTREE);
        let vol = fstree_volume();
        let mut out = Vec::new();
        // walk_fs_tree(None) is the full, unpruned descent — the oracle.
        walk_fs_tree(&mut r, &vol, FSTREE_BLOCK_SIZE, None, &mut |k, _| {
            if decode_jkey(crate::bytes::le_u64(k, 0)).0 == oid {
                out.push(k.to_vec());
            }
        })
        .expect("full walk");
        out
    }

    fn keys_for_oid_keyed(oid: u64) -> Vec<Vec<u8>> {
        use std::io::Cursor;
        let mut r = Cursor::new(FSTREE);
        let vol = fstree_volume();
        let mut out = Vec::new();
        for_each_fs_record_for_oid(&mut r, &vol, FSTREE_BLOCK_SIZE, oid, &mut |k, _| {
            if decode_jkey(crate::bytes::le_u64(k, 0)).0 == oid {
                out.push(k.to_vec());
            }
        })
        .expect("keyed walk");
        out
    }

    #[test]
    fn keyed_walk_matches_full_walk_on_real_fs_tree() {
        // Root dir (2), Dir1 (18), and a file inode (22) — each must yield the
        // same record set keyed as it does via the filtered full walk.
        for oid in [2u64, 18, 22] {
            assert_eq!(
                keys_for_oid_keyed(oid),
                keys_for_oid_full(oid),
                "keyed vs full record set for oid {oid}"
            );
        }
        // A non-existent oid yields nothing either way.
        assert!(keys_for_oid_keyed(999_999).is_empty());
        assert_eq!(keys_for_oid_keyed(999_999), keys_for_oid_full(999_999));
    }

    #[test]
    fn decode_unhashed_drec_name() {
        // A case-sensitive volume uses j_drec_key_t: name_len u16 @8, name @10.
        // Force the hashed path to miss (its low-10-bit length must not fit) by
        // making the u32 length point past the key, then the unhashed fallback
        // decodes "Xy\0" (len 3) at offset 10.
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        key.extend_from_slice(&3u16.to_le_bytes()); // name_len = 3
        key.extend_from_slice(b"Xy\0");
        // The hashed interpretation reads name_len_and_hash = u32 @8. Here the
        // upper two name bytes ("Xy") become part of that u32, giving a bogus
        // hashed length that runs past the key, so the unhashed branch is used.
        let name = decode_drec_name(&key);
        assert_eq!(name.as_deref(), Some("Xy"));
    }

    #[test]
    fn decode_drec_name_rejects_overlong_length() {
        // A key claiming a name longer than its bytes yields None (no over-read).
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        key.extend_from_slice(&0u32.to_le_bytes()); // hashed len 0
                                                    // no name bytes; unhashed len also reads 0 -> None
        assert_eq!(decode_drec_name(&key), None);
    }

    #[test]
    fn decode_drec_name_unhashed_length_past_key_is_none() {
        // unhashed_len > 0 but the name slice runs past the key, AND the hashed
        // interpretation's length also doesn't fit: both branches miss -> None
        // (exercises the unhashed `key.get(..)` None arm — no over-read).
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        // name_len u16 @8 = 200 (way past the key); the hashed u32 @8 low-10-bit
        // length is also 200, whose name@12 slice does not fit either.
        key.extend_from_slice(&200u16.to_le_bytes());
        key.extend_from_slice(b"z"); // only one trailing byte
        assert_eq!(decode_drec_name(&key), None);
    }

    #[test]
    fn parse_dir_entry_decodes_value() {
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        key.extend_from_slice(&5u32.to_le_bytes());
        key.extend_from_slice(b"abcd\0");
        let mut value = Vec::new();
        value.extend_from_slice(&42u64.to_le_bytes()); // file_id
        value.extend_from_slice(&1234u64.to_le_bytes()); // date_added
        value.extend_from_slice(&7u16.to_le_bytes()); // flags
        let e = parse_dir_entry(&key, &value).expect("parse drec");
        assert_eq!(e.name, "abcd");
        assert_eq!(e.file_id, 42);
        assert_eq!(e.date_added, 1234);
        assert_eq!(e.flags, 7);
    }

    #[test]
    fn parse_dir_entry_rejects_unnamed_key() {
        // A key with no decodable name yields None (the record is skipped).
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(9, 2));
        key.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_dir_entry(&key, &[0u8; 18]).is_none());
    }
}
