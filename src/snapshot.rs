//! Snapshots: the snapshot-metadata tree, the snapshot-name tree, and the
//! point-in-time volume view.
//!
//! A volume's snapshots live in a single B-tree located by a **physical** block
//! number in the APSB (`apfs_snap_meta_tree_oid`, offset 152 — despite the
//! `_oid` name it is a block address; libfsapfs names the field
//! `snapshot_metadata_tree_block_number` and the tree's `o_subtype` is
//! `SNAPMETATREE 0x10`, stored physically `0x40000002`).
//!
//! `j_snap_metadata_val_t` field offsets within the value (verified verbatim
//! against libfsapfs `fsapfs_snapshot_metadata_btree_value` *and* dissect.apfs's
//! `j_snap_metadata_val`, which agree exactly):
//!
//! | off | size | field                 |
//! |-----|------|-----------------------|
//! | 0   | 8    | `extentref_tree_oid`  |
//! | 8   | 8    | `sblock_oid` (volume superblock block number) |
//! | 16  | 8    | `create_time` (ns since 1970-01-01 UTC) |
//! | 24  | 8    | `change_time`         |
//! | 32  | 8    | `inum`                |
//! | 40  | 4    | `extentref_tree_type` |
//! | 44  | 4    | `flags`               |
//! | 48  | 2    | `name_len` (incl. trailing NUL) |
//! | 50  | …    | `name[name_len]`      |

use std::io::{Read, Seek};

use crate::btree::{self, BTreeSubtype};
use crate::fsrecord::{decode_jkey, RecordType};
use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};
use crate::omap::ObjectMap;
use crate::volume::ApfsVolume;

/// `o_subtype` of the snapshot-metadata tree (`OBJECT_TYPE_SNAPMETATREE`).
const OBJECT_SUBTYPE_SNAPMETATREE: u32 = 0x10;

// `j_snap_name_key_t`: u16 name_len @8 (after the 8-byte j_key), name @10.
const OFF_SNAP_NAME_KEY_LEN: usize = 8;
const OFF_SNAP_NAME_KEY_NAME: usize = 10;

// `j_snap_metadata_val_t` field offsets within the value.
const OFF_SNAP_EXTENTREF_TREE_OID: usize = 0;
const OFF_SNAP_SBLOCK_OID: usize = 8;
const OFF_SNAP_CREATE_TIME: usize = 16;
const OFF_SNAP_CHANGE_TIME: usize = 24;
const OFF_SNAP_INUM: usize = 32;
const OFF_SNAP_FLAGS: usize = 44;
const OFF_SNAP_NAME_LEN: usize = 48;
const OFF_SNAP_NAME: usize = 50;

/// Depth cap on a snapshot-metadata-tree descent (cyclic-oid guard).
const MAX_SNAP_TREE_DEPTH: usize = 64;

/// Hard cap on a snapshot name length (incl. NUL) — a snapshot name is bounded;
/// cap well above any legal name to reject an allocation-bomb `name_len`.
const MAX_SNAP_NAME_LEN: usize = 4096;

/// A parsed snapshot (one `APFS_TYPE_SNAP_METADATA` record).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Snapshot {
    /// The snapshot's transaction id (the snap-metadata key's low 60 bits).
    pub xid: u64,
    /// The snapshot name (`j_snap_metadata_val_t.name`, NUL-terminated).
    pub name: String,
    /// `create_time` (ns since 1970-01-01 UTC).
    pub create_time: u64,
    /// `change_time` (ns since 1970-01-01 UTC).
    pub change_time: u64,
    /// `sblock_oid` — the block address of the volume superblock (APSB) frozen at
    /// this snapshot.
    pub sblock_oid: u64,
    /// `extentref_tree_oid` — the snapshot's extent-reference tree oid.
    pub extentref_tree_oid: u64,
    /// `inum` — the snapshot's `inum` field.
    pub inum: u64,
    /// `flags` (`j_snap_metadata_val_t.flags`).
    pub flags: u32,
}

/// Decode a `j_snap_metadata_val_t` value for a snapshot at `xid`. Bounds-checked:
/// missing fields read as 0, an over-long `name_len` is clamped, and the name is
/// taken only from bytes that fit (never panics, never over-reads).
fn parse_snap_metadata(xid: u64, value: &[u8]) -> Snapshot {
    let name_len = (crate::bytes::le_u16(value, OFF_SNAP_NAME_LEN) as usize).min(MAX_SNAP_NAME_LEN);
    let name = value
        .get(OFF_SNAP_NAME..OFF_SNAP_NAME + name_len)
        .map_or_else(String::new, decode_cstr);
    Snapshot {
        xid,
        name,
        create_time: crate::bytes::le_u64(value, OFF_SNAP_CREATE_TIME),
        change_time: crate::bytes::le_u64(value, OFF_SNAP_CHANGE_TIME),
        sblock_oid: crate::bytes::le_u64(value, OFF_SNAP_SBLOCK_OID),
        extentref_tree_oid: crate::bytes::le_u64(value, OFF_SNAP_EXTENTREF_TREE_OID),
        inum: crate::bytes::le_u64(value, OFF_SNAP_INUM),
        flags: crate::bytes::le_u32(value, OFF_SNAP_FLAGS),
    }
}

/// Enumerate a volume's snapshots from the snapshot-metadata tree, sorted by xid.
///
/// # Errors
/// [`crate::ApfsError::ChecksumMismatch`] / [`crate::ApfsError::CycleGuard`] /
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::Io`] on a
/// structurally invalid tree or a read failure.
pub fn list_snapshots<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
) -> crate::Result<Vec<Snapshot>> {
    let mut out = Vec::new();
    for_each_snap_record(reader, volume, block_size, &mut |key, value| {
        let (xid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty == Some(RecordType::SnapMetadata) {
            out.push(parse_snap_metadata(xid, value));
        }
    })?;
    out.sort_by_key(|s| s.xid);
    Ok(out)
}

/// Resolve a snapshot **name** to its xid via the snapshot-name tree records
/// (`APFS_TYPE_SNAP_NAME`, value `j_snap_name_val_t { xid_t snap_xid }`). `None`
/// if no snapshot of that name exists.
///
/// # Errors
/// As [`list_snapshots`].
pub fn resolve_snapshot_xid<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    name: &str,
    block_size: usize,
) -> crate::Result<Option<u64>> {
    let mut found = None;
    for_each_snap_record(reader, volume, block_size, &mut |key, value| {
        if found.is_some() {
            return;
        }
        let (_oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::SnapName) {
            return;
        }
        if decode_snap_name_key(key).as_deref() == Some(name) {
            // j_snap_name_val_t { xid_t snap_xid } — the xid is the whole value.
            found = Some(crate::bytes::le_u64(value, 0));
        }
    })?;
    Ok(found)
}

/// Mount a snapshot as a point-in-time [`ApfsVolume`]: read the volume
/// superblock (APSB) frozen at `snapshot.sblock_oid`, parse it, and graft the
/// **live** volume's object map onto it.
///
/// A snapshot's frozen `apfs_superblock_t` carries `apfs_omap_oid == 0` —
/// snapshots have no object map of their own; their fs-tree is read through the
/// containing volume's omap, resolved at the snapshot's `xid` (the omap B-tree
/// retains the historical `(oid, xid) → paddr` mappings a snapshot pins). The
/// returned volume therefore keeps the frozen superblock's `root_tree_oid` and
/// `xid` but borrows `live_volume`'s `omap_oid`, so the existing [`crate::dir`]
/// / [`crate::extent`] navigation reads the volume exactly as it stood at
/// snapshot time. (Without the graft, navigation would read the snapshot's
/// `omap_oid == 0`, i.e. block 0 — the container superblock — and fail.)
///
/// # Errors
/// [`crate::ApfsError::UnexpectedObjectType`] if `sblock_oid` does not point at a
/// volume superblock; [`crate::ApfsError::ChecksumMismatch`] on a Fletcher-64
/// failure; [`crate::ApfsError::Io`] on a read/seek failure.
pub fn mount_snapshot<R: Read + Seek>(
    reader: &mut R,
    live_volume: &ApfsVolume,
    snapshot: &Snapshot,
    block_size: usize,
) -> crate::Result<ApfsVolume> {
    let mut buf = vec![0u8; block_size];
    let offset = snapshot.sblock_oid.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;
    Ok(ApfsVolume::parse(&buf)?.with_omap_oid(live_volume.omap_oid()))
}

/// Walk the snapshot-metadata tree, invoking `visit(key, value)` for every leaf
/// record (both `SNAP_METADATA` and `SNAP_NAME`). The root is read by its
/// physical block address ([`ApfsVolume::snap_meta_tree_oid`]); index-node
/// children are *virtual* oids resolved through the volume omap at the volume's
/// xid (libfsapfs resolves snap-meta-tree sub-nodes via the object map),
/// mirroring [`crate::dir`]'s fs-tree walk. Each node's Fletcher-64 checksum is
/// verified before its TOC is trusted, the descent depth is capped, and a
/// visited-set guards against cyclic node oids.
fn for_each_snap_record<R, F>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    // Read the volume omap header (a physical object at apfs_omap_oid) — needed
    // to resolve any virtual sub-node oids of the snap-meta tree.
    let mut buf = vec![0u8; block_size];
    let omap_off = volume.omap_oid().saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(omap_off))?;
    reader.read_exact(&mut buf)?;
    let omap = ObjectMap::parse(&buf)?;

    let mut visited = std::collections::HashSet::new();
    descend_snap(
        reader,
        &omap,
        volume.snap_meta_tree_oid(),
        true,
        volume.xid(),
        block_size,
        0,
        &mut visited,
        visit,
    )
}

#[allow(clippy::too_many_arguments)]
fn descend_snap<R, F>(
    reader: &mut R,
    omap: &ObjectMap,
    node_oid: u64,
    is_root: bool,
    xid: u64,
    block_size: usize,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    let cycle = || crate::ApfsError::CycleGuard {
        cap: MAX_SNAP_TREE_DEPTH,
    };
    // The visited-set guard below dominates any realizable cycle; this depth cap
    // is defense-in-depth against a pathological deep acyclic tree.
    if depth >= MAX_SNAP_TREE_DEPTH {
        return Err(cycle()); // cov:unreachable: visited-set guard dominates any realizable cycle
    }
    if !visited.insert(node_oid) {
        return Err(cycle());
    }

    // The root is a direct block address; a sub-node is a virtual oid resolved
    // through the volume omap.
    let paddr = if is_root {
        node_oid
    } else {
        omap.resolve(reader, node_oid, xid, block_size)?.paddr
    };

    let mut buf = vec![0u8; block_size];
    let offset = paddr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;

    // Checksum-before-trust.
    let stored = fletcher64_stored(&buf);
    let computed = fletcher64_checksum(&buf);
    if stored != computed {
        let block = ObjPhys::parse(&buf).map_or(paddr, |h| h.oid);
        return Err(crate::ApfsError::ChecksumMismatch {
            block,
            stored,
            computed,
        });
    }

    let Some(hdr) = btree::parse_node_header(&buf) else {
        return Ok(()); // cov:unreachable: buf is block_size >= node header length
    };

    // The snap-meta tree is a variable-KV tree (variable keys: 8-byte metadata
    // key vs name key); its layout matches the fs-tree, so BTreeSubtype::FsTree
    // supplies the right (variable-KV, 8-byte branch) entry geometry.
    if hdr.is_leaf() {
        for e in btree::node_entries(&buf, BTreeSubtype::FsTree) {
            visit(e.key, e.value);
        }
        return Ok(());
    }

    // Index node: each value is an 8-byte child *virtual* oid; descend each.
    let children: Vec<u64> = btree::node_entries(&buf, BTreeSubtype::FsTree)
        .iter()
        .map(|e| crate::bytes::le_u64(e.value, 0))
        .collect();
    for child in children {
        descend_snap(
            reader,
            omap,
            child,
            false,
            xid,
            block_size,
            depth + 1,
            visited,
            visit,
        )?;
    }
    Ok(())
}

/// Decode a `j_snap_name_key_t` name from a snap-name record key (u16 `name_len`
/// @8, name @10). `None` if the length is zero or runs past the key (never
/// over-reads).
fn decode_snap_name_key(key: &[u8]) -> Option<String> {
    let name_len =
        (crate::bytes::le_u16(key, OFF_SNAP_NAME_KEY_LEN) as usize).min(MAX_SNAP_NAME_LEN);
    if name_len == 0 {
        return None;
    }
    key.get(OFF_SNAP_NAME_KEY_NAME..OFF_SNAP_NAME_KEY_NAME + name_len)
        .map(decode_cstr)
}

/// Decode a NUL-terminated UTF-8 byte string (the snapshot name form).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// The snapshot-metadata tree's `o_subtype` (`OBJECT_TYPE_SNAPMETATREE`).
#[must_use]
pub fn snap_meta_tree_subtype() -> u32 {
    OBJECT_SUBTYPE_SNAPMETATREE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_snap_metadata_value_decodes_all_fields() {
        let mut v = Vec::new();
        v.extend_from_slice(&0x11u64.to_le_bytes()); // extentref_tree_oid @0
        v.extend_from_slice(&0x22u64.to_le_bytes()); // sblock_oid @8
        v.extend_from_slice(&1000u64.to_le_bytes()); // create_time @16
        v.extend_from_slice(&2000u64.to_le_bytes()); // change_time @24
        v.extend_from_slice(&99u64.to_le_bytes()); // inum @32
        v.extend_from_slice(&0x4000_0002u32.to_le_bytes()); // extentref_tree_type @40
        v.extend_from_slice(&0x1u32.to_le_bytes()); // flags @44
        v.extend_from_slice(&6u16.to_le_bytes()); // name_len @48 ("snap1\0")
        v.extend_from_slice(b"snap1\0"); // name @50

        let s = parse_snap_metadata(42, &v);
        assert_eq!(s.xid, 42);
        assert_eq!(s.extentref_tree_oid, 0x11);
        assert_eq!(s.sblock_oid, 0x22);
        assert_eq!(s.create_time, 1000);
        assert_eq!(s.change_time, 2000);
        assert_eq!(s.inum, 99);
        assert_eq!(s.flags, 0x1);
        assert_eq!(s.name, "snap1");
    }

    #[test]
    fn parse_snap_metadata_clamps_overlong_name() {
        let mut v = vec![0u8; OFF_SNAP_NAME];
        v[OFF_SNAP_NAME_LEN..OFF_SNAP_NAME_LEN + 2].copy_from_slice(&50000u16.to_le_bytes());
        let s = parse_snap_metadata(1, &v);
        assert_eq!(s.name, "");
    }

    #[test]
    fn parse_snap_metadata_truncated_value_reads_zero() {
        let s = parse_snap_metadata(7, &[0u8; 4]);
        assert_eq!(s.sblock_oid, 0);
        assert_eq!(s.create_time, 0);
        assert_eq!(s.name, "");
    }

    #[test]
    fn snap_meta_tree_subtype_is_snapmetatree() {
        assert_eq!(snap_meta_tree_subtype(), 0x10);
    }

    /// Build an 8-byte `j_key` header word from a 4-bit type and a 60-bit oid.
    fn jkey(ty: u64, oid: u64) -> [u8; 8] {
        ((ty << 60) | oid).to_le_bytes()
    }

    #[test]
    fn decode_snap_name_key_reads_name() {
        // j_snap_name_key_t: j_key (SNAP_NAME=11) + name_len u16 @8 + name @10.
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(11, 0)); // snap-name keys carry oid 0
        key.extend_from_slice(&6u16.to_le_bytes()); // name_len = 6 ("snap1\0")
        key.extend_from_slice(b"snap1\0");
        assert_eq!(decode_snap_name_key(&key).as_deref(), Some("snap1"));
    }

    #[test]
    fn decode_snap_name_key_rejects_zero_and_overlong() {
        // name_len 0 -> None; name_len past the key -> None (no over-read).
        let mut zero = Vec::new();
        zero.extend_from_slice(&jkey(11, 0));
        zero.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_snap_name_key(&zero), None);

        let mut overlong = Vec::new();
        overlong.extend_from_slice(&jkey(11, 0));
        overlong.extend_from_slice(&200u16.to_le_bytes());
        overlong.extend_from_slice(b"z");
        assert_eq!(decode_snap_name_key(&overlong), None);
    }

    // The point-in-time seam: a snapshot's sblock_oid is a *physical* APSB block
    // number, so mount_snapshot must read that block and parse it as an
    // ApfsVolume identical to parsing the block directly. Validated against the
    // real Apple-minted P4 fixture's live APSB (block 438) — a Snapshot whose
    // sblock_oid points at it must "mount" to the same volume the existing
    // navigation already reads.
    const P4_CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
    const P4_BLOCK_SIZE: usize = 4096;
    const P4_APSB_BLOCK: u64 = 438;

    fn snapshot_pointing_at(sblock_oid: u64) -> Snapshot {
        Snapshot {
            xid: 0,
            name: "synthetic-pointer".to_string(),
            create_time: 0,
            change_time: 0,
            sblock_oid,
            extentref_tree_oid: 0,
            inum: 0,
            flags: 0,
        }
    }

    #[test]
    fn mount_snapshot_reads_sblock_as_volume() {
        use std::io::Cursor;
        let mut r = Cursor::new(P4_CONTENT);
        // The live volume is block 438; a snapshot whose sblock_oid is also 438
        // mounts to the same superblock with the live omap grafted on.
        let start = P4_APSB_BLOCK as usize * P4_BLOCK_SIZE;
        let live =
            ApfsVolume::parse(&P4_CONTENT[start..start + P4_BLOCK_SIZE]).expect("parse live APSB");
        let snap = snapshot_pointing_at(P4_APSB_BLOCK);
        let mounted = mount_snapshot(&mut r, &live, &snap, P4_BLOCK_SIZE).expect("mount snapshot");

        // The frozen superblock supplies oid/xid/root-tree/name; the live omap is
        // grafted on (here identical to the block's own, since live == the block).
        assert_eq!(mounted.oid(), live.oid());
        assert_eq!(mounted.xid(), live.xid());
        assert_eq!(mounted.omap_oid(), live.omap_oid());
        assert_eq!(mounted.root_tree_oid(), live.root_tree_oid());
        assert_eq!(mounted.name(), live.name());
        assert_eq!(mounted.name(), "APFSP4");
    }

    #[test]
    fn mount_snapshot_grafts_live_omap_over_snapshot_zero() {
        use std::io::Cursor;
        // A real snapshot superblock has apfs_omap_oid == 0; mount_snapshot must
        // graft the live volume's omap so the point-in-time view is navigable
        // (resolving block 0 — the container superblock — would fail). Block 438
        // has a non-zero omap; grafting a distinct live omap must take effect.
        let mut r = Cursor::new(P4_CONTENT);
        let start = P4_APSB_BLOCK as usize * P4_BLOCK_SIZE;
        let block438 =
            ApfsVolume::parse(&P4_CONTENT[start..start + P4_BLOCK_SIZE]).expect("parse APSB");
        let live = block438.clone().with_omap_oid(999_111);
        let snap = snapshot_pointing_at(P4_APSB_BLOCK);
        let mounted = mount_snapshot(&mut r, &live, &snap, P4_BLOCK_SIZE).expect("mount snapshot");
        assert_eq!(
            mounted.omap_oid(),
            999_111,
            "the live volume's omap must be grafted onto the snapshot view"
        );
        // The frozen identity fields still come from the snapshot's own block.
        assert_eq!(mounted.xid(), block438.xid());
        assert_eq!(mounted.root_tree_oid(), block438.root_tree_oid());
    }

    #[test]
    fn mount_snapshot_rejects_non_apsb_block() {
        use std::io::Cursor;
        let mut r = Cursor::new(P4_CONTENT);
        let start = P4_APSB_BLOCK as usize * P4_BLOCK_SIZE;
        let live =
            ApfsVolume::parse(&P4_CONTENT[start..start + P4_BLOCK_SIZE]).expect("parse live APSB");
        // Block 0 is the container superblock (NXSB), not a volume APSB; mounting
        // it must fail loudly with UnexpectedObjectType, never silently succeed.
        let snap = snapshot_pointing_at(0);
        let err = mount_snapshot(&mut r, &live, &snap, P4_BLOCK_SIZE).unwrap_err();
        assert!(
            matches!(err, crate::ApfsError::UnexpectedObjectType { .. }),
            "mounting a non-APSB block must fail loudly, got {err:?}"
        );
    }

    // ---------------------------------------------------------------------
    // Synthetic-image walk tests.
    //
    // The real P4 fixture validates tree *location* + the *empty* case on
    // Apple-authored bytes; the populated-tree paths (leaf record dispatch,
    // index-node virtual descent, checksum/cycle guards) need a tree that
    // actually carries records. Minting a populated snapshot tree on this host
    // is blocked by SIP (fs_snapshot_create requires an entitlement — see
    // docs/validation.md), so the *walk algorithm* is exercised here against a
    // hand-built, spec-faithful APFS micro-image: real obj_phys headers, real
    // Fletcher-64 checksums, real variable-KV btree TOC/key/value layout
    // (verified vs btree.rs + the Apple reference). This is a Tier-3 vector for
    // the walk control flow only; every on-disk *offset/decode* it relies on is
    // independently validated on real data by the P1–P5 fixtures.
    const BS: usize = 4096;

    /// Stamp a valid Fletcher-64 `o_cksum` into the first 8 bytes of `block`.
    fn seal(block: &mut [u8]) {
        let c = fletcher64_checksum(block);
        block[0..8].copy_from_slice(&c.to_le_bytes());
    }

    /// Build a 32-byte `obj_phys_t` prefix into `block` (cksum left for `seal`).
    fn obj_hdr(block: &mut [u8], oid: u64, xid: u64, o_type: u32, o_subtype: u32) {
        block[8..16].copy_from_slice(&oid.to_le_bytes());
        block[16..24].copy_from_slice(&xid.to_le_bytes());
        block[24..28].copy_from_slice(&o_type.to_le_bytes());
        block[28..32].copy_from_slice(&o_subtype.to_le_bytes());
    }

    /// Build a variable-KV B-tree node block (root) from `(key, value)` records.
    /// `is_leaf` selects `BTNODE_LEAF`; a non-leaf node's values are 8-byte child
    /// block numbers. Layout matches `btree::node_entries` exactly: a TOC of
    /// 8-byte `kvloc_t` entries at the start of `btn_data`, keys growing forward
    /// from the end of the TOC, values growing backward from the footer.
    fn btree_node(oid: u64, xid: u64, is_leaf: bool, records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        const FOOTER: usize = 40;
        let mut b = vec![0u8; BS];
        // btn_flags: ROOT(0x1) | (LEAF 0x2 if leaf). Variable-KV (no FIXED bit).
        let flags: u16 = 0x1 | if is_leaf { 0x2 } else { 0 };
        b[32..34].copy_from_slice(&flags.to_le_bytes());
        let level: u16 = u16::from(!is_leaf);
        b[34..36].copy_from_slice(&level.to_le_bytes());
        b[36..40].copy_from_slice(&(records.len() as u32).to_le_bytes());

        let toc_len = records.len() * 8;
        // btn_table_space nloc: off (relative to btn_data @56) = 0, len = toc_len.
        b[40..42].copy_from_slice(&0u16.to_le_bytes());
        b[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

        let toc_start = 56; // btn_data + 0
        let key_area = toc_start + toc_len;
        let val_base = BS - FOOTER; // root: values reversed from footer start

        let mut key_off = 0usize; // forward from key_area
        let mut val_off = 0usize; // backward from val_base
        for (i, (k, v)) in records.iter().enumerate() {
            let e = toc_start + i * 8;
            b[e..e + 2].copy_from_slice(&(key_off as u16).to_le_bytes());
            b[e + 2..e + 4].copy_from_slice(&(k.len() as u16).to_le_bytes());
            // value_offs is the reversed distance from val_base to the value end.
            let this_val = v.len();
            let v_reversed = val_off + this_val;
            b[e + 4..e + 6].copy_from_slice(&(v_reversed as u16).to_le_bytes());
            b[e + 6..e + 8].copy_from_slice(&(this_val as u16).to_le_bytes());

            let ks = key_area + key_off;
            b[ks..ks + k.len()].copy_from_slice(k);
            let vs = val_base - v_reversed;
            b[vs..vs + this_val].copy_from_slice(v);

            key_off += k.len();
            val_off += this_val;
        }
        obj_hdr(&mut b, oid, xid, 0x4000_0002, 0x10); // PHYSICAL|BTREE, SNAPMETATREE
        seal(&mut b);
        b
    }

    /// `j_key` header for a snap record: top-4 type, low-60 oid/xid.
    fn snap_jkey(ty: u64, id: u64) -> Vec<u8> {
        ((ty << 60) | id).to_le_bytes().to_vec()
    }

    /// A `j_snap_metadata_val_t` with a given `sblock_oid`, name, `create_time`.
    fn snap_meta_val(sblock: u64, create: u64, name: &str) -> Vec<u8> {
        let mut v = vec![0u8; OFF_SNAP_NAME];
        v[OFF_SNAP_SBLOCK_OID..OFF_SNAP_SBLOCK_OID + 8].copy_from_slice(&sblock.to_le_bytes());
        v[OFF_SNAP_CREATE_TIME..OFF_SNAP_CREATE_TIME + 8].copy_from_slice(&create.to_le_bytes());
        let mut name_b = name.as_bytes().to_vec();
        name_b.push(0);
        v[OFF_SNAP_NAME_LEN..OFF_SNAP_NAME_LEN + 2]
            .copy_from_slice(&(name_b.len() as u16).to_le_bytes());
        v.extend_from_slice(&name_b);
        v
    }

    /// A `j_snap_name_key_t` (name) record key.
    fn snap_name_key(name: &str) -> Vec<u8> {
        let mut k = snap_jkey(11, 0);
        let mut name_b = name.as_bytes().to_vec();
        name_b.push(0);
        k.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        k.extend_from_slice(&name_b);
        k
    }

    /// Build a minimal valid APSB at `oid`/`xid` referencing `omap_oid` +
    /// `snap_meta_tree_oid`.
    fn apsb(oid: u64, xid: u64, omap_oid: u64, snap_meta_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        b[32..36].copy_from_slice(&0x4253_5041u32.to_le_bytes()); // "APSB"
        b[128..136].copy_from_slice(&omap_oid.to_le_bytes()); // apfs_omap_oid
        b[152..160].copy_from_slice(&snap_meta_oid.to_le_bytes()); // snap_meta_tree
        obj_hdr(&mut b, oid, xid, 0x0d, 0); // OBJECT_TYPE_FS
        seal(&mut b);
        b
    }

    /// Build a minimal volume omap (`omap_phys`) whose btree (a single physical
    /// fixed-KV leaf at `tree_block`) maps `(virt_oid, xid) -> phys`.
    fn omap_block(oid: u64, tree_block: u64) -> Vec<u8> {
        let mut b = vec![0u8; BS];
        b[40..44].copy_from_slice(&0x4000_0002u32.to_le_bytes()); // om_tree_type
        b[48..56].copy_from_slice(&tree_block.to_le_bytes()); // om_tree_oid (physical)
        obj_hdr(&mut b, oid, 0, 0x0b, 0); // OBJECT_TYPE_OMAP
        seal(&mut b);
        b
    }

    /// Build a fixed-KV omap btree leaf mapping each `(virt, xid) -> phys`.
    fn omap_leaf(oid: u64, entries: &[(u64, u64, u64)]) -> Vec<u8> {
        const FOOTER: usize = 40;
        let mut b = vec![0u8; BS];
        let flags: u16 = 0x1 | 0x2 | 0x4; // ROOT | LEAF | FIXED_KV_SIZE
        b[32..34].copy_from_slice(&flags.to_le_bytes());
        b[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        let toc_len = entries.len() * 4; // fixed TOC: key_offs,value_offs (u16,u16)
        b[40..42].copy_from_slice(&0u16.to_le_bytes());
        b[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());
        let toc_start = 56;
        let key_area = toc_start + toc_len;
        let val_base = BS - FOOTER;
        let mut key_off = 0usize;
        let mut val_off = 0usize;
        for (i, (virt, xid, phys)) in entries.iter().enumerate() {
            let e = toc_start + i * 4;
            b[e..e + 2].copy_from_slice(&(key_off as u16).to_le_bytes());
            // omap_key { ok_oid u64, ok_xid u64 } = 16 bytes
            let mut k = vec![0u8; 16];
            k[0..8].copy_from_slice(&virt.to_le_bytes());
            k[8..16].copy_from_slice(&xid.to_le_bytes());
            let ks = key_area + key_off;
            b[ks..ks + 16].copy_from_slice(&k);
            // omap_val { ov_flags u32, ov_size u32, ov_paddr u64 } = 16 bytes
            let mut v = vec![0u8; 16];
            v[8..16].copy_from_slice(&phys.to_le_bytes());
            let v_reversed = val_off + 16;
            b[e + 2..e + 4].copy_from_slice(&(v_reversed as u16).to_le_bytes());
            let vs = val_base - v_reversed;
            b[vs..vs + 16].copy_from_slice(&v);
            key_off += 16;
            val_off += 16;
        }
        obj_hdr(&mut b, oid, 0, 0x4000_0002, 0x0b); // PHYSICAL|BTREE, omap subtype
        seal(&mut b);
        b
    }

    /// Assemble a block image (`Vec` of `(block_index, bytes)`) into one buffer.
    fn image(blocks: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let max = blocks.iter().map(|(i, _)| *i).max().unwrap_or(0) as usize;
        let mut buf = vec![0u8; (max + 1) * BS];
        for (i, b) in blocks {
            let off = *i as usize * BS;
            buf[off..off + BS].copy_from_slice(b);
        }
        buf
    }

    /// A volume whose snap-meta tree root is a single leaf at `snap_tree_block`,
    /// with `omap` at `omap_block_idx` (empty map — not needed for a leaf root).
    fn single_leaf_volume(snap_records: &[(Vec<u8>, Vec<u8>)]) -> (Vec<u8>, ApfsVolume) {
        let snap_leaf = btree_node(50, 7, true, snap_records);
        let omap = omap_block(40, 41);
        let omap_tree = omap_leaf(41, &[]); // no virtual nodes to resolve for a leaf root
        let apsb_b = apsb(1026, 7, 40, 50);
        let buf = image(&[(40, omap), (41, omap_tree), (50, snap_leaf), (1026, apsb_b)]);
        let vol = ApfsVolume::parse(&buf[1026 * BS..1027 * BS]).expect("parse synth APSB");
        (buf, vol)
    }

    #[test]
    fn lists_snapshots_from_populated_leaf() {
        use std::io::Cursor;
        // A snap-meta leaf with two SNAP_METADATA records (xid 5, xid 9) plus a
        // SNAP_NAME record. list_snapshots returns the two metadata records,
        // sorted by xid; the name record is ignored by list_snapshots.
        let records = vec![
            (snap_jkey(1, 5), snap_meta_val(0x200, 1000, "snapA")),
            (snap_jkey(1, 9), snap_meta_val(0x300, 2000, "snapB")),
            (snap_name_key("snapA"), 5u64.to_le_bytes().to_vec()),
        ];
        let (buf, vol) = single_leaf_volume(&records);
        let mut r = Cursor::new(buf);
        let snaps = list_snapshots(&mut r, &vol, BS).expect("list");
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].xid, 5);
        assert_eq!(snaps[0].name, "snapA");
        assert_eq!(snaps[0].sblock_oid, 0x200);
        assert_eq!(snaps[0].create_time, 1000);
        assert_eq!(snaps[1].xid, 9);
        assert_eq!(snaps[1].name, "snapB");
    }

    #[test]
    fn resolves_snap_name_from_populated_leaf() {
        use std::io::Cursor;
        let records = vec![
            (snap_jkey(1, 5), snap_meta_val(0x200, 1000, "snapA")),
            (snap_name_key("snapA"), 5u64.to_le_bytes().to_vec()),
            (snap_name_key("snapB"), 9u64.to_le_bytes().to_vec()),
        ];
        let (buf, vol) = single_leaf_volume(&records);
        let mut r = Cursor::new(buf);
        assert_eq!(
            resolve_snapshot_xid(&mut r, &vol, "snapB", BS).expect("resolve"),
            Some(9)
        );
        assert_eq!(
            resolve_snapshot_xid(&mut r, &vol, "snapA", BS).expect("resolve"),
            Some(5)
        );
        assert_eq!(
            resolve_snapshot_xid(&mut r, &vol, "absent", BS).expect("resolve"),
            None
        );
    }

    #[test]
    fn walks_index_node_resolving_child_virtually() {
        use std::io::Cursor;
        // Snap-meta tree ROOT is an INDEX node (level 1) whose single child is a
        // *virtual* oid (1500) resolved through the volume omap to a physical leaf
        // block (60). This exercises the virtual sub-node resolve + descent path.
        let leaf = btree_node(
            60,
            7,
            true,
            &[(snap_jkey(1, 3), snap_meta_val(0x99, 500, "s"))],
        );
        // Index root: one record whose value is the 8-byte child virtual oid 1500.
        let index = btree_node(
            50,
            7,
            false,
            &[(snap_jkey(1, 3), 1500u64.to_le_bytes().to_vec())],
        );
        let omap = omap_block(40, 41);
        // omap maps (virtual 1500, xid 7) -> physical block 60.
        let omap_tree = omap_leaf(41, &[(1500, 7, 60)]);
        let apsb_b = apsb(1026, 7, 40, 50);
        let buf = image(&[
            (40, omap),
            (41, omap_tree),
            (50, index),
            (60, leaf),
            (1026, apsb_b),
        ]);
        let vol = ApfsVolume::parse(&buf[1026 * BS..1027 * BS]).expect("parse APSB");
        let mut r = Cursor::new(buf);
        let snaps = list_snapshots(&mut r, &vol, BS).expect("list via index");
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].xid, 3);
        assert_eq!(snaps[0].sblock_oid, 0x99);
    }

    #[test]
    fn snap_tree_checksum_mismatch_is_loud() {
        use std::io::Cursor;
        let records = vec![(snap_jkey(1, 5), snap_meta_val(0x200, 1000, "snapA"))];
        let (mut buf, vol) = single_leaf_volume(&records);
        // Corrupt the snap-meta leaf (block 50) body after its checksum was sealed.
        buf[50 * BS + 100] ^= 0xff;
        let mut r = Cursor::new(buf);
        let err = list_snapshots(&mut r, &vol, BS).unwrap_err();
        assert!(
            matches!(err, crate::ApfsError::ChecksumMismatch { .. }),
            "a corrupted snap-meta node must fail loudly, got {err:?}"
        );
    }

    #[test]
    fn snap_tree_cycle_is_rejected() {
        use std::io::Cursor;
        // An index root (block 50, virtual oid 50) whose child resolves back to
        // block 50 — a cycle. The visited-set guard must reject it.
        let index = btree_node(
            50,
            7,
            false,
            &[(snap_jkey(1, 3), 1500u64.to_le_bytes().to_vec())],
        );
        let omap = omap_block(40, 41);
        // virtual 1500 -> physical 50 (the root again) => revisiting block oid 50.
        let omap_tree = omap_leaf(41, &[(1500, 7, 50)]);
        let apsb_b = apsb(1026, 7, 40, 50);
        let buf = image(&[(40, omap), (41, omap_tree), (50, index), (1026, apsb_b)]);
        let vol = ApfsVolume::parse(&buf[1026 * BS..1027 * BS]).expect("parse APSB");
        let mut r = Cursor::new(buf);
        let err = list_snapshots(&mut r, &vol, BS).unwrap_err();
        assert!(
            matches!(err, crate::ApfsError::CycleGuard { .. }),
            "a cyclic snap-meta tree must be rejected, got {err:?}"
        );
    }
}
