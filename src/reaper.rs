//! Reaper (`nx_reaper_phys_t`, type `OBJECT_TYPE_NX_REAPER 0x11`) — lazy object
//! deletion state.
//!
//! Large objects (e.g. a deleted volume or a dropped snapshot's extents) are not
//! freed atomically; the reaper records them on a `nx_reap_list_phys_t`
//! (`OBJECT_TYPE_NX_REAP_LIST 0x12`) and releases their space incrementally
//! across transactions. The forensic value: objects queued in the reaper are
//! **logically deleted but still physically present** — a residue lead the
//! analyzer surfaces (`APFS-REAPER-PENDING-OBJECT`, Info/Low).

/// An object pending reaping (logically deleted, physically present).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReapPending {
    pub oid: u64,
    pub obj_type: u32,
}

/// Read the reaper's pending objects (the in-progress object plus every queued
/// reap-list entry).
///
/// `reaper_paddr` is the live reaper's physical block (resolve it from the
/// container's checkpoint map). The reap lists are ephemeral objects chained by
/// `nrl_next`, so their oids are resolved to physical blocks through `mappings`
/// (the same checkpoint-map mappings used to locate the reaper).
pub fn pending_objects<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    reaper_paddr: u64,
    mappings: &[crate::checkpoint::CheckpointMapping],
    block_size: usize,
) -> crate::Result<Vec<ReapPending>> {
    use crate::bytes::{le_u32, le_u64};
    use crate::spaceman::read_obj_block;

    // nx_reaper_phys_t field offsets (after the 32-byte obj_phys header).
    const NR_HEAD: usize = 48; // u64 — ephemeral oid of the first reap list
    const NR_TYPE: usize = 72; // u32 — in-progress object type
    const NR_OID: usize = 88; // u64 — in-progress object id (0 if none)
                              // nx_reap_list_phys_t field offsets.
    const NRL_NEXT: usize = 32; // u64 — ephemeral oid of the next list (0 = end)
    const NRL_COUNT: usize = 48; // u32
    const NRL_ENTRIES: usize = 64; // nx_reap_list_entry_t[]
    const NRLE_LEN: usize = 40;
    const NRLE_TYPE: usize = 8; // u32
    const NRLE_OID: usize = 24; // u64
                                // A reap-list chain longer than this is a cyclic/corrupt graph.
    const MAX_REAP_LISTS: usize = 4096;

    let reaper = read_obj_block(reader, reaper_paddr, block_size)?;
    let mut out = Vec::new();

    // The object whose reaping is in progress, if any.
    let nr_oid = le_u64(&reaper, NR_OID);
    if nr_oid != 0 {
        out.push(ReapPending {
            oid: nr_oid,
            obj_type: le_u32(&reaper, NR_TYPE),
        });
    }

    // Walk the reap-list chain (ephemeral oids resolved through the mappings).
    let max_entries = block_size.saturating_sub(NRL_ENTRIES) / NRLE_LEN;
    let mut seen = std::collections::HashSet::new();
    let mut next_oid = le_u64(&reaper, NR_HEAD);
    while next_oid != 0 {
        if !seen.insert(next_oid) || seen.len() > MAX_REAP_LISTS {
            return Err(crate::ApfsError::CycleGuard {
                cap: MAX_REAP_LISTS,
            });
        }
        let paddr = mappings
            .iter()
            .find(|m| m.oid == next_oid)
            .map(|m| m.paddr)
            .ok_or(crate::ApfsError::OmapUnresolved {
                oid: next_oid,
                xid: 0,
            })?;
        let list = read_obj_block(reader, paddr, block_size)?;
        let count = (le_u32(&list, NRL_COUNT) as usize).min(max_entries);
        for i in 0..count {
            let e = NRL_ENTRIES + i * NRLE_LEN;
            let oid = le_u64(&list, e + NRLE_OID);
            if oid != 0 {
                out.push(ReapPending {
                    oid,
                    obj_type: le_u32(&list, e + NRLE_TYPE),
                });
            }
        }
        next_oid = le_u64(&list, NRL_NEXT);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointMapping;
    use std::io::Cursor;

    const BS: usize = 4096;

    /// Stamp a valid Fletcher-64 over block `b` so `read_obj_block` trusts it.
    fn stamp(img: &mut [u8], b: usize) {
        let blk = &img[b * BS..(b + 1) * BS];
        let cks = crate::object::fletcher64_checksum(blk).to_le_bytes();
        img[b * BS..b * BS + 8].copy_from_slice(&cks);
    }

    fn put_u64(img: &mut [u8], b: usize, off: usize, v: u64) {
        img[b * BS + off..b * BS + off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(img: &mut [u8], b: usize, off: usize, v: u32) {
        img[b * BS + off..b * BS + off + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Synthetic reaper → one reap list of two queued objects, chained by an
    // ephemeral oid resolved through the checkpoint mappings. Validates the walk
    // (header → reap-list → entries) that no committed fixture exercises.
    #[test]
    fn walks_reap_list_entries_via_mappings() {
        let mut img = vec![0u8; BS * 4];
        let reaper_b = 1usize;
        let list_b = 2usize;
        let list_oid = 0x4001u64;

        // Reaper header: nr_head/nr_tail point at the reap-list's ephemeral oid;
        // nr_oid == 0 (no in-progress object).
        put_u64(&mut img, reaper_b, 48, list_oid); // nr_head
        put_u64(&mut img, reaper_b, 56, list_oid); // nr_tail
        stamp(&mut img, reaper_b);

        // Reap list: nrl_next == 0 (end), nrl_count == 2, two entries at @64.
        put_u64(&mut img, list_b, 32, 0); // nrl_next
        put_u32(&mut img, list_b, 48, 2); // nrl_count
                                          // entry 0 @64: nrle_type@8, nrle_oid@24
        put_u32(&mut img, list_b, 64 + 8, 0x4000_000d); // FS object
        put_u64(&mut img, list_b, 64 + 24, 500);
        // entry 1 @104
        put_u32(&mut img, list_b, 104 + 8, 0x4000_0002); // BTREE object
        put_u64(&mut img, list_b, 104 + 24, 600);
        stamp(&mut img, list_b);

        let mappings = [CheckpointMapping {
            oid: list_oid,
            paddr: list_b as u64,
            obj_type: 0x8000_0012,
            subtype: 0,
        }];

        let mut r = Cursor::new(img);
        let pending = pending_objects(&mut r, reaper_b as u64, &mappings, BS).expect("walk");
        let got: Vec<(u64, u32)> = pending.iter().map(|p| (p.oid, p.obj_type)).collect();
        assert_eq!(got, vec![(500, 0x4000_000d), (600, 0x4000_0002)]);
    }

    // An in-progress object (nr_oid != 0) is reported even with no reap lists.
    #[test]
    fn reports_in_progress_object() {
        let mut img = vec![0u8; BS * 2];
        let reaper_b = 1usize;
        put_u64(&mut img, reaper_b, 48, 0); // nr_head == 0 (no lists)
        put_u32(&mut img, reaper_b, 72, 0x4000_000d); // nr_type
        put_u64(&mut img, reaper_b, 88, 777); // nr_oid
        stamp(&mut img, reaper_b);

        let mut r = Cursor::new(img);
        let pending = pending_objects(&mut r, reaper_b as u64, &[], BS).expect("read");
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].oid, pending[0].obj_type), (777, 0x4000_000d));
    }
}
