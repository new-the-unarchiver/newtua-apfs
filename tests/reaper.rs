//! Reaper pending-object enumeration on the real self-minted container
//! `apfs_container_chain.bin` (Tier 2).
//!
//! The fixture is a freshly-minted container with nothing deleted, so its live
//! reaper (`nx_reaper_oid` 1025 → block 12) is **empty** (`nr_head == 0`,
//! `nr_oid == 0`). `pending_objects` must therefore return no entries — the
//! correct "no logically-deleted-but-present objects" result on a clean volume.
//! (The populated reap-list walk is covered by a synthetic unit test in
//! `reaper.rs`, since no committed fixture has a queued reaper.)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::reaper::pending_objects;

const CHAIN: &[u8] = include_bytes!("../../tests/data/apfs_container_chain.bin");
const BLOCK_SIZE: usize = 4096;
/// The live reaper (`nx_reaper_oid` 1025) resolves to block 12.
const REAPER_BLOCK: u64 = 12;

#[test]
fn empty_reaper_has_no_pending_objects() {
    let mut r = Cursor::new(CHAIN);
    // nr_head == 0 and nr_oid == 0, so no mappings are needed to enumerate.
    let pending = pending_objects(&mut r, REAPER_BLOCK, &[], BLOCK_SIZE).expect("read reaper");
    assert!(
        pending.is_empty(),
        "clean container's reaper must be empty, got {pending:?}"
    );
}
