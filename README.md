# newtua-apfs

Pure-Rust from-scratch APFS (Apple File System) reader — container/volume
superblocks, object map, B-trees, file-system records, file extents,
snapshots, and transparent `decmpfs` decompression over any `Read + Seek`
source. Library import path: `apfs_core`.

Maintained only as a dependency of
**[New The Unarchiver](https://github.com/new-the-unarchiver)** (`newtua`) — a
cross-platform archive extractor written in Rust, a modern rewrite of the macOS
tool The Unarchiver.

## This is a forced fork

It exists to unblock our own build, not as a product of its own. We do **not
develop it**, do **not accept outside changes**, and make **no maintenance
promises**.

**Upstream:** [`SecurityRonin/apfs-forensic`](https://github.com/SecurityRonin/apfs-forensic),
subdirectory `core/` (package `apfs-core`, version 0.2.0), license Apache-2.0.

**Why the fork exists:** upstream pulls in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon)
as a *mandatory* dependency. `forensicnomicon` is a catalog of DFIR (digital
forensics and incident response) artifacts — UserAssist, Shimcache,
Prefetch, `$MFT`, EVTX, MITRE ATT&CK mappings — none of which have anything
to do with reading an APFS volume. Pulling it in adds roughly 5.1 MiB
(`forensicnomicon` 4348 KiB + `forensicnomicon-data` 725 KiB +
`forensicnomicon-core` 57 KiB) on top of `apfs-core` itself, which is only
104 KiB. We cut this dependency down to the one self-contained module we
actually use (see below).

We will drop this fork and go back to the upstream crate as soon as upstream
meets our needs. If you want this code for its own sake, take the upstream
crate, not our fork.

### A note on the version we forked

This fork is pinned to upstream **0.2.0**, the version already vendored and
tested against our own fixtures. Upstream has since moved on to 0.2.3. We
made a deliberate choice to ship the version we've already exercised rather
than chase the latest release under time pressure; catching up to a newer
upstream is tracked as future work, not a promise of any particular
timeline.

## Modifications from upstream 0.2.0

1. **`[package]` in `Cargo.toml`**: `name`, `version`, `edition`,
   `repository`, and `readme` were changed to describe this fork
   (`newtua-apfs`, `0.2.0-newtua.2`, this repository); the edition stays
   upstream's 2021. The
   `[lib]` section is unchanged: `name = "apfs_core"` — the bare `apfs` name
   on crates.io belongs to an unrelated read-only parser, so the import path
   stays `apfs_core`, exactly as upstream had it. Dependencies that used to
   read `X.workspace = true` (inherited from the upstream `apfs-forensic`
   Cargo workspace) are now pinned to concrete versions, since this crate no
   longer lives in that workspace.
2. **`forensicnomicon` dependency removed.** The only use site was
   `src/compression.rs`, importing `forensicnomicon::decmpfs::{classify,
   Algorithm, Storage, CHUNK_SIZE, COMPRESSION_TYPE_OFFSET, HEADER_LEN, MAGIC,
   UNCOMPRESSED_SIZE_OFFSET}` — one self-contained, dependency-free module
   (`crates/core/src/decmpfs.rs` upstream) from
   [`SecurityRonin/forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon)
   (also Apache-2.0). That file is copied verbatim into `src/decmpfs.rs`
   (private module) with an attribution header; `compression.rs` now imports
   from `crate::decmpfs` instead. No other file references
   `forensicnomicon`.
3. **`[lints]` (`workspace = true`) removed.** The upstream workspace's lint
   set is its own "paranoid" profile (`forbid` on `unwrap`/`expect`/`panic!`,
   `pedantic` warn, etc.). The crate compiles clean without any `[lints]`
   section.
4. **`sha2` dev-dependency** is pinned directly (`sha2 = "0.10"`) instead of
   inheriting it from the upstream workspace.
5. **Bug fix: stream-backed `com.apple.decmpfs` xattrs.** Upstream's
   `xattr::decmpfs_header` returns `None` when the xattr is stored as a data
   stream (`XATTR_DATA_STREAM`), treating that form as unexpected. It is not:
   APFS embeds an xattr value only while it fits in the fs-tree record and
   spills anything larger (a couple of hundred bytes) into a stream, so on an
   ordinary volume roughly half the transparently-compressed files take that
   path — and each one read back as **zero bytes with no error**. The stream
   form is now read through `extent::read_stream`, exactly as
   `xattr::resource_fork` already did, under a 1 MiB sanity cap on the
   image-supplied stream size. Two additions come with it, because a compressed
   file has no data stream and therefore no inode size at all:
   `compression::uncompressed_size` (the logical size a decmpfs header
   declares) and `extent::data_size` (that size for a compressed file, the
   inode's `DSTREAM` size otherwise); `vfs::…::meta` now reports the former
   instead of a constant 0. `tests/decmpfs_forms.rs` +
   `tests/data/apfs_decmpfs.bin` pin all of it against a macOS-minted image
   carrying both xattr forms. Purely additive to the public API.

Everything else (`src/`, `tests/`) is unmodified from upstream 0.2.0. The
`vfs`/`forensic-vfs` feature is present but not enabled by default —
low-level navigation (`dir::`, `extent::`, …) is used directly by
consumers instead.

## License

Apache-2.0 (see `LICENSE`), unchanged from upstream.
