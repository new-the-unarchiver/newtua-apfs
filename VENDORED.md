# Vendored crate: `apfs-core`

Source: [`SecurityRonin/apfs-forensic`](https://github.com/SecurityRonin/apfs-forensic),
subdirectory `core/` (package `apfs-core` 0.2.0, `[lib] name = "apfs_core"`).
License: Apache-2.0 (see `LICENSE` in this directory).

Taken as a `newtua` path-member (same house style as `vendor/unrar-0.5.8`) rather
than a crates.io dependency, so the `forensicnomicon` dependency below could be
cut and so the crate lives directly in our tree/CI without an external release
cadence. Chosen over the thinner `apfs` (Dil4rd) crate because it fully supports
transparent `decmpfs` decompression (zlib/LZVN/LZFSE) — see
`task_n_reports/task-21c-apfs.md` §1 for the full comparison that drove this pick.

## Modifications from upstream 0.2.0

1. **`[package]` in `Cargo.toml`**: `edition`/`rust-version`/`license`/
   `repository`/`homepage`/`authors`/`categories`/`readme` were `*.workspace =
   true`, inherited from the upstream `apfs-forensic` workspace. Replaced with
   the concrete values from that workspace's `[workspace.package]`, since this
   crate now lives in the `newtua` workspace instead.
2. **`forensicnomicon` dependency removed.** The only use site was
   `src/compression.rs`, importing `forensicnomicon::decmpfs::{classify,
   Algorithm, Storage, CHUNK_SIZE, COMPRESSION_TYPE_OFFSET, HEADER_LEN, MAGIC,
   UNCOMPRESSED_SIZE_OFFSET}` — one self-contained, dependency-free module
   (`crates/core/src/decmpfs.rs`, 267 lines, zero external `use`) from
   [`SecurityRonin/forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon)
   (also Apache-2.0). That file is copied verbatim to `src/decmpfs.rs` (private
   module) with an attribution header; `compression.rs` now imports from
   `crate::decmpfs` instead. No other file references `forensicnomicon`.
3. **`[lints]` (`workspace = true`) removed.** The upstream workspace's lint
   set is its own "paranoid" profile (`forbid` on `unwrap`/`expect`/`panic!`,
   `pedantic` warn, etc.) — pulling `[lints] workspace = true` here would
   instead apply *newtua's* workspace lints, which is not what upstream's
   `#![forbid(unsafe_code)]` code was written against. The crate compiles
   clean without any `[lints]` section (as `vendor/unrar` does).
4. **`sha2` dev-dependency**: `sha2.workspace = true` → `sha2 = "0.10"`
   (upstream's pinned version, declared directly since `newtua`'s workspace
   does not otherwise depend on `sha2`).

Everything else (`src/`, `tests/`) is unmodified from upstream 0.2.0. The
`vfs`/`forensic-vfs` feature is present but not enabled by `newtua-core` (see
`task_n_reports/task-21c-apfs.md` §11) — low-level navigation (`dir::`,
`extent::`, …) is used directly instead.

Compatibility with `newtua`'s own `LGPL-2.1-or-later` license: this crate
remains under its own Apache-2.0 as a separate workspace member (same
arrangement as `vendor/unrar`); the two licenses are compatible (Apache-2.0
work may be combined into an LGPL-2.1-or-later project).
