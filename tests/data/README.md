# newtua-apfs test data

This crate's own `tests/data/`. `src/` and `tests/` reach fixtures with a
relative `include_bytes!("tests/data/<file>")` (never a symlink — git on
Windows materialises symlinks as text). Large images are **gitignored and
downloaded/minted manually**, env-gated in tests (skip cleanly when absent).

Carried over from the upstream `apfs-forensic` repository's shared
`tests/data/`, which the vendored copy of this crate reached via a relative
`../../tests/data/` path (upstream keeps two workspace members sharing one
root-level fixture directory). This fork lives in its own repository, so the
fixtures are copied in directly and every `include_bytes!` path was adjusted
accordingly.

## Committed fixtures

#### `apfs_nxsb_head.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first 17 blocks (68 KiB, 4096-byte blocks) of a real APFS
  *container partition* — block 0 (a copy of the live container superblock),
  the checkpoint **descriptor area** (blocks 1–8: alternating
  `checkpoint_map_phys_t` + `nx_superblock_t`), and the head of the checkpoint
  **data area** (blocks 9+: spaceman, reaper, btree objects). Holds a complete,
  verifiable checkpoint ring.
- **Source:** minted on this macOS host by Apple's own `hdiutil`, so every
  on-disk structure (incl. the stored Fletcher-64 checksums) is Apple-authored.
- **Verbatim mint + carve commands:**
  ```sh
  # 1. Mint a 128 MiB GPT+APFS container image (Apple driver authors it)
  hdiutil create -size 128m -fs APFS -volname APFSORACLE -layout GPTSPUD /tmp/apfs_oracle
  # 2. Attach without mounting; the APFS container sits on a GPT partition
  hdiutil attach -nomount /tmp/apfs_oracle.dmg          # -> /dev/diskN, partition diskNs1
  # 3. Carve the first 17 blocks of the container partition (Apple_APFS slice)
  dd if=/dev/diskNs1 of=apfs_nxsb_head.bin bs=4096 count=17
  ```
  (`mmls` shows the Apple_APFS partition starts at sector 40 = byte 20480 of the
  whole `.dmg`; reading `/dev/diskNs1` addresses the partition directly so the
  carve starts at NXSB block 0.)
- **MD5:** `81505414be7754a3927091574aaea5a4`
- **Container UUID (cross-checked):** `40115033-9523-4496-96A2-0EDADEECA565`
  — echoed verbatim by `diskutil info /dev/diskN` (`Disk / Partition UUID`).
- **Independent oracles:** Apple `hdiutil`/`diskutil` (block size 4096, container
  UUID); the *documented construction* (magic `NXSB`, 4096-byte blocks); the
  stored Fletcher-64 checksum of every object recomputes to its `o_cksum`.
- **Redistribution:** entirely machine-generated empty container; no third-party
  or personal content. Safe to commit.
- **Consumed by:** `tests/object.rs` (obj_phys + Fletcher-64),
  `tests/container.rs` (NXSB geometry), `tests/checkpoint.rs`
  (checkpoint-ring walk to the live superblock).

#### `apfs_container_chain.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first **345 blocks** (1.38 MiB, 4096-byte blocks) of a real
  APFS *container partition* — a strict superset of `apfs_nxsb_head.bin` that
  also reaches the **container object map** and the **volume superblock**. The
  slice holds the complete checkpoint ring (blocks 0–8) **and** the full chain
  NXSB (live @ block 4) → container `omap_phys` (block 343, `om_tree_oid` 344) →
  omap B-tree root (block 344, a single root+leaf fixed-KV node) → volume
  superblock APSB (block 342, the resolution of virtual `nx_fs_oid` 1026). 345
  blocks is the smallest carve in which the omap→volume chain resolves (the omap
  + APSB objects live at blocks 342–344).
- **Source:** minted on this macOS host by Apple's own `hdiutil`, so every
  on-disk structure (incl. the stored Fletcher-64 checksums) is Apple-authored.
- **Verbatim mint + carve commands:**
  ```sh
  # 1. Mint a 128 MiB GPT+APFS container image (Apple driver authors it)
  hdiutil create -size 128m -fs APFS -volname APFSORACLE -layout GPTSPUD /tmp/apfs_p2
  # 2. Attach without mounting; the APFS container sits on a GPT partition
  hdiutil attach -nomount /tmp/apfs_p2.dmg        # -> /dev/diskN, partition diskNs1
  # 3. Carve the first 345 blocks of the container partition (Apple_APFS slice)
  dd if=/dev/diskNs1 of=apfs_container_chain.bin bs=4096 count=345
  ```
- **MD5:** `b25546419bbcd153317232888701a98a`
- **Independent oracles (run on THIS committed fixture):**
  - **libfsapfs `fsapfsinfo apfs_container_chain.bin`** → `Number of volumes: 1`,
    volume id `fa8b74aa-4a8b-439a-9ea9-db428f982f5d`, name `APFSORACLE`.
  - **Apple `diskutil apfs list`** (on the attached container) → one volume
    `APFSORACLE`, volume UUID `FA8B74AA-4A8B-439A-9EA9-DB428F982F5D`.
  - The resolved APSB (block 342) carries magic `APSB` (LE `0x42535041`) and its
    stored Fletcher-64 recomputes to `o_cksum`.
  Both oracles agree with the reader's single resolved volume superblock at
  paddr 342.
- **Redistribution:** entirely machine-generated empty container; no third-party
  or personal content. Safe to commit.
- **Consumed by:** `tests/omap.rs` (omap_phys header),
  `tests/btree.rs` (node header + TOC iterate),
  `tests/btree_descend.rs` (root→leaf descent + cksum/cycle guards),
  `tests/volume_resolve.rs` (virtual `nx_fs_oid` → physical APSB paddr,
  end-to-end).

#### `apfs_fstree.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first **374 blocks** (1.46 MiB, 4096-byte blocks) of a real
  APFS *container partition* carrying a **known directory tree**. The carve holds
  the complete chain: block 0 + checkpoint ring → live NXSB (block 4) → container
  `omap_phys` (372) + its B-tree root (373) → volume superblock APSB (371) →
  volume `omap_phys` (366) + its B-tree root (367) → the **file-system tree leaf
  node** (block 365, a single root+leaf variable-KV node holding all 35 fs
  records). 374 blocks is the smallest carve in which the full name→inode chain
  resolves.
- **Known tree (ground truth):**

  | path | inode | size | mode | uid/gid |
  |---|---|---|---|---|
  | `/` (root) | 2 | — | 040755 | 501/20 |
  | `/top.txt` | 22 | 15 | 100644 | 99/99 |
  | `/Dir1` | 18 | — | 040755 | 99/99 |
  | `/Dir1/Beth.txt` | 20 | 38 | 100644 | 99/99 |
  | `/Dir1/Sub` | 19 | — | 040755 | 99/99 |
  | `/Dir1/Sub/secret.bin` | 21 | 26 | 100644 | 99/99 |

- **Source:** minted on this macOS host by Apple's own `hdiutil`, so every
  on-disk structure (incl. the stored Fletcher-64 checksums) is Apple-authored.
- **Verbatim mint + populate + carve commands:**
  ```sh
  # 1. Mint a 128 MiB GPT+APFS container image
  hdiutil create -size 128m -fs APFS -volname APFSP3 -layout GPTSPUD /tmp/apfsp3
  # 2. Attach + mount, write a known tree, flush, detach
  hdiutil attach /tmp/apfsp3.dmg                     # -> /Volumes/APFSP3 (+ /dev/diskN)
  mkdir -p /Volumes/APFSP3/Dir1/Sub
  printf 'Beth was here. APFS P3 known fixture.\n' > /Volumes/APFSP3/Dir1/Beth.txt
  printf 'TOPSECRET-0123456789ABCDEF'              > /Volumes/APFSP3/Dir1/Sub/secret.bin
  printf 'top level file\n'                          > /Volumes/APFSP3/top.txt
  sync; hdiutil detach /dev/diskN
  # 3. Carve the first 374 blocks of the container partition (Apple_APFS slice
  #    begins at sector 40 of the .dmg)
  dd if=/tmp/apfsp3.dmg of=apfs_fstree.bin bs=512 skip=40 count=$((374*8))
  ```
- **MD5:** `976d6ab26b34c46f38bc44960e934be9`
- **Independent oracles (run on the SAME image):**
  - **TSK `fls -r -o 40 -B 371`** lists the tree (top.txt 22, Dir1 18, Beth.txt
    20, Sub 19, secret.bin 21); **`istat -o 40 -B 371 <inode>`** gives each
    inode's size, mode, uid/gid, child/link count, and ns-timestamps — the
    reader's `open_path` results match per file (e.g. Beth.txt: parent 18,
    size 38, mode 0644, created `1782060082608648902`, accessed `…733745215`,
    all equal to `istat`).
  - **macOS `stat -f`** on the mounted volume reported the same inode numbers +
    sizes before detach.
  - **TSK `pstat -o 40`** / Apple `diskutil apfs list`: one volume `APFSP3`,
    APSB block 371, oid 1026, xid 6.
- **Redistribution:** entirely machine-generated container with author-written
  placeholder text; no third-party or personal content. Safe to commit.
- **Consumed by:** `tests/volume.rs` (APSB parse), `tests/fsrecord.rs`
  (j_key dispatch + xf_blob), `tests/inode.rs` (`j_inode_val_t` vs istat),
  `tests/dir.rs` (DIR_REC listing + name→inode navigation vs fls/istat).

#### `apfs_content.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first **442 blocks** (1.73 MiB, 4096-byte blocks) of a real
  APFS *container partition* carrying **known content covering every P4 read
  path**. The carve holds the full chain block 0 + checkpoint ring → live NXSB
  (block 4, xid 14) → container `omap_phys` (372) + tree (373) → live volume
  superblock APSB (block 438, xid 14) → volume `omap_phys` (433) + tree (434) →
  the **file-system tree leaf** (block 432, 44 records) **and** every file's data
  extents + the compressed file's resource fork (blocks 345–426).
- **Known content (ground truth — captured by macOS before detach):**

  | path | inode | dstream | size | macOS SHA-256 | notes |
  |---|---|---|---|---|---|
  | `/plain.txt` | 18 | 18 | 35 | `289af0a0…abf86b` | single extent @ phys 347; xattrs `com.example.tag`="forensic-marker-P4", `user.note`="second custom attr" |
  | `/sparse.bin` | 22 | 22 | 69632 | `fe0fc4fa…cc822a` | **sparse**: 64 KiB hole (`phys 0`) + 4 KiB tail @65536 (phys 371) |
  | `/compressed.txt` | 23 | rfork 24 | 180000 | `3f58a418…3abc78` | **decmpfs type 8 (LZVN, resource fork)**; `com.apple.decmpfs` header embedded, `com.apple.ResourceFork` stream (dstream 24, 1526 B, 3 LZVN chunks @378) |
  | `/Dir1/Beth.txt` | 28 | 28 | 33 | `ee7c2682…cfeb96` | single extent @ phys 400 |
  | `/symlink_to_beth` | 29 | — | — | target `Dir1/Beth.txt` | symlink; `com.apple.fs.symlink` embedded xattr = `"Dir1/Beth.txt\0"` |

- **Source:** minted on this macOS host by Apple's own `hdiutil` + `ditto`, so
  every on-disk structure (incl. the decmpfs LZVN payload and Fletcher-64
  checksums) is Apple-authored.
- **Verbatim mint + populate + carve commands:**
  ```sh
  # 1. Mint a 128 MiB GPT+APFS container image
  hdiutil create -size 128m -fs APFS -volname APFSP4 -layout GPTSPUD /tmp/apfsp4
  # 2. Attach + mount
  hdiutil attach /tmp/apfsp4.dmg                       # -> /Volumes/APFSP4 (+ /dev/diskN)
  cd /Volumes/APFSP4
  # plain file
  printf 'APFS P4 plain file. Hello extents.\n' > plain.txt
  # sparse file: a single 4 KiB block at logical offset 64 KiB (a 64 KiB hole)
  dd if=/dev/urandom of=/tmp/p4blk bs=4096 count=1
  dd if=/tmp/p4blk of=sparse.bin bs=4096 count=1 seek=16
  # transparently-compressed file (macOS chooses decmpfs type 8 LZVN resource fork)
  python3 -c "open('/tmp/src.txt','w').write('The quick brown fox jumps over the lazy dog. '*4000)"
  ditto --hfsCompression /tmp/src.txt compressed.txt
  # custom xattrs
  xattr -w com.example.tag 'forensic-marker-P4' plain.txt
  xattr -w user.note 'second custom attr' plain.txt
  # symlink
  mkdir -p Dir1; printf 'Beth target content for symlink.\n' > Dir1/Beth.txt
  ln -sf Dir1/Beth.txt symlink_to_beth
  cd -; sync; hdiutil detach /dev/diskN
  # 3. Carve the first 442 blocks of the container partition (Apple_APFS slice
  #    begins at sector 40 of the .dmg)
  dd if=/tmp/apfsp4.dmg of=apfs_content.bin bs=512 skip=40 count=$((442*8))
  ```
- **MD5:** `edb98667c10e8457d9ed6a4eb97d111f`
- **Independent oracles (run on the SAME image / committed fixture):**
  - **macOS `shasum -a 256`** of each file (Apple's own driver, post-decmpfs):
    the SHA-256 column above — every one matches `apfs_core::extent::read_data`.
  - **macOS `xattr -l plain.txt`**: the two custom attrs + values.
  - **macOS `readlink symlink_to_beth`** → `Dir1/Beth.txt`.
  - The decmpfs LZVN resource fork decodes (via `forensicnomicon::decmpfs` +
    `lzvn-core`) to the same 180000-byte content macOS `cp` produces.
- **Redistribution:** entirely machine-generated container with author-written
  placeholder text + a public-domain pangram; no third-party or personal content.
  Safe to commit.
- **Consumed by:** `tests/extent.rs` (plain/sparse/nested assembly + guards),
  `tests/compression.rs` (decmpfs all types vs macOS cp SHA-256),
  `tests/xattr.rs` (xattr listing + symlink target vs `xattr -l`/`readlink`).

#### `apfs_decmpfs.bin`

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2.
- **What it is:** the first **202 blocks** (808 KiB, 4096-byte blocks) of a real
  APFS *container partition* whose four files are **all** transparently
  compressed the same way (decmpfs type 3, zlib inside the
  `com.apple.decmpfs` xattr) and differ **only in how APFS stores that xattr**:
  two embedded in the fs-tree record, two spilled into a data stream. 202 blocks
  is the smallest prefix in which all four still read (verified by bisecting the
  prefix: 201 fails, 202 passes).
- **Why it exists:** a reader that handles only the embedded form
  (`XATTR_DATA_EMBEDDED`, flags `0x2`) returns **zero bytes and no error** for
  every stream-backed one (`XATTR_DATA_STREAM`, flags `0x1`) — a silently empty
  file. `apfs_content.bin` cannot catch that: its single compressed file is
  embedded-form. Half the files on an ordinary volume are the other form.
- **Known content (ground truth — captured by macOS before detach):**

  | path | inode | xattr form | flags | xattr len | size | macOS SHA-256 |
  |---|---|---|---|---:|---:|---|
  | `/hello.txt` | 21 | embedded | `0x2` | 32 | 15 | `d8bfbcfd…ffce42` |
  | `/привет.txt` | 17 | embedded | `0x2` | 39 | 22 | `f509c862…a840ca` |
  | `/big.txt` | 16 | stream (dstream 22) | `0x1` | 226 | 65529 | `df1515a6…216bec` |
  | `/nested/deep/tiny.bin` | 20 | stream (dstream 23) | `0x1` | 273 | 256 | `1455fb51…5e0a36` |

  Every one has `inode.size == 0`: a compressed file has no data stream, so it
  carries no `INO_EXT_TYPE_DSTREAM` xfield — the logical size above is the
  decmpfs header's `uncompressed_size` (`extent::data_size`). The live volume
  superblock (APSB) sits at block **199**; block size 4096.
- **Source:** minted on this macOS host by Apple's own `hdiutil` plus `afsctool`
  (Homebrew), so both the on-disk structures and the decmpfs payloads are
  written by Apple's own APFS driver.
- **Verbatim mint + populate + compress + carve commands:**
  ```sh
  # 1. A read-write 20 MiB APFS image (compression can only be applied to files
  #    already lying on a mounted writable volume, never at image-creation time)
  hdiutil create -quiet -size 20m -fs APFS -volname corpus-decmpfs \
      -type UDIF -o /tmp/apfs-decmpfs-rw.dmg
  hdiutil attach /tmp/apfs-decmpfs-rw.dmg -nobrowse -readwrite   # -> /Volumes/corpus-decmpfs
  cd /Volumes/corpus-decmpfs
  printf 'Hello, newtua!\n'   > hello.txt                     # 15 B, embedded xattr
  printf 'Привет, newtua!\n'  > привет.txt                    # 22 B, embedded xattr
  # 65529 B of repeating text: compresses to a 226-byte xattr -> stream form
  python3 -c "open('big.txt','w').write('newtua corpus payload line\n'*2427)"
  # 256 incompressible bytes: stored raw behind decmpfs's 0xFF marker, so the
  # xattr grows to 273 bytes -> stream form, from a 256-byte file
  mkdir -p nested/deep; dd if=/dev/urandom of=nested/deep/tiny.bin bs=256 count=1
  cd -; sync
  afsctool -cf /Volumes/corpus-decmpfs        # apply decmpfs to every file
  afsctool -v  /Volumes/corpus-decmpfs/big.txt   # oracle, see below
  shasum -a 256 /Volumes/corpus-decmpfs/hello.txt … # oracle, see below
  hdiutil detach /Volumes/corpus-decmpfs
  hdiutil convert /tmp/apfs-decmpfs-rw.dmg -format UDRO -o /tmp/apfs_decmpfs.dmg -ov
  # 2. Attach read-only and carve the first 202 blocks of the Apple_APFS slice
  hdiutil attach -readonly -nobrowse /tmp/apfs_decmpfs.dmg   # -> /dev/diskNs1 Apple_APFS
  dd if=/dev/diskNs1 of=apfs_decmpfs.bin bs=4096 count=202
  hdiutil detach /Volumes/corpus-decmpfs
  ```
  The source DMG is kept in the private corpus repository as
  `corpus/archives/apfs/apfs_decmpfs.dmg` (minted by
  `corpus/scripts/make-apfs-decmpfs.sh`, the script the commands above inline).
- **MD5:** `ad5258e00879390ae7de759aceecd53d`
- **Independent oracles (run on the SAME image):**
  - **macOS `shasum -a 256`** of each mounted file (Apple's own driver, post-
    decmpfs): the SHA-256 column above — every one matches
    `apfs_core::extent::read_data` on the committed carve.
  - **macOS `ls -l`** on the mounted volume: 15 / 22 / 65529 / 256 bytes — the
    sizes `apfs_core::extent::data_size` reports, and the ones the inode does
    *not* carry.
  - **`afsctool -v`** on each file: "File is HFS+/APFS compressed",
    "Compression type: ZLIB in decmpfs xattr (3)", and "Uncompressed file size
    reported in compressed header: 65529 / 256 bytes" — a second, independent
    reading of the same decmpfs headers.
- **Redistribution:** entirely machine-generated container with author-written
  placeholder text and random bytes; no third-party or personal content. Safe to
  commit (808 KiB raw, ~6 KiB inside the gzipped `.crate`).
- **Consumed by:** `tests/decmpfs_forms.rs` (both xattr storage forms, content
  vs the macOS SHA-256 oracle, `data_size` vs `inode.size`).

## Synthetic fixtures (other mint commands)

Recorded here verbatim when added. Planned set (see `docs/validation.md`):

```sh
# Plain APFS container (GPT + APFS volume)
hdiutil create -size 64m -fs APFS -volname APFSTEST -layout GPTSPUD apfstest.dmg

# decmpfs-compressed files (macoS is the decode oracle)
#   attach apfstest.dmg, then:
ditto --hfsCompression /path/to/src /Volumes/APFSTEST/compressed

# Clones (shared extents)
cp -c bigfile /Volumes/APFSTEST/bigfile.clone

# Snapshots (see the P5 fixture section above — `tmutil localsnapshot` only
# snapshots the TM-eligible system data volume, NOT a DMG; arbitrary-volume
# snapshot creation needs the com.apple.developer.vfs.snapshot entitlement,
# so mint on a SIP-relaxed host with fs_snapshot_create / a TM-registered volume)

# Encrypted volume
hdiutil create -size 64m -encryption -stdinpass -fs APFS -volname APFSENC apfsenc.dmg
```

## P5 snapshot fixture (gitignored, env-gated)

#### `apfs_p5_snapshots.bin` (env `APFS_P5_FIXTURE`)

- **Class:** SYNTHETIC (self-minted real APFS), Tier 2. **Not committed** — minted
  inside a throwaway macOS VM, then pointed at by `APFS_P5_FIXTURE`. **VALIDATED**
  (2026-06-25): the populated test passed byte-identical to the macOS oracle.
- **What it is:** a whole **GPT disk image** (a Tart VM `disk.img`) whose main
  APFS container holds the System + Data volumes. The Data volume carries **two
  snapshots** and a file `/Users/admin/changing.txt` whose content **differs
  between a snapshot and live** (`VERSION ONE` @snapshot → `VERSION TWO` @live),
  plus an unchanged `static.txt`. Drives
  `tests/snapshot.rs::populated_fixture_point_in_time_read`: enumerates the
  snapshots, round-trips every snap-name→xid, and reads `changing.txt` at the
  earliest snapshot (**v1**) via `mount_snapshot` vs the live volume (**v2**) —
  each byte-identical (SHA-256) to what macOS wrote.
- **Why a VM (not a DMG).** On a stock SIP-enabled host, APFS snapshot *creation*
  on a DMG needs the `com.apple.developer.vfs.snapshot` entitlement
  (`fs_snapshot_create(2)` → `EPERM` even as root; `diskutil apfs` has no
  `addSnapshot`; `tmutil localsnapshot` only snapshots the FileVault-encrypted
  system data volume, which the reader can't parse). A fresh macOS VM is
  unencrypted (FileVault off) and `tmutil localsnapshot` works in-guest with no
  entitlement — so it mints a reader-parsable snapshot fixture for free.
- **Recorded values** (this fixture; gitignored, re-mint to refresh):
  - `APFS_P5_PART_OFFSET=524308480` — byte offset of the **main** APFS container
    in `disk.img` (part0 @`0x5000` is the small `iBootSystemContainer`; pick the
    large standard-APFS-GUID partition).
  - `APFS_P5_FILE=/Users/admin/changing.txt`
  - `APFS_P5_V1_SHA256=da27342b7ff10001475dd9b6b863998923e6e2318d2b73226e172d0da6c6fc55`
  - `APFS_P5_V2_SHA256=cfd0476c457d81b8724ec773c3dfeaf6cf55d8c9a74ccceb043411cc0c1c9263`
  - snapshot XIDs: 6094 (v1) / 6096 (v2). The live APSB block is **derived** by
    the test from the container omap (no `APFS_P5_LIVE_APSB` needed).
- **Mint recipe (Tart VM):**
  ```sh
  tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest p5mint   # raw disk, CoW
  tart run --vnc-experimental --dir=p5share:~/p5share p5mint &    # loopback console + host share
  # In the VM Terminal (admin/admin), run the mint script (writes the oracle to the share):
  #   printf 'VERSION ONE\n' > ~/changing.txt; sync; tmutil localsnapshot
  #   printf 'VERSION TWO\n' > ~/changing.txt; sync; tmutil localsnapshot
  #   diskutil apfs listSnapshots <dataDev>   # oracle: snapshot names + xids
  tart stop p5mint
  # disk.img is now the fixture: ~/.tart/vms/p5mint/disk.img
  ```
  (`~/p5share/mint.sh` automates the in-VM steps. Host→VM SSH is gated by macOS
  Local Network Privacy; the loopback VNC + `--dir` share avoids needing it.)
- **Performance.** With keyed `omap.resolve` (point descent), this test runs in
  **~5 s** on the real ~50 GB volume — down from ~83 min before the keyed descent
  (see `docs/validation.md` P5).
- **Consumed by:** `tests/snapshot.rs` (env-gated populated test).

> The committed P5 validations (empty snap-meta tree, `mount_snapshot` seam, walk
> control flow) reuse `apfs_content.bin` (above) and in-test synthetic vectors;
> no new committed fixture was added for P5.

## Real datasets (gitignored, env-gated)

Documented with Source / Identity / download URL / MD5 / contents /
redistribution when added (e.g. a real macOS Signed System Volume image for
Tier-1 sealed-volume validation). Consumed via an env var pointing at the path,
like the issen iOS corpus pattern.
