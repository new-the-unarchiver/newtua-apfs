//! decmpfs transparent-compression decode, validated against the REAL macOS
//! `cp` SHA-256 oracle on the minted `apfs_content.bin` fixture, plus
//! synthetic/round-trip coverage for the inline + zlib/lzfse code paths that the
//! macOS `ditto --hfsCompression` heuristic did not produce on this corpus.
//!
//! Ground truth: `/compressed.txt` (inode 23) is a `decmpfs` **type-8 LZVN
//! resource-fork** file, `uncompressed_size` 180000, whose macOS-read content has
//! SHA-256 `3f58a418…`. The resource fork (dstream oid 24, 1526 B) holds three
//! LZVN chunks (end-offsets 560/1104/1526). This is the macOS default and the
//! exact case hfsplus-forensic validated 25/25 on real data.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use apfs_core::compression::decompress_decmpfs;
use apfs_core::dir::open_path;
use apfs_core::extent::read_data;
use apfs_core::volume::ApfsVolume;
use sha2::{Digest, Sha256};

const CONTENT: &[u8] = include_bytes!("../../tests/data/apfs_content.bin");
const BLOCK_SIZE: usize = 4096;
const APSB_BLOCK: usize = 438;

fn volume() -> ApfsVolume {
    let block = &CONTENT[APSB_BLOCK * BLOCK_SIZE..(APSB_BLOCK + 1) * BLOCK_SIZE];
    ApfsVolume::parse(block).expect("parse live APSB")
}

fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The decmpfs 16-byte header for a given type + uncompressed size.
fn header(compression_type: u32, uncompressed_size: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.extend_from_slice(&0x636d_7066u32.to_le_bytes()); // 'cmpf'
    h.extend_from_slice(&compression_type.to_le_bytes());
    h.extend_from_slice(&uncompressed_size.to_le_bytes());
    h
}

fn xattr(compression_type: u32, uncompressed_size: u64, payload: &[u8]) -> Vec<u8> {
    let mut x = header(compression_type, uncompressed_size);
    x.extend_from_slice(payload);
    x
}

// ── REAL macOS data: end-to-end through the reader ──

#[test]
fn reads_compressed_file_byte_identical() {
    // read_data transparently decodes the type-8 LZVN resource fork and returns
    // the original 180000-byte content, byte-identical to macOS cp.
    let mut r = Cursor::new(CONTENT);
    let vol = volume();
    let inode = open_path(&mut r, &vol, "/compressed.txt", BLOCK_SIZE).expect("open compressed");
    let bytes = read_data(&mut r, &vol, &inode, BLOCK_SIZE).expect("decode compressed");
    assert_eq!(bytes.len(), 180_000, "uncompressed size");
    assert_eq!(
        sha256_hex(&bytes),
        "3f58a41850c1096de883ada14c98c2375a85b473c80ccbef03c9e72c113abc78",
        "compressed.txt decoded content SHA-256 must match macOS cp"
    );
    // Spot-check the actual content (it is repeated "quick brown fox" text).
    assert!(bytes.starts_with(b"The quick brown fox jumps over the lazy dog. "));
}

// ── inline paths (synthetic / round-trip — ditto chose resource-fork on this
//    corpus, so the inline branches are exercised here) ──

#[test]
fn decodes_inline_uncompressed_type1() {
    let data = b"the quick brown fox jumps over the lazy dog";
    let x = xattr(1, data.len() as u64, data);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 1"), data);
}

#[test]
fn decodes_inline_uncompressed_type9_marker() {
    // Type 9: one storage-marker byte precedes the verbatim content.
    let content = b"type 9 is uncompressed-inline, a variant of type 1";
    let mut payload = vec![0xCCu8];
    payload.extend_from_slice(content);
    let x = xattr(9, content.len() as u64, &payload);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 9"), content);
}

#[test]
fn decodes_inline_zlib_type3() {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let data = b"compress this with zlib inline, type 3, the quick brown fox";
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    let payload = enc.finish().unwrap();
    let x = xattr(3, data.len() as u64, &payload);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 3"), data);
}

#[test]
fn decodes_inline_zlib_type3_stored_marker() {
    // A leading 0xFF means the remainder is stored verbatim.
    let data = b"stored verbatim after the 0xFF marker";
    let mut payload = vec![0xFFu8];
    payload.extend_from_slice(data);
    let x = xattr(3, data.len() as u64, &payload);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 3 stored"), data);
}

#[test]
fn decodes_inline_lzvn_type7() {
    // Wrap a REAL LZVN chunk (the first 65536-byte chunk of the fixture's type-8
    // resource fork, bytes [16, 560)) as an inline type-7 xattr and decode it
    // through the inline LZVN path. The chunk decodes to exactly one CHUNK_SIZE.
    let chunk = &CONTENT[378 * BLOCK_SIZE + 16..378 * BLOCK_SIZE + 560];
    let x = xattr(7, 65536, chunk);
    let out = decompress_decmpfs(&x, None).expect("type 7 inline LZVN");
    assert_eq!(out.len(), 65536);
    // It is the start of the repeated "quick brown fox" text.
    assert!(out.starts_with(b"The quick brown fox jumps over the lazy dog. "));
}

#[test]
fn decodes_inline_lzvn_type7_stored_marker() {
    // A leading 0x06 (LZVN end-of-stream opcode) marks raw-stored data.
    let data = b"raw stored after 0x06 marker";
    let mut payload = vec![0x06u8];
    payload.extend_from_slice(data);
    let x = xattr(7, data.len() as u64, &payload);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 7 stored"), data);
}

#[test]
fn decodes_inline_lzfse_type11() {
    let data = b"lzfse inline type 11 payload, the quick brown fox jumps high";
    let mut encoded = Vec::new();
    lzfse_rust::encode_bytes(data, &mut encoded).unwrap();
    let x = xattr(11, data.len() as u64, &encoded);
    assert_eq!(decompress_decmpfs(&x, None).expect("type 11"), data);
}

// ── resource-fork paths (type-8 from real fork bytes; uncompressed type 10) ──

#[test]
fn decodes_real_type8_lzvn_resource_fork_direct() {
    // The real resource fork carved from the fixture (dstream 24, block 378).
    let fork = &CONTENT[378 * BLOCK_SIZE..378 * BLOCK_SIZE + 1526];
    let hdr = header(8, 180_000);
    let out = decompress_decmpfs(&hdr, Some(fork)).expect("real LZVN fork");
    assert_eq!(out.len(), 180_000);
    assert_eq!(
        sha256_hex(&out),
        "3f58a41850c1096de883ada14c98c2375a85b473c80ccbef03c9e72c113abc78"
    );
}

/// Build an even-type chunked resource fork (`HFSPlusCmpfLZVNRsrcHead`):
/// little-endian headerSize then one end-offset per chunk.
fn chunked_fork(chunks: &[Vec<u8>]) -> Vec<u8> {
    let header_size = 4 * (chunks.len() + 1);
    let mut fork = Vec::new();
    fork.extend_from_slice(&(header_size as u32).to_le_bytes());
    let mut end = header_size;
    for c in chunks {
        end += c.len();
        fork.extend_from_slice(&(end as u32).to_le_bytes());
    }
    for c in chunks {
        fork.extend_from_slice(c);
    }
    fork
}

#[test]
fn decodes_uncompressed_resource_fork_type10() {
    let mut data = Vec::new();
    for i in 0..(65536 + 5000) {
        data.push((i % 251) as u8);
    }
    let c0 = data[..65536].to_vec();
    let c1 = data[65536..].to_vec();
    let fork = chunked_fork(&[c0, c1]);
    let hdr = header(10, data.len() as u64);
    assert_eq!(
        decompress_decmpfs(&hdr, Some(&fork)).expect("type 10"),
        data
    );
}

#[test]
fn decodes_lzfse_resource_fork_type12() {
    // One LZFSE-compressed chunk (< CHUNK_SIZE) in a chunked resource fork.
    let data: Vec<u8> = (0..50_000).map(|i| (i % 64) as u8).collect();
    let mut chunk = Vec::new();
    lzfse_rust::encode_bytes(&data, &mut chunk).unwrap();
    let fork = chunked_fork(&[chunk]);
    let hdr = header(12, data.len() as u64);
    assert_eq!(
        decompress_decmpfs(&hdr, Some(&fork)).expect("type 12"),
        data
    );
}

#[test]
fn chunked_fork_stops_at_uncompressed_size_with_padding_slots() {
    // A fork whose end-offset table over-allocates (an extra zero-padding slot
    // beyond the real chunks) must stop once `uncompressed_size` bytes are
    // produced, never reading the padding slot.
    let data: Vec<u8> = (0..30_000).map(|i| (i % 97) as u8).collect();
    let mut chunk = Vec::new();
    lzfse_rust::encode_bytes(&data, &mut chunk).unwrap();
    // header_size for 2 slots (one real chunk + one padding), then end-offsets.
    let header_size = 4 * 3; // 1 headerSize word + 2 slots
    let mut fork = (header_size as u32).to_le_bytes().to_vec();
    let end = header_size + chunk.len();
    fork.extend_from_slice(&(end as u32).to_le_bytes()); // real chunk end
    fork.extend_from_slice(&0u32.to_le_bytes()); // padding slot (never read)
    fork.extend_from_slice(&chunk);
    let hdr = header(12, data.len() as u64);
    assert_eq!(decompress_decmpfs(&hdr, Some(&fork)).expect("padded"), data);
}

#[test]
fn rejects_chunked_fork_backward_offset() {
    // An end-offset that goes backward (< the running source position) is a
    // malformed fork — refuse, never over-read.
    let header_size = 4 * 2; // 1 headerSize + 1 slot
    let mut fork = (header_size as u32).to_le_bytes().to_vec();
    fork.extend_from_slice(&0u32.to_le_bytes()); // end-offset 0 < src (8)
    let hdr = header(8, 100);
    assert!(matches!(
        decompress_decmpfs(&hdr, Some(&fork)),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn decodes_zlib_resource_fork_type4() {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    // Build a classic Resource-Manager fork: headerSize(BE)=256, then at 256 a
    // BE total-size, then LE numBlocks + (offset,size) table, then the blocks.
    let block_data = b"zlib resource fork type 4 content block zero";
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(block_data).unwrap();
    let comp = enc.finish().unwrap();
    let header_size = 256usize;
    let mut fork = vec![0u8; header_size];
    fork[0..4].copy_from_slice(&(header_size as u32).to_be_bytes()); // BE headerSize
    fork.extend_from_slice(&0u32.to_be_bytes()); // BE total-size prefix @256
    fork.extend_from_slice(&1u32.to_le_bytes()); // numBlocks = 1
                                                 // offsets are relative to header_size+4 (start of numBlocks). Block 0 starts
                                                 // right after the table: numBlocks(4) + one (offset,size) entry(8) = 12.
    fork.extend_from_slice(&12u32.to_le_bytes()); // offset
    fork.extend_from_slice(&(comp.len() as u32).to_le_bytes()); // size
    fork.extend_from_slice(&comp);
    let hdr = header(4, block_data.len() as u64);
    assert_eq!(
        decompress_decmpfs(&hdr, Some(&fork)).expect("type 4"),
        block_data
    );
}

// ── fail-loud refusals (never fabricate) ──

#[test]
fn rejects_bad_magic() {
    let mut x = xattr(1, 0, &[]);
    x[0] ^= 0xFF;
    assert!(matches!(
        decompress_decmpfs(&x, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_truncated_header() {
    assert!(matches!(
        decompress_decmpfs(&[0u8; 8], None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_unknown_type() {
    let x = xattr(99, 0, &[]);
    assert!(matches!(
        decompress_decmpfs(&x, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_dedup_type5() {
    let x = xattr(5, 0, &[]);
    assert!(matches!(
        decompress_decmpfs(&x, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_lzbitmap_type13() {
    let x = xattr(13, 0, &[]);
    assert!(matches!(
        decompress_decmpfs(&x, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_resource_fork_type_without_fork() {
    let hdr = header(8, 100);
    assert!(matches!(
        decompress_decmpfs(&hdr, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}

#[test]
fn rejects_length_mismatch() {
    // claim 999, payload is 19 verbatim bytes -> loud refusal, not a short buffer.
    let data = b"the quick brown fox";
    let x = xattr(1, 999, data);
    assert!(matches!(
        decompress_decmpfs(&x, None),
        Err(apfs_core::ApfsError::Decmpfs(_))
    ));
}
