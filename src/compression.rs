//! Transparent decmpfs decompression (REUSE — not reinvented).
//!
//! APFS reuses HFS+'s `com.apple.decmpfs` scheme verbatim: a 16-byte header
//! (`MAGIC 0x636d_7066` "cmpf", a compression-type byte, uncompressed size),
//! `CHUNK_SIZE 65536`, payload either embedded in the xattr (odd types) or in the
//! `com.apple.ResourceFork` stream (even types). The fleet already solved and
//! validated this against real macOS in `hfsplus-forensic`; this module is the
//! thin APFS-side glue over the same codec stack:
//!
//! - **type→algorithm/storage map**: [`crate::decmpfs::classify`] — used here,
//!   never re-defined (vendored from `forensicnomicon` — see
//!   `crates/apfs-core/VENDORED.md`).
//! - **zlib/DEFLATE (types 3/4)**: `flate2`.
//! - **LZVN (types 7/8)**: our length-tolerant `lzvn` crate (`lzvn-core`) — real
//!   decmpfs LZVN blocks carry trailing bytes after the end-of-stream opcode that
//!   `lzfse_rust`'s strict path rejects (validated 25/25 on macOS Tahoe by
//!   hfsplus-forensic; the bug that motivated the length-tolerant decoder).
//! - **LZFSE (types 11/12)**: `lzfse_rust`.
//!
//! All pure-Rust, preserving `unsafe_code = "forbid"`. The only APFS-specific
//! part is locating the decmpfs payload (xattr vs resource-fork stream). Any
//! decode failure is a **named refusal** ([`crate::ApfsError::Decmpfs`]) — never
//! fabricated plaintext (fail-loud: fabricating file content is the worst bug in
//! a forensic tool).

use std::io::{Read, Seek};

use crate::decmpfs::{
    self, Algorithm, CHUNK_SIZE, COMPRESSION_TYPE_OFFSET, HEADER_LEN, MAGIC, Storage,
    UNCOMPRESSED_SIZE_OFFSET,
};

use crate::ApfsError;
use crate::inode::Inode;
use crate::volume::ApfsVolume;

/// Read a transparently-compressed file's content: decode the decmpfs payload
/// (inline in the `header` xattr, or in the `com.apple.ResourceFork` stream)
/// rather than the raw extent bytes.
///
/// # Errors
/// [`ApfsError::Decmpfs`] on any malformed header, unknown/unsupported
/// compression type, missing resource fork, codec failure, or output-length
/// mismatch (the decode never returns a partial buffer as success); the
/// structural errors of [`crate::xattr::resource_fork`] when fetching the fork.
pub fn read_compressed<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    inode: &Inode,
    header: &[u8],
    block_size: usize,
) -> crate::Result<Vec<u8>> {
    // Resolve the compression type to decide whether a resource fork is needed
    // before paying to read it.
    let compression_type = le_u32(header, COMPRESSION_TYPE_OFFSET)?;
    let needs_fork =
        decmpfs::classify(compression_type).is_some_and(|c| c.storage == Storage::ResourceFork);

    let fork = if needs_fork {
        crate::xattr::resource_fork(reader, volume, inode.oid, block_size)?
    } else {
        None
    };

    decompress_decmpfs(header, fork.as_deref())
}

/// Decode a decmpfs payload given its 16-byte header and the file's resource fork
/// (required only for even/resource-fork compression types; `None` for inline).
///
/// Mirrors the validated `hfsplus-forensic` decoder. Returns the original file
/// bytes, or a named [`ApfsError::Decmpfs`] — never a partially-decoded buffer.
///
/// # Errors
/// [`ApfsError::Decmpfs`] on a truncated/bad-magic header, an unknown or
/// unsupported `compression_type`, a missing resource fork, a codec rejection, or
/// a decoded length that disagrees with the header's `uncompressed_size`.
pub fn decompress_decmpfs(header: &[u8], resource_fork: Option<&[u8]>) -> crate::Result<Vec<u8>> {
    if header.len() < HEADER_LEN {
        return Err(ApfsError::Decmpfs(
            "decmpfs xattr shorter than 16-byte header",
        ));
    }
    let magic = le_u32(header, 0)?;
    if magic != MAGIC {
        return Err(ApfsError::Decmpfs("decmpfs bad magic (expected 'cmpf')"));
    }
    let compression_type = le_u32(header, COMPRESSION_TYPE_OFFSET)?;
    let uncompressed_size = le_u64(header, UNCOMPRESSED_SIZE_OFFSET)? as usize;

    let Some(kind) = decmpfs::classify(compression_type) else {
        return Err(match compression_type {
            5 => ApfsError::Decmpfs("decmpfs type 5 (de-dup generation store, no payload)"),
            _ => ApfsError::Decmpfs("decmpfs unknown compression_type"),
        });
    };
    if kind.algorithm == Algorithm::LzBitmap {
        return Err(ApfsError::Decmpfs("decmpfs LZBitmap (no public spec)"));
    }

    let out = match kind.storage {
        Storage::Inline => {
            let payload = header
                .get(HEADER_LEN..)
                .ok_or(ApfsError::Decmpfs("decmpfs inline payload truncated"))?;
            decode_inline(kind.algorithm, payload, uncompressed_size, compression_type)?
        }
        Storage::ResourceFork => {
            let fork = resource_fork.ok_or(ApfsError::Decmpfs(
                "decmpfs resource-fork type but no fork present",
            ))?;
            decode_resource_fork(kind.algorithm, fork, uncompressed_size)?
        }
    };

    if out.len() != uncompressed_size {
        return Err(ApfsError::Decmpfs(
            "decmpfs decoded length != uncompressed_size",
        ));
    }
    Ok(out)
}

/// Decode an inline (odd-type) payload that follows the 16-byte header.
///
/// `compression_type` is threaded in for the two inline-uncompressed types that
/// share [`Algorithm::Uncompressed`] but differ in framing: type 1 stores its
/// bytes verbatim, type 9 is marker-prefixed (one leading byte). That is a
/// documented decmpfs discontinuity (confirmed on real macOS 26.5 type-9 files in
/// hfsplus-forensic), not a special case.
fn decode_inline(
    algorithm: Algorithm,
    payload: &[u8],
    uncompressed_size: usize,
    compression_type: u32,
) -> crate::Result<Vec<u8>> {
    match algorithm {
        Algorithm::Uncompressed => match compression_type {
            9 => Ok(payload.get(1..).unwrap_or(&[]).to_vec()),
            _ => Ok(payload.to_vec()),
        },
        Algorithm::Zlib => match payload.first() {
            // A leading 0xFF means the remainder is stored verbatim.
            Some(0xFF) => Ok(payload.get(1..).unwrap_or(&[]).to_vec()),
            _ => inflate(payload),
        },
        Algorithm::Lzvn => match payload.first() {
            // A leading 0x06 (the LZVN end-of-stream opcode) marks raw-stored data.
            Some(0x06) => Ok(payload.get(1..).unwrap_or(&[]).to_vec()),
            _ => lzvn_decode(payload, uncompressed_size),
        },
        Algorithm::Lzfse => lzfse_decode(payload),
        _ => unreachable_algorithm(), // cov:unreachable: LzBitmap rejected before dispatch
    }
}

/// Decode an even-type payload stored across the resource fork.
fn decode_resource_fork(
    algorithm: Algorithm,
    fork: &[u8],
    uncompressed_size: usize,
) -> crate::Result<Vec<u8>> {
    match algorithm {
        Algorithm::Zlib => decode_zlib_resource_fork(fork, uncompressed_size),
        Algorithm::Lzvn | Algorithm::Lzfse | Algorithm::Uncompressed => {
            decode_chunked_resource_fork(algorithm, fork, uncompressed_size)
        }
        _ => unreachable_algorithm(), // cov:unreachable: LzBitmap rejected before dispatch
    }
}

/// The decmpfs algorithm dispatch arms below are total against the
/// `#[non_exhaustive]` [`Algorithm`] enum, but `LzBitmap` is rejected before any
/// dispatch and every other variant is routed, so this arm is unreachable on real
/// and crafted input alike — kept as defense-in-depth against a future variant.
#[inline]
fn unreachable_algorithm() -> crate::Result<Vec<u8>> {
    Err(ApfsError::Decmpfs("decmpfs unsupported algorithm")) // cov:unreachable: LzBitmap rejected pre-dispatch, all other variants routed
}

/// Zlib resource fork (type 4): classic Resource-Manager header + block table.
fn decode_zlib_resource_fork(fork: &[u8], uncompressed_size: usize) -> crate::Result<Vec<u8>> {
    // HFSPlusCmpfRsrcHead: big-endian headerSize, totalSize, dataSize, flags.
    let header_size = be_u32(fork, 0)? as usize;
    // At `header_size`: a big-endian total-size prefix (4 bytes), then the block
    // table — little-endian numBlocks, then numBlocks × (offset, size). Block
    // offsets are relative to `header_size + 4` (the numBlocks field).
    let table = header_size.checked_add(4).ok_or(ApfsError::Decmpfs(
        "decmpfs zlib fork table offset overflow",
    ))?;
    let num_blocks = le_u32(fork, table)? as usize;
    let mut out = Vec::with_capacity(uncompressed_size.min(MAX_DECMPFS_CAP));
    for i in 0..num_blocks {
        let entry = table
            .checked_add(4)
            .and_then(|b| b.checked_add(i.checked_mul(8)?))
            .ok_or(ApfsError::Decmpfs(
                "decmpfs zlib fork entry offset overflow",
            ))?;
        let offset = le_u32(fork, entry)? as usize;
        let size = le_u32(fork, entry + 4)? as usize;
        let start = table
            .checked_add(offset)
            .ok_or(ApfsError::Decmpfs("decmpfs zlib fork block start overflow"))?;
        let end = start
            .checked_add(size)
            .ok_or(ApfsError::Decmpfs("decmpfs zlib fork block end overflow"))?;
        let block = fork
            .get(start..end)
            .ok_or(ApfsError::Decmpfs("decmpfs zlib fork block out of bounds"))?;
        out.extend_from_slice(&inflate(block)?);
    }
    Ok(out)
}

/// LZVN/LZFSE/uncompressed resource fork (types 8/12/10):
/// `HFSPlusCmpfLZVNRsrcHead` — little-endian headerSize then chunk end-offsets.
fn decode_chunked_resource_fork(
    algorithm: Algorithm,
    fork: &[u8],
    uncompressed_size: usize,
) -> crate::Result<Vec<u8>> {
    let header_size = le_u32(fork, 0)? as usize;
    // The header holds headerSize/4 − 1 chunk end-offsets (the first u32 is the
    // headerSize itself); chunk data begins at `header_size`. The slot count is
    // an upper bound — the compressor may zero-pad unused slots, so the loop stops
    // once it has produced `uncompressed_size` bytes (true count = ceil(size /
    // CHUNK_SIZE)).
    let n_slots = (header_size / 4)
        .checked_sub(1)
        .ok_or(ApfsError::Decmpfs("decmpfs chunked fork header too small"))?;
    let mut out = Vec::with_capacity(uncompressed_size.min(MAX_DECMPFS_CAP));
    let mut src = header_size;
    for i in 0..n_slots {
        if out.len() >= uncompressed_size {
            break;
        }
        let end = le_u32(fork, 4 + i * 4)? as usize;
        if end < src {
            return Err(ApfsError::Decmpfs(
                "decmpfs chunked fork end-offset goes backward",
            ));
        }
        let chunk = fork.get(src..end).ok_or(ApfsError::Decmpfs(
            "decmpfs chunked fork chunk out of bounds",
        ))?;
        let chunk_uncompressed = uncompressed_size
            .checked_sub(out.len())
            .ok_or(ApfsError::Decmpfs("decmpfs chunked fork size underflow"))? // cov:unreachable: loop breaks when out.len() >= uncompressed_size
            .min(CHUNK_SIZE);
        let decoded = match algorithm {
            Algorithm::Lzvn => lzvn_decode(chunk, chunk_uncompressed)?,
            Algorithm::Lzfse => lzfse_decode(chunk)?,
            Algorithm::Uncompressed => chunk.to_vec(),
            // Zlib forks take the classic-header path; LzBitmap is rejected before
            // dispatch. Either here is a routing bug, not bad input.
            _ => return unreachable_algorithm(), // cov:unreachable: only Lzvn/Lzfse/Uncompressed routed here
        };
        out.extend_from_slice(&decoded);
        src = end;
    }
    Ok(out)
}

/// Allocation cap for a decmpfs `Vec::with_capacity` hint — never trust the
/// header's `uncompressed_size` to pre-allocate unbounded memory.
const MAX_DECMPFS_CAP: usize = 1 << 30; // 1 GiB

/// Inflate a zlib stream (DEFLATE with a zlib wrapper).
fn inflate(data: &[u8]) -> crate::Result<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|_| ApfsError::Decmpfs("decmpfs zlib codec error"))?;
    Ok(out)
}

/// Decode a raw LZVN chunk with the length-tolerant `lzvn` codec (stops at the
/// end-of-stream opcode, ignoring decmpfs trailing bytes).
fn lzvn_decode(chunk: &[u8], uncompressed_len: usize) -> crate::Result<Vec<u8>> {
    lzvn::decode(chunk, uncompressed_len)
        .map_err(|_| ApfsError::Decmpfs("decmpfs lzvn codec error"))
}

/// Decode a complete LZFSE stream.
fn lzfse_decode(stream: &[u8]) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    lzfse_rust::decode_bytes(stream, &mut out)
        .map_err(|_| ApfsError::Decmpfs("decmpfs lzfse codec error"))?;
    Ok(out)
}

// ── bounds-checked little/big-endian readers (panic-free) ──

fn le_u32(data: &[u8], offset: usize) -> crate::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(ApfsError::Decmpfs("decmpfs read offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or(ApfsError::Decmpfs("decmpfs read out of bounds"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn be_u32(data: &[u8], offset: usize) -> crate::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(ApfsError::Decmpfs("decmpfs read offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or(ApfsError::Decmpfs("decmpfs read out of bounds"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], offset: usize) -> crate::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or(ApfsError::Decmpfs("decmpfs read offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or(ApfsError::Decmpfs("decmpfs read out of bounds"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(a))
}
