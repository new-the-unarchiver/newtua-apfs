//! Bounds-checked little-endian integer reads over untrusted buffers.
//!
//! APFS on-disk structures are little-endian. Length, offset, and count fields
//! in a disk image are attacker-controllable, so every multi-byte read goes
//! through these helpers: an out-of-range offset yields `0` instead of
//! panicking. This keeps the parsers panic-free without sprinkling
//! `try_into().unwrap()` (which the paranoid lint set forbids) across every
//! field decode. Mirrors `ntfs-core`'s `bytes.rs`; helpers are added as each
//! phase needs them.

/// Read a little-endian `u16` at `offset`; `0` if it would run past `data`.
pub(crate) fn le_u16(data: &[u8], offset: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(offset..offset + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Read a little-endian `u32` at `offset`; `0` if it would run past `data`.
pub(crate) fn le_u32(data: &[u8], offset: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(offset..offset + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a little-endian `u64` at `offset`; `0` if it would run past `data`.
pub(crate) fn le_u64(data: &[u8], offset: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(offset..offset + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Copy the `N`-byte array at `offset`; zero-filled where it runs past `data`.
pub(crate) fn arr<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    let mut b = [0u8; N];
    if let Some(s) = data.get(offset..offset + N) {
        b.copy_from_slice(s);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_reads_in_bounds() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(le_u32(&d, 0), 0x0403_0201);
        assert_eq!(le_u64(&d, 0), 0x0807_0605_0403_0201);
        assert_eq!(arr::<4>(&d, 2), [0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn out_of_range_yields_zero() {
        let d = [0xAAu8; 3];
        assert_eq!(le_u32(&d, 0), 0);
        assert_eq!(le_u64(&d, 0), 0);
        assert_eq!(arr::<8>(&d, 0), [0u8; 8]);
    }

    #[test]
    fn offset_past_end_yields_zero() {
        let d = [0x11u8, 0x22];
        assert_eq!(le_u32(&d, 100), 0);
        assert_eq!(arr::<2>(&d, 100), [0u8; 2]);
    }
}
