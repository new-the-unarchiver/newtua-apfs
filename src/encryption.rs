//! Encryption: keybag parsing and crypto-state records — **state surfacing
//! only** (no key cracking, no hand-rolled crypto).
//!
//! An encrypted container/volume stores wrapped keys in keybags. The container
//! keybag (referenced from `nx_keylocker`) holds, per volume,
//! `KB_TAG_VOLUME_KEY 0x02` (a wrapped volume encryption key / KEK packed
//! object) and `KB_TAG_VOLUME_UNLOCK_RECORDS 0x03` (the volume keybag extent);
//! the volume keybag holds `KB_TAG_WRAPPING_KEY 0x01` and
//! `KB_TAG_VOLUME_PASSPHRASE_HINT 0x04`. Keybag tag values (libfsapfs):
//! `KB_TAG_UNKNOWN 0x00`, `KB_TAG_WRAPPING_KEY 0x01`, `KB_TAG_VOLUME_KEY 0x02`,
//! `KB_TAG_VOLUME_UNLOCK_RECORDS 0x03`, `KB_TAG_VOLUME_PASSPHRASE_HINT 0x04`,
//! `KB_TAG_USER_PAYLOAD 0xf8`.
//!
//! Per-file crypto state is `APFS_TYPE_CRYPTO_STATE 7` (`j_crypto_val_t` with a
//! `wrapped_meta_crypto_state_t`). This module **reports** what is present —
//! locked/unlocked, which tags, hint presence — and, only when a key/passphrase
//! is *supplied*, unwraps via a vetted crate (`RustCrypto` AES/HMAC/PBKDF2,
//! AES-XTS). With no key it **refuses** to return plaintext; it never fabricates.

/// Keybag tag values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeybagTag {
    Unknown = 0x00,
    WrappingKey = 0x01,
    VolumeKey = 0x02,
    VolumeUnlockRecords = 0x03,
    VolumePassphraseHint = 0x04,
    UserPayload = 0xf8,
}

impl KeybagTag {
    /// Map a raw `ke_tag` value to a known tag, or [`KeybagTag::Unknown`].
    #[must_use]
    pub fn from_u16(tag: u16) -> Self {
        match tag {
            0x01 => Self::WrappingKey,
            0x02 => Self::VolumeKey,
            0x03 => Self::VolumeUnlockRecords,
            0x04 => Self::VolumePassphraseHint,
            0xf8 => Self::UserPayload,
            _ => Self::Unknown,
        }
    }
}

/// Observed encryption state of a volume (no secrets).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EncryptionState {
    pub encrypted: bool,
    pub tags_present: Vec<KeybagTag>,
    pub has_passphrase_hint: bool,
    /// Raw `(ke_tag, entry offset)` pairs for keybag entries whose tag is not a
    /// recognised `KB_TAG_*` value — surfaced so an audit can report the
    /// offending value + location (show-the-value rule), not just "unknown".
    pub unknown_tags: Vec<(u16, u64)>,
}

// `kb_locker` header field offsets, then 16-byte-aligned `keybag_entry_t`s.
const KL_NKEYS: usize = 2; // u16
const KL_ENTRIES_OFF: usize = 16; // entries begin after the 16-byte header
const KE_TAG: usize = 16; // u16 within an entry
const KE_KEYLEN: usize = 18; // u16 within an entry
const KE_HEADER_LEN: usize = 24; // uuid(16) + tag(2) + keylen(2) + pad(4)
/// Cap on `kl_nkeys` (a hostile blob must not drive an unbounded loop).
const MAX_KEYBAG_ENTRIES: usize = 4096;

/// Parse a container/volume keybag (`kb_locker`) into observed state — which
/// tags are present, whether a passphrase hint exists, and whether key material
/// is present — **without** unwrapping any key.
///
/// # Errors
/// [`crate::ApfsError::Io`] never (in-memory); returns `Ok` with whatever the
/// blob structurally yields. A malformed entry stops the walk early rather than
/// over-reading.
pub fn read_keybag(data: &[u8]) -> crate::Result<EncryptionState> {
    let nkeys = (crate::bytes::le_u16(data, KL_NKEYS) as usize).min(MAX_KEYBAG_ENTRIES);
    let mut tags_present = Vec::new();
    let mut unknown_tags = Vec::new();
    let mut off = KL_ENTRIES_OFF;
    for _ in 0..nkeys {
        // Stop if the entry header would run past the blob (never over-read).
        if off + KE_HEADER_LEN > data.len() {
            break;
        }
        let raw_tag = crate::bytes::le_u16(data, off + KE_TAG);
        let tag = KeybagTag::from_u16(raw_tag);
        let keylen = crate::bytes::le_u16(data, off + KE_KEYLEN) as usize;
        if tag == KeybagTag::Unknown {
            unknown_tags.push((raw_tag, off as u64));
        }
        if !tags_present.contains(&tag) {
            tags_present.push(tag);
        }
        // Advance by the 16-byte-aligned entry size.
        let entry_len = (KE_HEADER_LEN + keylen + 15) & !15;
        off += entry_len.max(16);
    }
    let has_passphrase_hint = tags_present.contains(&KeybagTag::VolumePassphraseHint);
    // "Encrypted" = actual key material is present (a wrapping key, a wrapped
    // volume key, or the volume-keybag unlock records).
    let encrypted = tags_present.iter().any(|t| {
        matches!(
            t,
            KeybagTag::WrappingKey | KeybagTag::VolumeKey | KeybagTag::VolumeUnlockRecords
        )
    });
    Ok(EncryptionState {
        encrypted,
        tags_present,
        has_passphrase_hint,
        unknown_tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `kb_locker` keybag blob: 16-byte header (`kl_version`@0,
    /// `kl_nkeys`@2, `kl_nbytes`@4, pad), then `keybag_entry_t` entries
    /// (`ke_uuid`@0[16], `ke_tag`@16, `ke_keylen`@18, pad[4], `ke_keydata`@24),
    /// each 16-byte aligned (libfsapfs layout).
    fn keybag(entries: &[(u16, usize)]) -> Vec<u8> {
        let mut data = vec![0u8; 16];
        data[0..2].copy_from_slice(&1u16.to_le_bytes()); // kl_version
        data[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes()); // kl_nkeys
        for &(tag, keylen) in entries {
            let mut e = vec![0u8; 24 + keylen];
            e[16..18].copy_from_slice(&tag.to_le_bytes()); // ke_tag
            e[18..20].copy_from_slice(&(keylen as u16).to_le_bytes()); // ke_keylen
            let padded = (e.len() + 15) & !15; // 16-byte align
            e.resize(padded, 0);
            data.extend_from_slice(&e);
        }
        let nbytes = data.len() as u32;
        data[4..8].copy_from_slice(&nbytes.to_le_bytes()); // kl_nbytes
        data
    }

    #[test]
    fn reads_volume_key_and_hint_tags() {
        // A volume keybag with a wrapped volume key and a passphrase hint.
        let kb = keybag(&[(0x02, 32), (0x04, 8)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.encrypted, "a keybag with a volume key is encrypted");
        assert!(st.tags_present.contains(&KeybagTag::VolumeKey));
        assert!(st.tags_present.contains(&KeybagTag::VolumePassphraseHint));
        assert!(st.has_passphrase_hint);
    }

    #[test]
    fn empty_keybag_reports_not_encrypted() {
        let kb = keybag(&[]);
        let st = read_keybag(&kb).expect("parse empty keybag");
        assert!(!st.encrypted);
        assert!(st.tags_present.is_empty());
        assert!(!st.has_passphrase_hint);
    }

    #[test]
    fn unknown_tag_maps_to_unknown_and_records_raw_value() {
        // A reserved/unexpected tag must decode as Unknown (never panic) and its
        // raw value + offset must be retained for the show-the-value rule.
        let kb = keybag(&[(0x55, 4)]);
        let st = read_keybag(&kb).expect("parse keybag");
        assert!(st.tags_present.contains(&KeybagTag::Unknown));
        assert_eq!(st.unknown_tags, vec![(0x55u16, 16u64)]);
    }
}
