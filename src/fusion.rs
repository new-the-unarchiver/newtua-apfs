//! Fusion (SSD + HDD) support.
//!
//! A Fusion container spans two devices: a fast tier (SSD) and a slow tier
//! (HDD). The fusion middle tree (`OBJECT_TYPE_FUSION_MIDDLE_TREE 0x15`) maps
//! logical addresses across tiers, and a write-back cache
//! (`OBJECT_TYPE_NX_FUSION_WBC 0x16` / `..._WBC_LIST 0x17`) buffers writes. The
//! high bit of a Fusion physical address selects the tier.
//!
//! **Ordering note (Codex):** Fusion changes physical-address resolution, so the
//! reader cannot correctly read a Fusion image's blocks without at least minimal
//! tier-aware translation. P1/P2 must therefore either implement the minimal
//! address split **or** detect a Fusion container and fail loud with
//! [`crate::ApfsError::UnsupportedFusion`] — never silently mis-read addresses.

/// Detect whether a container is a Fusion container, from the
/// `NX_INCOMPAT_FUSION` bit in the NXSB `nx_incompatible_features` word.
#[must_use]
pub fn is_fusion(superblock: &crate::container::NxSuperblock) -> bool {
    superblock.incompatible_features & crate::container::NX_INCOMPAT_FUSION != 0
}

/// The Fusion tier-2 (HDD) device byte-address marker (Apple *APFS Reference* /
/// linux-apfs `APFS_FUSION_TIER2_DEVICE_BYTE_ADDR`). A tier-2 **block** base is
/// `FUSION_TIER2_DEVICE_BYTE_ADDR >> block_size_bits` (so it depends on the
/// block size); a physical block at or above that base lives on tier 2 at
/// `paddr - tier2_base`.
pub const FUSION_TIER2_DEVICE_BYTE_ADDR: u64 = 0x4000_0000_0000_0000;

/// Translate a Fusion physical address to a device-relative block.
///
/// **Not yet supported.** Correct translation needs the block size (the tier-2
/// base is `FUSION_TIER2_DEVICE_BYTE_ADDR >> block_size_bits`, not a fixed bit)
/// **and** the fusion middle tree (`OBJECT_TYPE_FUSION_MIDDLE_TREE`) to remap
/// logical↔physical across tiers — which requires a real Fusion image to
/// validate (none is available). Rather than ship an unvalidated address
/// transform, this fails loud, consistent with [`crate::ApfsContainer::open`]
/// already rejecting a Fusion container at open time
/// ([`crate::ApfsError::UnsupportedFusion`]). So this is currently unreachable
/// defensive code; it will gain real translation when a Fusion fixture exists.
///
/// # Errors
/// Always [`crate::ApfsError::UnsupportedFusion`] until full Fusion support and
/// a validating fixture land.
pub fn translate_address(_paddr: u64) -> crate::Result<u64> {
    Err(crate::ApfsError::UnsupportedFusion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_address_fails_loud_not_panics() {
        // Unreachable in practice (open() rejects Fusion), but must fail loud
        // rather than panic or return a bogus address.
        let tier2 = FUSION_TIER2_DEVICE_BYTE_ADDR >> 12; // 4 KiB block base
        assert!(matches!(
            translate_address(tier2),
            Err(crate::ApfsError::UnsupportedFusion)
        ));
        assert!(matches!(
            translate_address(5),
            Err(crate::ApfsError::UnsupportedFusion)
        ));
    }
}
