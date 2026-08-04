//! Versioned, backend-pinned wire ABI for the account-backed VK registry.

use crate::encoding::{FQ12_BYTES, G2_BYTES, PAIR_BYTES};

pub const REGISTRY_ABI_VERSION: u16 = 3;
pub const REGISTRY_HEADER_BYTES: usize = 80;
pub const REGISTRY_PREPARED_G2_BYTES: usize = 37_584;
pub const REGISTRY_G2_ENTRY_BYTES: usize = 32 + G2_BYTES + REGISTRY_PREPARED_G2_BYTES;
pub const REGISTRY_GT_ENTRY_BYTES: usize = 32 + PAIR_BYTES + FQ12_BYTES;
pub const REGISTRY_MAX_G2_ENTRIES: usize = 16;
pub const REGISTRY_MAX_GT_ENTRIES: usize = 16;
pub const REGISTRY_MAX_REGISTERED_PAIRS: usize = 256;

pub const fn pack_registry_init_shape(g2_count: u16, gt_count: u16, account_index: u16) -> u64 {
    g2_count as u64
        | ((gt_count as u64) << 16)
        | ((account_index as u64) << 32)
        | ((REGISTRY_ABI_VERSION as u64) << 48)
}

pub const fn pack_registered_pairing_shape(
    full_count: u16,
    registered_count: u16,
    account_index: u16,
) -> u64 {
    full_count as u64
        | ((registered_count as u64) << 16)
        | ((account_index as u64) << 32)
        | ((REGISTRY_ABI_VERSION as u64) << 48)
}

pub const fn pack_gt_multiexp_shape(target_count: u16, account_index: u16) -> u64 {
    target_count as u64 | ((account_index as u64) << 32) | ((REGISTRY_ABI_VERSION as u64) << 48)
}

pub const fn registry_account_len(g2_count: usize, gt_count: usize) -> usize {
    REGISTRY_HEADER_BYTES
        .saturating_add(g2_count.saturating_mul(REGISTRY_G2_ENTRY_BYTES))
        .saturating_add(gt_count.saturating_mul(REGISTRY_GT_ENTRY_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_v3_sizes_and_shapes_are_pinned() {
        assert_eq!(REGISTRY_G2_ENTRY_BYTES, 37_744);
        assert_eq!(REGISTRY_GT_ENTRY_BYTES, 608);
        assert_eq!(registry_account_len(3, 1), 113_920);
        assert_eq!(pack_registry_init_shape(3, 1, 2) >> 48, 3);
        assert_eq!(pack_registered_pairing_shape(5, 3, 2) >> 48, 3);
        assert_eq!(pack_gt_multiexp_shape(1, 2) >> 48, 3);
    }
}
