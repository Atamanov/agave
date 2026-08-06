//! Lane padding for the 8-wide pairing kernel.
//!
//! The B5 IFMA kernel takes pairs eight at a time and runs whatever is left
//! over on the scalar path, so a call that fills a lane can be both faster and
//! cheaper than a shorter one. The runtime prices that shape, and this module
//! is the one place that decides how many pairs to add to reach it.
//!
//! Padding must be inert. A pair of nonzero points never is: the pairing is
//! non-degenerate, so `e(P, Q) = 1` forces `P` or `Q` to infinity. An infinity
//! pair would be inert, but the runtime drops it before the kernel sees it, so
//! it buys a lane in the charge and not in the work. Every pad here is a block
//! of real pairs over the two generators whose G1 coefficients sum to zero.

use solana_bn254_batch_syscall::{PodG1G2Pair, PodG1Point, PodG2Point};

/// Pairs the IFMA kernel takes per lane.
pub const PAIRING_LANE_WIDTH: usize = 8;

/// Identity pairs to append to a call of `full` unregistered and `registered`
/// registered pairs so the runtime charges as little as possible for it, or an
/// empty slice when nothing is to be gained. `cap` is the pair limit of the
/// syscall the call goes to. The pad is always full pairs.
///
/// `SVMTransactionExecutionCost::alt_bn128_pairing_cost` charges
/// `6,105 + 4,350k` below one lane and
/// `4,655 + 22,505*(k / 8) + 5,865*(k % 8)` at or above it. So a full lane at
/// 27,160 undercuts the 5, 6 and 7 pairs that fail to fill one (27,855, 32,205
/// and 36,555), and past the first lane a remainder of four or more costs more
/// than the 22,505 of the lane it would complete. Nothing else is worth
/// padding: four pairs on their own cost 23,505 against the lane's 27,160, and
/// a remainder of three costs 17,595.
///
/// A remainder of seven cannot reach the lane boundary, because that needs one
/// added pair and no single pair is inert. Two pairs still beat standing still,
/// 33,025 against 36,555.
///
/// The registered-pair credit splits on the same boundary, 2,819 below a lane
/// and 1,142 at or above one, so padding out of the sub-lane regime gives back
/// 1,677 per registered pair. That buys the three limits below: it eats the
/// 695 a five-pair call saves at one registered pair, the 5,045 a six-pair
/// call saves at four, and the 3,530 a seven-pair call saves at three. Past
/// the first lane the credit does not move and the pair count decides alone.
#[inline]
pub fn lane_padding_pairs(full: usize, registered: usize, cap: usize) -> &'static [PodG1G2Pair] {
    let pairs = full.saturating_add(registered);
    let filled_a_lane = pairs >= PAIRING_LANE_WIDTH;
    let pad: &'static [PodG1G2Pair] = match (pairs % PAIRING_LANE_WIDTH, filled_a_lane) {
        (4, true) => &PAD[..4],
        (5, true) => &PAD_ODD,
        (5, false) if registered == 0 => &PAD_ODD,
        (6 | 7, true) => &PAD[..2],
        (6, false) if registered <= 3 => &PAD[..2],
        (7, false) if registered <= 2 => &PAD[..2],
        _ => &[],
    };
    if pairs.saturating_add(pad.len()) > cap {
        return &[];
    }
    pad
}

/// `[G, -G, G, -G]`: any even-length prefix pairs to the identity.
static PAD: [PodG1G2Pair; 4] = [
    pad_pair(GENERATOR_G1),
    pad_pair(NEGATED_GENERATOR_G1),
    pad_pair(GENERATOR_G1),
    pad_pair(NEGATED_GENERATOR_G1),
];

/// `[G, G, -2G]`, the shortest odd block that sums to zero.
static PAD_ODD: [PodG1G2Pair; 3] = [
    pad_pair(GENERATOR_G1),
    pad_pair(GENERATOR_G1),
    pad_pair(NEGATED_DOUBLE_GENERATOR_G1),
];

const fn pad_pair(g1: PodG1Point) -> PodG1G2Pair {
    PodG1G2Pair {
        g1,
        g2: GENERATOR_G2,
    }
}

/// `G1::generator()`, `(1, 2)`.
const GENERATOR_G1: PodG1Point = PodG1Point([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
]);

/// `-G1::generator()`, `(1, p - 2)`.
const NEGATED_GENERATOR_G1: PodG1Point = PodG1Point([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x45,
]);

/// `-[2] G1::generator()`.
const NEGATED_DOUBLE_GENERATOR_G1: PodG1Point = PodG1Point([
    0x03, 0x06, 0x44, 0xe7, 0x2e, 0x13, 0x1a, 0x02, 0x9b, 0x85, 0x04, 0x5b, 0x68, 0x18, 0x15, 0x85,
    0xd9, 0x78, 0x16, 0xa9, 0x16, 0x87, 0x1c, 0xa8, 0xd3, 0xc2, 0x08, 0xc1, 0x6d, 0x87, 0xcf, 0xd3,
    0x1a, 0x76, 0xda, 0xe6, 0xd3, 0x27, 0x23, 0x96, 0xd0, 0xcb, 0xe6, 0x1f, 0xce, 0xd2, 0xbc, 0x53,
    0x2e, 0xda, 0xc6, 0x47, 0x85, 0x1e, 0x3a, 0xc5, 0x3c, 0xe1, 0xcc, 0x9c, 0x7e, 0x64, 0x5a, 0x83,
]);

/// `G2::generator()`, encoded `x1 | x0 | y1 | y0`.
const GENERATOR_G2: PodG2Point = PodG2Point([
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
]);

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{G1Affine, G2Affine},
        ark_ec::AffineRepr,
        solana_bn254_batch_syscall::{
            PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, Version, alt_bn128_pairing_check,
        },
    };

    /// `SVMTransactionExecutionCost::alt_bn128_pairing_cost`, restated so the
    /// rule can be checked against the charge rather than against the residues
    /// it was reduced to.
    fn charge(full: usize, registered: usize) -> usize {
        let pairs = full.saturating_add(registered);
        let lanes = pairs / 8;
        let remainder = pairs % 8;
        let (core, credit) = if lanes == 0 {
            (
                6_105usize.saturating_add(4_350usize.saturating_mul(remainder)),
                2_819usize,
            )
        } else {
            (
                4_655usize
                    .saturating_add(22_505usize.saturating_mul(lanes))
                    .saturating_add(5_865usize.saturating_mul(remainder)),
                1_142usize,
            )
        };
        core.saturating_sub(credit.saturating_mul(registered))
    }

    #[test]
    fn padding_points_are_the_generators() {
        let generator = G1Affine::generator();
        assert_eq!(GENERATOR_G1.to_affine(), Ok(generator));
        assert_eq!(NEGATED_GENERATOR_G1.to_affine(), Ok(-generator));
        let double: G1Affine = (generator + generator).into();
        assert_eq!(NEGATED_DOUBLE_GENERATOR_G1.to_affine(), Ok(-double));
        assert_eq!(GENERATOR_G2.to_affine(), Ok(G2Affine::generator()));
    }

    #[test]
    fn every_pad_block_is_the_identity_in_gt() {
        for pairs in 0..PAIRING_MAX_PAIRS {
            let pad = lane_padding_pairs(pairs, 0, PAIRING_MAX_PAIRS);
            if pad.is_empty() {
                continue;
            }
            assert_eq!(
                alt_bn128_pairing_check(Version::V0, pad),
                Ok(true),
                "pad for {pairs} pairs is not inert"
            );
        }
    }

    #[test]
    fn no_pad_contains_an_infinity_point() {
        // An infinity pair is inert but the runtime drops it before the
        // kernel, so it would buy a lane in the charge and not in the work.
        for pairs in 0..PAIRING_MAX_PAIRS {
            for pair in lane_padding_pairs(pairs, 0, PAIRING_MAX_PAIRS) {
                assert!(!pair.g1.0.iter().all(|byte| *byte == 0));
                assert!(!pair.g2.0.iter().all(|byte| *byte == 0));
            }
        }
    }

    #[test]
    fn padding_is_the_cheapest_reachable_shape() {
        for registered in 0..=16usize {
            for full in 1..64usize {
                let pairs = full + registered;
                let pad = lane_padding_pairs(full, registered, PAIRING_MAX_PAIRS).len();
                // No single pair is inert, so one more pair is out of reach.
                let best = (0..=PAIRING_LANE_WIDTH)
                    .filter(|candidate| *candidate != 1 && pairs + candidate <= PAIRING_MAX_PAIRS)
                    .min_by_key(|candidate| charge(full + candidate, registered))
                    .expect("no pad is always a candidate");
                assert_eq!(
                    charge(full + pad, registered),
                    charge(full + best, registered),
                    "{full} full and {registered} registered pairs padded by {pad}, \
                     but {best} is cheaper"
                );
            }
        }
    }

    #[test]
    fn padding_never_exceeds_the_cap() {
        for cap in [PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS] {
            for pairs in 1..=cap {
                assert!(pairs + lane_padding_pairs(pairs, 0, cap).len() <= cap);
            }
        }
    }

    #[test]
    fn the_map_cap_never_blocks_a_same_vk_batch() {
        // n + 2 pairs for n in 1..=SAME_VK_FP12_MAX_PROOFS: every shape the
        // dedicated path can produce still gets its pad.
        for pairs in 3..=PAIRING_MAP_MAX_PAIRS {
            assert_eq!(
                lane_padding_pairs(pairs, 0, PAIRING_MAP_MAX_PAIRS),
                lane_padding_pairs(pairs, 0, PAIRING_MAX_PAIRS),
                "the map cap withheld the pad at {pairs} pairs"
            );
        }
    }
}
