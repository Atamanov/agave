use {
    crate::encoding::{G1_BYTES, G2_BYTES, SCALAR_BYTES},
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encoding::{parse_fr, parse_g1, parse_g2, serialize_g1},
        validation::{AltBn128BatchError, validate_g1, validate_g2},
    },
    ark_bn254::{Fr, G1Affine, G2Affine},
    ark_ff::PrimeField,
};

/// G1 affine point: 64 big-endian bytes (x | y), all-zeros = infinity. The wire
/// encoding, never Montgomery limbs; the arkworks type stays inside `to_affine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1Point(pub [u8; G1_BYTES]);

/// G2 affine point: 128 big-endian bytes (x1 | x0 | y1 | y0), all-zeros = infinity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2Point(pub [u8; G2_BYTES]);

/// Scalar in the BN254 scalar field: 32 big-endian bytes, canonical (< q).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; SCALAR_BYTES]);

/// One pairing input, a G1 point then its G2 partner: 192 contiguous bytes with
/// no padding, so a raw pair buffer casts to `&[PodG1G2Pair]` directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodG1G2Pair {
    pub g1: PodG1Point,
    pub g2: PodG2Point,
}

/// The 32-byte pairing verdict word, byte-identical to the group-op pairing
/// output: big-endian 1 iff the product is the identity, all zeros otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodPairingResult(pub [u8; 32]);

#[cfg(not(target_os = "solana"))]
impl PodG1Point {
    /// Canonical coordinates, on-curve; G1 cofactor is 1 so on-curve implies
    /// subgroup membership. Infinity is a valid group element here.
    pub fn to_affine(&self) -> Result<G1Affine, AltBn128BatchError> {
        let point = parse_g1(&self.0)?;
        validate_g1(&point)?;
        Ok(point)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&G1Affine> for PodG1Point {
    fn from(point: &G1Affine) -> Self {
        Self(serialize_g1(point))
    }
}

#[cfg(not(target_os = "solana"))]
impl PodG2Point {
    /// Canonical coordinates, on-curve, r-order subgroup membership.
    pub fn to_affine(&self) -> Result<G2Affine, AltBn128BatchError> {
        let point = parse_g2(&self.0)?;
        validate_g2(&point)?;
        Ok(point)
    }
}

#[cfg(not(target_os = "solana"))]
impl PodScalar {
    pub fn to_fr(&self) -> Result<Fr, AltBn128BatchError> {
        parse_fr(&self.0)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&Fr> for PodScalar {
    fn from(scalar: &Fr) -> Self {
        // serialize the four limbs big-endian in place; no allocation, unlike
        // into_bigint().to_bytes_be(), so batch_invert stays alloc-free per element
        let limbs = scalar.into_bigint().0;
        let mut out = [0u8; SCALAR_BYTES];
        for (i, limb) in limbs.iter().enumerate() {
            let start = SCALAR_BYTES - 8 * (i + 1);
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        Self(out)
    }
}

impl PodPairingResult {
    pub fn from_verdict(verdict: bool) -> Self {
        let mut word = [0u8; 32];
        word[31] = u8::from(verdict);
        Self(word)
    }

    pub fn verdict(&self) -> bool {
        self == &Self::from_verdict(true)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::PAIR_BYTES,
            test_utils::{random_g1, rng},
        },
        core::mem::{align_of, offset_of, size_of},
    };

    // the pointer casts in the host boundary and the test seams are sound only
    // if these hold: exact wire sizes, no padding in the pair, align 1 so any
    // guest byte buffer is trivially aligned
    #[test]
    fn test_pod_layout_matches_wire() {
        assert_eq!(size_of::<PodG1Point>(), G1_BYTES);
        assert_eq!(size_of::<PodG2Point>(), G2_BYTES);
        assert_eq!(size_of::<PodScalar>(), SCALAR_BYTES);
        assert_eq!(size_of::<PodG1G2Pair>(), PAIR_BYTES);
        assert_eq!(size_of::<PodPairingResult>(), 32);
        assert_eq!(align_of::<PodG1G2Pair>(), 1);
        assert_eq!(offset_of!(PodG1G2Pair, g1), 0);
        assert_eq!(offset_of!(PodG1G2Pair, g2), G1_BYTES);
    }

    #[test]
    fn test_pair_cast_splits_bytes() {
        let mut bytes = [0u8; 2 * PAIR_BYTES];
        bytes[G1_BYTES] = 0xab;
        let pairs: &[PodG1G2Pair] = bytemuck::cast_slice(&bytes);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].g1.0, [0u8; G1_BYTES]);
        assert_eq!(pairs[0].g2.0[0], 0xab);
    }

    #[test]
    fn test_g1_pod_round_trip() {
        let mut rng = rng();
        let point = random_g1(&mut rng);
        assert_eq!(PodG1Point::from(&point).to_affine().unwrap(), point);
    }

    #[test]
    fn test_pairing_result_word() {
        assert_eq!(PodPairingResult::from_verdict(false).0, [0u8; 32]);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(PodPairingResult::from_verdict(true).0, one);
        assert!(PodPairingResult::from_verdict(true).verdict());
        assert!(!PodPairingResult::from_verdict(false).verdict());

        // A corrupt or non-conforming runtime result must never be interpreted
        // as acceptance merely because its last byte happens to be one.
        let mut non_canonical_true = one;
        non_canonical_true[0] = 1;
        assert!(!PodPairingResult(non_canonical_true).verdict());
        let mut out_of_range = [0u8; 32];
        out_of_range[31] = 2;
        assert!(!PodPairingResult(out_of_range).verdict());
    }
}
