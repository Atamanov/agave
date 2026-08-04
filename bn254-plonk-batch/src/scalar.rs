//! Fr <-> wire-byte conversions that run on every target. The pod parse
//! helpers (`PodScalar::to_fr`, the `From` impls) are host-only.

use {
    ark_bn254::Fr,
    ark_ff::PrimeField,
    solana_bn254_batch_syscall::{G1_BYTES, PodG1Point, PodScalar, SCALAR_BYTES},
};

/// [1] G1 in wire bytes: x = 1, y = 2, big-endian.
pub(crate) const G1_GENERATOR: PodG1Point = {
    let mut bytes = [0u8; G1_BYTES];
    bytes[31] = 1;
    bytes[63] = 2;
    PodG1Point(bytes)
};

/// Parse a canonical big-endian scalar; `None` for a value >= r.
pub(crate) fn fr_from_be(scalar: &PodScalar) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = SCALAR_BYTES - 8 * (i + 1);
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&scalar.0[start..start + 8]);
        *limb = u64::from_be_bytes(chunk);
    }
    Fr::from_bigint(<Fr as PrimeField>::BigInt::new(limbs))
}

/// Serialize the four limbs big-endian in place; no allocation, unlike
/// into_bigint().to_bytes_be().
pub(crate) fn fr_to_pod(scalar: &Fr) -> PodScalar {
    let limbs = scalar.into_bigint().0;
    let mut out = [0u8; SCALAR_BYTES];
    for (i, limb) in limbs.iter().enumerate() {
        let start = SCALAR_BYTES - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    PodScalar(out)
}

#[cfg(test)]
mod tests {
    use {super::*, ark_ec::AffineRepr};

    #[test]
    fn test_generator_bytes_match_arkworks() {
        assert_eq!(
            G1_GENERATOR,
            PodG1Point::from(&ark_bn254::G1Affine::generator())
        );
    }

    #[test]
    fn test_round_trip_matches_pod_helpers() {
        let scalar = Fr::from(123456789u64);
        assert_eq!(fr_to_pod(&scalar), PodScalar::from(&scalar));
        assert_eq!(fr_from_be(&fr_to_pod(&scalar)), Some(scalar));
        // non-canonical: all-ones is >= r
        assert_eq!(fr_from_be(&PodScalar([0xff; SCALAR_BYTES])), None);
    }
}
