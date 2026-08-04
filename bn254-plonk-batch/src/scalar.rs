//! Fr <-> wire-byte conversions that run on every target. The pod parse
//! helpers (`PodScalar::to_fr`, the `From` impls) are host-only.

#[cfg(test)]
use solana_bn254_batch_syscall::PodG2Point;
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

/// Canonical EIP-197 BN254 `[1]_2`, encoded as
/// `x.c1 || x.c0 || y.c1 || y.c0`.
#[cfg(test)]
pub(crate) const G2_GENERATOR: PodG2Point = PodG2Point([
    0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d, 0x25,
    0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3, 0x12, 0xc2,
    0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e, 0x5c, 0x44, 0x79,
    0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c, 0xd9, 0x92, 0xf6, 0xed,
    0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99, 0xad, 0x69, 0x0c, 0x33, 0x95,
    0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac, 0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b,
    0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a, 0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f,
    0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b, 0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
]);

/// Parse a canonical big-endian scalar; `None` for a value >= r.
pub(crate) fn fr_from_be(scalar: &PodScalar) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(scalar.0.rchunks_exact(8)) {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(bytes);
        *limb = u64::from_be_bytes(chunk);
    }
    Fr::from_bigint(<Fr as PrimeField>::BigInt::new(limbs))
}

/// Serialize the four limbs big-endian in place; no allocation, unlike
/// into_bigint().to_bytes_be().
pub(crate) fn fr_to_pod(scalar: &Fr) -> PodScalar {
    let limbs = scalar.into_bigint().0;
    let mut out = [0u8; SCALAR_BYTES];
    for (limb, bytes) in limbs.iter().zip(out.rchunks_exact_mut(8)) {
        bytes.copy_from_slice(&limb.to_be_bytes());
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
        assert_eq!(
            G2_GENERATOR.to_affine().unwrap(),
            ark_bn254::G2Affine::generator()
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
