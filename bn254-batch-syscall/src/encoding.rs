//! Wire parsing and serialization.
//!
//! The compute path parses into mcl types with all canonicality checks done
//! in Rust on the big-endian wire bytes BEFORE any mcl setter runs (mcl's
//! setters silently mask out-of-range input, which would turn a NonCanonical
//! rejection into a wrong answer). A small arkworks compat section serves
//! the wire-frozen ark-typed pod surface and the test fixtures; it performs
//! representation conversion only, never arithmetic.

use {
    crate::validation::AltBn128BatchError,
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{BigInt, PrimeField, Zero},
    solana_bn254_mcl_sys::{MclFr, MclG1, MclG2, api},
};

// wire format is big-endian, byte-for-byte the encoding of the existing
// `sol_alt_bn128_group_op` pairing; all-zeros is the point at infinity in both
// groups
pub const G1_BYTES: usize = 64;
pub const G2_BYTES: usize = 128;
pub const PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
pub const SCALAR_BYTES: usize = 32;

pub const MSM_MAX_POINTS: usize = 2048;
pub const PAIRING_MAX_PAIRS: usize = 256;
pub const FR_MAX_ELEMS: usize = 2048;

const FQ_BYTES: usize = 32;

/// One canonical coordinate limb: 32 big-endian bytes < p. Big-endian arrays
/// compare lexicographically as integers, so the range check is a byte
/// compare; this is exactly the `from_bigint` rejection the validation order
/// requires before any arithmetic.
fn fq_limb(bytes: &[u8]) -> Result<[u8; FQ_BYTES], AltBn128BatchError> {
    debug_assert_eq!(bytes.len(), FQ_BYTES);
    let mut out = [0u8; FQ_BYTES];
    out.copy_from_slice(bytes);
    if out >= api::FQ_MODULUS_BE {
        return Err(AltBn128BatchError::NonCanonical);
    }
    Ok(out)
}

pub(crate) fn parse_g1(bytes: &[u8]) -> Result<MclG1, AltBn128BatchError> {
    if bytes.len() != G1_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let x = fq_limb(&bytes[..FQ_BYTES])?;
    let y = fq_limb(&bytes[FQ_BYTES..])?;
    if x == [0u8; FQ_BYTES] && y == [0u8; FQ_BYTES] {
        return Ok(api::g1_infinity());
    }
    Ok(api::g1_affine(api::fp_from_be(&x), api::fp_from_be(&y)))
}

// Fq2 limb order: imaginary part first (x1 | x0 | y1 | y0); the limbs
// are range-checked in wire order
pub(crate) fn parse_g2(bytes: &[u8]) -> Result<MclG2, AltBn128BatchError> {
    if bytes.len() != G2_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let x1 = fq_limb(&bytes[0..32])?;
    let x0 = fq_limb(&bytes[32..64])?;
    let y1 = fq_limb(&bytes[64..96])?;
    let y0 = fq_limb(&bytes[96..128])?;
    if bytes.iter().all(|&b| b == 0) {
        return Ok(api::g2_infinity());
    }
    Ok(api::g2_affine(
        api::fp_from_be(&x0),
        api::fp_from_be(&x1),
        api::fp_from_be(&y0),
        api::fp_from_be(&y1),
    ))
}

pub(crate) fn parse_fr(bytes: &[u8]) -> Result<MclFr, AltBn128BatchError> {
    if bytes.len() != SCALAR_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let mut out = [0u8; SCALAR_BYTES];
    out.copy_from_slice(bytes);
    if out >= api::FR_MODULUS_BE {
        return Err(AltBn128BatchError::NonCanonical);
    }
    Ok(api::fr_from_be(&out))
}

pub(crate) fn serialize_g1(point: &MclG1) -> [u8; G1_BYTES] {
    let mut out = [0u8; G1_BYTES];
    if let Some((x, y)) = api::g1_xy(point) {
        out[..FQ_BYTES].copy_from_slice(&api::fp_to_be(&x));
        out[FQ_BYTES..].copy_from_slice(&api::fp_to_be(&y));
    }
    out
}

// ---------------------------------------------------------------------------
// arkworks compat: representation conversion for the wire-frozen ark-typed
// pod surface and the test fixtures; no curve or field arithmetic happens
// here beyond the to-Montgomery conversion inside `from_bigint`

fn bigint_from_be(bytes: &[u8]) -> BigInt<4> {
    debug_assert_eq!(bytes.len(), FQ_BYTES);
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = FQ_BYTES - 8 * (i + 1);
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[start..start + 8]);
        *limb = u64::from_be_bytes(chunk);
    }
    BigInt::new(limbs)
}

pub(crate) fn fq_to_be(value: &Fq, out: &mut [u8]) {
    debug_assert_eq!(out.len(), FQ_BYTES);
    for (i, limb) in value.into_bigint().0.iter().enumerate() {
        let start = FQ_BYTES - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
}

/// The B2 scalar parse, kept verbatim for `PodScalar::to_fr`: `from_bigint`
/// returns `None` for values >= r, exactly the NonCanonical rejection.
pub(crate) fn ark_fr(bytes: &[u8]) -> Result<Fr, AltBn128BatchError> {
    if bytes.len() != SCALAR_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    Fr::from_bigint(bigint_from_be(bytes)).ok_or(AltBn128BatchError::NonCanonical)
}

/// Wire bytes to an arkworks point WITHOUT validation: the caller has
/// already run the mcl-side parse + validate on these exact bytes.
pub(crate) fn ark_g1_unchecked(bytes: &[u8; G1_BYTES]) -> G1Affine {
    let x = Fq::from_bigint(bigint_from_be(&bytes[..FQ_BYTES])).expect("validated canonical");
    let y = Fq::from_bigint(bigint_from_be(&bytes[FQ_BYTES..])).expect("validated canonical");
    if x.is_zero() && y.is_zero() {
        return G1Affine::zero();
    }
    G1Affine::new_unchecked(x, y)
}

/// See `ark_g1_unchecked`; Fq2 limb order (x1 | x0 | y1 | y0).
pub(crate) fn ark_g2_unchecked(bytes: &[u8; G2_BYTES]) -> G2Affine {
    let limb = |range: core::ops::Range<usize>| {
        Fq::from_bigint(bigint_from_be(&bytes[range])).expect("validated canonical")
    };
    let x = Fq2::new(limb(32..64), limb(0..32));
    let y = Fq2::new(limb(96..128), limb(64..96));
    if x.is_zero() && y.is_zero() {
        return G2Affine::zero();
    }
    G2Affine::new_unchecked(x, y)
}

/// Ark point to wire bytes, for the wire-frozen `From<&G1Affine>` fixture
/// surface.
pub(crate) fn serialize_g1_ark(point: &G1Affine) -> [u8; G1_BYTES] {
    let mut out = [0u8; G1_BYTES];
    if let Some((x, y)) = point.xy() {
        fq_to_be(&x, &mut out[..FQ_BYTES]);
        fq_to_be(&y, &mut out[FQ_BYTES..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{
            be_add_one, fq_modulus_be, g1_bytes, g2_bytes, random_g1, random_g2, rng,
        },
        ark_ec::AffineRepr,
    };

    #[test]
    fn test_g1_round_trip() {
        let mut rng = rng();
        for _ in 0..16 {
            let point = random_g1(&mut rng);
            let bytes = g1_bytes(&point);
            assert_eq!(serialize_g1(&parse_g1(&bytes).unwrap()), bytes);
        }
        assert!(solana_bn254_mcl_sys::api::g1_is_zero(
            &parse_g1(&[0u8; G1_BYTES]).unwrap()
        ));
        assert_eq!(
            serialize_g1(&parse_g1(&[0u8; G1_BYTES]).unwrap()),
            [0u8; G1_BYTES]
        );
    }

    #[test]
    fn test_g2_round_trip() {
        use solana_bn254_mcl_sys::api;
        let mut rng = rng();
        for _ in 0..16 {
            let point = random_g2(&mut rng);
            let bytes = g2_bytes(&point);
            let ((x0, x1), (y0, y1)) = api::g2_xy(&parse_g2(&bytes).unwrap()).unwrap();
            let mut out = [0u8; G2_BYTES];
            out[..32].copy_from_slice(&api::fp_to_be(&x1));
            out[32..64].copy_from_slice(&api::fp_to_be(&x0));
            out[64..96].copy_from_slice(&api::fp_to_be(&y1));
            out[96..].copy_from_slice(&api::fp_to_be(&y0));
            assert_eq!(out, bytes);
        }
        assert!(api::g2_is_zero(&parse_g2(&[0u8; G2_BYTES]).unwrap()));
    }

    #[test]
    fn test_ark_compat_matches_mcl_parse() {
        let mut rng = rng();
        for _ in 0..8 {
            let point = random_g1(&mut rng);
            let bytes = g1_bytes(&point);
            assert_eq!(ark_g1_unchecked(&bytes), point);
            // and back out through the ark serializer
            assert_eq!(serialize_g1_ark(&ark_g1_unchecked(&bytes)), bytes);
        }
        assert_eq!(ark_g1_unchecked(&[0u8; G1_BYTES]), G1Affine::zero());
        let point = random_g2(&mut rng);
        let bytes = g2_bytes(&point);
        assert_eq!(ark_g2_unchecked(&bytes), point);
        assert_eq!(ark_g2_unchecked(&[0u8; G2_BYTES]), G2Affine::zero());
    }

    #[test]
    fn test_g1_layout_matches_solana_bn254() {
        // pin the byte layout to the existing group-op syscall: multiplying the
        // generator by 1 must reproduce our serialization of the generator
        let generator = G1Affine::generator();
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(&g1_bytes(&generator));
        input[95] = 1;
        let product = solana_bn254::prelude::alt_bn128_g1_multiplication_be(&input).unwrap();
        assert_eq!(product.as_slice(), g1_bytes(&generator).as_slice());
    }

    #[test]
    fn test_rejects_noncanonical_coordinate() {
        let modulus = fq_modulus_be();
        let mut bytes = [0u8; G1_BYTES];
        bytes[..32].copy_from_slice(&modulus);
        assert_eq!(
            parse_g1(&bytes).unwrap_err(),
            AltBn128BatchError::NonCanonical
        );

        let mut plus_one = modulus;
        be_add_one(&mut plus_one);
        let mut bytes = [0u8; G1_BYTES];
        bytes[32..].copy_from_slice(&plus_one);
        assert_eq!(
            parse_g1(&bytes).unwrap_err(),
            AltBn128BatchError::NonCanonical
        );

        // x = p, y = p is a non-canonical encoding of the identity; an
        // implementation that reduces instead of rejecting would accept it
        let mut bytes = [0u8; G1_BYTES];
        bytes[..32].copy_from_slice(&modulus);
        bytes[32..].copy_from_slice(&modulus);
        assert_eq!(
            parse_g1(&bytes).unwrap_err(),
            AltBn128BatchError::NonCanonical
        );
    }
}
