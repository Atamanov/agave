use {
    crate::validation::AltBn128BatchError,
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{BigInt, PrimeField, Zero},
};

// wire format is big-endian, byte-for-byte the encoding of the existing
// `sol_alt_bn128_group_op` pairing; all-zeros is the point at infinity in both
// groups
pub use helios_bn254::{
    FR_MAX_ELEMS, G1_BYTES, G2_BYTES, MSM_MAX_POINTS, PAIR_BYTES, PAIRING_MAX_PAIRS, SCALAR_BYTES,
};

// the widths and caps are consensus-frozen; a backend that changed one must
// fail here, not resize the wire contract through the re-export
const _: () = {
    assert!(G1_BYTES == 64);
    assert!(G2_BYTES == 128);
    assert!(PAIR_BYTES == 192);
    assert!(SCALAR_BYTES == 32);
    assert!(MSM_MAX_POINTS == 2048);
    assert!(PAIRING_MAX_PAIRS == 256);
    assert!(FR_MAX_ELEMS == 2048);
};

const FQ_BYTES: usize = 32;

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

// `from_bigint` returns `None` for values >= the modulus, which is exactly the
// non-canonical rejection the validation order requires before any arithmetic
fn fq_from_be(bytes: &[u8]) -> Result<Fq, AltBn128BatchError> {
    Fq::from_bigint(bigint_from_be(bytes)).ok_or(AltBn128BatchError::NonCanonical)
}

pub(crate) fn fq_to_be(value: &Fq, out: &mut [u8]) {
    debug_assert_eq!(out.len(), FQ_BYTES);
    for (i, limb) in value.into_bigint().0.iter().enumerate() {
        let start = FQ_BYTES - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
}

pub(crate) fn parse_g1(bytes: &[u8]) -> Result<G1Affine, AltBn128BatchError> {
    if bytes.len() != G1_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let x = fq_from_be(&bytes[..FQ_BYTES])?;
    let y = fq_from_be(&bytes[FQ_BYTES..])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }
    Ok(G1Affine::new_unchecked(x, y))
}

// Fq2 limb order: imaginary part first (x1 | x0 | y1 | y0)
pub(crate) fn parse_g2(bytes: &[u8]) -> Result<G2Affine, AltBn128BatchError> {
    if bytes.len() != G2_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let x1 = fq_from_be(&bytes[0..32])?;
    let x0 = fq_from_be(&bytes[32..64])?;
    let y1 = fq_from_be(&bytes[64..96])?;
    let y0 = fq_from_be(&bytes[96..128])?;
    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }
    Ok(G2Affine::new_unchecked(x, y))
}

pub(crate) fn parse_fr(bytes: &[u8]) -> Result<Fr, AltBn128BatchError> {
    if bytes.len() != SCALAR_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    Fr::from_bigint(bigint_from_be(bytes)).ok_or(AltBn128BatchError::NonCanonical)
}

pub(crate) fn serialize_g1(point: &G1Affine) -> [u8; G1_BYTES] {
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
            assert_eq!(parse_g1(&serialize_g1(&point)).unwrap(), point);
        }
        assert_eq!(parse_g1(&[0u8; G1_BYTES]).unwrap(), G1Affine::zero());
        assert_eq!(serialize_g1(&G1Affine::zero()), [0u8; G1_BYTES]);
    }

    #[test]
    fn test_g2_round_trip() {
        let mut rng = rng();
        for _ in 0..16 {
            let point = random_g2(&mut rng);
            assert_eq!(parse_g2(&g2_bytes(&point)).unwrap(), point);
        }
        assert_eq!(parse_g2(&[0u8; G2_BYTES]).unwrap(), G2Affine::zero());
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
        assert_eq!(parse_g1(&bytes), Err(AltBn128BatchError::NonCanonical));

        let mut plus_one = modulus;
        be_add_one(&mut plus_one);
        let mut bytes = [0u8; G1_BYTES];
        bytes[32..].copy_from_slice(&plus_one);
        assert_eq!(parse_g1(&bytes), Err(AltBn128BatchError::NonCanonical));

        // x = p, y = p is a non-canonical encoding of the identity; an
        // implementation that reduces instead of rejecting would accept it
        let mut bytes = [0u8; G1_BYTES];
        bytes[..32].copy_from_slice(&modulus);
        bytes[32..].copy_from_slice(&modulus);
        assert_eq!(parse_g1(&bytes), Err(AltBn128BatchError::NonCanonical));
    }
}
