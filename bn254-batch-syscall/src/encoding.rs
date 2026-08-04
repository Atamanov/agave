#[cfg(not(target_os = "solana"))]
use {
    crate::validation::AltBn128BatchError,
    ark_bn254::{Fq, Fq2, Fq6, Fq12, Fr, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{BigInt, PrimeField, Zero},
};

// The point format matches `sol_alt_bn128_group_op`. It is big-endian, and an
// all-zero point is the identity in each group.
pub const G1_BYTES: usize = 64;
pub const G2_BYTES: usize = 128;
pub const PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
pub const SCALAR_BYTES: usize = 32;
/// A canonical BN254 extension-field element: twelve base-field coefficients,
/// each encoded as a 32-byte big-endian canonical integer.
pub const FQ12_BYTES: usize = 12 * 32;

pub const MSM_MAX_POINTS: usize = 2048;
pub const PAIRING_MAX_PAIRS: usize = 256;
pub const PAIRING_MAP_MAX_PAIRS: usize = 16;
pub const FR_MAX_ELEMS: usize = 2048;

// The synthetic PLONK reducer accepts verifier-derived challenges. The
// canonical reducers derive the transcript. All reducers return scalar
// coefficients and keep the two MSM bases in the verifier. Nine Q-side points
// per proof set the maximum batch size for the G1 MSM syscall.
pub const PLONK_CHALLENGES: usize = 6;
pub const PLONK_EVALUATIONS: usize = 6;
pub const PLONK_SHARED_OUTPUTS: usize = 9;
pub const PLONK_PER_PROOF_OUTPUTS: usize = 11;
/// Multi-VK output has eight key-local coefficients per context. The ninth
/// shared coefficient (the G1 generator) is collapsed once across all keys.
pub const PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS: usize = 8;
pub const PLONK_REDUCE_MAX_PROOFS: usize = (MSM_MAX_POINTS - PLONK_SHARED_OUTPUTS) / 9;

/// Canonical snarkjs transcript inputs. The verification key contributes
/// `(Qm,Ql,Qr,Qo,Qc,S1,S2,S3)` and each proof contributes
/// `(A,B,C,Z,T1,T2,T3,Wxi,Wxiw)`, all as raw 64-byte EIP-196 G1 encodings.
pub const SNARKJS_PLONK_VK_POINTS: usize = 8;
pub const SNARKJS_PLONK_PROOF_POINTS: usize = 9;

/// Atomic multi-verifying-key PLONK shape packing.
///
/// The syscall ABI has five registers, so the complete dynamic shape is
/// carried in one word: 16 bits of context count, 24 bits of proof count, and
/// 24 bits of flattened public-input count. The arithmetic caps below are far
/// tighter than any of the packed integer maxima.
pub const PLONK_MULTI_VK_COUNT_BITS: u32 = 16;
pub const PLONK_MULTI_VK_PROOF_BITS: u32 = 24;
pub const PLONK_MULTI_VK_PUBLIC_BITS: u32 = 24;
const PLONK_MULTI_VK_24_MASK: u64 = (1u64 << 24) - 1;

pub const fn plonk_reduction_output_count(num_proofs: usize) -> Option<usize> {
    if num_proofs == 0 || num_proofs > PLONK_REDUCE_MAX_PROOFS {
        return None;
    }
    match PLONK_PER_PROOF_OUTPUTS.checked_mul(num_proofs) {
        Some(per_proof) => PLONK_SHARED_OUTPUTS.checked_add(per_proof),
        None => None,
    }
}

/// Pack both declared dynamic dimensions into the syscall's first u64
/// argument so the runtime can charge the complete cost before translating
/// any guest pointer.
pub const fn plonk_reduction_shape(num_proofs: usize, num_public_inputs: usize) -> Option<u64> {
    if num_proofs == 0
        || num_proofs > PLONK_REDUCE_MAX_PROOFS
        || num_public_inputs > u32::MAX as usize
    {
        return None;
    }
    Some(((num_public_inputs as u64) << 32) | num_proofs as u64)
}

pub const fn unpack_plonk_reduction_shape(shape: u64) -> (u64, u64) {
    (shape & u32::MAX as u64, shape >> 32)
}

/// Scalar count returned by the atomic multi-VK reducer.
///
/// Each context owns eight collapsed shared coefficients, the batch owns one
/// global generator coefficient, and each proof owns eleven coefficients.
/// The Q-side MSM has one global generator, eight
/// verifying-key points per context, and nine points per proof.
pub const fn snarkjs_plonk_multi_vk_output_count(
    num_contexts: usize,
    num_proofs: usize,
) -> Option<usize> {
    if num_contexts == 0 || num_proofs == 0 {
        return None;
    }
    let Some(shared) = PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS.checked_mul(num_contexts) else {
        return None;
    };
    let Some(per_proof) = PLONK_PER_PROOF_OUTPUTS.checked_mul(num_proofs) else {
        return None;
    };
    let Some(vk_points) = SNARKJS_PLONK_VK_POINTS.checked_mul(num_contexts) else {
        return None;
    };
    let Some(proof_points) = SNARKJS_PLONK_PROOF_POINTS.checked_mul(num_proofs) else {
        return None;
    };
    let q_points = match vk_points.checked_add(proof_points) {
        Some(value) => match value.checked_add(1) {
            Some(value) => value,
            None => return None,
        },
        None => return None,
    };
    if q_points > MSM_MAX_POINTS || num_proofs > MSM_MAX_POINTS / 2 {
        return None;
    }
    match shared.checked_add(1) {
        Some(value) => value.checked_add(per_proof),
        None => None,
    }
}

/// Pack the exact atomic multi-VK input dimensions.
pub const fn snarkjs_plonk_multi_vk_shape(
    num_contexts: usize,
    num_proofs: usize,
    num_public_inputs: usize,
) -> Option<u64> {
    if snarkjs_plonk_multi_vk_output_count(num_contexts, num_proofs).is_none()
        || num_contexts >= (1usize << PLONK_MULTI_VK_COUNT_BITS)
        || num_proofs >= (1usize << PLONK_MULTI_VK_PROOF_BITS)
        || num_public_inputs >= (1usize << PLONK_MULTI_VK_PUBLIC_BITS)
        || num_public_inputs > FR_MAX_ELEMS
    {
        return None;
    }
    Some(((num_contexts as u64) << 48) | ((num_public_inputs as u64) << 24) | num_proofs as u64)
}

pub const fn unpack_snarkjs_plonk_multi_vk_shape(shape: u64) -> (u64, u64, u64) {
    (
        shape >> 48,
        shape & PLONK_MULTI_VK_24_MASK,
        (shape >> 24) & PLONK_MULTI_VK_24_MASK,
    )
}

#[cfg(not(target_os = "solana"))]
const FQ_BYTES: usize = 32;

#[cfg(not(target_os = "solana"))]
pub(crate) fn bigint_from_be(bytes: &[u8]) -> BigInt<4> {
    debug_assert_eq!(bytes.len(), FQ_BYTES);
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(bytes);
        *limb = u64::from_be_bytes(chunk);
    }
    BigInt::new(limbs)
}

// `from_bigint` returns `None` for values >= the modulus, which is exactly the
// non-canonical rejection the validation order requires before any arithmetic
#[cfg(not(target_os = "solana"))]
fn fq_from_be(bytes: &[u8]) -> Result<Fq, AltBn128BatchError> {
    Fq::from_bigint(bigint_from_be(bytes)).ok_or(AltBn128BatchError::NonCanonical)
}

#[cfg(not(target_os = "solana"))]
pub(crate) fn fq_to_be(value: &Fq, out: &mut [u8]) {
    debug_assert_eq!(out.len(), FQ_BYTES);
    for (out, limb) in out.rchunks_exact_mut(8).zip(value.into_bigint().0) {
        out.copy_from_slice(&limb.to_be_bytes());
    }
}

#[cfg(not(target_os = "solana"))]
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
#[cfg(not(target_os = "solana"))]
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

#[cfg(not(target_os = "solana"))]
pub(crate) fn parse_fr(bytes: &[u8]) -> Result<Fr, AltBn128BatchError> {
    if bytes.len() != SCALAR_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    Fr::from_bigint(bigint_from_be(bytes)).ok_or(AltBn128BatchError::NonCanonical)
}

#[cfg(not(target_os = "solana"))]
pub(crate) fn serialize_g1(point: &G1Affine) -> [u8; G1_BYTES] {
    let mut out = [0u8; G1_BYTES];
    if let Some((x, y)) = point.xy() {
        fq_to_be(&x, &mut out[..FQ_BYTES]);
        fq_to_be(&y, &mut out[FQ_BYTES..]);
    }
    out
}

/// Serialize an Fq12 value without exposing arkworks' Montgomery limbs or
/// in-memory layout.  The coefficient order is the tower order
///
/// `c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1,
///  c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1`,
///
/// where `Fq12 = c0 + c1*w`, every `Fq6 = c0 + c1*v + c2*v^2`, and every
/// `Fq2 = c0 + c1*u`.  Each Fq coefficient is canonical big-endian.
#[cfg(not(target_os = "solana"))]
pub(crate) fn serialize_fq12(value: &Fq12) -> [u8; FQ12_BYTES] {
    let coefficients = [
        &value.c0.c0.c0,
        &value.c0.c0.c1,
        &value.c0.c1.c0,
        &value.c0.c1.c1,
        &value.c0.c2.c0,
        &value.c0.c2.c1,
        &value.c1.c0.c0,
        &value.c1.c0.c1,
        &value.c1.c1.c0,
        &value.c1.c1.c1,
        &value.c1.c2.c0,
        &value.c1.c2.c1,
    ];
    let mut out = [0u8; FQ12_BYTES];
    for (out, coefficient) in out.chunks_exact_mut(FQ_BYTES).zip(coefficients) {
        fq_to_be(coefficient, out);
    }
    out
}

/// Parse the stable Fq12 wire format used by [`serialize_fq12`].  Rejecting
/// coefficients greater than or equal to p prevents alternate encodings of a
/// target-group element.
#[cfg(not(target_os = "solana"))]
pub(crate) fn parse_fq12(bytes: &[u8]) -> Result<Fq12, AltBn128BatchError> {
    if bytes.len() != FQ12_BYTES {
        return Err(AltBn128BatchError::InvalidLength);
    }
    let mut coefficients = bytes.chunks_exact(FQ_BYTES);
    let mut coefficient = || {
        coefficients
            .next()
            .ok_or(AltBn128BatchError::InvalidLength)
            .and_then(fq_from_be)
    };
    Ok(Fq12::new(
        Fq6::new(
            Fq2::new(coefficient()?, coefficient()?),
            Fq2::new(coefficient()?, coefficient()?),
            Fq2::new(coefficient()?, coefficient()?),
        ),
        Fq6::new(
            Fq2::new(coefficient()?, coefficient()?),
            Fq2::new(coefficient()?, coefficient()?),
            Fq2::new(coefficient()?, coefficient()?),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{
            be_add_one, fq_modulus_be, g1_bytes, g2_bytes, random_g1, random_g2, rng,
        },
        ark_ec::AffineRepr,
        ark_ff::{BigInteger, UniformRand},
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

    #[test]
    fn test_fq12_canonical_round_trip_and_coefficient_order() {
        let mut rng = rng();
        for _ in 0..16 {
            let value = Fq12::rand(&mut rng);
            let encoded = serialize_fq12(&value);
            assert_eq!(parse_fq12(&encoded).unwrap(), value);
            assert_eq!(&encoded[0..32], value.c0.c0.c0.into_bigint().to_bytes_be());
            assert_eq!(
                &encoded[11 * 32..12 * 32],
                value.c1.c2.c1.into_bigint().to_bytes_be()
            );
        }
    }

    #[test]
    fn test_fq12_rejects_noncanonical_coefficient_in_every_slot() {
        let modulus = fq_modulus_be();
        for slot in 0..12 {
            let mut encoded = serialize_fq12(&Fq12::from(7u64));
            encoded[slot * 32..(slot + 1) * 32].copy_from_slice(&modulus);
            assert_eq!(
                parse_fq12(&encoded),
                Err(AltBn128BatchError::NonCanonical),
                "slot {slot}"
            );
        }
    }
}
