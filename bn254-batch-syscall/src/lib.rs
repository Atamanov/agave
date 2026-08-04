#![cfg(feature = "agave-unstable-api")]

/// The batch syscall ABI version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// The initial canonical byte ABI.
    V0,
}

pub use crate::{
    encoding::{
        FQ12_BYTES, FR_MAX_ELEMS, G1_BYTES, G2_BYTES, MSM_MAX_POINTS, PAIR_BYTES,
        PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, PLONK_CHALLENGES, PLONK_EVALUATIONS,
        PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS, PLONK_PER_PROOF_OUTPUTS, PLONK_REDUCE_MAX_PROOFS,
        PLONK_SHARED_OUTPUTS, SCALAR_BYTES, SNARKJS_PLONK_PROOF_POINTS, SNARKJS_PLONK_VK_POINTS,
        plonk_reduction_output_count, plonk_reduction_shape, snarkjs_plonk_multi_vk_output_count,
        snarkjs_plonk_multi_vk_shape, unpack_plonk_reduction_shape,
        unpack_snarkjs_plonk_multi_vk_shape,
    },
    pod::{
        PodG1G2Pair, PodG1Point, PodG2Point, PodGtElement, PodPairingResult,
        PodPlonkReductionContext, PodPlonkReductionInput, PodScalar, PodSnarkjsPlonkMultiVkContext,
        PodSnarkjsPlonkMultiVkInput, PodSnarkjsPlonkReductionContext,
        PodSnarkjsPlonkReductionInput,
    },
    validation::AltBn128BatchError,
};
// The wire encoding and the entry-point signatures are the same on both
// targets. Off-chain the arithmetic runs here, on-chain the runtime performs it.
#[cfg(target_os = "solana")]
pub use crate::syscalls::{
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map, alt_bn128_plonk_batch_reduce, alt_bn128_snarkjs_plonk_batch_reduce,
    alt_bn128_snarkjs_plonk_multi_vk_batch_reduce,
};
#[cfg(not(target_os = "solana"))]
pub use crate::{
    backend::{
        alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
        alt_bn128_pairing_map,
    },
    plonk::alt_bn128_plonk_batch_reduce,
    snarkjs_plonk::alt_bn128_snarkjs_plonk_batch_reduce,
    snarkjs_plonk_multi_vk::alt_bn128_snarkjs_plonk_multi_vk_batch_reduce,
};

#[cfg(not(target_os = "solana"))]
pub(crate) mod backend;
mod backend_selection;
pub(crate) mod encoding;
#[cfg(all(
    not(target_os = "solana"),
    any(
        feature = "backend-b1-arkworks",
        not(any(
            feature = "backend-b2-arkworks-optimized",
            feature = "backend-b3-mcl",
            feature = "backend-b4-helios",
            feature = "backend-b5-helios-ifma"
        )),
        test
    )
))]
pub(crate) mod fr;
#[cfg(all(
    not(target_os = "solana"),
    any(
        feature = "backend-b1-arkworks",
        not(any(
            feature = "backend-b2-arkworks-optimized",
            feature = "backend-b3-mcl",
            feature = "backend-b4-helios",
            feature = "backend-b5-helios-ifma"
        )),
        test
    )
))]
pub(crate) mod msm;
#[cfg(all(
    not(target_os = "solana"),
    any(
        feature = "backend-b1-arkworks",
        not(any(
            feature = "backend-b2-arkworks-optimized",
            feature = "backend-b3-mcl",
            feature = "backend-b4-helios",
            feature = "backend-b5-helios-ifma"
        )),
        test
    )
))]
pub(crate) mod pairing;
#[cfg(not(target_os = "solana"))]
pub(crate) mod plonk;
pub(crate) mod pod;
#[cfg(not(target_os = "solana"))]
pub(crate) mod snarkjs_plonk;
#[cfg(not(target_os = "solana"))]
pub(crate) mod snarkjs_plonk_multi_vk;
#[cfg(target_os = "solana")]
pub(crate) mod syscalls;
pub(crate) mod validation;

#[cfg(test)]
pub(crate) mod test_utils {
    use {
        crate::encoding::{G1_BYTES, G2_BYTES, PAIR_BYTES, SCALAR_BYTES, fq_to_be},
        ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        ark_std::rand::{SeedableRng, rngs::StdRng},
        core::ops::{AddAssign, Mul, Neg},
    };

    pub fn rng() -> StdRng {
        StdRng::seed_from_u64(0xa17b428)
    }

    pub fn random_g1(rng: &mut StdRng) -> G1Affine {
        G1Projective::generator().mul(Fr::rand(rng)).into_affine()
    }

    pub fn random_g2(rng: &mut StdRng) -> G2Affine {
        G2Projective::generator().mul(Fr::rand(rng)).into_affine()
    }

    pub fn g1_bytes(point: &G1Affine) -> [u8; G1_BYTES] {
        crate::encoding::serialize_g1(point)
    }

    pub fn g2_bytes(point: &G2Affine) -> [u8; G2_BYTES] {
        let mut out = [0u8; G2_BYTES];
        if let Some((x, y)) = point.xy() {
            fq_to_be(&x.c1, &mut out[0..32]);
            fq_to_be(&x.c0, &mut out[32..64]);
            fq_to_be(&y.c1, &mut out[64..96]);
            fq_to_be(&y.c0, &mut out[96..128]);
        }
        out
    }

    pub fn fr_bytes(scalar: &Fr) -> [u8; SCALAR_BYTES] {
        let mut out = [0u8; SCALAR_BYTES];
        out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
        out
    }

    pub fn pair_bytes(g1: &G1Affine, g2: &G2Affine) -> [u8; PAIR_BYTES] {
        let mut out = [0u8; PAIR_BYTES];
        out[..G1_BYTES].copy_from_slice(&g1_bytes(g1));
        out[G1_BYTES..].copy_from_slice(&g2_bytes(g2));
        out
    }

    pub fn fq_modulus_be() -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Fq::MODULUS.to_bytes_be());
        out
    }

    pub fn fr_modulus_be() -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Fr::MODULUS.to_bytes_be());
        out
    }

    pub fn be_add_one(bytes: &mut [u8; 32]) {
        for byte in bytes.iter_mut().rev() {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                break;
            }
        }
    }

    /// Returns a deterministic on-curve G2 point outside the scalar subgroup.
    pub fn non_subgroup_g2() -> G2Affine {
        for k in 0u64.. {
            let x = Fq2::new(Fq::from(k), Fq::zero());
            if let Some(point) = G2Affine::get_point_from_x_unchecked(x, true) {
                assert!(point.is_on_curve());
                if !point.is_in_correct_subgroup_assuming_on_curve() {
                    return point;
                }
            }
        }
        unreachable!("BN254 twist has non-subgroup points with small x");
    }

    /// Returns `n` pairs over one G2 point whose pairing product is the identity.
    pub fn telescoping_pairs(rng: &mut StdRng, n: usize) -> Vec<u8> {
        assert!(n >= 2, "telescoping construction needs at least two pairs");
        let p = G1Projective::generator();
        let q = G2Projective::generator().mul(Fr::rand(rng)).into_affine();
        let mut sum = Fr::zero();
        let mut out = Vec::with_capacity(n.checked_mul(PAIR_BYTES).unwrap());
        for _ in (0..n).take(n.saturating_sub(1)) {
            let s = Fr::rand(rng);
            sum.add_assign(s);
            out.extend_from_slice(&pair_bytes(&p.mul(s).into_affine(), &q));
        }
        out.extend_from_slice(&pair_bytes(&p.mul(sum.neg()).into_affine(), &q));
        out
    }

    pub fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2));
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
