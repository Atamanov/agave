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
        PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair, PodG2Point, PodGtElement, PodPairingResult,
        PodPlonkReductionContext, PodPlonkReductionInput, PodScalar, PodSnarkjsPlonkMultiVkContext,
        PodSnarkjsPlonkMultiVkInput, PodSnarkjsPlonkReductionContext,
        PodSnarkjsPlonkReductionInput, PodTrustedGtExponent,
    },
    registry_abi::{
        REGISTRY_ABI_VERSION, REGISTRY_G2_ENTRY_BYTES, REGISTRY_GT_ENTRY_BYTES,
        REGISTRY_HEADER_BYTES, REGISTRY_MAX_G2_ENTRIES, REGISTRY_MAX_GT_ENTRIES,
        REGISTRY_MAX_REGISTERED_PAIRS, REGISTRY_PREPARED_G2_BYTES, pack_gt_multiexp_shape,
        pack_registered_pairing_shape, pack_registry_init_shape, registry_account_len,
    },
    validation::AltBn128BatchError,
};
// The wire encoding and the entry-point signatures are the same on both
// targets. Off-chain the arithmetic runs here, on-chain the runtime performs it.
#[cfg(target_os = "solana")]
pub use crate::syscalls::{
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_check_registered, alt_bn128_pairing_map, alt_bn128_plonk_batch_reduce,
    alt_bn128_snarkjs_plonk_batch_reduce, alt_bn128_snarkjs_plonk_multi_vk_batch_reduce,
    alt_bn128_trusted_gt_multiexp, alt_bn128_vk_registry_init,
};
#[cfg(not(target_os = "solana"))]
pub use crate::{
    backend::alt_bn128_fr_batch_invert, plonk::alt_bn128_plonk_batch_reduce,
    snarkjs_plonk::alt_bn128_snarkjs_plonk_batch_reduce,
    snarkjs_plonk_multi_vk::alt_bn128_snarkjs_plonk_multi_vk_batch_reduce,
};

#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub use crate::backend::{
    RegisteredG2, RegisteredG2Pair, TrustedGt, registered_g2_from_authenticated_bytes,
    trusted_gt_from_authenticated_bytes, trusted_gt_from_pair, trusted_gt_to_bytes,
};

#[cfg(not(target_os = "solana"))]
pub use crate::backend::{FinalExponentiationProbe, FinalExponentiationResult, G2SubgroupProbe};

#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub const PREPARED_G2_BYTES: usize = helius_bn254::PREPARED_G2_BYTES;

#[cfg(not(target_os = "solana"))]
pub fn alt_bn128_g1_msm(
    version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    let result = backend::alt_bn128_g1_msm(version, points, scalars);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_msm(points.len());
    }
    result
}

#[cfg(not(target_os = "solana"))]
pub fn alt_bn128_fr_lincomb(
    version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    let result = backend::alt_bn128_fr_lincomb(version, a, b);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_fr_lincomb(a.len());
    }
    result
}

#[cfg(not(target_os = "solana"))]
pub fn alt_bn128_pairing_check(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let result = backend::alt_bn128_pairing_check(version, pairs);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        let nonidentity = research_observer::nonidentity_pairs(pairs);
        research_observer::record_pairing_check(pairs.len(), nonidentity);
        #[cfg(all(
            any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
            not(feature = "backend-b1-arkworks"),
            not(feature = "backend-b2-arkworks-optimized"),
            not(feature = "backend-b3-mcl")
        ))]
        if helius_bn254::selects_ifma_batch8(nonidentity) {
            research_observer::record_ifma_batch8_dispatch();
        }
    }
    result
}

#[cfg(not(target_os = "solana"))]
pub fn alt_bn128_pairing_map(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128BatchError> {
    let result = backend::alt_bn128_pairing_map(version, pairs);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        let nonidentity = research_observer::nonidentity_pairs(pairs);
        research_observer::record_pairing_map(pairs.len(), nonidentity);
        #[cfg(all(
            any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
            not(feature = "backend-b1-arkworks"),
            not(feature = "backend-b2-arkworks-optimized"),
            not(feature = "backend-b3-mcl")
        ))]
        if helius_bn254::selects_ifma_batch8(nonidentity) {
            research_observer::record_ifma_batch8_dispatch();
        }
    }
    result
}

#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub fn pairing_check_registered(
    full: &[PodG1G2Pair],
    registered: &[RegisteredG2Pair],
) -> Result<bool, AltBn128BatchError> {
    let result = backend::pairing_check_registered(full, registered);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        let nonidentity = research_observer::nonidentity_pairs(full).saturating_add(
            registered
                .iter()
                .filter(|pair| pair.g1.0.iter().any(|byte| *byte != 0))
                .count(),
        );
        research_observer::record_registered(full.len(), registered.len(), nonidentity);
        if helius_bn254::selects_ifma_batch8(nonidentity) {
            research_observer::record_ifma_mixed_batch8_dispatch();
        }
    }
    result
}

#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub fn validate_registered_g2(source: &PodG2Point) -> Result<RegisteredG2, AltBn128BatchError> {
    let result = backend::validate_registered_g2(source);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_registry_g2_preparation();
    }
    result
}

#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub fn trusted_gt_multiexp(
    targets: &[TrustedGt],
    exponents: &[PodScalar],
) -> Result<PodGtElement, AltBn128BatchError> {
    let result = backend::trusted_gt_multiexp(targets, exponents);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_gt_multiexp(exponents);
    }
    result
}

#[cfg(not(target_os = "solana"))]
pub fn probe_g2_subgroup(source: &PodG2Point) -> Result<bool, AltBn128BatchError> {
    let probe = prepare_g2_subgroup_probe(source)?;
    run_g2_subgroup_probe(&probe)
}

/// Decodes and checks the curve equation outside the measured subgroup predicate.
#[cfg(not(target_os = "solana"))]
pub fn prepare_g2_subgroup_probe(
    source: &PodG2Point,
) -> Result<G2SubgroupProbe, AltBn128BatchError> {
    backend::prepare_g2_subgroup_probe(source)
}

/// Runs only the selected backend's subgroup-membership predicate.
#[cfg(not(target_os = "solana"))]
pub fn run_g2_subgroup_probe(probe: &G2SubgroupProbe) -> Result<bool, AltBn128BatchError> {
    let result = backend::run_g2_subgroup_probe(probe);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_subgroup_probe();
    }
    result
}

#[cfg(not(target_os = "solana"))]
pub fn prepare_final_exponentiation_probe(
    pairs: &[PodG1G2Pair],
) -> Result<FinalExponentiationProbe, AltBn128BatchError> {
    backend::prepare_final_exponentiation_probe(pairs)
}

#[cfg(not(target_os = "solana"))]
pub fn run_final_exponentiation_probe(
    probe: &FinalExponentiationProbe,
) -> Result<FinalExponentiationResult, AltBn128BatchError> {
    let result = backend::run_final_exponentiation_probe(probe);
    #[cfg(feature = "research-observer")]
    if result.is_ok() {
        research_observer::record_final_exp_probe();
    }
    result
}

/// Encodes a final-exponentiation result outside the measured operation.
#[cfg(not(target_os = "solana"))]
pub fn encode_final_exponentiation_result(
    result: &FinalExponentiationResult,
) -> Result<PodGtElement, AltBn128BatchError> {
    backend::encode_final_exponentiation_result(result)
}

/// Compile-time attestation for the linked B5 AVX-512 IFMA artifact.
#[cfg(all(
    not(target_os = "solana"),
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub const fn selected_backend_compiled_with_avx512_ifma() -> bool {
    helius_bn254::AVX512_IFMA_COMPILED
}

/// Compile-time attestation is false for every non-Helius backend.
#[cfg(all(
    not(target_os = "solana"),
    not(all(
        any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
        not(feature = "backend-b1-arkworks"),
        not(feature = "backend-b2-arkworks-optimized"),
        not(feature = "backend-b3-mcl")
    ))
))]
pub const fn selected_backend_compiled_with_avx512_ifma() -> bool {
    false
}

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
            feature = "backend-b4-helius",
            feature = "backend-b5-helius-ifma"
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
            feature = "backend-b4-helius",
            feature = "backend-b5-helius-ifma"
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
            feature = "backend-b4-helius",
            feature = "backend-b5-helius-ifma"
        )),
        test
    )
))]
pub(crate) mod pairing;
#[cfg(not(target_os = "solana"))]
pub(crate) mod plonk;
pub(crate) mod pod;
pub(crate) mod registry_abi;
#[cfg(all(not(target_os = "solana"), feature = "research-observer"))]
pub mod research_observer;
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
