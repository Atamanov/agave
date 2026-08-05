//! Dedicated target-comparison batching for vanilla Groth16 proofs under one
//! authenticated verifying key.
//!
//! For coefficients whose sum is one, the `alpha/beta` side of every proof
//! collapses to the single immutable target `T = e(alpha, beta)`. The dynamic
//! product therefore needs only one pair per proof plus one gamma and one
//! delta fold. The pairing-map result is compared byte-for-byte with `T`; no
//! target-group exponentiation or second native call is involved.

use {
    crate::{
        Groth16BatchError,
        transcript::{RandomizerMode, derive_seed, small_plus_lo128},
        verify::{
            MINUS_ONE_BE, ONE_BE, Proof, fr_inner_product, fr_negate, fr_sum, fr_to_pod,
            is_canonical_fr_be, msm, validate_batch_shape,
        },
        vk::ValidatedVerifyingKey,
    },
    ark_bn254::Fr,
    ark_ff::{One, Zero},
    core::ops::{AddAssign, Sub},
    solana_bn254_batch_syscall::{
        PAIRING_MAP_MAX_PAIRS, PodG1G2Pair, PodG1Point, PodGtElement, PodScalar,
        Version as SyscallVersion, alt_bn128_pairing_map,
    },
    solana_keccak_hasher::hashv,
};

/// Sixteen proof-specific pairs plus the folded gamma and delta terms.
pub const SAME_VK_FP12_MAX_PROOFS: usize = PAIRING_MAP_MAX_PAIRS - 2;

const TRANSCRIPT_DOMAIN: &[u8] = b"solana-bn254-groth16-same-vk-target:v1:affine-sum-one";
const COEFFICIENT_DOMAIN: &[u8] = b"coef";

/// The offset that lifts a 128-bit draw off zero and off one. It also puts the
/// tail sum strictly above one, which is what makes the affine first
/// coefficient nonzero.
const TAIL_OFFSET: u8 = 2;

const ZERO_BE: [u8; 32] = [0u8; 32];

/// A canonical GT target paired with one complete validated verifying-key
/// digest.
///
/// This value carries no provenance or authentication capability. In
/// particular, Rust lifetimes cannot distinguish a compiled literal from
/// runtime bytes leaked into a `'static` allocation. The concrete verifier
/// handler must establish the trust boundary: either embed this complete
/// record in its artifact, or authenticate owner/PDA/version/frozen state for
/// an account-backed record before calling this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SameVkTarget {
    vk_digest: [u8; 32],
    target: PodGtElement,
}

impl SameVkTarget {
    /// Construct a target record after the concrete handler has established
    /// its provenance. The handler's build/test pipeline must independently
    /// prove that `target == e(alpha, beta)` for the key named by `vk_digest`;
    /// the hot verifier deliberately does not recompute that pairing.
    pub const fn new(vk_digest: [u8; 32], target: PodGtElement) -> Self {
        Self { vk_digest, target }
    }

    /// Return the canonical bytes used for the direct map comparison.
    pub const fn target(&self) -> &PodGtElement {
        &self.target
    }

    fn for_key(&self, vk: &ValidatedVerifyingKey) -> Result<&PodGtElement, Groth16BatchError> {
        if self.vk_digest != *vk.digest() {
            return Err(Groth16BatchError::SameVkTargetKeyMismatch);
        }
        Ok(&self.target)
    }
}

/// Verify vanilla Groth16 proofs under exactly one key by comparing a single
/// `n + 2` pairing-map output with a caller-authenticated target.
///
/// `application_context` is a fixed-width digest chosen by the consumer. It
/// must bind the deployment/ABI and any application state whose substitution
/// would change the meaning of the batch. The function binds it and the
/// supplied target into the Fiat-Shamir transcript, but deliberately does not
/// establish its provenance or recompute it in the hot path.
pub fn groth16_same_vk_fp12_verify(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    authenticated_target: &SameVkTarget,
) -> Result<bool, Groth16BatchError> {
    validate_same_vk_target_shape(vk, proofs)?;
    let target = authenticated_target.for_key(vk)?;
    let randomizers = derive_same_vk_sum_one_randomizer_scalars_prevalidated(
        vk,
        proofs,
        application_context,
        target,
    )?;
    let pairs = fold_same_vk_target_pairs_prevalidated(vk, proofs, &randomizers)?;
    let mapped = alt_bn128_pairing_map(SyscallVersion::V0, &pairs)?;
    Ok(mapped == *target)
}

/// Return the exact map shape for a valid same-VK target batch.
pub fn same_vk_target_pair_count(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
) -> Result<usize, Groth16BatchError> {
    validate_same_vk_target_shape(vk, proofs)?;
    proofs
        .len()
        .checked_add(2)
        .ok_or(Groth16BatchError::TooManyPairs)
}

/// Derive independent nonzero 128-bit tail coefficients and an affine first
/// coefficient so that the complete vector sums to exactly one in Fr.
///
/// For `1 < n <= 16`, every tail is in `[2, 2^128 + 1]`. Their sum is
/// therefore strictly between one and the BN254 scalar modulus, which proves
/// that the affine first coefficient is nonzero without rejection sampling.
/// For `n = 1`, the sole coefficient is one.
pub fn derive_same_vk_sum_one_randomizers(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    authenticated_target: &SameVkTarget,
) -> Result<Vec<Fr>, Groth16BatchError> {
    validate_same_vk_target_shape(vk, proofs)?;
    let target = authenticated_target.for_key(vk)?;
    derive_same_vk_sum_one_randomizers_prevalidated(vk, proofs, application_context, target)
}

fn derive_same_vk_sum_one_randomizers_prevalidated(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    target: &PodGtElement,
) -> Result<Vec<Fr>, Groth16BatchError> {
    let seed = same_vk_transcript_seed(vk, proofs, application_context, target);

    let mut randomizers = Vec::with_capacity(proofs.len());
    randomizers.push(Fr::zero());
    let mut tail_sum = Fr::zero();
    for index in 1..proofs.len() {
        let mut coefficient = Fr::from(u128::from_be_bytes(tail_draw(&seed, index)));
        coefficient.add_assign(Fr::from(u64::from(TAIL_OFFSET)));
        debug_assert!(!coefficient.is_zero());
        tail_sum.add_assign(coefficient);
        randomizers.push(coefficient);
    }
    randomizers[0] = Fr::one().sub(tail_sum);

    if randomizers.iter().any(Zero::is_zero) || randomizers.iter().copied().sum::<Fr>() != Fr::one()
    {
        return Err(Groth16BatchError::InvalidSameVkRandomizers);
    }
    Ok(randomizers)
}

/// [`derive_same_vk_sum_one_randomizers`] in the canonical big-endian encoding
/// the MSM and inner-product syscalls consume, which is the form the fold
/// actually needs.
///
/// A tail is `TAIL_OFFSET + lo128(digest)`, at most `2^128 + 1`, so it is built
/// in bytes with no reduction. Only the affine first coefficient wraps, and it
/// is one inner product against `-1`.
/// `derived_scalars_are_the_field_derivation` pins the whole vector against
/// [`reference_derive_same_vk_sum_one_randomizers`] element by element.
fn derive_same_vk_sum_one_randomizer_scalars_prevalidated(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    target: &PodGtElement,
) -> Result<Vec<PodScalar>, Groth16BatchError> {
    let seed = same_vk_transcript_seed(vk, proofs, application_context, target);

    let mut randomizers = Vec::with_capacity(proofs.len());
    randomizers.push(ONE_BE);
    for index in 1..proofs.len() {
        randomizers.push(small_plus_lo128(TAIL_OFFSET, &tail_draw(&seed, index)));
    }
    let first = affine_first_coefficient(randomizers.get(1..).unwrap_or_default())?;
    randomizers[0] = first;

    check_sum_one_randomizers(&randomizers)?;
    Ok(randomizers)
}

/// The Fiat-Shamir seed both derivations draw from, so neither can drift from
/// the other's transcript.
fn same_vk_transcript_seed(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    target: &PodGtElement,
) -> [u8; 32] {
    let batch_seed = derive_seed(
        RandomizerMode::Independent,
        core::slice::from_ref(vk),
        proofs,
    );
    hashv(&[
        TRANSCRIPT_DOMAIN,
        application_context,
        &batch_seed,
        &target.0,
    ])
    .to_bytes()
}

/// The low 128 bits of the coefficient digest for a one-based tail position.
fn tail_draw(seed: &[u8; 32], index: usize) -> [u8; 16] {
    let index = (index as u64).to_be_bytes();
    let digest = hashv(&[seed, COEFFICIENT_DOMAIN, &index]).to_bytes();
    let mut low = [0u8; 16];
    low.copy_from_slice(&digest[16..]);
    low
}

/// `1 - sum(tails)` in one inner product.
///
/// Every tail is at most `2^128 + 1` and there are at most
/// `SAME_VK_FP12_MAX_PROOFS - 1` of them, so the integer tail sum stays inside
/// `[2, r)` and can never equal one. The difference is therefore nonzero
/// without rejection sampling, which is the invariant the fold's constant IC
/// coefficient of `-1` rests on.
/// `the_tail_sum_stays_between_one_and_the_modulus` pins the bound.
fn affine_first_coefficient(tails: &[PodScalar]) -> Result<PodScalar, Groth16BatchError> {
    if tails.is_empty() {
        return Ok(ONE_BE);
    }
    let mut left = Vec::with_capacity(tails.len().saturating_add(1));
    left.push(ONE_BE);
    left.extend_from_slice(tails);
    let mut right = vec![MINUS_ONE_BE; left.len()];
    right[0] = ONE_BE;
    fr_inner_product(&left, &right)
}

/// Reject any coefficient vector that would invalidate the fold's constant IC
/// coefficient of `-1`: every entry must be a canonical nonzero scalar and the
/// whole vector must sum to exactly one in Fr.
fn check_sum_one_randomizers(randomizers: &[PodScalar]) -> Result<(), Groth16BatchError> {
    let usable = !randomizers.is_empty()
        && randomizers
            .iter()
            .all(|randomizer| randomizer.0 != ZERO_BE && is_canonical_fr_be(randomizer));
    if !usable || fr_sum(randomizers)? != ONE_BE {
        return Err(Groth16BatchError::InvalidSameVkRandomizers);
    }
    Ok(())
}

/// Build exactly `n + 2` dynamic pairs, excluding `alpha/beta` entirely.
/// The caller may supply coefficients from a joint transcript, but this
/// checked surface requires all of them to be nonzero and their sum to be one.
pub fn fold_same_vk_target_pairs(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    validate_same_vk_target_shape(vk, proofs)?;
    let coefficients: Vec<PodScalar> = randomizers.iter().map(fr_to_pod).collect();
    fold_same_vk_target_pairs_prevalidated(vk, proofs, &coefficients)
}

fn fold_same_vk_target_pairs_prevalidated(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    coefficients: &[PodScalar],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    if coefficients.len() != proofs.len() {
        return Err(Groth16BatchError::RandomizerCountMismatch);
    }
    // the derivation is the producer of these and checks the same invariant,
    // but the fold is also a public surface and its -1 constant depends on it
    check_sum_one_randomizers(coefficients)?;

    let pair_count = proofs
        .len()
        .checked_add(2)
        .ok_or(Groth16BatchError::TooManyPairs)?;
    // every key-side term of a coefficient enters the fold negated, so -c_i is
    // derived once and serves both the gamma columns and the delta MSM
    let neg_coefficients = coefficients
        .iter()
        .map(fr_negate)
        .collect::<Result<Vec<PodScalar>, _>>()?;

    let mut pairs = Vec::with_capacity(pair_count);
    for (proof, coefficient) in proofs.iter().zip(coefficients) {
        pairs.push(PodG1G2Pair {
            g1: msm(
                core::slice::from_ref(&proof.a),
                core::slice::from_ref(coefficient),
            )?,
            g2: proof.b,
        });
    }

    let key = vk.key();
    // sum(c_i) = 1, so the constant IC coefficient is exactly -1.
    let mut gamma_points: Vec<PodG1Point> = vec![key.ic[0]];
    let mut gamma_scalars: Vec<PodScalar> = vec![MINUS_ONE_BE];
    // column j is the inner product <-c, x_j>, one scalar-field call
    let mut column: Vec<PodScalar> = Vec::with_capacity(proofs.len());
    for (input_index, ic) in key.ic.iter().enumerate().skip(1) {
        let input_index = input_index
            .checked_sub(1)
            .ok_or(Groth16BatchError::InputCountMismatch)?;
        column.clear();
        for proof in proofs {
            let input = proof
                .public_inputs
                .get(input_index)
                .ok_or(Groth16BatchError::InputCountMismatch)?;
            // The syscall also rejects a non-canonical scalar, but the reject
            // stays here so an unvalidated batch fails with the input error
            // rather than a backend-shaped one.
            if !is_canonical_fr_be(input) {
                return Err(Groth16BatchError::NonCanonicalInput);
            }
            column.push(*input);
        }
        gamma_points.push(*ic);
        gamma_scalars.push(fr_inner_product(&neg_coefficients, &column)?);
    }
    pairs.push(PodG1G2Pair {
        g1: msm(&gamma_points, &gamma_scalars)?,
        g2: key.gamma_g2,
    });

    let delta_points: Vec<PodG1Point> = proofs.iter().map(|proof| proof.c).collect();
    pairs.push(PodG1G2Pair {
        g1: msm(&delta_points, &neg_coefficients)?,
        g2: key.delta_g2,
    });

    if pairs.len() != pair_count {
        return Err(Groth16BatchError::TooManyPairs);
    }
    Ok(pairs)
}

fn validate_same_vk_target_shape(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
) -> Result<(), Groth16BatchError> {
    validate_batch_shape(core::slice::from_ref(vk), proofs)?;
    if vk.key().pedersen.is_some() {
        return Err(Groth16BatchError::SameVkTargetRequiresVanillaKey);
    }
    if proofs.len() > SAME_VK_FP12_MAX_PROOFS {
        return Err(Groth16BatchError::TooManyPairs);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            test_utils::{g1, g1_bytes, make_proof, make_vk, rng},
            verify::ProofCommitment,
        },
        ark_bn254::{Bn254, Fr, G1Affine},
        ark_ec::{AffineRepr, CurveGroup, pairing::Pairing},
        ark_ff::{Field, One, UniformRand},
        solana_bn254_batch_syscall::PodG1Point,
    };

    const CONTEXT: [u8; 32] = [0x53; 32];

    fn fixture(n: usize) -> (ValidatedVerifyingKey, Vec<Proof>, SameVkTarget) {
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng, 1, false);
        let proofs = (0..n)
            .map(|_| {
                let input = Fr::rand(&mut rng);
                make_proof(&mut rng, &trapdoor, 0, &[input])
            })
            .collect();
        let target = Bn254::pairing(
            vk.key().alpha_g1.to_affine().unwrap(),
            vk.key().beta_g2.to_affine().unwrap(),
        );
        let target = PodGtElement::from(&target.0);
        let authenticated = SameVkTarget::new(*vk.digest(), target);
        (vk, proofs, authenticated)
    }

    #[test]
    fn valid_batches_use_n_plus_two_pairs_and_match_the_static_target() {
        for n in [1usize, 2, 5, SAME_VK_FP12_MAX_PROOFS] {
            let (vk, proofs, target) = fixture(n);
            let coefficients =
                derive_same_vk_sum_one_randomizers(&vk, &proofs, &CONTEXT, &target).unwrap();
            assert_eq!(coefficients.len(), n);
            assert!(
                coefficients
                    .iter()
                    .all(|coefficient| !coefficient.is_zero())
            );
            assert_eq!(coefficients.iter().copied().sum::<Fr>(), Fr::one());
            assert_eq!(same_vk_target_pair_count(&vk, &proofs), Ok(n + 2));

            let pairs = fold_same_vk_target_pairs(&vk, &proofs, &coefficients).unwrap();
            assert_eq!(pairs.len(), n + 2);
            assert_eq!(
                alt_bn128_pairing_map(SyscallVersion::V0, &pairs),
                Ok(*target.target())
            );
            assert_eq!(
                groth16_same_vk_fp12_verify(&vk, &proofs, &CONTEXT, &target),
                Ok(true)
            );
        }
    }

    #[test]
    fn transcript_binds_context_target_proof_statement_count_and_order() {
        let (vk, proofs, target) = fixture(5);
        let baseline = derive_same_vk_sum_one_randomizers(&vk, &proofs, &CONTEXT, &target).unwrap();

        let mut context = CONTEXT;
        context[0] ^= 1;
        assert_ne!(
            baseline,
            derive_same_vk_sum_one_randomizers(&vk, &proofs, &context, &target).unwrap()
        );

        let mut other_target_bytes = *target.target();
        other_target_bytes.0[0] ^= 1;
        let other_target = SameVkTarget::new(*vk.digest(), other_target_bytes);
        assert_ne!(
            baseline,
            derive_same_vk_sum_one_randomizers(&vk, &proofs, &CONTEXT, &other_target).unwrap()
        );

        let mut mutated = proofs.clone();
        mutated[0].public_inputs[0].0[31] ^= 1;
        assert_ne!(
            baseline,
            derive_same_vk_sum_one_randomizers(&vk, &mutated, &CONTEXT, &target).unwrap()
        );

        let mut reordered = proofs.clone();
        reordered.swap(0, 1);
        assert_ne!(
            baseline,
            derive_same_vk_sum_one_randomizers(&vk, &reordered, &CONTEXT, &target).unwrap()
        );
        assert_ne!(
            baseline[..4],
            derive_same_vk_sum_one_randomizers(&vk, &proofs[..4], &CONTEXT, &target).unwrap()[..]
        );
    }

    #[test]
    fn coefficient_derivation_is_exactly_low_128_bits_plus_two() {
        let (vk, proofs, target) = fixture(5);
        let coefficients =
            derive_same_vk_sum_one_randomizers(&vk, &proofs, &CONTEXT, &target).unwrap();
        let batch_seed = derive_seed(
            RandomizerMode::Independent,
            core::slice::from_ref(&vk),
            &proofs,
        );
        let seed =
            hashv(&[TRANSCRIPT_DOMAIN, &CONTEXT, &batch_seed, &target.target().0]).to_bytes();
        let mut tail_sum = Fr::zero();
        for (index, coefficient) in coefficients.iter().enumerate().skip(1) {
            let index = (index as u64).to_be_bytes();
            let digest = hashv(&[&seed, COEFFICIENT_DOMAIN, &index]).to_bytes();
            let mut low = [0u8; 16];
            low.copy_from_slice(&digest[16..]);
            let expected = Fr::from(u128::from_be_bytes(low)) + Fr::from(2u64);
            assert_eq!(*coefficient, expected);
            tail_sum += expected;
        }
        assert_eq!(coefficients[0], Fr::one() - tail_sum);
    }

    #[test]
    fn direct_byte_comparison_rejects_target_and_proof_mutations() {
        let (vk, proofs, target) = fixture(5);

        let mut wrong_target_bytes = *target.target();
        wrong_target_bytes.0[31] ^= 1;
        let wrong_target = SameVkTarget::new(*vk.digest(), wrong_target_bytes);
        assert_eq!(
            groth16_same_vk_fp12_verify(&vk, &proofs, &CONTEXT, &wrong_target),
            Ok(false)
        );

        let mut bad = proofs.clone();
        let point = bad[2].c.to_affine().unwrap();
        bad[2].c = PodG1Point::from(&(point + g1(Fr::one())).into_affine());
        assert_eq!(
            groth16_same_vk_fp12_verify(&vk, &bad, &CONTEXT, &target),
            Ok(false)
        );
    }

    #[test]
    fn cancellation_attack_with_unit_weights_is_rejected_by_derived_weights() {
        let (vk, mut proofs, target) = fixture(2);
        let d = g1(Fr::from(9u64));
        let c0 = proofs[0].c.to_affine().unwrap();
        let c1 = proofs[1].c.to_affine().unwrap();
        proofs[0].c = g1_bytes(&(c0 + d).into_affine());
        proofs[1].c = g1_bytes(&(c1 - d).into_affine());

        let unit_sum = [Fr::from(2u64).inverse().unwrap(); 2];
        let naive = fold_same_vk_target_pairs(&vk, &proofs, &unit_sum).unwrap();
        assert_eq!(
            alt_bn128_pairing_map(SyscallVersion::V0, &naive),
            Ok(*target.target()),
            "equal weights demonstrate the cancelling-error attack"
        );
        assert_eq!(
            groth16_same_vk_fp12_verify(&vk, &proofs, &CONTEXT, &target),
            Ok(false)
        );
    }

    #[test]
    fn rejects_committed_keys_bad_indices_randomizers_and_the_cap() {
        let (vk, proofs, target) = fixture(1);
        assert_eq!(
            fold_same_vk_target_pairs(&vk, &proofs, &[]),
            Err(Groth16BatchError::RandomizerCountMismatch)
        );
        assert_eq!(
            fold_same_vk_target_pairs(&vk, &proofs, &[Fr::zero()]),
            Err(Groth16BatchError::InvalidSameVkRandomizers)
        );

        let mut bad_index = proofs.clone();
        bad_index[0].vk_index = 1;
        assert_eq!(
            groth16_same_vk_fp12_verify(&vk, &bad_index, &CONTEXT, &target),
            Err(Groth16BatchError::UnknownVerifyingKey)
        );

        let mut rng = rng();
        let (committed_trapdoor, committed_vk) = make_vk(&mut rng, 1, true);
        let committed_proof = make_proof(&mut rng, &committed_trapdoor, 0, &[Fr::one()]);
        let committed_target = Bn254::pairing(
            committed_vk.key().alpha_g1.to_affine().unwrap(),
            committed_vk.key().beta_g2.to_affine().unwrap(),
        );
        let committed_target = SameVkTarget::new(
            *committed_vk.digest(),
            PodGtElement::from(&committed_target.0),
        );
        assert_eq!(
            groth16_same_vk_fp12_verify(
                &committed_vk,
                &[committed_proof],
                &CONTEXT,
                &committed_target,
            ),
            Err(Groth16BatchError::SameVkTargetRequiresVanillaKey)
        );

        let (_, max_proofs, _) = fixture(SAME_VK_FP12_MAX_PROOFS);
        let mut over_cap = max_proofs;
        over_cap.push(over_cap[0].clone());
        assert_eq!(
            same_vk_target_pair_count(&vk, &over_cap),
            Err(Groth16BatchError::TooManyPairs)
        );

        let mut commitment_on_vanilla = proofs.clone();
        commitment_on_vanilla[0].commitment = Some(ProofCommitment {
            com: g1_bytes(&G1Affine::generator()),
            pok: g1_bytes(&G1Affine::generator()),
        });
        assert_eq!(
            same_vk_target_pair_count(&vk, &commitment_on_vanilla),
            Err(Groth16BatchError::CommitmentMismatch)
        );
        let mut wrong_digest = *vk.digest();
        wrong_digest[0] ^= 1;
        let other_key_target = SameVkTarget::new(wrong_digest, *target.target());
        assert_eq!(
            groth16_same_vk_fp12_verify(&vk, &proofs, &CONTEXT, &other_key_target),
            Err(Groth16BatchError::SameVkTargetKeyMismatch)
        );
    }
}

/// The derivation this module shipped before the coefficients moved into the
/// byte domain, self-contained down to the digest so that a change to either
/// the shared transcript helpers or the byte arithmetic fails
/// [`derived_scalars_are_the_field_derivation`].
#[cfg(test)]
fn reference_derive_same_vk_sum_one_randomizers(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    application_context: &[u8; 32],
    target: &PodGtElement,
) -> Result<Vec<Fr>, Groth16BatchError> {
    let batch_seed = derive_seed(
        RandomizerMode::Independent,
        core::slice::from_ref(vk),
        proofs,
    );
    let seed = hashv(&[
        TRANSCRIPT_DOMAIN,
        application_context,
        &batch_seed,
        &target.0,
    ])
    .to_bytes();

    let mut randomizers = Vec::with_capacity(proofs.len());
    randomizers.push(Fr::zero());
    let mut tail_sum = Fr::zero();
    for index in 1..proofs.len() {
        let index = (index as u64).to_be_bytes();
        let digest = hashv(&[&seed, COEFFICIENT_DOMAIN, &index]).to_bytes();
        let mut low = [0u8; 16];
        low.copy_from_slice(&digest[16..]);
        let mut coefficient = Fr::from(u128::from_be_bytes(low));
        coefficient.add_assign(Fr::from(2u64));
        debug_assert!(!coefficient.is_zero());
        tail_sum.add_assign(coefficient);
        randomizers.push(coefficient);
    }
    randomizers[0] = Fr::one().sub(tail_sum);

    if randomizers.iter().any(Zero::is_zero) || randomizers.iter().copied().sum::<Fr>() != Fr::one()
    {
        return Err(Groth16BatchError::InvalidSameVkRandomizers);
    }
    Ok(randomizers)
}

/// The fold this module shipped before the coefficients moved into the
/// scalar-field syscall, kept as the bit-exactness reference for
/// [`fold_identity_tests`].
#[cfg(test)]
fn reference_fold_same_vk_target_pairs(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    use {
        crate::verify::fr_from_be,
        core::ops::{Mul, Neg},
    };

    if randomizers.len() != proofs.len() {
        return Err(Groth16BatchError::RandomizerCountMismatch);
    }
    if randomizers.iter().any(Zero::is_zero) || randomizers.iter().copied().sum::<Fr>() != Fr::one()
    {
        return Err(Groth16BatchError::InvalidSameVkRandomizers);
    }

    let pair_count = proofs
        .len()
        .checked_add(2)
        .ok_or(Groth16BatchError::TooManyPairs)?;
    let mut pairs = Vec::with_capacity(pair_count);
    for (proof, coefficient) in proofs.iter().zip(randomizers) {
        pairs.push(PodG1G2Pair {
            g1: msm(
                core::slice::from_ref(&proof.a),
                core::slice::from_ref(&fr_to_pod(coefficient)),
            )?,
            g2: proof.b,
        });
    }

    let key = vk.key();
    let mut gamma_points: Vec<PodG1Point> = vec![key.ic[0]];
    let mut gamma_scalars: Vec<Fr> = vec![Fr::one().neg()];
    for (input_index, ic) in key.ic.iter().enumerate().skip(1) {
        let input_index = input_index
            .checked_sub(1)
            .ok_or(Groth16BatchError::InputCountMismatch)?;
        let mut coefficient = Fr::zero();
        for (proof, randomizer) in proofs.iter().zip(randomizers) {
            let input = proof
                .public_inputs
                .get(input_index)
                .ok_or(Groth16BatchError::InputCountMismatch)?;
            coefficient.add_assign(randomizer.mul(&fr_from_be(input)?));
        }
        gamma_points.push(*ic);
        gamma_scalars.push(coefficient.neg());
    }
    let gamma_scalars: Vec<PodScalar> = gamma_scalars.iter().map(fr_to_pod).collect();
    pairs.push(PodG1G2Pair {
        g1: msm(&gamma_points, &gamma_scalars)?,
        g2: key.gamma_g2,
    });

    let delta_points: Vec<PodG1Point> = proofs.iter().map(|proof| proof.c).collect();
    let delta_scalars: Vec<PodScalar> = randomizers
        .iter()
        .map(|coefficient| fr_to_pod(&coefficient.neg()))
        .collect();
    pairs.push(PodG1G2Pair {
        g1: msm(&delta_points, &delta_scalars)?,
        g2: key.delta_g2,
    });

    if pairs.len() != pair_count {
        return Err(Groth16BatchError::TooManyPairs);
    }
    Ok(pairs)
}

#[cfg(test)]
mod fold_identity_tests {
    use {
        super::*,
        crate::test_utils::{fr_bytes, make_proof, make_vk, rng},
        ark_ff::{BigInteger, PrimeField, UniformRand},
        ark_std::rand::rngs::StdRng,
    };

    const CONTEXT: [u8; 32] = [0x53; 32];

    const R_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    /// A batch and a target record bound to its key. Every surface under test
    /// checks shape before it looks at the target, so the target bytes here
    /// need no pairing provenance.
    fn fixture(n: usize) -> (ValidatedVerifyingKey, Vec<Proof>, SameVkTarget) {
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng, 1, false);
        let proofs = (0..n)
            .map(|_| {
                let input = Fr::rand(&mut rng);
                make_proof(&mut rng, &trapdoor, 0, &[input])
            })
            .collect();
        let target = SameVkTarget::new(*vk.digest(), PodGtElement([7u8; 384]));
        (vk, proofs, target)
    }

    /// Every batch shape this fold distinguishes: one proof, several proofs, a
    /// zero-input circuit, a multi-column circuit, and a committed key. The
    /// committed key never reaches the checked surface, which rejects it, but
    /// the prevalidated fold must still not diverge on one.
    fn batches() -> Vec<(&'static str, ValidatedVerifyingKey, Vec<Proof>)> {
        let mut rng = rng();
        let mut out = Vec::new();
        for (label, n, inputs, committed) in [
            ("n1", 1usize, 1usize, false),
            ("n2", 2, 1, false),
            ("n5", 5, 1, false),
            ("n16", SAME_VK_FP12_MAX_PROOFS, 1, false),
            ("zero_inputs_n3", 3, 0, false),
            ("four_inputs_n3", 3, 4, false),
            ("committed_n3", 3, 1, true),
        ] {
            let (trapdoor, vk) = make_vk(&mut rng, inputs, committed);
            let proofs = (0..n)
                .map(|_| {
                    let values: Vec<Fr> = (0..inputs).map(|_| Fr::rand(&mut rng)).collect();
                    make_proof(&mut rng, &trapdoor, 0, &values)
                })
                .collect();
            out.push((label, vk, proofs));
        }
        out
    }

    /// A coefficient vector of the shape the fold requires: every entry
    /// nonzero and the whole vector summing to one.
    fn sum_to_one(tail: &[Fr]) -> Vec<Fr> {
        let mut out = Vec::with_capacity(tail.len().saturating_add(1));
        out.push(Fr::one().sub(tail.iter().copied().sum::<Fr>()));
        out.extend_from_slice(tail);
        out
    }

    fn random_sum_to_one(rng: &mut StdRng, n: usize) -> Vec<Fr> {
        let tail: Vec<Fr> = (1..n).map(|_| Fr::rand(rng)).collect();
        sum_to_one(&tail)
    }

    fn assert_same_fold(
        label: &str,
        vk: &ValidatedVerifyingKey,
        proofs: &[Proof],
        randomizers: &[Fr],
    ) {
        let coefficients: Vec<PodScalar> = randomizers.iter().map(fr_to_pod).collect();
        let expected = reference_fold_same_vk_target_pairs(vk, proofs, randomizers);
        let folded = fold_same_vk_target_pairs_prevalidated(vk, proofs, &coefficients);
        match (&expected, &folded) {
            (Ok(expected), Ok(folded)) => {
                assert_eq!(expected.len(), folded.len(), "{label}: pair count");
                for (index, (expected, folded)) in expected.iter().zip(folded).enumerate() {
                    assert_eq!(expected, folded, "{label}: pair {index}");
                }
            }
            _ => assert_eq!(expected, folded, "{label}"),
        }
    }

    /// The fold must be bit-identical to the field-arithmetic reference over
    /// the transcript's own coefficients, on every shape and on the verifying
    /// surface that consumes them.
    #[test]
    fn derived_coefficients_fold_identically() {
        for (label, vk, proofs) in batches() {
            let target = SameVkTarget::new(*vk.digest(), PodGtElement([7u8; 384]));
            let randomizers = derive_same_vk_sum_one_randomizers_prevalidated(
                &vk,
                &proofs,
                &CONTEXT,
                target.target(),
            )
            .expect("derivation must produce a sum-one vector");
            assert_eq!(randomizers.len(), proofs.len());
            assert_same_fold(label, &vk, &proofs, &randomizers);

            let scalars = derive_same_vk_sum_one_randomizer_scalars_prevalidated(
                &vk,
                &proofs,
                &CONTEXT,
                target.target(),
            )
            .expect("byte derivation must produce a sum-one vector");
            let expected = reference_fold_same_vk_target_pairs(&vk, &proofs, &randomizers);
            let folded = fold_same_vk_target_pairs_prevalidated(&vk, &proofs, &scalars);
            assert_eq!(expected, folded, "{label}: byte-derived fold");
        }
    }

    /// The byte derivation must reproduce the field derivation exactly. It
    /// feeds the MSM scalars, so a divergence changes the statement the
    /// pairing check proves while still verifying.
    #[test]
    fn derived_scalars_are_the_field_derivation() {
        for (label, vk, proofs) in batches() {
            for context in [CONTEXT, [0u8; 32], [0xff; 32]] {
                let target = SameVkTarget::new(*vk.digest(), PodGtElement([7u8; 384]));
                let expected: Vec<PodScalar> = reference_derive_same_vk_sum_one_randomizers(
                    &vk,
                    &proofs,
                    &context,
                    target.target(),
                )
                .expect("reference derivation")
                .iter()
                .map(fr_to_pod)
                .collect();
                let live = derive_same_vk_sum_one_randomizers_prevalidated(
                    &vk,
                    &proofs,
                    &context,
                    target.target(),
                )
                .expect("field derivation");
                let scalars = derive_same_vk_sum_one_randomizer_scalars_prevalidated(
                    &vk,
                    &proofs,
                    &context,
                    target.target(),
                )
                .expect("byte derivation");
                assert_eq!(scalars.len(), proofs.len(), "{label}");
                for (index, expected) in expected.iter().enumerate() {
                    assert_eq!(scalars.get(index), Some(expected), "{label} scalar {index}");
                    assert_eq!(
                        live.get(index).map(fr_to_pod).as_ref(),
                        Some(expected),
                        "{label} field {index}"
                    );
                }
            }
        }
    }

    type Big = <Fr as PrimeField>::BigInt;

    /// A 32-byte big-endian scalar as an exact integer, so the wrap can be
    /// checked outside the field the code under test computes in.
    fn big_from_be(bytes: &[u8; 32]) -> Big {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.rchunks_exact(8)) {
            let mut buffer = [0u8; 8];
            buffer.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(buffer);
        }
        Big::new(limbs)
    }

    /// The affine first coefficient over tail vectors the keccak draw cannot be
    /// steered to: both ends of the 128-bit range, every admissible length, and
    /// mixed vectors. Every nonempty case wraps, and the wrap is pinned against
    /// exact integer arithmetic, not against the subtraction under test.
    #[test]
    fn affine_first_coefficient_matches_the_field_subtraction() {
        let draws = [
            0u128,
            1,
            2,
            1 << 127,
            u128::MAX - 2,
            u128::MAX - 1,
            u128::MAX,
        ];
        let mut vectors: Vec<Vec<u128>> = Vec::new();
        for draw in draws {
            for count in 0..SAME_VK_FP12_MAX_PROOFS {
                vectors.push(vec![draw; count]);
            }
        }
        vectors.push(draws.to_vec());
        vectors.push(draws.iter().rev().copied().collect());

        let one = Big::new([1, 0, 0, 0]);
        for draws in vectors {
            let tails: Vec<PodScalar> = draws
                .iter()
                .map(|draw| small_plus_lo128(TAIL_OFFSET, &draw.to_be_bytes()))
                .collect();
            let first = affine_first_coefficient(&tails).expect("affine coefficient");

            let field_sum: Fr = draws
                .iter()
                .map(|draw| Fr::from(*draw) + Fr::from(u64::from(TAIL_OFFSET)))
                .sum();
            assert_eq!(first, fr_to_pod(&Fr::one().sub(field_sum)));

            let mut integer_sum = Big::new([0; 4]);
            for tail in &tails {
                assert!(!integer_sum.add_with_carry(&big_from_be(&tail.0)));
            }
            if draws.is_empty() {
                assert_eq!(first, ONE_BE);
                continue;
            }
            // the tail sum never reduces and never reaches one, so 1 - tail_sum
            // is negative in the integers and the canonical answer is
            // r + 1 - tail_sum
            assert!(integer_sum < Fr::MODULUS, "tail sum must not reduce");
            assert!(integer_sum > one, "1 - tail_sum must wrap");
            let mut expected = Fr::MODULUS;
            assert!(!expected.add_with_carry(&one));
            assert!(!expected.sub_with_borrow(&integer_sum));
            assert_eq!(first.0.as_slice(), expected.to_bytes_be());
        }
    }

    /// The bound the nonzero claim rests on, at the largest batch the surface
    /// admits: the widest possible tail sum still cannot reach r, so it cannot
    /// reduce, and the narrowest is already above one.
    #[test]
    fn the_tail_sum_stays_between_one_and_the_modulus() {
        let tails = SAME_VK_FP12_MAX_PROOFS
            .checked_sub(1)
            .expect("the surface admits at least one proof");
        assert!(tails >= 1);
        // (2^128 - 1) + TAIL_OFFSET, the largest tail the draw can produce
        let largest = big_from_be(&small_plus_lo128(TAIL_OFFSET, &u128::MAX.to_be_bytes()).0);
        let mut expected = Big::new([0, 0, 1, 0]);
        assert!(!expected.sub_with_borrow(&Big::new([1, 0, 0, 0])));
        assert!(!expected.add_with_carry(&Big::new([u64::from(TAIL_OFFSET), 0, 0, 0])));
        assert_eq!(largest, expected);

        let mut widest = Big::new([0; 4]);
        for _ in 0..tails {
            assert!(
                !widest.add_with_carry(&largest),
                "tail sum overflowed 256 bits"
            );
        }
        assert!(widest < Fr::MODULUS, "the widest tail sum must not reduce");
        assert!(u64::from(TAIL_OFFSET) > 1, "the narrowest tail exceeds one");
    }

    /// Coefficient vectors at the edges of the field, still nonzero and still
    /// summing to one, plus a random vector so no two positions can alias.
    #[test]
    fn edge_coefficients_fold_identically() {
        let mut rng = rng();
        let tails = [
            Fr::from(2u64),
            Fr::zero().sub(Fr::one()),
            Fr::from(1u128 << 127),
            Fr::from(u128::MAX) + Fr::one(),
            Fr::from(u128::MAX),
        ];
        for (label, vk, proofs) in batches() {
            let n = proofs.len();
            for (index, tail) in tails.iter().enumerate() {
                if n == 1 {
                    continue;
                }
                let randomizers = sum_to_one(&vec![*tail; n.saturating_sub(1)]);
                if randomizers.iter().any(Zero::is_zero) {
                    continue;
                }
                assert_same_fold(
                    &format!("{label}/uniform-tail{index}"),
                    &vk,
                    &proofs,
                    &randomizers,
                );
            }
            assert_same_fold(
                &format!("{label}/one-only"),
                &vk,
                &proofs,
                &sum_to_one(&vec![Fr::zero(); n.saturating_sub(1)]),
            );
            assert_same_fold(
                &format!("{label}/random"),
                &vk,
                &proofs,
                &random_sum_to_one(&mut rng, n),
            );
        }
    }

    /// Public inputs at the ends of the canonical range, where a byte path
    /// that skipped the field would be most likely to diverge.
    #[test]
    fn edge_public_inputs_fold_identically() {
        let mut r_minus_one = R_BE;
        r_minus_one[31] = 0x00;
        let mut two_pow_128 = [0u8; 32];
        two_pow_128[15] = 1;
        let edges = [
            PodScalar([0u8; 32]),
            fr_bytes(&Fr::one()),
            PodScalar(r_minus_one),
            PodScalar(two_pow_128),
        ];

        let mut rng = rng();
        for (label, vk, proofs) in batches() {
            let randomizers = random_sum_to_one(&mut rng, proofs.len());
            for (index, edge) in edges.iter().enumerate() {
                let mut mutated = proofs.clone();
                for proof in &mut mutated {
                    for input in &mut proof.public_inputs {
                        *input = *edge;
                    }
                }
                assert_same_fold(
                    &format!("{label}/all-inputs-{index}"),
                    &vk,
                    &mutated,
                    &randomizers,
                );

                // and one input at a time, so a column with mixed values is
                // also covered
                let mut single = proofs.clone();
                if let Some(input) = single
                    .first_mut()
                    .and_then(|proof| proof.public_inputs.first_mut())
                {
                    *input = *edge;
                    assert_same_fold(
                        &format!("{label}/first-input-{index}"),
                        &vk,
                        &single,
                        &randomizers,
                    );
                }
            }
        }
    }

    /// A public input at or above r stays rejected, with the same error, on
    /// every surface that reaches this fold.
    #[test]
    fn non_canonical_public_input_is_still_rejected() {
        let (vk, proofs, target) = fixture(2);
        let mut r_plus_one = R_BE;
        r_plus_one[31] = 0x02;
        let coefficients = sum_to_one(&[Fr::from(2u64)]);
        let scalars: Vec<PodScalar> = coefficients.iter().map(fr_to_pod).collect();

        for bad in [R_BE, r_plus_one, [0xffu8; 32]] {
            for position in [0usize, 1] {
                let mut mutated = proofs.clone();
                mutated[position].public_inputs[0] = PodScalar(bad);
                assert_eq!(
                    fold_same_vk_target_pairs_prevalidated(&vk, &mutated, &scalars),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "prevalidated fold, position {position}"
                );
                assert_eq!(
                    fold_same_vk_target_pairs(&vk, &mutated, &coefficients),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "checked fold, position {position}"
                );
                assert_eq!(
                    groth16_same_vk_fp12_verify(&vk, &mutated, &CONTEXT, &target),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "verify, position {position}"
                );
                assert_eq!(
                    derive_same_vk_sum_one_randomizers(&vk, &mutated, &CONTEXT, &target),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "derivation, position {position}"
                );
            }
        }
    }

    /// The sum-to-one and nonzero invariants gate the fold before any scalar
    /// leaves the field, and the constant IC coefficient of -1 depends on them.
    #[test]
    fn coefficients_that_break_the_sum_one_invariant_are_rejected() {
        let (vk, proofs, _) = fixture(3);
        let broken = [
            vec![Fr::one(), Fr::one(), Fr::one()],
            vec![Fr::one(), Fr::zero(), Fr::zero()],
            sum_to_one(&[Fr::one(), Fr::from(3u64)])
                .iter()
                .map(|c| *c * Fr::from(2u64))
                .collect(),
            vec![Fr::zero().sub(Fr::one()); 3],
        ];
        for (index, randomizers) in broken.iter().enumerate() {
            let scalars: Vec<PodScalar> = randomizers.iter().map(fr_to_pod).collect();
            assert_eq!(
                fold_same_vk_target_pairs(&vk, &proofs, randomizers),
                Err(Groth16BatchError::InvalidSameVkRandomizers),
                "case {index}"
            );
            assert_eq!(
                fold_same_vk_target_pairs_prevalidated(&vk, &proofs, &scalars),
                Err(Groth16BatchError::InvalidSameVkRandomizers),
                "prevalidated case {index}"
            );
        }
        assert_eq!(
            fold_same_vk_target_pairs(&vk, &proofs, &[Fr::one()]),
            Err(Groth16BatchError::RandomizerCountMismatch)
        );
    }

    /// The byte fold reaches the same verdict on vectors the field surface
    /// cannot express: a zero, a scalar at or above r, and a sum that misses
    /// one by the modulus itself.
    #[test]
    fn byte_coefficients_that_break_the_sum_one_invariant_are_rejected() {
        let (vk, proofs, _) = fixture(3);
        let two = small_plus_lo128(TAIL_OFFSET, &[0u8; 16]);
        let broken: [Vec<PodScalar>; 6] = [
            vec![],
            vec![ONE_BE, ONE_BE, ONE_BE],
            vec![PodScalar(ZERO_BE), ONE_BE, MINUS_ONE_BE],
            vec![PodScalar(R_BE), two, MINUS_ONE_BE],
            vec![PodScalar([0xff; 32]), two, MINUS_ONE_BE],
            vec![two, two, MINUS_ONE_BE],
        ];
        for (index, scalars) in broken.iter().enumerate() {
            assert_eq!(
                check_sum_one_randomizers(scalars),
                Err(Groth16BatchError::InvalidSameVkRandomizers),
                "check case {index}"
            );
            if scalars.len() == proofs.len() {
                assert_eq!(
                    fold_same_vk_target_pairs_prevalidated(&vk, &proofs, scalars),
                    Err(Groth16BatchError::InvalidSameVkRandomizers),
                    "fold case {index}"
                );
            }
        }

        // and the vector the derivation actually produces still passes
        let target = SameVkTarget::new(*vk.digest(), PodGtElement([7u8; 384]));
        let derived = derive_same_vk_sum_one_randomizer_scalars_prevalidated(
            &vk,
            &proofs,
            &CONTEXT,
            target.target(),
        )
        .expect("byte derivation");
        assert_eq!(check_sum_one_randomizers(&derived), Ok(()));
    }
}
