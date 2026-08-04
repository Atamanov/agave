//! Atomic canonical snarkjs KZG-PLONK reduction across verifying keys.
//!
//! Unlike invoking the same-key reducer once per key, this operation freezes
//! every verifier-resolved key context, key/proof index, statement, proof, and
//! evaluation into one transcript before deriving one independent nonzero
//! randomizer per proof equation. This closes the cross-key cancellation and
//! group-omission surface created by independently seeded per-key calls.
//!
//! Output order is exact and compact:
//! - `9 * num_contexts` Q coefficients, in context order: eight verifying-key
//!   coefficients followed by the context generator coefficient;
//! - `11 * num_proofs` proof-local coefficients, in proof-index order.

use {
    crate::{
        AltBn128BatchError, FR_MAX_ELEMS, PLONK_EVALUATIONS, PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS,
        PLONK_PER_PROOF_OUTPUTS, PodScalar, PodSnarkjsPlonkMultiVkContext,
        PodSnarkjsPlonkMultiVkInput, Version,
        plonk::{NativeProof, reduce_one, validate_context},
        snarkjs_plonk::derive_challenges,
        snarkjs_plonk_multi_vk_output_count,
    },
    ark_bn254::Fr,
    ark_ff::{Field, One, Zero, batch_inversion},
    core::ops::{Add, Mul, Range, Sub},
    solana_keccak_hasher::hashv,
};

const MIN_DOMAIN_SIZE: u64 = 4;
const MAX_DOMAIN_SIZE: u64 = 1 << 28;
const DOMAIN: &[u8] = b"solana-snarkjs-plonk-multi-vk-batch:v1:independent";

struct ParsedContext {
    domain_size: u64,
    num_public_inputs: usize,
    lagrange_count: usize,
    omega: Fr,
    k1: Fr,
    k2: Fr,
}

struct PreparedProof {
    context_index: usize,
    public_range: Range<usize>,
    vanishing: Fr,
    native: NativeProof,
}

/// Host implementation of
/// `sol_alt_bn128_snarkjs_plonk_multi_vk_batch_reduce`.
pub fn alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
    _version: Version,
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let output_count = snarkjs_plonk_multi_vk_output_count(contexts.len(), inputs.len()).ok_or(
        if contexts.is_empty() || inputs.is_empty() {
            AltBn128BatchError::ZeroInput
        } else {
            AltBn128BatchError::CapExceeded
        },
    )?;
    if public_inputs.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut parsed_contexts = Vec::with_capacity(contexts.len());
    for (index, context) in contexts.iter().enumerate() {
        let context_index = usize::try_from(context.context_index())
            .map_err(|_| AltBn128BatchError::IndexMismatch)?;
        if context_index != index {
            return Err(AltBn128BatchError::IndexMismatch);
        }
        if context.reserved != [0u8; 4] || context.reduction.reserved != [0u8; 4] {
            return Err(AltBn128BatchError::InvalidContext);
        }
        if let Some(previous) = index.checked_sub(1).and_then(|i| contexts.get(i)) {
            // Application bindings are verifier-owned canonical context IDs.
            // Requiring strict order gives linear-time uniqueness and makes a
            // context reorder malformed instead of an alternate encoding.
            if previous.application_context >= context.application_context {
                return Err(
                    if previous.application_context == context.application_context {
                        AltBn128BatchError::DuplicateContext
                    } else {
                        AltBn128BatchError::IndexMismatch
                    },
                );
            }
        }

        let domain_size = context.reduction.domain_size();
        let encoded_public_input_count = context.reduction.num_public_inputs();
        let num_public_inputs = usize::try_from(encoded_public_input_count)
            .map_err(|_| AltBn128BatchError::BackendInvariant)?;
        if !domain_size.is_power_of_two()
            || !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&domain_size)
            || u64::from(encoded_public_input_count) >= domain_size
        {
            return Err(AltBn128BatchError::InvalidContext);
        }
        let omega = context.reduction.omega.to_fr()?;
        let k1 = context.reduction.k1.to_fr()?;
        let k2 = context.reduction.k2.to_fr()?;
        validate_context(domain_size, omega, k1, k2)?;
        parsed_contexts.push(ParsedContext {
            domain_size,
            num_public_inputs,
            lagrange_count: num_public_inputs.max(1),
            omega,
            k1,
            k2,
        });
    }

    // Resolve every proof's public-input slice in proof order and validate
    // every canonical scalar before hashing or inversion.
    let mut public_cursor = 0usize;
    let mut uses = vec![0usize; contexts.len()];
    let mut prepared = Vec::with_capacity(inputs.len());
    let mut denominator_count = 0usize;
    for (proof_index, input) in inputs.iter().enumerate() {
        let encoded_proof_index =
            usize::try_from(input.proof_index()).map_err(|_| AltBn128BatchError::IndexMismatch)?;
        if encoded_proof_index != proof_index {
            return Err(AltBn128BatchError::IndexMismatch);
        }
        let context_index = usize::try_from(input.context_index())
            .map_err(|_| AltBn128BatchError::IndexMismatch)?;
        let context = parsed_contexts
            .get(context_index)
            .ok_or(AltBn128BatchError::IndexMismatch)?;
        let use_count = uses
            .get_mut(context_index)
            .ok_or(AltBn128BatchError::IndexMismatch)?;
        *use_count = use_count
            .checked_add(1)
            .ok_or(AltBn128BatchError::CapExceeded)?;

        let public_end = public_cursor
            .checked_add(context.num_public_inputs)
            .ok_or(AltBn128BatchError::CapExceeded)?;
        let encoded_statement = public_inputs
            .get(public_cursor..public_end)
            .ok_or(AltBn128BatchError::LengthMismatch)?;
        let statement = encoded_statement
            .iter()
            .map(PodScalar::to_fr)
            .collect::<Result<Vec<_>, _>>()?;

        let mut evaluations = [Fr::zero(); PLONK_EVALUATIONS];
        for (out, encoded) in evaluations.iter_mut().zip(&input.proof.evaluations) {
            *out = encoded.to_fr()?;
        }
        let challenges = derive_challenges(
            &contexts
                .get(context_index)
                .ok_or(AltBn128BatchError::IndexMismatch)?
                .reduction,
            &input.proof,
            encoded_statement,
        )?;
        let zeta = challenges
            .get(3)
            .copied()
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        let vanishing = zeta.pow([context.domain_size]).sub(Fr::one());
        if vanishing.is_zero() {
            return Err(AltBn128BatchError::DegenerateChallenge);
        }
        denominator_count = denominator_count
            .checked_add(context.lagrange_count)
            .ok_or(AltBn128BatchError::CapExceeded)?;
        if denominator_count > FR_MAX_ELEMS {
            return Err(AltBn128BatchError::CapExceeded);
        }
        prepared.push(PreparedProof {
            context_index,
            public_range: public_cursor..public_end,
            vanishing,
            native: NativeProof {
                challenges,
                evaluations,
                public_inputs: statement,
                rho: Fr::one(),
            },
        });
        public_cursor = public_end;
    }
    if public_cursor != public_inputs.len() {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    if uses.contains(&0) {
        return Err(AltBn128BatchError::UnusedContext);
    }

    let seed = batch_digest(contexts, inputs, public_inputs, &prepared)?;
    for (index, proof) in prepared.iter_mut().enumerate() {
        let index = u64::try_from(index).map_err(|_| AltBn128BatchError::BackendInvariant)?;
        let digest = hashv(&[&seed, b"rho", &index.to_be_bytes()]).to_bytes();
        let mut low = [0u8; 16];
        low.copy_from_slice(&digest[16..]);
        proof.native.rho = Fr::from(u128::from_be_bytes(low)).add(Fr::one());
    }

    let mut denominators = Vec::with_capacity(denominator_count);
    for proof in &prepared {
        let context = parsed_contexts
            .get(proof.context_index)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        let n = Fr::from(context.domain_size);
        let zeta = proof
            .native
            .challenges
            .get(3)
            .copied()
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        let mut root = Fr::one();
        for _ in 0..context.lagrange_count {
            denominators.push(n.mul(zeta.sub(root)));
            root = root.mul(context.omega);
        }
    }
    batch_inversion(&mut denominators);

    let shared_count = PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS
        .checked_mul(contexts.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut output = vec![PodScalar([0u8; 32]); output_count];
    let mut shared = vec![[Fr::zero(); PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS]; contexts.len()];

    let (shared_output, proof_output) = output.split_at_mut(shared_count);
    let mut proof_rows = proof_output.chunks_exact_mut(PLONK_PER_PROOF_OUTPUTS);
    let mut remaining_denominators = denominators.as_slice();
    for proof in prepared {
        let context = parsed_contexts
            .get(proof.context_index)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        let (inverses, remaining) = remaining_denominators
            .split_at_checked(context.lagrange_count)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        remaining_denominators = remaining;
        let reduced = reduce_one(
            context.omega,
            context.k1,
            context.k2,
            &proof.native,
            proof.vanishing,
            inverses,
        )?;

        let context_shared = shared
            .get_mut(proof.context_index)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        reduced.accumulate_shared(proof.native.rho, context_shared)?;

        let row = proof_rows
            .next()
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        for (slot, scalar) in row.iter_mut().zip(reduced.weighted_row(proof.native.rho)) {
            *slot = PodScalar::from(&scalar);
        }
    }
    if !remaining_denominators.is_empty() || !proof_rows.into_remainder().is_empty() {
        return Err(AltBn128BatchError::BackendInvariant);
    }

    let mut context_rows = shared_output.chunks_exact_mut(PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS);
    for (row, coefficients) in (&mut context_rows).zip(shared) {
        for (slot, scalar) in row.iter_mut().zip(coefficients) {
            *slot = PodScalar::from(&scalar);
        }
    }
    if !context_rows.into_remainder().is_empty() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    Ok(output)
}

#[cfg(test)]
fn diagnostic_snarkjs_plonk_multi_vk_batch_digest(
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
) -> Result<[u8; 32], AltBn128BatchError> {
    // The reducer validates the complete input before the test reads its digest.
    alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, contexts, inputs, public_inputs)?;
    let mut cursor = 0usize;
    let mut prepared = Vec::with_capacity(inputs.len());
    for input in inputs {
        let context_index = usize::try_from(input.context_index())
            .map_err(|_| AltBn128BatchError::BackendInvariant)?;
        let encoded_count = contexts
            .get(context_index)
            .ok_or(AltBn128BatchError::BackendInvariant)?
            .reduction
            .num_public_inputs();
        let count =
            usize::try_from(encoded_count).map_err(|_| AltBn128BatchError::BackendInvariant)?;
        let public_end = cursor
            .checked_add(count)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        prepared.push(PreparedProof {
            context_index,
            public_range: cursor..public_end,
            vanishing: Fr::zero(),
            native: NativeProof {
                challenges: [Fr::zero(); 6],
                evaluations: [Fr::zero(); PLONK_EVALUATIONS],
                public_inputs: Vec::new(),
                rho: Fr::one(),
            },
        });
        cursor = public_end;
    }
    batch_digest(contexts, inputs, public_inputs, &prepared)
}

fn batch_digest(
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
    prepared: &[PreparedProof],
) -> Result<[u8; 32], AltBn128BatchError> {
    if inputs.len() != prepared.len() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    let context_count = u64::try_from(contexts.len())
        .map_err(|_| AltBn128BatchError::BackendInvariant)?
        .to_be_bytes();
    let proof_count = u64::try_from(inputs.len())
        .map_err(|_| AltBn128BatchError::BackendInvariant)?
        .to_be_bytes();
    let public_count = u64::try_from(public_inputs.len())
        .map_err(|_| AltBn128BatchError::BackendInvariant)?
        .to_be_bytes();
    let context_parts = contexts.iter().try_fold(4usize, |total, context| {
        let parts = context
            .reduction
            .transcript_vk_points
            .len()
            .checked_add(9)
            .ok_or(AltBn128BatchError::CapExceeded)?;
        total
            .checked_add(parts)
            .ok_or(AltBn128BatchError::CapExceeded)
    })?;
    let capacity =
        inputs
            .iter()
            .zip(prepared)
            .try_fold(context_parts, |total, (input, proof)| {
                let statement_parts = proof
                    .public_range
                    .end
                    .checked_sub(proof.public_range.start)
                    .ok_or(AltBn128BatchError::BackendInvariant)?;
                let proof_parts = input
                    .proof
                    .transcript_points
                    .len()
                    .checked_add(input.proof.evaluations.len())
                    .and_then(|value| value.checked_add(statement_parts))
                    .and_then(|value| value.checked_add(2))
                    .ok_or(AltBn128BatchError::CapExceeded)?;
                total
                    .checked_add(proof_parts)
                    .ok_or(AltBn128BatchError::CapExceeded)
            })?;
    let mut parts: Vec<&[u8]> = Vec::with_capacity(capacity);
    parts.extend([DOMAIN, &context_count, &proof_count, &public_count]);
    for context in contexts {
        parts.push(&context.context_index_be);
        parts.push(&context.application_context);
        parts.push(&context.reduction.domain_size_be);
        parts.push(&context.reduction.num_public_inputs_be);
        parts.push(&context.reduction.omega.0);
        parts.push(&context.reduction.k1.0);
        parts.push(&context.reduction.k2.0);
        for point in &context.reduction.transcript_vk_points {
            parts.push(&point.0);
        }
        parts.push(&context.reduction.x_2.0);
        parts.push(&context.g2_gen.0);
    }
    for (input, proof) in inputs.iter().zip(prepared) {
        parts.push(&input.proof_index_be);
        parts.push(&input.context_index_be);
        let statement = public_inputs
            .get(proof.public_range.clone())
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        for public in statement {
            parts.push(&public.0);
        }
        for point in &input.proof.transcript_points {
            parts.push(&point.0);
        }
        for evaluation in &input.proof.evaluations {
            parts.push(&evaluation.0);
        }
    }
    Ok(hashv(&parts).to_bytes())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            PodG1Point, PodG2Point, PodSnarkjsPlonkReductionContext, PodSnarkjsPlonkReductionInput,
            SNARKJS_PLONK_PROOF_POINTS, SNARKJS_PLONK_VK_POINTS,
        },
        ark_ff::FftField,
    };

    fn reduction(seed: u8) -> PodSnarkjsPlonkReductionContext {
        PodSnarkjsPlonkReductionContext {
            domain_size_be: 8u64.to_be_bytes(),
            num_public_inputs_be: 1u32.to_be_bytes(),
            reserved: [0u8; 4],
            omega: PodScalar::from(&Fr::get_root_of_unity(8).unwrap()),
            k1: PodScalar::from(&Fr::from(2u64)),
            k2: PodScalar::from(&Fr::from(3u64)),
            transcript_vk_points: core::array::from_fn(|i| {
                let mut bytes = [0u8; 64];
                bytes[31] = seed;
                bytes[63] = u8::try_from(i).unwrap_or(u8::MAX).saturating_add(1);
                PodG1Point(bytes)
            }),
            x_2: {
                let mut bytes = [0u8; 128];
                bytes[31] = seed;
                bytes[127] = 42;
                PodG2Point(bytes)
            },
        }
    }

    fn context(index: u32, application_id: u8, seed: u8) -> PodSnarkjsPlonkMultiVkContext {
        PodSnarkjsPlonkMultiVkContext {
            context_index_be: index.to_be_bytes(),
            reserved: [0u8; 4],
            application_context: [application_id; 32],
            reduction: reduction(seed),
            g2_gen: {
                let mut bytes = [0u8; 128];
                bytes[0] = seed;
                bytes[127] = 1;
                PodG2Point(bytes)
            },
        }
    }

    fn proof(index: u32, context_index: u32, seed: u8) -> PodSnarkjsPlonkMultiVkInput {
        PodSnarkjsPlonkMultiVkInput {
            proof_index_be: index.to_be_bytes(),
            context_index_be: context_index.to_be_bytes(),
            proof: PodSnarkjsPlonkReductionInput {
                transcript_points: core::array::from_fn(|i| {
                    let mut bytes = [0u8; 64];
                    bytes[31] = seed;
                    bytes[63] = u8::try_from(i).unwrap_or(u8::MAX).saturating_add(1);
                    PodG1Point(bytes)
                }),
                evaluations: core::array::from_fn(|i| {
                    let value = u64::from(seed)
                        .saturating_add(u64::try_from(i).unwrap_or(u64::MAX))
                        .saturating_add(11);
                    PodScalar::from(&Fr::from(value))
                }),
            },
        }
    }

    fn fixture() -> (
        [PodSnarkjsPlonkMultiVkContext; 2],
        [PodSnarkjsPlonkMultiVkInput; 2],
        [PodScalar; 2],
    ) {
        (
            [context(0, 1, 7), context(1, 2, 9)],
            [proof(0, 0, 11), proof(1, 1, 13)],
            [
                PodScalar::from(&Fr::from(101u64)),
                PodScalar::from(&Fr::from(103u64)),
            ],
        )
    }

    #[test]
    fn atomic_multi_vk_output_is_deterministic_canonical_and_exactly_sized() {
        let (contexts, proofs, publics) = fixture();
        let first = alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
            Version::V0,
            &contexts,
            &proofs,
            &publics,
        )
        .unwrap();
        let second = alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
            Version::V0,
            &contexts,
            &proofs,
            &publics,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 2 * PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS + 2 * 11);
        assert!(first.iter().all(|scalar| scalar.to_fr().is_ok()));
    }

    #[test]
    fn joint_digest_binds_contexts_proofs_publics_and_pairing_operands() {
        let (contexts, proofs, publics) = fixture();
        let baseline =
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&contexts, &proofs, &publics).unwrap();

        let mut changed = contexts;
        changed[0].application_context[0] = 0;
        assert_ne!(
            baseline,
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&changed, &proofs, &publics).unwrap()
        );

        let mut changed = contexts;
        changed[1].reduction.transcript_vk_points[0].0[0] ^= 1;
        assert_ne!(
            baseline,
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&changed, &proofs, &publics).unwrap()
        );

        let mut changed = contexts;
        changed[1].g2_gen.0[0] ^= 1;
        assert_ne!(
            baseline,
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&changed, &proofs, &publics).unwrap()
        );

        let mut changed_proofs = proofs;
        changed_proofs[1].proof.transcript_points[0].0[0] ^= 1;
        assert_ne!(
            baseline,
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&contexts, &changed_proofs, &publics,)
                .unwrap()
        );

        let mut changed_publics = publics;
        changed_publics[1] = PodScalar::from(&Fr::from(107u64));
        assert_ne!(
            baseline,
            diagnostic_snarkjs_plonk_multi_vk_batch_digest(&contexts, &proofs, &changed_publics,)
                .unwrap()
        );
    }

    #[test]
    fn rejects_noncanonical_indices_duplicates_unused_contexts_and_lengths() {
        let (contexts, proofs, publics) = fixture();

        let mut changed = contexts;
        changed[1].context_index_be = 7u32.to_be_bytes();
        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, &changed, &proofs, &publics,),
            Err(AltBn128BatchError::IndexMismatch)
        );

        let mut changed = contexts;
        changed[1].application_context = changed[0].application_context;
        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, &changed, &proofs, &publics,),
            Err(AltBn128BatchError::DuplicateContext)
        );

        let only_first = [proofs[0]];
        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
                Version::V0,
                &contexts,
                &only_first,
                &publics[..1],
            ),
            Err(AltBn128BatchError::UnusedContext)
        );

        let mut changed_proofs = proofs;
        changed_proofs[1].proof_index_be = 0u32.to_be_bytes();
        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
                Version::V0,
                &contexts,
                &changed_proofs,
                &publics,
            ),
            Err(AltBn128BatchError::IndexMismatch)
        );

        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
                Version::V0,
                &contexts,
                &proofs,
                &publics[..1],
            ),
            Err(AltBn128BatchError::LengthMismatch)
        );
        assert_eq!(
            alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, &[], &[], &[]),
            Err(AltBn128BatchError::ZeroInput)
        );
    }

    #[test]
    fn shape_pack_round_trip_and_caps_are_exact() {
        assert_eq!(SNARKJS_PLONK_VK_POINTS, 8);
        assert_eq!(SNARKJS_PLONK_PROOF_POINTS, 9);
        let shape = crate::snarkjs_plonk_multi_vk_shape(2, 3, 5).unwrap();
        assert_eq!(crate::unpack_snarkjs_plonk_multi_vk_shape(shape), (2, 3, 5));
        assert_eq!(
            crate::snarkjs_plonk_multi_vk_output_count(2, 3),
            Some(2 * 9 + 3 * 11)
        );
        assert!(crate::snarkjs_plonk_multi_vk_shape(1, 226, 0).is_some());
        assert!(crate::snarkjs_plonk_multi_vk_shape(1, 227, 0).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(226, 1, 0).is_some());
        assert!(crate::snarkjs_plonk_multi_vk_shape(227, 1, 0).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(0, 3, 5).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(2, 0, 5).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(2, 3, FR_MAX_ELEMS + 1).is_none());
    }
}
