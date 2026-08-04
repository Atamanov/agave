//! Atomic canonical snarkjs KZG-PLONK reduction across verifying keys.
//!
//! Unlike invoking the same-key reducer once per key, this operation freezes
//! every verifier-resolved key context, key/proof index, statement, proof, and
//! evaluation into one transcript before deriving one independent nonzero
//! randomizer per proof equation. This closes the cross-key cancellation and
//! group-omission surface created by independently seeded per-key calls.
//!
//! Output order is exact and compact:
//! - `8 * num_contexts` key-local Q coefficients, in context order;
//! - one generator coefficient collapsed across every context;
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
    public_start: usize,
    public_end: usize,
    denominator_start: usize,
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
        if context.context_index() as usize != index {
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
        let num_public_inputs = context.reduction.num_public_inputs() as usize;
        if !domain_size.is_power_of_two()
            || !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&domain_size)
            || num_public_inputs >= domain_size as usize
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
        if input.proof_index() as usize != proof_index {
            return Err(AltBn128BatchError::IndexMismatch);
        }
        let context_index = input.context_index() as usize;
        let context = parsed_contexts
            .get(context_index)
            .ok_or(AltBn128BatchError::IndexMismatch)?;
        uses[context_index] = uses[context_index]
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
            &contexts[context_index].reduction,
            &input.proof,
            encoded_statement,
        );
        let vanishing = challenges[3].pow([context.domain_size]) - Fr::one();
        if vanishing.is_zero() {
            return Err(AltBn128BatchError::DegenerateChallenge);
        }
        let denominator_start = denominator_count;
        denominator_count = denominator_count
            .checked_add(context.lagrange_count)
            .ok_or(AltBn128BatchError::CapExceeded)?;
        if denominator_count > FR_MAX_ELEMS {
            return Err(AltBn128BatchError::CapExceeded);
        }
        prepared.push(PreparedProof {
            context_index,
            public_start: public_cursor,
            public_end,
            denominator_start,
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

    let seed = batch_digest(contexts, inputs, public_inputs, &prepared);
    for (index, proof) in prepared.iter_mut().enumerate() {
        let digest = hashv(&[&seed, b"rho", &(index as u64).to_be_bytes()]).to_bytes();
        let mut low = [0u8; 16];
        low.copy_from_slice(&digest[16..]);
        proof.native.rho = Fr::from(u128::from_be_bytes(low)) + Fr::one();
    }

    let mut denominators = Vec::with_capacity(denominator_count);
    for proof in &prepared {
        let context = &parsed_contexts[proof.context_index];
        let n = Fr::from(context.domain_size);
        let zeta = proof.native.challenges[3];
        let mut root = Fr::one();
        for _ in 0..context.lagrange_count {
            denominators.push(n * (zeta - root));
            root *= context.omega;
        }
    }
    batch_inversion(&mut denominators);

    let shared_count = PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS * contexts.len();
    let generator_index = shared_count;
    let proof_outputs_start = generator_index + 1;
    let mut output = vec![PodScalar([0u8; 32]); output_count];
    let mut shared = vec![[Fr::zero(); PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS]; contexts.len()];
    let mut generator = Fr::zero();

    for (proof_index, proof) in prepared.into_iter().enumerate() {
        let context = &parsed_contexts[proof.context_index];
        let inverse_end = proof.denominator_start + context.lagrange_count;
        let reduced = reduce_one(
            context.domain_size,
            context.omega,
            context.k1,
            context.k2,
            &proof.native,
            proof.vanishing,
            &denominators[proof.denominator_start..inverse_end],
        );

        for (accumulator, coefficient) in
            shared[proof.context_index].iter_mut().zip(reduced.shared_q)
        {
            *accumulator -= proof.native.rho * coefficient;
        }
        generator -= proof.native.rho * reduced.generator;

        let base = proof_outputs_start + proof_index * PLONK_PER_PROOF_OUTPUTS;
        let per = [
            proof.native.rho,
            proof.native.rho * reduced.p_shifted,
            -(proof.native.rho * reduced.z),
            -(proof.native.rho * reduced.t_lo),
            -(proof.native.rho * reduced.t_mid),
            -(proof.native.rho * reduced.t_hi),
            -(proof.native.rho * reduced.a),
            -(proof.native.rho * reduced.b),
            -(proof.native.rho * reduced.c),
            -(proof.native.rho * reduced.w_zeta_q),
            -(proof.native.rho * reduced.w_zeta_omega_q),
        ];
        for (slot, scalar) in output[base..base + PLONK_PER_PROOF_OUTPUTS]
            .iter_mut()
            .zip(per)
        {
            *slot = PodScalar::from(&scalar);
        }
    }

    for (context_index, coefficients) in shared.into_iter().enumerate() {
        let base = context_index * PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS;
        for (slot, scalar) in output[base..base + PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS]
            .iter_mut()
            .zip(coefficients)
        {
            *slot = PodScalar::from(&scalar);
        }
    }
    output[generator_index] = PodScalar::from(&generator);
    Ok(output)
}

/// Host-only hook used by transcript-binding and omission tests.
#[doc(hidden)]
pub fn diagnostic_snarkjs_plonk_multi_vk_batch_digest(
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
) -> Result<[u8; 32], AltBn128BatchError> {
    // The production reducer proves every shape/canonicality invariant first.
    alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, contexts, inputs, public_inputs)?;
    let mut cursor = 0usize;
    let mut prepared = Vec::with_capacity(inputs.len());
    for input in inputs {
        let context_index = input.context_index() as usize;
        let count = contexts[context_index].reduction.num_public_inputs() as usize;
        prepared.push(PreparedProof {
            context_index,
            public_start: cursor,
            public_end: cursor + count,
            denominator_start: 0,
            vanishing: Fr::zero(),
            native: NativeProof {
                challenges: [Fr::zero(); 6],
                evaluations: [Fr::zero(); PLONK_EVALUATIONS],
                public_inputs: Vec::new(),
                rho: Fr::one(),
            },
        });
        cursor += count;
    }
    Ok(batch_digest(contexts, inputs, public_inputs, &prepared))
}

fn batch_digest(
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
    prepared: &[PreparedProof],
) -> [u8; 32] {
    let context_count = (contexts.len() as u64).to_be_bytes();
    let proof_count = (inputs.len() as u64).to_be_bytes();
    let public_count = (public_inputs.len() as u64).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(4 + contexts.len() * 17 + inputs.len() * 18);
    parts.push(DOMAIN);
    parts.push(&context_count);
    parts.push(&proof_count);
    parts.push(&public_count);
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
        for public in &public_inputs[proof.public_start..proof.public_end] {
            parts.push(&public.0);
        }
        for point in &input.proof.transcript_points {
            parts.push(&point.0);
        }
        for evaluation in &input.proof.evaluations {
            parts.push(&evaluation.0);
        }
    }
    hashv(&parts).to_bytes()
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
                bytes[63] = i as u8 + 1;
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
                    bytes[63] = i as u8 + 1;
                    PodG1Point(bytes)
                }),
                evaluations: core::array::from_fn(|i| {
                    PodScalar::from(&Fr::from(seed as u64 + i as u64 + 11))
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
        assert_eq!(
            first.len(),
            2 * PLONK_MULTI_VK_PER_CONTEXT_OUTPUTS + 1 + 2 * 11
        );
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
            Some(2 * 8 + 1 + 3 * 11)
        );
        assert!(crate::snarkjs_plonk_multi_vk_shape(0, 3, 5).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(2, 0, 5).is_none());
        assert!(crate::snarkjs_plonk_multi_vk_shape(2, 3, FR_MAX_ELEMS + 1).is_none());
    }
}
