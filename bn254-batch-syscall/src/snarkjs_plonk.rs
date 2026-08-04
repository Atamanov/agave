//! Canonical snarkjs KZG-PLONK transcript and native scalar reduction.
//!
//! This operation differs deliberately from the older synthetic reducer:
//! callers provide the raw verification-key and proof point encodings, not
//! caller-derived challenges. The native side replays snarkjs' six phased
//! Keccak challenges byte-for-byte, validates every scalar/domain input, and
//! returns only the signed coefficients for the existing two G1 MSMs. Curve
//! point validation and the final pairing remain outside this syscall.

use {
    crate::{
        AltBn128BatchError, FR_MAX_ELEMS, PLONK_EVALUATIONS, PLONK_PER_PROOF_OUTPUTS,
        PLONK_SHARED_OUTPUTS, PodScalar, PodSnarkjsPlonkReductionContext,
        PodSnarkjsPlonkReductionInput, SNARKJS_PLONK_PROOF_POINTS, Version,
        plonk::{NativeProof, reduce_one, validate_context},
        plonk_reduction_output_count,
    },
    ark_bn254::Fr,
    ark_ff::{Field, One, PrimeField, Zero, batch_inversion},
    core::ops::{Add, Mul, Sub},
    solana_keccak_hasher::hashv,
};

const MIN_DOMAIN_SIZE: u64 = 4;
const MAX_DOMAIN_SIZE: u64 = 1 << 28;

/// Host implementation of `sol_alt_bn128_snarkjs_plonk_batch_reduce`.
pub fn alt_bn128_snarkjs_plonk_batch_reduce(
    _version: Version,
    context: &PodSnarkjsPlonkReductionContext,
    inputs: &[PodSnarkjsPlonkReductionInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let output_count = plonk_reduction_output_count(inputs.len()).ok_or(if inputs.is_empty() {
        AltBn128BatchError::ZeroInput
    } else {
        AltBn128BatchError::CapExceeded
    })?;
    if context.reserved != [0u8; 4] {
        return Err(AltBn128BatchError::InvalidContext);
    }

    let domain_size = context.domain_size();
    let encoded_public_input_count = context.num_public_inputs();
    let num_public_inputs = usize::try_from(encoded_public_input_count)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    if !domain_size.is_power_of_two()
        || !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&domain_size)
        || u64::from(encoded_public_input_count) >= domain_size
    {
        return Err(AltBn128BatchError::InvalidContext);
    }
    let expected_public_inputs = num_public_inputs
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    if public_inputs.len() != expected_public_inputs {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    let lagrange_count = num_public_inputs.max(1);
    let denominator_count = lagrange_count
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    if denominator_count > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let omega = context.omega.to_fr()?;
    let k1 = context.k1.to_fr()?;
    let k2 = context.k2.to_fr()?;
    validate_context(domain_size, omega, k1, k2)?;

    // Parse every canonical scalar before performing inversions or writing
    // output. Raw G1 bytes are intentionally not parsed here: the two MSMs
    // validate exactly the points whose bytes this transcript binds.
    let mut native = Vec::with_capacity(inputs.len());
    let mut remaining_public_inputs = public_inputs;
    for input in inputs {
        let mut evaluations = [Fr::zero(); PLONK_EVALUATIONS];
        for (out, encoded) in evaluations.iter_mut().zip(&input.evaluations) {
            *out = encoded.to_fr()?;
        }
        let (encoded_statement, remaining) = remaining_public_inputs
            .split_at_checked(num_public_inputs)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        remaining_public_inputs = remaining;
        let statement = encoded_statement
            .iter()
            .map(PodScalar::to_fr)
            .collect::<Result<Vec<_>, _>>()?;
        let challenges = derive_challenges(context, input, encoded_statement)?;
        native.push(NativeProof {
            challenges,
            evaluations,
            public_inputs: statement,
            rho: Fr::one(),
        });
    }
    let randomizers = derive_batch_randomizers(context, inputs, public_inputs)?;
    for (proof, rho) in native.iter_mut().zip(randomizers) {
        proof.rho = rho;
    }

    let n = Fr::from(domain_size);
    let mut vanishings = Vec::with_capacity(native.len());
    let mut denominators = Vec::with_capacity(denominator_count);
    for proof in &native {
        let zeta = proof.challenges[3];
        let vanishing = zeta.pow([domain_size]).sub(Fr::one());
        if vanishing.is_zero() {
            return Err(AltBn128BatchError::DegenerateChallenge);
        }
        vanishings.push(vanishing);
        let mut root = Fr::one();
        for _ in 0..lagrange_count {
            denominators.push(n.mul(zeta.sub(root)));
            root = root.mul(omega);
        }
    }
    batch_inversion(&mut denominators);

    let mut output = vec![PodScalar([0u8; 32]); output_count];
    let mut shared = [Fr::zero(); PLONK_SHARED_OUTPUTS];
    let (shared_output, per_proof_output) = output.split_at_mut(PLONK_SHARED_OUTPUTS);
    let mut proof_rows = per_proof_output.chunks_exact_mut(PLONK_PER_PROOF_OUTPUTS);
    for (((proof, vanishing), inverses), row) in native
        .into_iter()
        .zip(vanishings)
        .zip(denominators.chunks_exact(lagrange_count))
        .zip(&mut proof_rows)
    {
        let reduced = reduce_one(omega, k1, k2, &proof, vanishing, inverses)?;
        reduced.accumulate_shared(proof.rho, &mut shared)?;
        for (slot, scalar) in row.iter_mut().zip(reduced.weighted_row(proof.rho)) {
            *slot = PodScalar::from(&scalar);
        }
    }
    if !proof_rows.into_remainder().is_empty() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    for (slot, scalar) in shared_output.iter_mut().zip(shared) {
        *slot = PodScalar::from(&scalar);
    }
    Ok(output)
}

/// snarkjs `getChallenge`: Keccak over concatenated canonical byte parts,
/// interpreted as a big-endian integer and reduced modulo BN254 Fr.
fn challenge(parts: &[&[u8]]) -> Fr {
    Fr::from_be_bytes_mod_order(&hashv(parts).to_bytes())
}

fn canonical_bytes(value: &Fr) -> [u8; 32] {
    PodScalar::from(value).0
}

/// Bind the full ordered canonical batch, including key (both the transcript
/// G1 points and pairing-only `X_2`), statement, proof
/// points, and evaluations. Each rho is `1 + low128(H(seed || be64(i)))`,
/// hence nonzero without rejection sampling and carries 128 bits of entropy
/// in the random-oracle model. Indices are frozen as zero-based: `i=0..n-1`.
fn derive_batch_randomizers(
    context: &PodSnarkjsPlonkReductionContext,
    inputs: &[PodSnarkjsPlonkReductionInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<Fr>, AltBn128BatchError> {
    const DOMAIN: &[u8] = b"solana-snarkjs-plonk-batch-v1";
    let proof_count = u64::try_from(inputs.len())
        .map_err(|_| AltBn128BatchError::BackendInvariant)?
        .to_be_bytes();
    let per_statement = usize::try_from(context.num_public_inputs())
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let per_proof_parts = SNARKJS_PLONK_PROOF_POINTS
        .checked_add(PLONK_EVALUATIONS)
        .and_then(|value| value.checked_add(per_statement))
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let proof_parts = per_proof_parts
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let fixed_parts = context
        .transcript_vk_points
        .len()
        .checked_add(8)
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let capacity = fixed_parts
        .checked_add(proof_parts)
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut parts: Vec<&[u8]> = Vec::with_capacity(capacity);
    parts.extend([
        DOMAIN,
        &proof_count,
        &context.domain_size_be,
        &context.num_public_inputs_be,
        &context.omega.0,
        &context.k1.0,
        &context.k2.0,
    ]);
    for point in &context.transcript_vk_points {
        parts.push(&point.0);
    }
    parts.push(&context.x_2.0);
    let mut remaining_public_inputs = public_inputs;
    for input in inputs {
        let (statement, remaining) = remaining_public_inputs
            .split_at_checked(per_statement)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        remaining_public_inputs = remaining;
        for public in statement {
            parts.push(&public.0);
        }
        for point in &input.transcript_points {
            parts.push(&point.0);
        }
        for evaluation in &input.evaluations {
            parts.push(&evaluation.0);
        }
    }
    let seed = hashv(&parts).to_bytes();
    (0..inputs.len())
        .map(|i| {
            let index = u64::try_from(i)
                .map_err(|_| AltBn128BatchError::BackendInvariant)?
                .to_be_bytes();
            let digest = hashv(&[&seed, &index]).to_bytes();
            let mut low = [0u8; 32];
            low[16..].copy_from_slice(&digest[16..]);
            Ok(Fr::from_be_bytes_mod_order(&low).add(Fr::one()))
        })
        .collect()
}

/// Canonical snarkjs phased transcript:
///
/// beta  = H(Qm,Ql,Qr,Qo,Qc,S1,S2,S3,publics,A,B,C)
/// gamma = H(beta)
/// alpha = H(beta,gamma,Z)
/// zeta  = H(alpha,T1,T2,T3)
/// v     = H(zeta,a,b,c,s1,s2,zw)
/// u     = H(Wxi,Wxiw)
pub(crate) fn derive_challenges(
    context: &PodSnarkjsPlonkReductionContext,
    input: &PodSnarkjsPlonkReductionInput,
    public_inputs: &[PodScalar],
) -> Result<[Fr; 6], AltBn128BatchError> {
    let capacity = context
        .transcript_vk_points
        .len()
        .checked_add(public_inputs.len())
        .and_then(|value| value.checked_add(3))
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut beta_parts: Vec<&[u8]> = Vec::with_capacity(capacity);
    for point in &context.transcript_vk_points {
        beta_parts.push(&point.0);
    }
    for public in public_inputs {
        beta_parts.push(&public.0);
    }
    let [a, b, c, z, t1, t2, t3, w_xi, w_xi_omega] = &input.transcript_points;
    for point in [a, b, c] {
        beta_parts.push(&point.0);
    }
    let beta = challenge(&beta_parts);
    let beta_bytes = canonical_bytes(&beta);

    let gamma = challenge(&[&beta_bytes]);
    let gamma_bytes = canonical_bytes(&gamma);

    let alpha = challenge(&[&beta_bytes, &gamma_bytes, &z.0]);
    let alpha_bytes = canonical_bytes(&alpha);

    let zeta = challenge(&[&alpha_bytes, &t1.0, &t2.0, &t3.0]);
    let zeta_bytes = canonical_bytes(&zeta);

    let [a_ev, b_ev, c_ev, s1_ev, s2_ev, zw_ev] = &input.evaluations;
    let v = challenge(&[
        &zeta_bytes,
        &a_ev.0,
        &b_ev.0,
        &c_ev.0,
        &s1_ev.0,
        &s2_ev.0,
        &zw_ev.0,
    ]);
    let u = challenge(&[&w_xi.0, &w_xi_omega.0]);
    Ok([beta, gamma, alpha, zeta, v, u])
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{PodG1Point, PodG2Point, SNARKJS_PLONK_PROOF_POINTS, SNARKJS_PLONK_VK_POINTS},
        ark_ff::FftField,
    };

    fn context(num_public_inputs: u32) -> PodSnarkjsPlonkReductionContext {
        PodSnarkjsPlonkReductionContext {
            domain_size_be: 8u64.to_be_bytes(),
            num_public_inputs_be: num_public_inputs.to_be_bytes(),
            reserved: [0u8; 4],
            omega: PodScalar::from(&Fr::get_root_of_unity(8).unwrap()),
            k1: PodScalar::from(&Fr::from(2u64)),
            k2: PodScalar::from(&Fr::from(3u64)),
            transcript_vk_points: core::array::from_fn(|i| {
                let mut bytes = [0u8; 64];
                bytes[63] = u8::try_from(i).unwrap_or(u8::MAX).saturating_add(1);
                PodG1Point(bytes)
            }),
            x_2: {
                let mut bytes = [0u8; 128];
                bytes[127] = 42;
                PodG2Point(bytes)
            },
        }
    }

    fn input(seed: u8) -> PodSnarkjsPlonkReductionInput {
        PodSnarkjsPlonkReductionInput {
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
        }
    }

    #[test]
    fn transcript_dimensions_are_frozen() {
        assert_eq!(SNARKJS_PLONK_VK_POINTS, 8);
        assert_eq!(SNARKJS_PLONK_PROOF_POINTS, 9);
        let ctx = context(1);
        let proof = input(7);
        let statement = [PodScalar::from(&Fr::from(101u64))];
        let challenges = derive_challenges(&ctx, &proof, &statement).unwrap();
        assert!(challenges.iter().all(|challenge| !challenge.is_zero()));
        let output =
            alt_bn128_snarkjs_plonk_batch_reduce(Version::V0, &ctx, &[proof], &statement).unwrap();
        assert_eq!(output.len(), PLONK_SHARED_OUTPUTS + PLONK_PER_PROOF_OUTPUTS);
        assert!(output.iter().all(|scalar| scalar.to_fr().is_ok()));
    }

    #[test]
    fn transcript_binds_vk_proof_and_statement_bytes() {
        let ctx = context(1);
        let proof = input(9);
        let statement = [PodScalar::from(&Fr::from(77u64))];
        let base = derive_challenges(&ctx, &proof, &statement).unwrap();

        let mut changed_vk = ctx;
        *changed_vk
            .transcript_vk_points
            .first_mut()
            .and_then(|point| point.0.first_mut())
            .unwrap() ^= 1;
        assert_ne!(
            base,
            derive_challenges(&changed_vk, &proof, &statement).unwrap()
        );

        let mut changed_proof = proof;
        *changed_proof
            .transcript_points
            .first_mut()
            .and_then(|point| point.0.first_mut())
            .unwrap() ^= 1;
        assert_ne!(
            base,
            derive_challenges(&ctx, &changed_proof, &statement).unwrap()
        );

        let changed_statement = [PodScalar::from(&Fr::from(78u64))];
        assert_ne!(
            base,
            derive_challenges(&ctx, &proof, &changed_statement).unwrap()
        );

        let rho = derive_batch_randomizers(&ctx, &[proof], &statement).unwrap();
        let changed_rho = derive_batch_randomizers(&changed_vk, &[proof], &statement).unwrap();
        assert_ne!(rho, changed_rho);

        // X_2 is pairing-only for the canonical snarkjs inner transcript, but
        // it must be frozen into the outer batch randomizer transcript.
        let mut changed_x_2 = ctx;
        *changed_x_2.x_2.0.first_mut().unwrap() ^= 1;
        assert_eq!(
            base,
            derive_challenges(&changed_x_2, &proof, &statement).unwrap()
        );
        assert_ne!(
            rho,
            derive_batch_randomizers(&changed_x_2, &[proof], &statement).unwrap()
        );
        assert!(rho.iter().all(|value| !value.is_zero()));
    }
}
