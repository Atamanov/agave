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
        PodSnarkjsPlonkReductionInput, Version,
        plonk::{NativeProof, reduce_one, validate_context},
        plonk_reduction_output_count,
    },
    ark_bn254::Fr,
    ark_ff::{Field, One, PrimeField, Zero, batch_inversion},
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
    let num_public_inputs = context.num_public_inputs() as usize;
    if !domain_size.is_power_of_two()
        || !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&domain_size)
        || num_public_inputs >= domain_size as usize
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
    if lagrange_count
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?
        > FR_MAX_ELEMS
    {
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
    for (i, input) in inputs.iter().enumerate() {
        let mut evaluations = [Fr::zero(); PLONK_EVALUATIONS];
        for (out, encoded) in evaluations.iter_mut().zip(&input.evaluations) {
            *out = encoded.to_fr()?;
        }
        let start = i * num_public_inputs;
        let end = start + num_public_inputs;
        let encoded_statement = &public_inputs[start..end];
        let statement = encoded_statement
            .iter()
            .map(PodScalar::to_fr)
            .collect::<Result<Vec<_>, _>>()?;
        let challenges = derive_challenges(context, input, encoded_statement);
        native.push(NativeProof {
            challenges,
            evaluations,
            public_inputs: statement,
            rho: Fr::one(),
        });
    }
    let randomizers = derive_batch_randomizers(context, inputs, public_inputs);
    for (proof, rho) in native.iter_mut().zip(randomizers) {
        proof.rho = rho;
    }

    let n = Fr::from(domain_size);
    let mut vanishings = Vec::with_capacity(native.len());
    let mut denominators = Vec::with_capacity(native.len() * lagrange_count);
    for proof in &native {
        let zeta = proof.challenges[3];
        let vanishing = zeta.pow([domain_size]) - Fr::one();
        if vanishing.is_zero() {
            return Err(AltBn128BatchError::DegenerateChallenge);
        }
        vanishings.push(vanishing);
        let mut root = Fr::one();
        for _ in 0..lagrange_count {
            denominators.push(n * (zeta - root));
            root *= omega;
        }
    }
    batch_inversion(&mut denominators);

    let mut output = vec![PodScalar([0u8; 32]); output_count];
    let mut shared = [Fr::zero(); PLONK_SHARED_OUTPUTS];
    for (i, (proof, vanishing)) in native.into_iter().zip(vanishings).enumerate() {
        let inv_start = i * lagrange_count;
        let inverses = &denominators[inv_start..inv_start + lagrange_count];
        let reduced = reduce_one(domain_size, omega, k1, k2, &proof, vanishing, inverses);

        for (accumulator, coefficient) in shared[..8].iter_mut().zip(reduced.shared_q) {
            *accumulator -= proof.rho * coefficient;
        }
        shared[8] -= proof.rho * reduced.generator;

        let base = PLONK_SHARED_OUTPUTS + i * PLONK_PER_PROOF_OUTPUTS;
        let per = [
            proof.rho,
            proof.rho * reduced.p_shifted,
            -(proof.rho * reduced.z),
            -(proof.rho * reduced.t_lo),
            -(proof.rho * reduced.t_mid),
            -(proof.rho * reduced.t_hi),
            -(proof.rho * reduced.a),
            -(proof.rho * reduced.b),
            -(proof.rho * reduced.c),
            -(proof.rho * reduced.w_zeta_q),
            -(proof.rho * reduced.w_zeta_omega_q),
        ];
        for (slot, scalar) in output[base..base + PLONK_PER_PROOF_OUTPUTS]
            .iter_mut()
            .zip(per)
        {
            *slot = PodScalar::from(&scalar);
        }
    }
    for (slot, scalar) in output[..PLONK_SHARED_OUTPUTS].iter_mut().zip(shared) {
        *slot = PodScalar::from(&scalar);
    }
    Ok(output)
}

/// Host-only conformance hook exposing the six canonical transcript scalars.
///
/// This is intentionally hidden from the on-chain API. It exists so fixture
/// tests can differential-check every phased challenge against an independent
/// snarkjs-compatible implementation; applications should call only the
/// reducer and consume its coefficient vector.
#[doc(hidden)]
pub fn diagnostic_snarkjs_plonk_challenges(
    context: &PodSnarkjsPlonkReductionContext,
    inputs: &[PodSnarkjsPlonkReductionInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<[PodScalar; 6]>, AltBn128BatchError> {
    // Reuse the production path for all shape, domain, and canonical-scalar
    // checks so this hook cannot accidentally report diagnostics for inputs
    // the syscall itself rejects.
    alt_bn128_snarkjs_plonk_batch_reduce(Version::V0, context, inputs, public_inputs)?;
    let per_statement = context.num_public_inputs() as usize;
    Ok(inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let statement = &public_inputs[i * per_statement..(i + 1) * per_statement];
            derive_challenges(context, input, statement).map(|value| PodScalar::from(&value))
        })
        .collect())
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
) -> Vec<Fr> {
    const DOMAIN: &[u8] = b"solana-snarkjs-plonk-batch-v1";
    let proof_count = (inputs.len() as u64).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(
        9 + context.transcript_vk_points.len() + inputs.len() * (1 + 9 + PLONK_EVALUATIONS),
    );
    parts.push(DOMAIN);
    parts.push(&proof_count);
    parts.push(&context.domain_size_be);
    parts.push(&context.num_public_inputs_be);
    parts.push(&context.omega.0);
    parts.push(&context.k1.0);
    parts.push(&context.k2.0);
    for point in &context.transcript_vk_points {
        parts.push(&point.0);
    }
    parts.push(&context.x_2.0);
    let per_statement = context.num_public_inputs() as usize;
    for (i, input) in inputs.iter().enumerate() {
        for public in &public_inputs[i * per_statement..(i + 1) * per_statement] {
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
            let index = (i as u64).to_be_bytes();
            let digest = hashv(&[&seed, &index]).to_bytes();
            let mut low = [0u8; 32];
            low[16..].copy_from_slice(&digest[16..]);
            Fr::from_be_bytes_mod_order(&low) + Fr::one()
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
) -> [Fr; 6] {
    let mut beta_parts: Vec<&[u8]> =
        Vec::with_capacity(context.transcript_vk_points.len() + public_inputs.len() + 3);
    for point in &context.transcript_vk_points {
        beta_parts.push(&point.0);
    }
    for public in public_inputs {
        beta_parts.push(&public.0);
    }
    for point in &input.transcript_points[..3] {
        beta_parts.push(&point.0);
    }
    let beta = challenge(&beta_parts);
    let beta_bytes = canonical_bytes(&beta);

    let gamma = challenge(&[&beta_bytes]);
    let gamma_bytes = canonical_bytes(&gamma);

    let alpha = challenge(&[&beta_bytes, &gamma_bytes, &input.transcript_points[3].0]);
    let alpha_bytes = canonical_bytes(&alpha);

    let zeta = challenge(&[
        &alpha_bytes,
        &input.transcript_points[4].0,
        &input.transcript_points[5].0,
        &input.transcript_points[6].0,
    ]);
    let zeta_bytes = canonical_bytes(&zeta);

    let v = challenge(&[
        &zeta_bytes,
        &input.evaluations[0].0,
        &input.evaluations[1].0,
        &input.evaluations[2].0,
        &input.evaluations[3].0,
        &input.evaluations[4].0,
        &input.evaluations[5].0,
    ]);
    let u = challenge(&[&input.transcript_points[7].0, &input.transcript_points[8].0]);
    [beta, gamma, alpha, zeta, v, u]
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
                bytes[63] = i as u8 + 1;
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
                bytes[63] = i as u8 + 1;
                PodG1Point(bytes)
            }),
            evaluations: core::array::from_fn(|i| {
                PodScalar::from(&Fr::from(seed as u64 + i as u64 + 11))
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
        let challenges = derive_challenges(&ctx, &proof, &statement);
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
        let base = derive_challenges(&ctx, &proof, &statement);

        let mut changed_vk = ctx;
        changed_vk.transcript_vk_points[0].0[0] ^= 1;
        assert_ne!(base, derive_challenges(&changed_vk, &proof, &statement));

        let mut changed_proof = proof;
        changed_proof.transcript_points[0].0[0] ^= 1;
        assert_ne!(base, derive_challenges(&ctx, &changed_proof, &statement));

        let changed_statement = [PodScalar::from(&Fr::from(78u64))];
        assert_ne!(base, derive_challenges(&ctx, &proof, &changed_statement));

        let rho = derive_batch_randomizers(&ctx, &[proof], &statement);
        let changed_rho = derive_batch_randomizers(&changed_vk, &[proof], &statement);
        assert_ne!(rho, changed_rho);

        // X_2 is pairing-only for the canonical snarkjs inner transcript, but
        // it must be frozen into the outer batch randomizer transcript.
        let mut changed_x_2 = ctx;
        changed_x_2.x_2.0[0] ^= 1;
        assert_eq!(base, derive_challenges(&changed_x_2, &proof, &statement));
        assert_ne!(
            rho,
            derive_batch_randomizers(&changed_x_2, &[proof], &statement)
        );
        assert!(rho.iter().all(|value| !value.is_zero()));
    }
}
