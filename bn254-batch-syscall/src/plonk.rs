//! Native scalar reduction for the KZG PLONK equation used by
//! `solana-bn254-plonk-batch`.
//!
//! ## Non-production synthetic baseline
//!
//! This older operation accepts caller-supplied challenge digests and `rho`.
//! It is retained only to reproduce the synthetic benchmark baseline. It is
//! not the recommended verifier API because it cannot enforce the canonical
//! snarkjs phased transcript or freeze the complete batch natively. Production
//! proposals must use `sol_alt_bn128_snarkjs_plonk_batch_reduce`.
//!
//! The syscall does not hash, inspect curve points, or decide a verdict. The
//! caller supplies raw Fiat-Shamir challenge digests, canonical proof scalars,
//! canonical nonzero outer randomizers, and a validated same-key scalar
//! context. The result is only the signed, rho-weighted scalar vector consumed
//! by the existing two MSMs.
//!
//! Output order:
//! - shared 0..8: `-sum rho_i * (q_m,q_l,q_r,q_o,q_c,s1,s2,s3)` coefficients;
//! - shared 8: `-sum rho_i * generator_coefficient`;
//! - per proof 0..2: `(rho, rho*u)` for `(W_zeta,W_zeta_omega)` on P;
//! - per proof 2..11: `-rho * (z,t_lo,t_mid,t_hi,a,b,c,Wz_q,Wzw_q)` on Q.

use {
    crate::{
        AltBn128BatchError, FR_MAX_ELEMS, PLONK_CHALLENGES, PLONK_EVALUATIONS,
        PLONK_PER_PROOF_OUTPUTS, PLONK_SHARED_OUTPUTS, PodPlonkReductionContext,
        PodPlonkReductionInput, PodScalar, Version, plonk_reduction_output_count,
    },
    ark_bn254::Fr,
    ark_ff::{Field, One, PrimeField, Zero, batch_inversion},
    core::ops::{Add, Div, Mul, Neg, Sub},
};

const MIN_DOMAIN_SIZE: u64 = 4;
const MAX_DOMAIN_SIZE: u64 = 1 << 28;

pub(crate) struct NativeProof {
    pub(crate) challenges: [Fr; PLONK_CHALLENGES],
    pub(crate) evaluations: [Fr; PLONK_EVALUATIONS],
    pub(crate) public_inputs: Vec<Fr>,
    pub(crate) rho: Fr,
}

/// Host implementation of the non-production synthetic baseline
/// `sol_alt_bn128_plonk_batch_reduce`.
pub fn alt_bn128_plonk_batch_reduce(
    _version: Version,
    context: &PodPlonkReductionContext,
    inputs: &[PodPlonkReductionInput],
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

    // Parse and validate every canonical input before performing the batch
    // inversion or writing any output.
    let mut native = Vec::with_capacity(inputs.len());
    let mut remaining_public_inputs = public_inputs;
    for input in inputs {
        let challenges =
            core::array::from_fn(|j| Fr::from_be_bytes_mod_order(&input.challenge_digests[j]));
        let mut evaluations = [Fr::zero(); PLONK_EVALUATIONS];
        for (out, encoded) in evaluations.iter_mut().zip(&input.evaluations) {
            *out = encoded.to_fr()?;
        }
        let rho = input.rho.to_fr()?;
        if rho.is_zero() {
            return Err(AltBn128BatchError::ZeroRandomizer);
        }
        let (statement, remaining) = remaining_public_inputs
            .split_at_checked(num_public_inputs)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        remaining_public_inputs = remaining;
        let statement = statement
            .iter()
            .map(PodScalar::to_fr)
            .collect::<Result<Vec<_>, _>>()?;
        native.push(NativeProof {
            challenges,
            evaluations,
            public_inputs: statement,
            rho,
        });
    }

    // One inversion for every Lagrange denominator in the whole same-key
    // batch, exactly the old verifier split but entirely native.
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
    // zeta outside the exact-order domain makes every denominator nonzero.
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

pub(crate) fn validate_context(
    domain_size: u64,
    omega: Fr,
    k1: Fr,
    k2: Fr,
) -> Result<(), AltBn128BatchError> {
    let one = Fr::one();
    if omega.pow([domain_size]) != one
        || omega.pow([domain_size / 2]) == one
        || k1.is_zero()
        || k2.is_zero()
        || k1.pow([domain_size]) == one
        || k2.pow([domain_size]) == one
        || k2.div(k1).pow([domain_size]) == one
    {
        return Err(AltBn128BatchError::InvalidContext);
    }
    Ok(())
}

pub(crate) struct Reduced {
    pub(crate) shared_q: [Fr; 8],
    pub(crate) generator: Fr,
    pub(crate) z: Fr,
    pub(crate) t_lo: Fr,
    pub(crate) t_mid: Fr,
    pub(crate) t_hi: Fr,
    pub(crate) a: Fr,
    pub(crate) b: Fr,
    pub(crate) c: Fr,
    pub(crate) w_zeta_q: Fr,
    pub(crate) w_zeta_omega_q: Fr,
    pub(crate) p_shifted: Fr,
}

impl Reduced {
    pub(crate) fn accumulate_shared_q(&self, rho: Fr, shared: &mut [Fr; 8]) {
        for (accumulator, coefficient) in shared.iter_mut().zip(self.shared_q) {
            *accumulator = accumulator.sub(rho.mul(coefficient));
        }
    }

    pub(crate) fn generator_contribution(&self, rho: Fr) -> Fr {
        rho.mul(self.generator)
    }

    pub(crate) fn accumulate_shared(
        &self,
        rho: Fr,
        shared: &mut [Fr; PLONK_SHARED_OUTPUTS],
    ) -> Result<(), AltBn128BatchError> {
        let shared_q: &mut [Fr; 8] = shared
            .get_mut(..8)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        self.accumulate_shared_q(rho, shared_q);
        let generator = shared
            .last_mut()
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        *generator = generator.sub(self.generator_contribution(rho));
        Ok(())
    }

    pub(crate) fn weighted_row(&self, rho: Fr) -> [Fr; PLONK_PER_PROOF_OUTPUTS] {
        [
            rho,
            rho.mul(self.p_shifted),
            rho.mul(self.z).neg(),
            rho.mul(self.t_lo).neg(),
            rho.mul(self.t_mid).neg(),
            rho.mul(self.t_hi).neg(),
            rho.mul(self.a).neg(),
            rho.mul(self.b).neg(),
            rho.mul(self.c).neg(),
            rho.mul(self.w_zeta_q).neg(),
            rho.mul(self.w_zeta_omega_q).neg(),
        ]
    }
}

pub(crate) fn reduce_one(
    omega: Fr,
    k1: Fr,
    k2: Fr,
    proof: &NativeProof,
    vanishing: Fr,
    denominator_inverses: &[Fr],
) -> Result<Reduced, AltBn128BatchError> {
    let [beta, gamma, alpha, zeta, v, u] = proof.challenges;
    let [a_ev, b_ev, c_ev, s1_ev, s2_ev, zw_ev] = proof.evaluations;

    let mut lagrange = Vec::with_capacity(denominator_inverses.len());
    let mut root = Fr::one();
    for inverse in denominator_inverses {
        lagrange.push(root.mul(vanishing).mul(*inverse));
        root = root.mul(omega);
    }
    let l1 = lagrange
        .first()
        .copied()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let pi = proof
        .public_inputs
        .iter()
        .zip(&lagrange)
        .map(|(input, basis)| input.mul(basis))
        .sum::<Fr>()
        .neg();

    let alpha_sq = alpha.mul(alpha);
    let perm_a = a_ev.add(beta.mul(s1_ev)).add(gamma);
    let perm_b = b_ev.add(beta.mul(s2_ev)).add(gamma);
    let r0 = pi.sub(l1.mul(alpha_sq)).sub(
        alpha
            .mul(perm_a)
            .mul(perm_b)
            .mul(c_ev.add(gamma))
            .mul(zw_ev),
    );

    let beta_zeta = beta.mul(zeta);
    let z = alpha
        .mul(a_ev.add(beta_zeta).add(gamma))
        .mul(b_ev.add(k1.mul(beta_zeta)).add(gamma))
        .mul(c_ev.add(k2.mul(beta_zeta)).add(gamma))
        .add(l1.mul(alpha_sq))
        .add(u);
    let s_sigma3 = alpha.mul(beta).mul(zw_ev).mul(perm_a).mul(perm_b).neg();
    let zeta_n = vanishing.add(Fr::one());
    let t_lo = vanishing.neg();
    let t_mid = vanishing.mul(zeta_n).neg();
    let t_hi = vanishing.mul(zeta_n).mul(zeta_n).neg();

    let v2 = v.mul(v);
    let v3 = v2.mul(v);
    let v4 = v3.mul(v);
    let v5 = v4.mul(v);
    let e_scalar = r0
        .neg()
        .add(v.mul(a_ev))
        .add(v2.mul(b_ev))
        .add(v3.mul(c_ev))
        .add(v4.mul(s1_ev))
        .add(v5.mul(s2_ev))
        .add(u.mul(zw_ev));

    Ok(Reduced {
        shared_q: [
            a_ev.mul(b_ev),
            a_ev,
            b_ev,
            c_ev,
            Fr::one(),
            v4,
            v5,
            s_sigma3,
        ],
        z,
        t_lo,
        t_mid,
        t_hi,
        a: v,
        b: v2,
        c: v3,
        w_zeta_q: zeta,
        w_zeta_omega_q: u.mul(zeta).mul(omega),
        generator: e_scalar.neg(),
        p_shifted: u,
    })
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{PLONK_REDUCE_MAX_PROOFS, plonk_reduction_output_count},
        ark_ff::FftField,
    };

    fn context(num_public_inputs: u32) -> PodPlonkReductionContext {
        PodPlonkReductionContext {
            domain_size_be: 8u64.to_be_bytes(),
            num_public_inputs_be: num_public_inputs.to_be_bytes(),
            reserved: [0u8; 4],
            omega: PodScalar::from(&Fr::get_root_of_unity(8).unwrap()),
            k1: PodScalar::from(&Fr::from(2u64)),
            k2: PodScalar::from(&Fr::from(3u64)),
        }
    }

    fn input(seed: u64) -> PodPlonkReductionInput {
        let offset = |index: usize, base: u64| {
            seed.saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
                .saturating_add(base)
        };
        let challenge_digests =
            core::array::from_fn(|i| PodScalar::from(&Fr::from(offset(i, 2))).0);
        PodPlonkReductionInput {
            challenge_digests,
            evaluations: core::array::from_fn(|i| PodScalar::from(&Fr::from(offset(i, 11)))),
            rho: PodScalar::from(&Fr::from(seed.saturating_add(1))),
        }
    }

    #[test]
    fn valid_shapes_are_deterministic_and_canonical() {
        for n in 1usize..=5 {
            let inputs: Vec<_> = (0..n)
                .map(|i| input(u64::try_from(i).unwrap().checked_add(1).unwrap()))
                .collect();
            let public_inputs: Vec<_> = (0..n)
                .map(|i| {
                    let value = u64::try_from(i).unwrap().checked_add(101).unwrap();
                    PodScalar::from(&Fr::from(value))
                })
                .collect();
            let first =
                alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &inputs, &public_inputs)
                    .unwrap();
            let second =
                alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &inputs, &public_inputs)
                    .unwrap();
            assert_eq!(first, second, "n = {n}");
            assert_eq!(first.len(), plonk_reduction_output_count(n).unwrap());
            assert!(first.iter().all(|scalar| scalar.to_fr().is_ok()));
        }
    }

    #[test]
    fn raw_challenge_digests_are_reduced_not_rejected() {
        let mut proof = input(7);
        // Challenge digests are hash outputs, not canonical field encodings.
        // Keep zeta nondegenerate and force the other five above the modulus.
        for (i, digest) in proof.challenge_digests.iter_mut().enumerate() {
            if i != 3 {
                *digest = [0xffu8; 32];
            }
        }
        assert!(
            alt_bn128_plonk_batch_reduce(
                Version::V0,
                &context(1),
                &[proof],
                &[PodScalar::from(&Fr::from(9u64))],
            )
            .is_ok()
        );
    }

    #[test]
    fn canonical_boundaries_and_randomizer_are_enforced() {
        let good = input(3);
        let statement = [PodScalar::from(&Fr::from(5u64))];

        let mut bad = good;
        bad.evaluations[4] = PodScalar([0xffu8; 32]);
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &[bad], &statement),
            Err(AltBn128BatchError::NonCanonical)
        );

        assert_eq!(
            alt_bn128_plonk_batch_reduce(
                Version::V0,
                &context(1),
                &[good],
                &[PodScalar([0xffu8; 32])],
            ),
            Err(AltBn128BatchError::NonCanonical)
        );

        let mut zero_rho = good;
        zero_rho.rho = PodScalar::from(&Fr::zero());
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &[zero_rho], &statement,),
            Err(AltBn128BatchError::ZeroRandomizer)
        );
    }

    #[test]
    fn malformed_context_and_degenerate_zeta_are_rejected() {
        let proof = input(4);
        let statement = [PodScalar::from(&Fr::from(6u64))];

        let mut bad = context(1);
        bad.reserved[0] = 1;
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &bad, &[proof], &statement),
            Err(AltBn128BatchError::InvalidContext)
        );
        let mut bad = context(1);
        bad.omega = PodScalar::from(&Fr::one());
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &bad, &[proof], &statement),
            Err(AltBn128BatchError::InvalidContext)
        );
        let mut bad = context(1);
        bad.k2 = bad.k1;
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &bad, &[proof], &statement),
            Err(AltBn128BatchError::InvalidContext)
        );

        let mut degenerate = proof;
        degenerate.challenge_digests[3] = PodScalar::from(&Fr::one()).0;
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &[degenerate], &statement,),
            Err(AltBn128BatchError::DegenerateChallenge)
        );
    }

    #[test]
    fn shape_and_length_caps_precede_arithmetic() {
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &[], &[]),
            Err(AltBn128BatchError::ZeroInput)
        );
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(1), &[input(1)], &[]),
            Err(AltBn128BatchError::LengthMismatch)
        );
        let over = vec![input(1); PLONK_REDUCE_MAX_PROOFS + 1];
        assert_eq!(
            alt_bn128_plonk_batch_reduce(Version::V0, &context(0), &over, &[]),
            Err(AltBn128BatchError::CapExceeded)
        );
    }
}
