//! Per-proof PLONK verifier reduction, emitting scalar coefficients over a
//! basis shared by the whole batch (never points), so the batch flattens into
//! exactly two G1 MSMs in verify.rs.
//!
//! Convention (PLONK verifier rounds 5-12, the convention snarkjs and gnark
//! follow): the gate identity on H is
//! q_m a b + q_l a + q_r b + q_o c + q_c + PI(X) = 0 with
//! PI(X) = -sum_i w_i L_i(X), so a public-input row carries q_l = 1 and
//! PI(zeta) enters r0. L_1 is anchored at omega^0 = 1, a deliberate deviation
//! from the standard omega anchoring that matches snarkjs; the fixture prover,
//! its grand product, and the PI rows all share that anchor. The signs are
//! fixed two ways: the fixture prover must verify, and the n = 1 batch must
//! match an independent arkworks computation of e(P, [tau]_2) e(-Q, [1]_2) = 1.

use {
    crate::{
        PlonkBatchError, proof::Proof, transcript::InnerChallenges, vk::ValidatedVerifyingKey,
    },
    ark_bn254::Fr,
    ark_ff::{Field, One, Zero},
    solana_bn254_batch_syscall::{PodScalar, alt_bn128_fr_lincomb},
};

/// Coefficients on the batch-shared Q-side basis points (the verifying key
/// commitments); summed with rho weights across the batch before the MSM.
pub(crate) struct VkCoeffs {
    pub q_m: Fr,
    pub q_l: Fr,
    pub q_r: Fr,
    pub q_o: Fr,
    pub q_c: Fr,
    pub s_sigma1: Fr,
    pub s_sigma2: Fr,
    pub s_sigma3: Fr,
}

/// One proof reduced to scalar coefficients: Q_i is the linearized
/// commitment D plus the v-batched openings minus E (rounds 9-11),
/// P_i = W_zeta + u W_zeta_omega, and validity of proof i alone is
/// e(P_i, [tau]_2) e(-Q_i, [1]_2) = 1.
pub(crate) struct ReducedProof {
    // Q-side coefficients
    pub vk_coeffs: VkCoeffs,
    pub z: Fr,
    pub t_lo: Fr,
    pub t_mid: Fr,
    pub t_hi: Fr,
    /// wire commitment coefficients v, v^2, v^3
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
    /// zeta on W_zeta and u zeta omega on W_zeta_omega
    pub w_zeta_q: Fr,
    pub w_zeta_omega_q: Fr,
    /// -(E scalar) on the G1 generator
    pub generator: Fr,
    // P-side coefficients: 1 on W_zeta and u on W_zeta_omega
    pub w_zeta_p: Fr,
    pub w_zeta_omega_p: Fr,
}

/// Z_H(zeta) = zeta^n - 1 (round 5). Zero means zeta landed in H,
/// which Fiat-Shamir reaches with probability |H|/r per proof; consensus
/// code proves totality, not typicality, so the case is a deterministic
/// reject before any division.
pub(crate) fn vanishing_eval(domain_size: u64, zeta: Fr) -> Result<Fr, PlonkBatchError> {
    let vanishing = zeta.pow([domain_size]) - Fr::one();
    if vanishing.is_zero() {
        return Err(PlonkBatchError::ZetaInEvaluationDomain);
    }
    Ok(vanishing)
}

/// How many Lagrange values a proof needs: one per public input, and always
/// L_1 for the alpha^2 terms even on an input-free statement.
pub(crate) fn lagrange_count(vk: &ValidatedVerifyingKey) -> usize {
    vk.num_public_inputs().max(1)
}

/// Denominators n (zeta - omega^i) of L_{i+1}(zeta) for i in 0..count, for
/// the batch-wide inversion in verify.rs. All nonzero: `vanishing_eval` ran
/// first, so zeta is outside H and no factor vanishes.
pub(crate) fn lagrange_denominators(vk: &ValidatedVerifyingKey, zeta: Fr, count: usize) -> Vec<Fr> {
    let n = Fr::from(vk.domain_size());
    let mut root = Fr::one();
    (0..count)
        .map(|_| {
            let denominator = n * (zeta - root);
            root *= vk.omega();
            denominator
        })
        .collect()
}

/// Verifier rounds 6-12 as coefficients. `denominator_inverses` are
/// this proof's slice of the single batch-wide alt_bn128_fr_batch_invert
/// call; `vanishing` is Z_H(zeta) from `vanishing_eval`.
pub(crate) fn reduce(
    vk: &ValidatedVerifyingKey,
    proof: &Proof,
    challenges: &InnerChallenges,
    vanishing: Fr,
    denominator_inverses: &[Fr],
) -> Result<ReducedProof, PlonkBatchError> {
    let InnerChallenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    } = *challenges;

    // round 6: L_{i+1}(zeta) = omega^i Z_H(zeta) / (n (zeta - omega^i))
    let mut lagrange = Vec::with_capacity(denominator_inverses.len());
    let mut root = Fr::one();
    for inverse in denominator_inverses {
        lagrange.push(root * vanishing * inverse);
        root *= vk.omega();
    }
    let l1 = lagrange[0];

    // round 7: PI(zeta) = -<w, L(zeta)> per this convention, with the
    // inner product the natural fr_lincomb fit; an input-free statement has
    // PI = 0 (the lincomb syscall rejects empty)
    let pi = if proof.public_inputs.is_empty() {
        Fr::zero()
    } else {
        let lagrange_pods: Vec<PodScalar> = lagrange.iter().map(PodScalar::from).collect();
        -alt_bn128_fr_lincomb(
            solana_bn254_batch_syscall::Version::V0,
            &proof.public_inputs,
            &lagrange_pods,
        )?
        .to_fr()
        .map_err(PlonkBatchError::Syscall)?
    };

    let evaluations = &proof.evaluations;
    let non_canonical = |_| PlonkBatchError::NonCanonicalScalar;
    let a_ev = evaluations.a.to_fr().map_err(non_canonical)?;
    let b_ev = evaluations.b.to_fr().map_err(non_canonical)?;
    let c_ev = evaluations.c.to_fr().map_err(non_canonical)?;
    let s1_ev = evaluations.s_sigma1.to_fr().map_err(non_canonical)?;
    let s2_ev = evaluations.s_sigma2.to_fr().map_err(non_canonical)?;
    let zw_ev = evaluations.z_omega.to_fr().map_err(non_canonical)?;

    let alpha_sq = alpha.square();
    let perm_a = a_ev + beta * s1_ev + gamma;
    let perm_b = b_ev + beta * s2_ev + gamma;

    // round 8: r0 = PI(zeta) - L_1(zeta) alpha^2
    //               - alpha (a + beta s1 + gamma)(b + beta s2 + gamma)(c + gamma) z_omega
    let r0 = pi - l1 * alpha_sq - alpha * perm_a * perm_b * (c_ev + gamma) * zw_ev;

    // round 9: coefficients of the linearized commitment D; the +u on [z]
    // and the u z_omega in E fold the shifted opening into the same check
    let z = alpha
        * (a_ev + beta * zeta + gamma)
        * (b_ev + beta * vk.k1() * zeta + gamma)
        * (c_ev + beta * vk.k2() * zeta + gamma)
        + l1 * alpha_sq
        + u;
    let s_sigma3 = -(alpha * beta * zw_ev * perm_a * perm_b);
    let zeta_n = vanishing + Fr::one();
    let t_lo = -vanishing;
    let t_mid = -vanishing * zeta_n;
    let t_hi = -vanishing * zeta_n.square();

    // round 10: F adds v powers on the wire and permutation commitments
    let v2 = v * v;
    let v3 = v2 * v;
    let v4 = v3 * v;
    let v5 = v4 * v;

    // round 11: E collects the expected openings on the generator; Q = ... - E,
    // so the generator coefficient is minus the E scalar
    let e_scalar = -r0 + v * a_ev + v2 * b_ev + v3 * c_ev + v4 * s1_ev + v5 * s2_ev + u * zw_ev;

    Ok(ReducedProof {
        vk_coeffs: VkCoeffs {
            q_m: a_ev * b_ev,
            q_l: a_ev,
            q_r: b_ev,
            q_o: c_ev,
            q_c: Fr::one(),
            s_sigma1: v4,
            s_sigma2: v5,
            s_sigma3,
        },
        z,
        t_lo,
        t_mid,
        t_hi,
        a: v,
        b: v2,
        c: v3,
        w_zeta_q: zeta,
        w_zeta_omega_q: u * zeta * vk.omega(),
        generator: -e_scalar,
        w_zeta_p: Fr::one(),
        w_zeta_omega_p: u,
    })
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_support::{DOMAIN_SIZE, make_vk, rng},
        ark_ff::UniformRand,
    };

    #[test]
    fn test_zeta_in_evaluation_domain_rejected() {
        // unit test on the guard itself: the transcript path cannot reach a
        // zeta in H (probability |H|/r per derivation), so the case is forced
        // by calling the Z_H helper directly
        let mut rng = rng();
        let (_, vk) = make_vk(&mut rng);
        let omega = vk.omega();
        for power in [0u64, 1, 5, DOMAIN_SIZE - 1] {
            assert_eq!(
                vanishing_eval(DOMAIN_SIZE, omega.pow([power])),
                Err(PlonkBatchError::ZetaInEvaluationDomain),
                "omega^{power}"
            );
        }
        let outside = Fr::rand(&mut rng);
        assert!(vanishing_eval(DOMAIN_SIZE, outside).is_ok());
    }

    #[test]
    fn test_lagrange_values_from_batched_denominators() {
        // pin the denominator/inverse split against the direct formula, and
        // check the partition-of-unity identity sum_i L_i(zeta) = 1 over the
        // full domain as an independent cross-check
        let mut rng = rng();
        let (_, vk) = make_vk(&mut rng);
        let zeta = Fr::rand(&mut rng);
        let vanishing = vanishing_eval(DOMAIN_SIZE, zeta).unwrap();
        let count = DOMAIN_SIZE as usize;
        let denominators = lagrange_denominators(&vk, zeta, count);
        let mut sum = Fr::zero();
        let mut root = Fr::one();
        for (i, denominator) in denominators.iter().enumerate() {
            let direct =
                root * vanishing * (Fr::from(DOMAIN_SIZE) * (zeta - root)).inverse().unwrap();
            assert_eq!(*denominator * direct, root * vanishing, "i = {i}");
            sum += direct;
            root *= vk.omega();
        }
        assert!(sum.is_one(), "Lagrange basis must sum to one");
    }
}
