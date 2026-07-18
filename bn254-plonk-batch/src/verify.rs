use {
    crate::{
        PlonkBatchError, Version,
        proof::Proof,
        reduce::{ReducedProof, lagrange_count, lagrange_denominators, reduce, vanishing_eval},
        transcript::{
            InnerChallenges, RandomizerMode, derive_inner, derive_randomizers, derive_seed,
        },
        vk::ValidatedVerifyingKey,
    },
    ark_bn254::{Fr, G1Affine},
    ark_ec::AffineRepr,
    solana_bn254_batch_syscall::{
        MSM_MAX_POINTS, PodG1G2Pair, PodG1Point, PodScalar, alt_bn128_fr_batch_invert,
        alt_bn128_g1_msm, alt_bn128_pairing_check,
    },
};

// Q-side MSM basis: 8 verifying-key commitments (five selectors, three
// permutation columns) plus the G1 generator carrying the E term, all shared
// across the batch; each proof adds [z], the three quotient parts, the three
// wire commitments, and the two opening proofs.
const Q_SHARED_POINTS: usize = 9;
const Q_POINTS_PER_PROOF: usize = 9;

/// Largest batch whose Q-side MSM fits the syscall point cap. The P-side MSM
/// (2 points per proof) and the fixed 2-pair check are strictly looser.
pub const MAX_PROOFS: usize = (MSM_MAX_POINTS - Q_SHARED_POINTS) / Q_POINTS_PER_PROOF;

// the boundary is exact: MAX_PROOFS fits, MAX_PROOFS + 1 does not
const _: () = assert!(Q_SHARED_POINTS + Q_POINTS_PER_PROOF * MAX_PROOFS <= MSM_MAX_POINTS);
const _: () = assert!(Q_SHARED_POINTS + Q_POINTS_PER_PROOF * (MAX_PROOFS + 1) > MSM_MAX_POINTS);

/// Batched KZG PLONK verification over the four batch syscalls, the reference
/// the on-chain program layer follows.
///
/// All proofs share one verifying key. Per proof, the PLONK verifier reduces
/// to scalar coefficients on a shared G1 basis; the rho-weighted sums P and
/// -Q come out of two G1 MSMs and the verdict is one boolean pairing check
/// e(P, [tau]_2) e(-Q, [1]_2) = 1. Field-side cost note: the Lagrange
/// denominators of the whole batch go through a single
/// alt_bn128_fr_batch_invert, so batches with
/// n * max(num_public_inputs, 1) > FR_MAX_ELEMS surface `CapExceeded`.
pub fn plonk_batch_verify(
    _version: Version,
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    mode: RandomizerMode,
) -> Result<bool, PlonkBatchError> {
    if proofs.is_empty() {
        // an empty batch would vacuously accept
        return Err(PlonkBatchError::EmptyBatch);
    }
    if proofs.len() > MAX_PROOFS {
        return Err(PlonkBatchError::TooManyProofs);
    }
    // shape and canonicality checks come before any hashing
    for proof in proofs {
        proof.validate(vk)?;
    }
    // inner challenges are proof-local, outer randomizers cover the frozen
    // batch; neither leaks into the other's domain
    let inner: Vec<InnerChallenges> = proofs.iter().map(|proof| derive_inner(vk, proof)).collect();
    let seed = derive_seed(mode, vk, proofs);
    let randomizers = derive_randomizers(&seed, proofs.len() as u64, mode);
    let reduced = reduce_batch(vk, proofs, &inner)?;
    let (p, negated_q) = assemble_msms(vk, proofs, &reduced, &randomizers)?;
    // deliberate deviation: this syscall surface has no
    // prepared-G2 lane, so the raw-G2 pairing check subgroup-checks its two
    // G2 inputs; the batch pays exactly two constant SRS subgroup checks
    // regardless of n, and still zero subgroup checks on untrusted data
    let pairs = [
        PodG1G2Pair {
            g1: p,
            g2: vk.key().g2_tau,
        },
        PodG1G2Pair {
            g1: negated_q,
            g2: vk.key().g2_gen,
        },
    ];
    Ok(alt_bn128_pairing_check(
        solana_bn254_batch_syscall::Version::V0,
        &pairs,
    )?)
}

/// Runs the per-proof reductions with the Lagrange denominators of the whole
/// batch inverted in a single alt_bn128_fr_batch_invert call.
pub(crate) fn reduce_batch(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    inner: &[InnerChallenges],
) -> Result<Vec<ReducedProof>, PlonkBatchError> {
    let count = lagrange_count(vk);
    let mut vanishings = Vec::with_capacity(proofs.len());
    let mut denominators: Vec<PodScalar> = Vec::with_capacity(proofs.len() * count);
    for challenges in inner {
        let vanishing = vanishing_eval(vk.domain_size(), challenges.zeta)?;
        vanishings.push(vanishing);
        denominators.extend(
            lagrange_denominators(vk, challenges.zeta, count)
                .iter()
                .map(PodScalar::from),
        );
    }
    let inverses =
        alt_bn128_fr_batch_invert(solana_bn254_batch_syscall::Version::V0, &denominators)?;
    let inverses: Vec<Fr> = inverses
        .iter()
        .map(|scalar| scalar.to_fr())
        .collect::<Result<_, _>>()?;
    proofs
        .iter()
        .zip(inner)
        .zip(vanishings)
        .enumerate()
        .map(|(i, ((proof, challenges), vanishing))| {
            reduce(
                vk,
                proof,
                challenges,
                vanishing,
                &inverses[i * count..(i + 1) * count],
            )
        })
        .collect()
}

/// The two batch MSMs: P = sum rho_i (W_zeta + u_i W_zeta_omega) over 2n
/// points, and -Q over 9 + 9n points. -Q is computed directly by negating
/// every Q coefficient before the MSM; no point is ever negated outside the
/// field. Shared-basis coefficients collapse to rho-weighted sums, so the
/// verifying-key commitments and the generator appear once whatever n is.
pub(crate) fn assemble_msms(
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
    reduced: &[ReducedProof],
    randomizers: &[Fr],
) -> Result<(PodG1Point, PodG1Point), PlonkBatchError> {
    let key = vk.key();
    let n = proofs.len();
    let mut p_points = Vec::with_capacity(2 * n);
    let mut p_scalars = Vec::with_capacity(2 * n);
    let mut q_points = Vec::with_capacity(Q_SHARED_POINTS + Q_POINTS_PER_PROOF * n);
    let mut q_scalars = Vec::with_capacity(Q_SHARED_POINTS + Q_POINTS_PER_PROOF * n);

    let mut shared = [Fr::from(0u64); Q_SHARED_POINTS];
    for (proof_coeffs, rho) in reduced.iter().zip(randomizers) {
        let vk_coeffs = &proof_coeffs.vk_coeffs;
        let coefficients = [
            vk_coeffs.q_m,
            vk_coeffs.q_l,
            vk_coeffs.q_r,
            vk_coeffs.q_o,
            vk_coeffs.q_c,
            vk_coeffs.s_sigma1,
            vk_coeffs.s_sigma2,
            vk_coeffs.s_sigma3,
            proof_coeffs.generator,
        ];
        for (accumulator, coefficient) in shared.iter_mut().zip(coefficients) {
            *accumulator += *rho * coefficient;
        }
    }
    let shared_points = [
        key.q_m,
        key.q_l,
        key.q_r,
        key.q_o,
        key.q_c,
        key.s_sigma[0],
        key.s_sigma[1],
        key.s_sigma[2],
        PodG1Point::from(&G1Affine::generator()),
    ];
    for (point, coefficient) in shared_points.iter().zip(shared) {
        q_points.push(*point);
        q_scalars.push(-coefficient);
    }

    for ((proof, proof_coeffs), rho) in proofs.iter().zip(reduced).zip(randomizers) {
        p_points.push(proof.opening);
        p_scalars.push(*rho * proof_coeffs.w_zeta_p);
        p_points.push(proof.shifted_opening);
        p_scalars.push(*rho * proof_coeffs.w_zeta_omega_p);

        let per_proof = [
            (proof.grand_product, proof_coeffs.z),
            (proof.quotient[0], proof_coeffs.t_lo),
            (proof.quotient[1], proof_coeffs.t_mid),
            (proof.quotient[2], proof_coeffs.t_hi),
            (proof.wire_commitments[0], proof_coeffs.a),
            (proof.wire_commitments[1], proof_coeffs.b),
            (proof.wire_commitments[2], proof_coeffs.c),
            (proof.opening, proof_coeffs.w_zeta_q),
            (proof.shifted_opening, proof_coeffs.w_zeta_omega_q),
        ];
        for (point, coefficient) in per_proof {
            q_points.push(point);
            q_scalars.push(-(*rho * coefficient));
        }
    }

    Ok((msm(&p_points, &p_scalars)?, msm(&q_points, &q_scalars)?))
}

fn msm(points: &[PodG1Point], scalars: &[Fr]) -> Result<PodG1Point, PlonkBatchError> {
    let scalars: Vec<PodScalar> = scalars.iter().map(PodScalar::from).collect();
    Ok(alt_bn128_g1_msm(
        solana_bn254_batch_syscall::Version::V0,
        points,
        &scalars,
    )?)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            test_support::{Trapdoor, g1_bytes, make_proof, make_vk, rng},
            transcript::RandomizerMode::Independent,
        },
        ark_bn254::{Bn254, Fq, G1Projective},
        ark_ec::{CurveGroup, pairing::Pairing},
        ark_ff::{Field, One, PrimeField, UniformRand},
        ark_std::rand::rngs::StdRng,
    };

    fn verify(vk: &ValidatedVerifyingKey, proofs: &[Proof]) -> Result<bool, PlonkBatchError> {
        plonk_batch_verify(Version::V0, vk, proofs, Independent)
    }

    fn batch(rng: &mut StdRng, n: usize) -> (Trapdoor, ValidatedVerifyingKey, Vec<Proof>) {
        let (trapdoor, vk) = make_vk(rng);
        let proofs = (0..n)
            .map(|_| make_proof(&trapdoor, Fr::rand(rng), Fr::rand(rng)))
            .collect();
        (trapdoor, vk, proofs)
    }

    fn parse_g1(point: &PodG1Point) -> G1Affine {
        G1Affine::new(
            Fq::from_be_bytes_mod_order(&point.0[..32]),
            Fq::from_be_bytes_mod_order(&point.0[32..]),
        )
    }

    #[test]
    fn test_valid_batches_verify() {
        let mut rng = rng();
        for n in [1usize, 2, 5] {
            let (_, vk, proofs) = batch(&mut rng, n);
            assert_eq!(verify(&vk, &proofs), Ok(true), "n = {n}");
            assert_eq!(
                plonk_batch_verify(Version::V0, &vk, &proofs, RandomizerMode::Powers),
                Ok(true),
                "n = {n} powers"
            );
        }
    }

    #[test]
    fn test_batch_of_one_matches_direct_arkworks_pairing() {
        // n = 1 is a batch of one, checked like any other; pin
        // the reduction against an independent computation of P and Q with
        // plain arkworks point arithmetic (points, not the MSM path) and
        // arkworks' own multi_pairing
        let mut rng = rng();
        let (_, vk, proofs) = batch(&mut rng, 1);
        let proof = &proofs[0];
        let challenges = derive_inner(&vk, proof);
        let reduced = reduce_batch(&vk, proofs.as_slice(), &[challenges])
            .unwrap()
            .remove(0);

        let point = |pod: &PodG1Point| G1Projective::from(pod.to_affine().unwrap());
        let key = vk.key();
        let p = point(&proof.opening) * reduced.w_zeta_p
            + point(&proof.shifted_opening) * reduced.w_zeta_omega_p;
        let vk_coeffs = &reduced.vk_coeffs;
        let q = point(&key.q_m) * vk_coeffs.q_m
            + point(&key.q_l) * vk_coeffs.q_l
            + point(&key.q_r) * vk_coeffs.q_r
            + point(&key.q_o) * vk_coeffs.q_o
            + point(&key.q_c) * vk_coeffs.q_c
            + point(&key.s_sigma[0]) * vk_coeffs.s_sigma1
            + point(&key.s_sigma[1]) * vk_coeffs.s_sigma2
            + point(&key.s_sigma[2]) * vk_coeffs.s_sigma3
            + G1Projective::from(G1Affine::generator()) * reduced.generator
            + point(&proof.grand_product) * reduced.z
            + point(&proof.quotient[0]) * reduced.t_lo
            + point(&proof.quotient[1]) * reduced.t_mid
            + point(&proof.quotient[2]) * reduced.t_hi
            + point(&proof.wire_commitments[0]) * reduced.a
            + point(&proof.wire_commitments[1]) * reduced.b
            + point(&proof.wire_commitments[2]) * reduced.c
            + point(&proof.opening) * reduced.w_zeta_q
            + point(&proof.shifted_opening) * reduced.w_zeta_omega_q;
        let direct = Bn254::multi_pairing(
            [p.into_affine(), (-q).into_affine()],
            [
                key.g2_tau.to_affine().unwrap(),
                key.g2_gen.to_affine().unwrap(),
            ],
        );
        assert!(direct.0.is_one(), "reduction must verify directly");

        // and the syscall path agrees
        assert_eq!(verify(&vk, &proofs), Ok(true));
    }

    #[test]
    fn test_perturbed_commitment_fails_the_batch() {
        let mut rng = rng();
        let (_, vk, mut proofs) = batch(&mut rng, 4);
        // perturb one grand-product commitment: individually invalid, and the
        // batch must see it
        let z = parse_g1(&proofs[2].grand_product);
        proofs[2].grand_product = g1_bytes(&(z + G1Affine::generator()).into_affine());
        assert_eq!(verify(&vk, &proofs), Ok(false));
    }

    #[test]
    fn test_duplicate_invalid_proof_still_rejected() {
        // a duplicated bad proof contributes E^(rho_a + rho_b),
        // which is 1 only with probability 2^-128
        let mut rng = rng();
        let (_, vk, mut proofs) = batch(&mut rng, 2);
        let w = parse_g1(&proofs[0].opening);
        proofs[0].opening = g1_bytes(&(w + G1Affine::generator()).into_affine());
        proofs[1] = proofs[0].clone();
        assert_eq!(verify(&vk, &proofs), Ok(false));
    }

    #[test]
    fn test_cancelling_perturbations_need_the_randomizers() {
        // PLONK shape. Exact GT-level cancellation through the
        // live transcript is not cheaply constructible: every proof byte is
        // absorbed before u is squeezed, so any point
        // perturbation moves the very coefficients the cancellation must be
        // solved against. The attack is therefore staged at the assembly
        // layer with frozen reduction coefficients, modelling a hypothetical
        // unrandomized verifier: perturb both proofs' opening slots so the
        // errors cancel in the plain sums P and Q, then show the rho-weighted
        // sums reject.
        let mut rng = rng();
        let (_, vk, proofs) = batch(&mut rng, 2);
        let inner: Vec<InnerChallenges> = proofs
            .iter()
            .map(|proof| derive_inner(&vk, proof))
            .collect();
        let reduced = reduce_batch(&vk, &proofs, &inner).unwrap();

        // perturbations s_i on W_zeta and t_i on W_zeta_omega add
        // (s_i + u_i t_i) G to P_i and (zeta_i s_i + u_i zeta_i omega t_i) G
        // to Q_i; with s_0 = 1, t_0 = 0 the unique cancelling choice is
        // t_1 = (zeta_1 - zeta_0) / (u_1 zeta_1 (omega - 1)), s_1 = -1 - u_1 t_1
        let omega = vk.omega();
        let (zeta_0, zeta_1) = (inner[0].zeta, inner[1].zeta);
        let u_1 = inner[1].u;
        let t_1 = (zeta_1 - zeta_0) * (u_1 * zeta_1 * (omega - Fr::one())).inverse().unwrap();
        let s_1 = -Fr::one() - u_1 * t_1;

        let generator = G1Projective::from(G1Affine::generator());
        let shift = |pod: &PodG1Point, scalar: Fr| {
            g1_bytes(
                &(G1Projective::from(pod.to_affine().unwrap()) + generator * scalar).into_affine(),
            )
        };
        let mut perturbed = proofs.clone();
        perturbed[0].opening = shift(&proofs[0].opening, Fr::one());
        perturbed[1].opening = shift(&proofs[1].opening, s_1);
        perturbed[1].shifted_opening = shift(&proofs[1].shifted_opening, t_1);

        let check = |randomizers: &[Fr]| -> bool {
            let (p, negated_q) = assemble_msms(&vk, &perturbed, &reduced, randomizers).unwrap();
            let pairs = [
                PodG1G2Pair {
                    g1: p,
                    g2: vk.key().g2_tau,
                },
                PodG1G2Pair {
                    g1: negated_q,
                    g2: vk.key().g2_gen,
                },
            ];
            alt_bn128_pairing_check(solana_bn254_batch_syscall::Version::V0, &pairs).unwrap()
        };

        // each perturbed proof is individually invalid under its frozen
        // coefficients
        assert!(!check(&[Fr::one(), Fr::from(0u64)]));
        assert!(!check(&[Fr::from(0u64), Fr::one()]));

        // the unrandomized sums cancel: that is the attack
        assert!(check(&[Fr::one(), Fr::one()]));

        // derived randomizers over the perturbed batch kill it
        let seed = derive_seed(Independent, &vk, &perturbed);
        let randomizers = derive_randomizers(&seed, 2, Independent);
        assert!(!check(&randomizers));

        // and the full verifier (which also re-derives inner challenges)
        // rejects the perturbed batch
        assert_eq!(verify(&vk, &perturbed), Ok(false));
    }

    #[test]
    fn test_max_proofs_is_the_msm_cap() {
        // the boundary consts at the top of the module prove exactness at
        // compile time; pin the resulting value here
        assert_eq!(MAX_PROOFS, 226);
    }

    #[test]
    fn test_batch_size_guards_at_the_boundary() {
        let mut rng = rng();
        let (_, vk, proofs) = batch(&mut rng, 1);

        assert_eq!(verify(&vk, &[]), Err(PlonkBatchError::EmptyBatch));

        // the cap is on proof count, so cheap clones exercise the exact
        // boundary; the guard fires before any per-proof work
        let mut clones = vec![proofs[0].clone(); MAX_PROOFS + 1];
        assert_eq!(verify(&vk, &clones), Err(PlonkBatchError::TooManyProofs));
        clones.truncate(MAX_PROOFS);
        assert_eq!(verify(&vk, &clones), Ok(true));
    }

    #[test]
    fn test_shape_errors_and_precedence() {
        let mut rng = rng();
        let (_, vk, proofs) = batch(&mut rng, 1);

        // wrong input count, caught before any hashing
        let mut mutated = proofs.clone();
        mutated[0].public_inputs.push(PodScalar([0u8; 32]));
        assert_eq!(
            verify(&vk, &mutated),
            Err(PlonkBatchError::InputCountMismatch)
        );

        // infinity in a proof position
        let mut mutated = proofs.clone();
        mutated[0].quotient[1] = PodG1Point([0u8; 64]);
        assert_eq!(
            verify(&vk, &mutated),
            Err(PlonkBatchError::InfinityInProofPosition)
        );

        // non-canonical evaluation and public input
        let mut mutated = proofs.clone();
        mutated[0].evaluations.s_sigma1 = PodScalar([0xffu8; 32]);
        assert_eq!(
            verify(&vk, &mutated),
            Err(PlonkBatchError::NonCanonicalScalar)
        );
        let mut mutated = proofs.clone();
        mutated[0].public_inputs[0] = PodScalar([0xffu8; 32]);
        assert_eq!(
            verify(&vk, &mutated),
            Err(PlonkBatchError::NonCanonicalScalar)
        );

        // an off-curve proof point passes shape validation here and surfaces
        // from the MSM syscall's own validation
        let mut mutated = proofs.clone();
        mutated[0].opening.0[63] = mutated[0].opening.0[63].wrapping_add(1);
        assert!(matches!(
            verify(&vk, &mutated),
            Err(PlonkBatchError::Syscall(_))
        ));
    }

    #[test]
    fn test_wrong_statement_rejected() {
        // a valid proof bound to a different public input must fail: the
        // statement enters both transcripts and PI(zeta)
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let mut proof = make_proof(&trapdoor, x, y);
        let claimed = x * y + x + Fr::one();
        proof.public_inputs[0] = PodScalar::from(&claimed);
        assert_eq!(verify(&vk, &[proof]), Ok(false));
    }
}
