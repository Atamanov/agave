use {
    crate::{
        Groth16BatchError, Version,
        transcript::{RandomizerMode, derive_randomizers, derive_seed},
        vk::ValidatedVerifyingKey,
    },
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
    solana_bn254_batch_syscall::{
        G1_BYTES, G2_BYTES, PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, alt_bn128_g1_msm,
        alt_bn128_pairing_check,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCommitment {
    pub com: PodG1Point,
    pub pok: PodG1Point,
}

/// One batch record, in the typed wire encoding of the batch syscalls.
/// `vk_index` names the proof's key within the batch's key list; whether
/// `commitment` must be present is a function of that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub vk_index: u16,
    pub a: PodG1Point,
    pub b: PodG2Point,
    pub c: PodG1Point,
    pub commitment: Option<ProofCommitment>,
    pub public_inputs: Vec<PodScalar>,
}

/// Batched Groth16 verification over the two batch syscalls, the reference the
/// on-chain program layer follows.
///
/// Every randomizer folds into the G1 side by bilinearity, so the whole fold
/// is G1 MSMs; the fixed-G2 terms collapse per key, giving n + 3 pair terms
/// per vanilla key and n + 5 per committed key in a single boolean pairing
/// check. Randomizers attach to verification equations, not proofs: a
/// committed proof draws r_i for the Groth16 relation and a separate s_i for
/// the Pedersen proof of knowledge.
pub fn groth16_batch_verify(
    _version: Version,
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    mode: RandomizerMode,
) -> Result<bool, Groth16BatchError> {
    // shape and canonicality checks come before any hashing
    validate_batch_shape(vks, proofs)?;
    let seed = derive_seed(mode, vks, proofs);
    let randomizers = derive_randomizers(&seed, equation_count(proofs), mode);
    let pairs = fold_pairs(vks, proofs, &randomizers)?;
    Ok(alt_bn128_pairing_check(
        solana_bn254_batch_syscall::Version::V0,
        &pairs,
    )?)
}

// a proof point must never be infinity; the syscall would silently skip it as
// the identity factor
fn is_infinity_g1(point: &PodG1Point) -> bool {
    point.0 == [0u8; G1_BYTES]
}

/// One verification equation per proof plus one more for a committed proof's
/// Pedersen proof of knowledge; the randomizer stream is indexed by equation.
pub fn equation_count(proofs: &[Proof]) -> u64 {
    proofs
        .iter()
        .map(|proof| if proof.commitment.is_some() { 2u64 } else { 1 })
        .sum()
}

/// Shape and canonicality checks over the frozen batch, before any hashing.
/// Public as a composition surface: a joint (multi-scheme) verifier runs the
/// same checks before absorbing this batch into its own transcript.
pub fn validate_batch_shape(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
) -> Result<(), Groth16BatchError> {
    if proofs.is_empty() {
        // an empty batch would vacuously accept; the syscall rejects zero
        // pairs too, but the SDK boundary rejects first
        return Err(Groth16BatchError::EmptyBatch);
    }
    // vk_index is a u16 and the transcript frames the key count as a u16, so a
    // longer key list both leaves keys unaddressable and truncates the count
    // prefix, desyncing the digest list from the proof region
    if vks.len() > usize::from(u16::MAX) {
        return Err(Groth16BatchError::TooManyVerifyingKeys);
    }
    for proof in proofs {
        let vk = vks
            .get(usize::from(proof.vk_index))
            .ok_or(Groth16BatchError::UnknownVerifyingKey)?;
        if proof.public_inputs.len() != vk.key().num_public_inputs() {
            return Err(Groth16BatchError::InputCountMismatch);
        }
        if proof.commitment.is_some() != vk.key().pedersen.is_some() {
            return Err(Groth16BatchError::CommitmentMismatch);
        }
        // the syscall would skip an infinity pair as the identity factor;
        // in a proof position that is a degenerate proof, so reject here

        if is_infinity_g1(&proof.a) || proof.b.0 == [0u8; G2_BYTES] || is_infinity_g1(&proof.c) {
            return Err(Groth16BatchError::InfinityInProofPosition);
        }
        if let Some(commitment) = &proof.commitment {
            if is_infinity_g1(&commitment.com) || is_infinity_g1(&commitment.pok) {
                return Err(Groth16BatchError::InfinityInProofPosition);
            }
        }
        for input in &proof.public_inputs {
            fr_from_be(input)?;
        }
    }
    Ok(())
}

/// The folded pair list: per proof e([r_i]A_i, B_i), then per key the
/// MSM-fed fixed-G2 terms. Negations fold into the MSM scalars ((r - s)P
/// = -[s]P), so no point is ever negated outside the field.
///
/// Public as a composition surface: a joint verifier concatenates this pair
/// list with other schemes' pairs into one pairing check. `randomizers` are
/// one per verification equation ([`equation_count`]) in proof order, the
/// Groth16 equation before the PoK within a committed proof; the caller runs
/// [`validate_batch_shape`] first.
pub fn fold_pairs(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    // assign per-equation randomizers in proof order: r_i always, s_i for
    // the PoK equation of a committed proof
    let mut next = randomizers.iter().copied();
    let mut next_randomizer = || next.next().expect("randomizer count matches equations");
    let assigned: Vec<(Fr, Option<Fr>)> = proofs
        .iter()
        .map(|proof| {
            (
                next_randomizer(),
                proof.commitment.as_ref().map(|_| next_randomizer()),
            )
        })
        .collect();

    let mut pairs: Vec<PodG1G2Pair> = Vec::new();
    let mut push_pair = |g1: PodG1Point, g2: PodG2Point| pairs.push(PodG1G2Pair { g1, g2 });

    // e([r_i]A_i, B_i): the per-proof G2 points are the only ones that
    // resist folding
    for (proof, (r, _)) in proofs.iter().zip(&assigned) {
        push_pair(msm(&[proof.a], &[*r])?, proof.b);
    }

    for (key_index, vk) in vks.iter().enumerate() {
        let key_proofs: Vec<(&Proof, Fr, Option<Fr>)> = proofs
            .iter()
            .zip(&assigned)
            .filter(|(proof, _)| usize::from(proof.vk_index) == key_index)
            .map(|(proof, (r, s))| (proof, *r, *s))
            .collect();
        if key_proofs.is_empty() {
            continue;
        }
        let key = vk.key();
        let r_sum: Fr = key_proofs.iter().map(|(_, r, _)| *r).sum();

        // e(-[sum r_i] alpha, beta)
        push_pair(msm(&[key.alpha_g1], &[-r_sum])?, key.beta_g2);

        // e(-sum_i [r_i] L_i, gamma) with L_i = IC_0 + sum_j x_ij IC_j
        // (+ com_i on the committed rail), all folded into one MSM
        let mut gamma_points: Vec<PodG1Point> = vec![key.ic[0]];
        let mut gamma_scalars: Vec<Fr> = vec![-r_sum];
        for (j, ic) in key.ic.iter().enumerate().skip(1) {
            let mut coefficient = Fr::from(0u64);
            for (proof, r, _) in &key_proofs {
                coefficient += *r * fr_from_be(&proof.public_inputs[j - 1])?;
            }
            gamma_points.push(*ic);
            gamma_scalars.push(-coefficient);
        }
        for (proof, r, _) in &key_proofs {
            if let Some(commitment) = &proof.commitment {
                gamma_points.push(commitment.com);
                gamma_scalars.push(-*r);
            }
        }
        push_pair(msm(&gamma_points, &gamma_scalars)?, key.gamma_g2);

        // e(-sum [r_i] C_i, delta)
        let mut delta_points: Vec<PodG1Point> = Vec::new();
        let mut delta_scalars: Vec<Fr> = Vec::new();
        for (proof, r, _) in &key_proofs {
            delta_points.push(proof.c);
            delta_scalars.push(-*r);
        }
        push_pair(msm(&delta_points, &delta_scalars)?, key.delta_g2);

        // committed rail: e(sum [s_i] com_i, g2) * e(-sum [s_i] pok_i,
        // sigma_g2), two pair terms per key whatever n is; the PoK equations
        // take their own s_i, never the proof's r_i
        if let Some(pedersen) = &key.pedersen {
            let mut com_points: Vec<PodG1Point> = Vec::new();
            let mut pok_points: Vec<PodG1Point> = Vec::new();
            let mut com_scalars: Vec<Fr> = Vec::new();
            let mut pok_scalars: Vec<Fr> = Vec::new();
            for (proof, _, s) in &key_proofs {
                let commitment = proof.commitment.as_ref().expect("shape checked");
                let s = s.expect("committed proof draws two randomizers");
                com_points.push(commitment.com);
                com_scalars.push(s);
                pok_points.push(commitment.pok);
                pok_scalars.push(-s);
            }
            push_pair(msm(&com_points, &com_scalars)?, pedersen.g2);
            push_pair(msm(&pok_points, &pok_scalars)?, pedersen.sigma_g2);
        }
    }
    Ok(pairs)
}

fn msm(points: &[PodG1Point], scalars: &[Fr]) -> Result<PodG1Point, Groth16BatchError> {
    let scalars: Vec<PodScalar> = scalars.iter().map(fr_to_pod).collect();
    Ok(alt_bn128_g1_msm(
        solana_bn254_batch_syscall::Version::V0,
        points,
        &scalars,
    )?)
}

fn fr_to_pod(scalar: &Fr) -> PodScalar {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&scalar.into_bigint().to_bytes_be());
    PodScalar(bytes)
}

fn fr_from_be(scalar: &PodScalar) -> Result<Fr, Groth16BatchError> {
    // Parse big-endian Fr without host-only PodScalar::to_fr (SBF-safe).
    use ark_ff::PrimeField;
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 32 - 8 * (i + 1);
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&scalar.0[start..start + 8]);
        *limb = u64::from_be_bytes(chunk);
    }
    let bi = <Fr as PrimeField>::BigInt::new(limbs);
    Fr::from_bigint(bi).ok_or(Groth16BatchError::NonCanonicalInput)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            test_utils::{
                TrapdoorKey, fr_bytes, g1, g1_bytes, g2_bytes, make_proof, make_vk,
                non_subgroup_g2, rng,
            },
            transcript::{RandomizerMode, RandomizerMode::Independent, derive_seed},
        },
        ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{CurveGroup, PrimeGroup, pairing::Pairing},
        ark_ff::{Field, One, PrimeField, UniformRand},
        ark_std::rand::rngs::StdRng,
        solana_bn254_batch_syscall::AltBn128BatchError,
    };

    fn verify(vks: &[ValidatedVerifyingKey], proofs: &[Proof]) -> Result<bool, Groth16BatchError> {
        groth16_batch_verify(Version::V0, vks, proofs, Independent)
    }

    fn vanilla_batch(
        rng: &mut StdRng,
        n: usize,
    ) -> (TrapdoorKey, Vec<ValidatedVerifyingKey>, Vec<Proof>) {
        let (key, vk) = make_vk(rng, 1, false);
        let proofs = (0..n)
            .map(|_| {
                let x = Fr::rand(rng);
                make_proof(rng, &key, 0, &[x])
            })
            .collect();
        (key, vec![vk], proofs)
    }

    fn parse_g1(point: &PodG1Point) -> G1Affine {
        G1Affine::new(
            Fq::from_be_bytes_mod_order(&point.0[..32]),
            Fq::from_be_bytes_mod_order(&point.0[32..]),
        )
    }

    fn parse_g2(point: &PodG2Point) -> G2Affine {
        let x1 = Fq::from_be_bytes_mod_order(&point.0[0..32]);
        let x0 = Fq::from_be_bytes_mod_order(&point.0[32..64]);
        let y1 = Fq::from_be_bytes_mod_order(&point.0[64..96]);
        let y0 = Fq::from_be_bytes_mod_order(&point.0[96..128]);
        G2Affine::new(Fq2::new(x0, x1), Fq2::new(y0, y1))
    }

    #[test]
    fn test_valid_batches_verify() {
        let mut rng = rng();
        for n in [1usize, 2, 5] {
            let (_, vks, proofs) = vanilla_batch(&mut rng, n);
            assert_eq!(verify(&vks, &proofs), Ok(true), "n = {n}");
        }
    }

    #[test]
    fn test_invalid_proof_fails_the_batch() {
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 4);
        // perturb one C: individually invalid, and the batch must see it
        let c = parse_g1(&proofs[2].c);
        proofs[2].c = g1_bytes(&(c + g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &proofs), Ok(false));
    }

    #[test]
    fn test_cancelling_perturbations_need_the_randomizers() {
        // perturb one proof's C by +D and another's by -D. The
        // error terms e(D, delta) and e(-D, delta) cancel in the naive
        // product, so with randomizers forced to one the batch accepts two
        // individually invalid proofs; the derived randomizers reject them.
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 2);
        let d = g1(Fr::rand(&mut rng));
        let c0 = parse_g1(&proofs[0].c);
        let c1 = parse_g1(&proofs[1].c);
        proofs[0].c = g1_bytes(&(c0 + d).into_affine());
        proofs[1].c = g1_bytes(&(c1 - d).into_affine());

        let ones = vec![Fr::one(); 2];
        let pairs = fold_pairs(&vks, &proofs, &ones).unwrap();
        let naive = alt_bn128_pairing_check(solana_bn254_batch_syscall::Version::V0, &pairs);
        assert_eq!(
            naive,
            Ok(true),
            "the unrandomized product must cancel, that is the attack"
        );

        assert_eq!(verify(&vks, &proofs), Ok(false), "the challenge kills it");
    }

    #[test]
    fn test_committed_rail_verifies_and_counts_pairs() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, true);
        let proofs: Vec<Proof> = (0..3)
            .map(|_| {
                let x = Fr::rand(&mut rng);
                make_proof(&mut rng, &key, 0, &[x])
            })
            .collect();
        let vks = vec![vk];
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // n + 5 pair terms for one committed key
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 6, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 3 + 5);

        // ... and a committed proof draws two distinct randomizers
        assert_eq!(randomizers.len(), 2 * proofs.len());
        assert_ne!(randomizers[0], randomizers[1]);
    }

    #[test]
    fn test_vanilla_batch_is_n_plus_3_pairs() {
        let mut rng = rng();
        let (_, vks, proofs) = vanilla_batch(&mut rng, 4);
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 4, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 4 + 3);
    }

    #[test]
    fn test_mixed_batch_two_keys() {
        let mut rng = rng();
        let (vanilla_key, vanilla_vk) = make_vk(&mut rng, 1, false);
        let (committed_key, committed_vk) = make_vk(&mut rng, 2, true);
        let inputs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let proofs = vec![
            make_proof(&mut rng, &vanilla_key, 0, &inputs[0..1]),
            make_proof(&mut rng, &committed_key, 1, &inputs[1..3]),
            make_proof(&mut rng, &vanilla_key, 0, &inputs[3..4]),
        ];
        let vks = vec![vanilla_vk, committed_vk];
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // n + 3 + 5 pair terms for one vanilla and one committed key
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 4, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 3 + 3 + 5);

        // one bad proof anywhere fails the mixed batch
        let mut bad = proofs.clone();
        let c = parse_g1(&bad[1].c);
        bad[1].c = g1_bytes(&(c + g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &bad), Ok(false));
    }

    #[test]
    fn test_duplicate_invalid_proof_still_rejected() {
        // a duplicated bad proof contributes E^(r_a + r_b),
        // which is 1 only with probability 2^-128
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 2);
        let c = parse_g1(&proofs[0].c);
        proofs[0].c = g1_bytes(&(c + g1(Fr::one())).into_affine());
        proofs[1] = proofs[0].clone();
        assert_eq!(verify(&vks, &proofs), Ok(false));
    }

    #[test]
    fn test_batch_of_one_matches_direct_verification() {
        // n = 1 is a batch of one, checked like any other; pin
        // it against an independent direct computation of the Groth16
        // equation e(A,B) e(-alpha,beta) e(-L,gamma) e(-C,delta) == 1 with
        // arkworks' own multi_pairing
        let mut rng = rng();
        let (key, vks, proofs) = vanilla_batch(&mut rng, 1);
        let proof = &proofs[0];
        let x = super::fr_from_be(&proof.public_inputs[0]).unwrap();
        let l = key.ic[0] + x * key.ic[1];
        let direct = Bn254::multi_pairing(
            [
                parse_g1(&proof.a),
                (-G1Projective::from(g1(key.alpha))).into_affine(),
                (-G1Projective::from(g1(l))).into_affine(),
                (-G1Projective::from(parse_g1(&proof.c))).into_affine(),
            ],
            [
                parse_g2(&proof.b),
                (G2Projective::generator() * key.beta).into_affine(),
                (G2Projective::generator() * key.gamma).into_affine(),
                (G2Projective::generator() * key.delta).into_affine(),
            ],
        );
        assert!(direct.0.is_one(), "fixture must verify directly");
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // and a directly-invalid proof is a false batch of one
        let mut bad = proofs.clone();
        let c = parse_g1(&bad[0].c);
        bad[0].c = g1_bytes(&(c + g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &bad), Ok(false));
    }

    #[test]
    fn test_groth16_malleability_is_real() {
        // (A, B, C) -> (sA, s^-1 B + t delta, C + st A) is a
        // distinct valid proof of the same statement; proof bytes are not an
        // identity, so replay protection must key on the statement
        let mut rng = rng();
        let (key, vks, mut proofs) = vanilla_batch(&mut rng, 1);
        let s = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);
        let a = parse_g1(&proofs[0].a);
        let b = parse_g2(&proofs[0].b);
        let c = parse_g1(&proofs[0].c);
        let delta_g2 = G2Projective::generator() * key.delta;

        let original = proofs[0].clone();
        proofs[0].a = g1_bytes(&(G1Projective::from(a) * s).into_affine());
        proofs[0].b =
            g2_bytes(&(G2Projective::from(b) * s.inverse().unwrap() + delta_g2 * t).into_affine());
        proofs[0].c =
            g1_bytes(&(G1Projective::from(c) + G1Projective::from(a) * (s * t)).into_affine());
        assert_ne!(
            proofs[0], original,
            "the malleated proof has distinct bytes"
        );
        assert_eq!(verify(&vks, &proofs), Ok(true), "and it still verifies");
    }

    #[test]
    fn test_shape_errors() {
        let mut rng = rng();
        let (key, vks, mut proofs) = vanilla_batch(&mut rng, 1);

        assert_eq!(verify(&vks, &[]), Err(Groth16BatchError::EmptyBatch));

        // wrong input count, caught before any hashing
        proofs[0].public_inputs.push(fr_bytes(&Fr::one()));
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::InputCountMismatch)
        );
        proofs[0].public_inputs.truncate(1);

        // unknown key index
        proofs[0].vk_index = 7;
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::UnknownVerifyingKey)
        );
        proofs[0].vk_index = 0;

        // key list longer than the u16 count/index can frame, rejected before
        // hashing so the count prefix never truncates
        let padded: Vec<ValidatedVerifyingKey> = std::iter::repeat_with(|| vks[0].clone())
            .take(usize::from(u16::MAX) + 1)
            .collect();
        assert_eq!(
            verify(&padded, &proofs),
            Err(Groth16BatchError::TooManyVerifyingKeys)
        );

        // rail mismatch: a commitment on a vanilla key has no framing
        proofs[0].commitment = Some(ProofCommitment {
            com: g1_bytes(&g1(Fr::one())),
            pok: g1_bytes(&g1(Fr::one())),
        });
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::CommitmentMismatch)
        );
        proofs[0].commitment = None;

        // infinity in a proof position
        let saved = proofs[0].a;
        proofs[0].a = PodG1Point([0u8; 64]);
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::InfinityInProofPosition)
        );
        proofs[0].a = saved;

        // non-canonical public input
        proofs[0].public_inputs[0] = PodScalar([0xffu8; 32]);
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::NonCanonicalInput)
        );
        proofs[0].public_inputs[0] = fr_bytes(&Fr::one());

        // zero-input circuit: L degenerates to the constant IC_0 and the
        // batch still verifies
        let (zero_key, zero_vk) = make_vk(&mut rng, 0, false);
        let zero_proofs = vec![make_proof(&mut rng, &zero_key, 0, &[])];
        assert_eq!(verify(&[zero_vk], &zero_proofs), Ok(true));

        let _ = key;
    }

    #[test]
    fn test_bad_proof_points_surface_as_syscall_errors() {
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 1);
        // a non-subgroup B lands in the pairing check's validation
        proofs[0].b = g2_bytes(&non_subgroup_g2());
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::Syscall(
                AltBn128BatchError::NotInSubgroup
            ))
        );
    }

    #[test]
    fn test_powers_mode_verifies() {
        let mut rng = rng();
        let (_, vks, proofs) = vanilla_batch(&mut rng, 3);
        assert_eq!(
            groth16_batch_verify(Version::V0, &vks, &proofs, RandomizerMode::Powers),
            Ok(true)
        );
    }
}
