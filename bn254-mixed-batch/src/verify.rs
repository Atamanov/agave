use {
    crate::{MixedBatchError, Version, transcript::RandomizerMode},
    ark_bn254::Fr,
    solana_bn254_batch_syscall::{PAIRING_MAX_PAIRS, PodG1G2Pair, alt_bn128_pairing_check},
    solana_bn254_groth16_batch as groth16, solana_bn254_plonk_batch as plonk,
};

/// One PLONK verifying key and its proofs. Groups under one SRS (equal
/// `g2_gen` and `g2_tau` bytes) merge into a single two-pair tail.
pub struct PlonkGroup<'a> {
    pub vk: &'a plonk::ValidatedVerifyingKey,
    pub proofs: &'a [plonk::Proof],
}

/// A frozen mixed batch. Either section may be empty, not both.
/// `groth16_proofs` name their keys by `vk_index` into `groth16_vks`.
pub struct MixedBatch<'a> {
    pub groth16_vks: &'a [groth16::ValidatedVerifyingKey],
    pub groth16_proofs: &'a [groth16::Proof],
    pub plonk_groups: &'a [PlonkGroup<'a>],
}

/// Mixed batched verification: both sections fold under one joint transcript
/// and one randomizer stream into a single boolean pairing check.
///
/// The pair list is the Groth16 fold (n + 3 or n + 5 terms per key) followed
/// by two terms per distinct PLONK SRS. Soundness is the small-exponents
/// argument applied across schemes: every verification equation, Groth16 or
/// PLONK, carries its own 128-bit randomizer from the joint seed, so a
/// cross-scheme cancellation of error terms survives with probability at
/// most 2^-128 per equation.
pub fn mixed_batch_verify(
    _version: Version,
    batch: &MixedBatch,
    mode: RandomizerMode,
) -> Result<bool, MixedBatchError> {
    let has_groth16 = !batch.groth16_proofs.is_empty();
    if !has_groth16 && batch.plonk_groups.is_empty() {
        return Err(MixedBatchError::EmptyBatch);
    }
    if batch.groth16_vks.len() > usize::from(u16::MAX) {
        return Err(groth16::Groth16BatchError::TooManyVerifyingKeys.into());
    }
    if batch.plonk_groups.len() > usize::from(u16::MAX) {
        return Err(MixedBatchError::TooManyPairs);
    }

    // shape and canonicality checks over every section before any hashing
    if has_groth16 {
        if let Err(error) = groth16::validate_batch_shape(batch.groth16_vks, batch.groth16_proofs) {
            if error == groth16::Groth16BatchError::TooManyPairs {
                return Err(MixedBatchError::TooManyPairs);
            }
            return Err(error.into());
        }
    }
    for group in batch.plonk_groups {
        plonk::validate_batch_shape(group.vk, group.proofs)?;
    }
    if folded_pair_count(batch) > PAIRING_MAX_PAIRS {
        return Err(MixedBatchError::TooManyPairs);
    }

    // the joint seed absorbs each section's own seed digest; an empty
    // groth16 section still contributes its (count-framed) digest so the
    // layout is fixed
    let groth16_seed =
        groth16::derive_seed(mode.groth16(), batch.groth16_vks, batch.groth16_proofs);
    let plonk_seeds: Vec<[u8; 32]> = batch
        .plonk_groups
        .iter()
        .map(|group| plonk::derive_seed(mode.plonk(), group.vk, group.proofs))
        .collect();
    let seed = crate::transcript::derive_seed(mode, &groth16_seed, &plonk_seeds)
        .ok_or(MixedBatchError::TooManyPairs)?;

    let groth16_equations = groth16::equation_count(batch.groth16_proofs);
    let plonk_equations = batch.plonk_groups.iter().try_fold(0u64, |count, group| {
        let group_count =
            u64::try_from(group.proofs.len()).map_err(|_| MixedBatchError::TooManyPairs)?;
        count
            .checked_add(group_count)
            .ok_or(MixedBatchError::TooManyPairs)
    })?;
    let equation_count = groth16_equations
        .checked_add(plonk_equations)
        .ok_or(MixedBatchError::TooManyPairs)?;
    let randomizers = crate::transcript::derive_randomizers(&seed, equation_count, mode);
    let groth16_equations =
        usize::try_from(groth16_equations).map_err(|_| MixedBatchError::TooManyPairs)?;
    let (groth16_randomizers, plonk_randomizers) = randomizers
        .split_at_checked(groth16_equations)
        .ok_or(MixedBatchError::TooManyPairs)?;

    let mut pairs: Vec<PodG1G2Pair> = if has_groth16 {
        groth16::fold_pairs_prevalidated(
            batch.groth16_vks,
            batch.groth16_proofs,
            groth16_randomizers,
        )?
    } else {
        Vec::new()
    };
    fold_plonk_tail(batch.plonk_groups, plonk_randomizers, &mut pairs)?;

    if pairs.len() > PAIRING_MAX_PAIRS {
        return Err(MixedBatchError::TooManyPairs);
    }
    Ok(alt_bn128_pairing_check(
        solana_bn254_batch_syscall::Version::V0,
        &pairs,
    )?)
}

/// Exact output-pair count from validated shapes, computed before hashing or
/// any MSM/reduction work so an over-cap mixed batch fails cheaply.
fn folded_pair_count(batch: &MixedBatch) -> usize {
    let mut count = batch.groth16_proofs.len();
    let mut seen = vec![false; batch.groth16_vks.len()];
    for proof in batch.groth16_proofs {
        let index = usize::from(proof.vk_index);
        if !seen[index] {
            seen[index] = true;
            count = count.saturating_add(if batch.groth16_vks[index].key().pedersen.is_some() {
                5
            } else {
                3
            });
        }
    }

    let mut distinct_srs = Vec::new();
    for group in batch.plonk_groups {
        let key = group.vk.key();
        if !distinct_srs
            .iter()
            .any(|(g2_gen, g2_tau)| *g2_gen == &key.g2_gen && *g2_tau == &key.g2_tau)
        {
            distinct_srs.push((&key.g2_gen, &key.g2_tau));
            count = count.saturating_add(2);
        }
    }
    count
}

/// Clusters the PLONK groups by their SRS points (first-appearance order) and
/// appends one (P, [tau]_2), (-Q, [1]_2) pair per cluster. Clustering by the
/// G2 bytes is what makes the merge sound: the fold verifies against exactly
/// the SRS its groups committed under.
fn fold_plonk_tail(
    groups: &[PlonkGroup],
    randomizers: &[Fr],
    pairs: &mut Vec<PodG1G2Pair>,
) -> Result<(), MixedBatchError> {
    // per-group randomizer slices, in group order
    let mut offsets = Vec::with_capacity(groups.len());
    let mut offset = 0usize;
    for group in groups {
        offsets.push(offset);
        offset = offset
            .checked_add(group.proofs.len())
            .ok_or(MixedBatchError::TooManyPairs)?;
    }

    let mut clusters: Vec<(usize, Vec<usize>)> = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let key = group.vk.key();
        let cluster = clusters.iter_mut().find(|(first, _)| {
            let first_key = groups[*first].vk.key();
            first_key.g2_gen == key.g2_gen && first_key.g2_tau == key.g2_tau
        });
        match cluster {
            Some((_, members)) => members.push(index),
            None => clusters.push((index, vec![index])),
        }
    }

    for (first, members) in &clusters {
        let fold_groups: Vec<plonk::FoldGroup> = members
            .iter()
            .map(|&index| plonk::FoldGroup {
                vk: groups[index].vk,
                proofs: groups[index].proofs,
            })
            .collect();
        let mut cluster_randomizers = Vec::new();
        for &index in members {
            let end = offsets[index]
                .checked_add(groups[index].proofs.len())
                .ok_or(MixedBatchError::TooManyPairs)?;
            let group_randomizers = randomizers
                .get(offsets[index]..end)
                .ok_or(plonk::PlonkBatchError::RandomizerCountMismatch)?;
            cluster_randomizers.extend_from_slice(group_randomizers);
        }
        let (p, negated_q) = plonk::fold_msms_prevalidated(&fold_groups, &cluster_randomizers)?;
        let srs = groups[*first].vk.key();
        pairs.push(PodG1G2Pair {
            g1: p,
            g2: srs.g2_tau,
        });
        pairs.push(PodG1G2Pair {
            g1: negated_q,
            g2: srs.g2_gen,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{Fr, G1Affine, G1Projective},
        ark_ec::{AffineRepr, CurveGroup},
        ark_ff::{Field, One, UniformRand},
        ark_std::rand::rngs::StdRng,
        core::ops::{Add, Mul},
        groth16::test_utils as g16_fix,
        plonk::test_support as plonk_fix,
        solana_bn254_batch_syscall::PodG1Point,
    };

    fn rng() -> StdRng {
        g16_fix::rng()
    }

    fn verify(batch: &MixedBatch) -> Result<bool, MixedBatchError> {
        mixed_batch_verify(Version::V0, batch, RandomizerMode::Independent)
    }

    struct Fixture {
        g16_vks: Vec<groth16::ValidatedVerifyingKey>,
        g16_proofs: Vec<groth16::Proof>,
        plonk_vk: plonk::ValidatedVerifyingKey,
        plonk_proofs: Vec<plonk::Proof>,
    }

    impl Fixture {
        fn batch<'a>(&'a self, groups: &'a mut Vec<PlonkGroup<'a>>) -> MixedBatch<'a> {
            groups.push(PlonkGroup {
                vk: &self.plonk_vk,
                proofs: &self.plonk_proofs,
            });
            MixedBatch {
                groth16_vks: &self.g16_vks,
                groth16_proofs: &self.g16_proofs,
                plonk_groups: groups,
            }
        }
    }

    fn make_fixture(rng: &mut StdRng, g16_n: usize, plonk_n: usize) -> Fixture {
        let (key, vk) = g16_fix::make_vk(rng, 1, false);
        let g16_proofs = (0..g16_n)
            .map(|_| {
                let input = Fr::rand(rng);
                g16_fix::make_proof(rng, &key, 0, &[input])
            })
            .collect();
        let (trapdoor, plonk_vk) = plonk_fix::make_vk(rng);
        let plonk_proofs = (0..plonk_n)
            .map(|_| plonk_fix::make_proof(&trapdoor, Fr::rand(rng), Fr::rand(rng)))
            .collect();
        Fixture {
            g16_vks: vec![vk],
            g16_proofs,
            plonk_vk,
            plonk_proofs,
        }
    }

    fn shift_g1(point: &PodG1Point, scalar: Fr) -> PodG1Point {
        let affine = point.to_affine().unwrap();
        let generator = G1Projective::from(G1Affine::generator());
        PodG1Point::from(
            &G1Projective::from(affine)
                .add(generator.mul(scalar))
                .into_affine(),
        )
    }

    #[test]
    fn test_valid_mixed_batches_verify() {
        let mut rng = rng();
        for (g16_n, plonk_n) in [(1usize, 1usize), (3, 2), (2, 5)] {
            let fixture = make_fixture(&mut rng, g16_n, plonk_n);
            let mut groups = Vec::new();
            let batch = fixture.batch(&mut groups);
            assert_eq!(verify(&batch), Ok(true), "{g16_n} + {plonk_n}");
            assert_eq!(
                mixed_batch_verify(Version::V0, &batch, RandomizerMode::Powers),
                Ok(true),
                "{g16_n} + {plonk_n} powers"
            );
        }
    }

    #[test]
    fn test_single_scheme_agreement_and_single_sided_batches() {
        // the mixed verdict agrees with the single-scheme verifiers on the
        // same fixtures (verdict-level: the randomizer streams differ)
        let mut rng = rng();
        let fixture = make_fixture(&mut rng, 2, 2);
        assert_eq!(
            groth16::groth16_batch_verify(
                groth16::Version::V0,
                &fixture.g16_vks,
                &fixture.g16_proofs,
                groth16::RandomizerMode::Independent,
            ),
            Ok(true)
        );
        assert_eq!(
            plonk::plonk_batch_verify(
                plonk::Version::V0,
                &fixture.plonk_vk,
                &fixture.plonk_proofs,
                plonk::RandomizerMode::Independent,
            ),
            Ok(true)
        );
        let mut groups = Vec::new();
        assert_eq!(verify(&fixture.batch(&mut groups)), Ok(true));

        // either side alone is a valid mixed batch
        let groth16_only = MixedBatch {
            groth16_vks: &fixture.g16_vks,
            groth16_proofs: &fixture.g16_proofs,
            plonk_groups: &[],
        };
        assert_eq!(verify(&groth16_only), Ok(true));
        let plonk_group = [PlonkGroup {
            vk: &fixture.plonk_vk,
            proofs: &fixture.plonk_proofs,
        }];
        let plonk_only = MixedBatch {
            groth16_vks: &[],
            groth16_proofs: &[],
            plonk_groups: &plonk_group,
        };
        assert_eq!(verify(&plonk_only), Ok(true));

        // but not neither
        let empty = MixedBatch {
            groth16_vks: &[],
            groth16_proofs: &[],
            plonk_groups: &[],
        };
        assert_eq!(verify(&empty), Err(MixedBatchError::EmptyBatch));
    }

    #[test]
    fn test_one_bad_proof_on_either_side_fails_the_batch() {
        let mut rng = rng();

        let mut fixture = make_fixture(&mut rng, 2, 2);
        fixture.g16_proofs[1].c = shift_g1(&fixture.g16_proofs[1].c, Fr::one());
        let mut groups = Vec::new();
        assert_eq!(
            verify(&fixture.batch(&mut groups)),
            Ok(false),
            "groth16 side"
        );

        let mut fixture = make_fixture(&mut rng, 2, 2);
        fixture.plonk_proofs[0].grand_product =
            shift_g1(&fixture.plonk_proofs[0].grand_product, Fr::one());
        let mut groups = Vec::new();
        assert_eq!(verify(&fixture.batch(&mut groups)), Ok(false), "plonk side");
    }

    #[test]
    fn test_cross_scheme_cancellation_needs_the_randomizers() {
        // perturb the groth16 C by +G (error gt^-delta at r = 1) and the
        // plonk opening by +sG (error gt^(s(tau - zeta)) at rho = 1, since
        // zeta is squeezed before the opening is absorbed and the honest
        // commitments satisfy the u-linear KZG combination for any u).
        // s = delta / (tau - zeta) cancels the pairing product exactly, so
        // the unrandomized joint check accepts two individually invalid
        // proofs; the derived randomizers reject them.
        let mut rng = rng();
        let (g16_key, g16_vk) = g16_fix::make_vk(&mut rng, 1, false);
        let input = Fr::rand(&mut rng);
        let mut g16_proof = g16_fix::make_proof(&mut rng, &g16_key, 0, &[input]);
        g16_proof.c = shift_g1(&g16_proof.c, Fr::one());

        let (trapdoor, plonk_vk) = plonk_fix::make_vk(&mut rng);
        let mut plonk_proof =
            plonk_fix::make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));
        let zeta = plonk_fix::derive_inner(&plonk_vk, &plonk_proof).zeta;
        let s = g16_key.delta * (trapdoor.tau - zeta).inverse().unwrap();
        plonk_proof.opening = shift_g1(&plonk_proof.opening, s);

        // each side is individually invalid
        let g16_vks = [g16_vk];
        let g16_proofs = [g16_proof];
        assert_eq!(
            groth16::groth16_batch_verify(
                groth16::Version::V0,
                &g16_vks,
                &g16_proofs,
                groth16::RandomizerMode::Independent,
            ),
            Ok(false)
        );
        let plonk_proofs = [plonk_proof];
        assert_eq!(
            plonk::plonk_batch_verify(
                plonk::Version::V0,
                &plonk_vk,
                &plonk_proofs,
                plonk::RandomizerMode::Independent,
            ),
            Ok(false)
        );

        // the unrandomized joint product cancels: that is the attack
        let mut pairs = groth16::fold_pairs(&g16_vks, &g16_proofs, &[Fr::one()]).unwrap();
        let groups = [PlonkGroup {
            vk: &plonk_vk,
            proofs: &plonk_proofs,
        }];
        fold_plonk_tail(&groups, &[Fr::one()], &mut pairs).unwrap();
        assert_eq!(
            alt_bn128_pairing_check(solana_bn254_batch_syscall::Version::V0, &pairs),
            Ok(true),
            "the unrandomized product must cancel across schemes"
        );

        // the joint challenge kills it
        let batch = MixedBatch {
            groth16_vks: &g16_vks,
            groth16_proofs: &g16_proofs,
            plonk_groups: &groups,
        };
        assert_eq!(verify(&batch), Ok(false));
    }

    #[test]
    fn test_shared_srs_groups_merge_into_one_tail() {
        // two distinct circuits under one tau cost two pairs; a third group
        // under another tau costs two more
        let mut rng = rng();
        let tau = Fr::rand(&mut rng);
        let (trapdoor_a, vk_a) = plonk_fix::make_vk_with_tau(tau, true);
        let (trapdoor_b, vk_b) = plonk_fix::make_vk_with_tau(tau, false);
        let (trapdoor_c, vk_c) = plonk_fix::make_vk(&mut rng);
        let proofs_a = [plonk_fix::make_proof(
            &trapdoor_a,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        )];
        let proofs_b = [plonk_fix::make_proof(
            &trapdoor_b,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        )];
        let proofs_c = [plonk_fix::make_proof(
            &trapdoor_c,
            Fr::rand(&mut rng),
            Fr::rand(&mut rng),
        )];

        let shared = [
            PlonkGroup {
                vk: &vk_a,
                proofs: &proofs_a,
            },
            PlonkGroup {
                vk: &vk_b,
                proofs: &proofs_b,
            },
        ];
        let mut pairs = Vec::new();
        fold_plonk_tail(&shared, &[Fr::one(), Fr::one()], &mut pairs).unwrap();
        assert_eq!(pairs.len(), 2, "one SRS, one tail");

        let split = [
            PlonkGroup {
                vk: &vk_a,
                proofs: &proofs_a,
            },
            PlonkGroup {
                vk: &vk_c,
                proofs: &proofs_c,
            },
        ];
        let mut pairs = Vec::new();
        fold_plonk_tail(&split, &[Fr::one(), Fr::one()], &mut pairs).unwrap();
        assert_eq!(pairs.len(), 4, "two SRS, two tails");

        // and heterogeneous shared-SRS batches verify end to end
        let batch = MixedBatch {
            groth16_vks: &[],
            groth16_proofs: &[],
            plonk_groups: &shared,
        };
        assert_eq!(verify(&batch), Ok(true));
    }

    #[test]
    fn test_seed_binds_sections_and_framing() {
        let g16_seed = [1u8; 32];
        let group_seeds = [[2u8; 32], [3u8; 32]];
        let baseline =
            crate::transcript::derive_seed(RandomizerMode::Independent, &g16_seed, &group_seeds);
        assert!(baseline.is_some());

        // each section digest
        let mut mutated = g16_seed;
        mutated[7] ^= 1;
        assert_ne!(
            baseline,
            crate::transcript::derive_seed(RandomizerMode::Independent, &mutated, &group_seeds)
        );
        let mut mutated = group_seeds;
        mutated[1][7] ^= 1;
        assert_ne!(
            baseline,
            crate::transcript::derive_seed(RandomizerMode::Independent, &g16_seed, &mutated)
        );

        // group order and count
        assert_ne!(
            baseline,
            crate::transcript::derive_seed(
                RandomizerMode::Independent,
                &g16_seed,
                &[group_seeds[1], group_seeds[0]],
            )
        );
        assert_ne!(
            baseline,
            crate::transcript::derive_seed(
                RandomizerMode::Independent,
                &g16_seed,
                &group_seeds[..1],
            )
        );
        let excessive_group_count = usize::from(u16::MAX).checked_add(1).unwrap();
        let excessive_group_seeds = vec![[0u8; 32]; excessive_group_count];
        assert_eq!(
            crate::transcript::derive_seed(
                RandomizerMode::Independent,
                &g16_seed,
                &excessive_group_seeds,
            ),
            None
        );

        // the domain tag: cross-mode replay is cross-context replay, and the
        // mixed tags are distinct from both section tags
        assert_ne!(
            baseline,
            crate::transcript::derive_seed(RandomizerMode::Powers, &g16_seed, &group_seeds)
        );
        for tag in [
            RandomizerMode::Independent.domain_tag(),
            RandomizerMode::Powers.domain_tag(),
        ] {
            let tag = core::str::from_utf8(tag).unwrap();
            assert!(tag.contains(":v1:"), "tag must carry a version: {tag}");
            assert!(
                tag.contains("mixed"),
                "tag must name the joint layer: {tag}"
            );
        }
    }

    #[test]
    fn test_pair_cap_is_enforced() {
        // 254 vanilla proofs on one key give 257 pair terms, one over the cap
        let mut rng = rng();
        let (key, vk) = g16_fix::make_vk(&mut rng, 1, false);
        let input = Fr::rand(&mut rng);
        let proof = g16_fix::make_proof(&mut rng, &key, 0, &[input]);
        let proofs: Vec<groth16::Proof> = vec![proof; 254];
        let batch = MixedBatch {
            groth16_vks: &[vk],
            groth16_proofs: &proofs,
            plonk_groups: &[],
        };
        assert_eq!(verify(&batch), Err(MixedBatchError::TooManyPairs));

        // The Groth16 section alone is exactly 255 pairs and therefore valid,
        // but one PLONK SRS tail raises the joint fold to 257. The mixed cap
        // must reject before transcript hashing or either scheme's MSM work.
        let fixture = make_fixture(&mut rng, 252, 1);
        let mut groups = Vec::new();
        let batch = fixture.batch(&mut groups);
        assert_eq!(verify(&batch), Err(MixedBatchError::TooManyPairs));
    }

    #[test]
    fn test_empty_groth16_section_checks_key_count_framing() {
        let mut rng = rng();
        let fixture = make_fixture(&mut rng, 0, 1);
        let key_count = usize::from(u16::MAX).checked_add(1).unwrap();
        let groth16_vks = vec![fixture.g16_vks[0].clone(); key_count];
        let plonk_groups = [PlonkGroup {
            vk: &fixture.plonk_vk,
            proofs: &fixture.plonk_proofs,
        }];
        let batch = MixedBatch {
            groth16_vks: &groth16_vks,
            groth16_proofs: &[],
            plonk_groups: &plonk_groups,
        };
        assert_eq!(
            verify(&batch),
            Err(MixedBatchError::Groth16(
                groth16::Groth16BatchError::TooManyVerifyingKeys,
            ))
        );
    }
}
