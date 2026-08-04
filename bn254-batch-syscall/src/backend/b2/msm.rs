//! G1 multi-scalar multiplication with GLV halving.
//!
//! Small batches share one Strauss-Shamir doubling walk. Larger batches use
//! Pippenger over the GLV half-width pairs.

use {
    super::arith::glv::{HALF_WNAF_MAX, half_to_u128, scalar_decomposition, wnaf_u128},
    crate::{
        Version,
        encoding::MSM_MAX_POINTS,
        pod::{PodG1Point, PodScalar},
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    ark_bn254::{Fr, G1Affine, G1Projective, g1::Config as G1Config},
    ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, scalar_mul::glv::GLVConfig},
    ark_ff::{AdditiveGroup, Zero},
    core::ops::{Add, Neg, Sub},
};

/// This boundary is the measured crossover with GLV Pippenger.
const STRAUSS_BAND_MAX: usize = 64;

/// One accumulator avoids duplicate doublings in the measured band.
const K_BAND: usize = 1;

/// Multi-scalar multiplication in G1: sum of scalars[i] * points[i].
///
/// Points are validated before scalars. G1 has cofactor one, so an on-curve
/// point is in the subgroup. Infinity serializes as zero bytes.
pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    validate_equal_lengths(points.len(), scalars.len())?;
    if points.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if points.len() > MSM_MAX_POINTS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut bases = Vec::with_capacity(points.len());
    for point in points {
        bases.push(point.to_affine()?);
    }
    let mut exponents: Vec<Fr> = Vec::with_capacity(scalars.len());
    for scalar in scalars {
        exponents.push(scalar.to_fr()?);
    }

    // Both paths compute the same group sum.
    let sum = if bases.len() <= STRAUSS_BAND_MAX {
        msm_band_strauss(&bases, &exponents)?
    } else {
        msm_pippenger_glv(&bases, &exponents)?
    };
    Ok(PodG1Point::from(&sum))
}

/// A band-walk digit stream: the owning point's index (the chain-partition
/// key), the wNAF digits, and the signed effective table.
type BandChain = (usize, [i8; HALF_WNAF_MAX], [G1Affine; 4]);

/// Build width-four wNAF chains for each nonzero GLV half. All odd-multiple
/// tables share one batch normalization. Psi maps normalized entries without
/// more curve operations.
fn build_band_chains(
    bases: &[G1Affine],
    exps: &[Fr],
) -> Result<(Vec<BandChain>, usize), AltBn128BatchError> {
    validate_equal_lengths(bases.len(), exps.len())?;
    let mut split = Vec::with_capacity(bases.len());
    for (base, exp) in bases.iter().zip(exps) {
        if base.is_zero() {
            continue;
        }
        let ((sgn1, k1), (sgn2, k2)) =
            scalar_decomposition(exp).ok_or(AltBn128BatchError::BackendInvariant)?;
        let k1 = half_to_u128(&k1).ok_or(AltBn128BatchError::BackendInvariant)?;
        let k2 = half_to_u128(&k2).ok_or(AltBn128BatchError::BackendInvariant)?;
        if k1 == 0 && k2 == 0 {
            continue;
        }
        split.push((*base, (sgn1, k1), (sgn2, k2)));
    }
    if split.is_empty() {
        return Ok((Vec::new(), 0));
    }
    // The prime-order group keeps these multiples finite for a nonzero base.
    let odd_capacity = 3usize
        .checked_mul(split.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut odd = Vec::with_capacity(odd_capacity);
    for (b, _, _) in &split {
        let two_b = b.into_group().double();
        let p3 = two_b.add(*b);
        let p5 = p3.add(two_b);
        let p7 = p5.add(two_b);
        odd.extend_from_slice(&[p3, p5, p7]);
    }
    let odd = G1Projective::normalize_batch(&odd);
    let mut walk_top = 0;
    let chain_capacity = 2usize
        .checked_mul(split.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut chains = Vec::with_capacity(chain_capacity);
    for (point, ((b, half1, half2), multiples)) in split.iter().zip(odd.chunks_exact(3)).enumerate()
    {
        let [p3, p5, p7] = multiples else {
            return Err(AltBn128BatchError::BackendInvariant);
        };
        let table_p = [*b, *p3, *p5, *p7];
        for (is_psi, &(sgn, k)) in [(false, half1), (true, half2)] {
            if k == 0 {
                continue;
            }
            let mut table = if is_psi {
                table_p.map(|p| G1Config::endomorphism_affine(&p))
            } else {
                table_p
            };
            if !sgn {
                table = table.map(Neg::neg);
            }
            let (digits, top) = wnaf_u128(k).ok_or(AltBn128BatchError::BackendInvariant)?;
            walk_top = walk_top.max(top);
            chains.push((point, digits, table));
        }
    }
    Ok((chains, walk_top))
}

/// Walk `K` accumulators from the most significant digit. Point index assigns
/// each digit stream to one accumulator. The final sum only reassociates group
/// additions, so all positive `K` values return the same group element.
fn strauss_walk<const K: usize>(
    chains: &[BandChain],
    walk_top: usize,
) -> Result<G1Projective, AltBn128BatchError> {
    if K == 0 || walk_top >= HALF_WNAF_MAX {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    let mut accs = [G1Projective::zero(); K];
    for i in (0..=walk_top).rev() {
        for acc in accs.iter_mut() {
            acc.double_in_place();
        }
        for (point, digits, table) in chains {
            let d = digits
                .get(i)
                .copied()
                .ok_or(AltBn128BatchError::BackendInvariant)?;
            if d != 0 {
                let table_index = usize::from(d.unsigned_abs() / 2);
                let entry = table
                    .get(table_index)
                    .ok_or(AltBn128BatchError::BackendInvariant)?;
                let chain = point
                    .checked_rem(K)
                    .ok_or(AltBn128BatchError::BackendInvariant)?;
                let acc = accs
                    .get_mut(chain)
                    .ok_or(AltBn128BatchError::BackendInvariant)?;
                if d > 0 {
                    *acc = acc.add(entry);
                } else {
                    *acc = acc.sub(entry);
                }
            }
        }
    }
    Ok(accs.into_iter().sum())
}

/// The n <= STRAUSS_BAND_MAX arm: shared-doubling Strauss-Shamir over the
/// GLV half-scalar chains.
fn msm_band_strauss(bases: &[G1Affine], exps: &[Fr]) -> Result<G1Affine, AltBn128BatchError> {
    let (chains, walk_top) = build_band_chains(bases, exps)?;
    if chains.is_empty() {
        return Ok(G1Affine::zero());
    }
    Ok(strauss_walk::<K_BAND>(&chains, walk_top)?.into_affine())
}

/// Split each scalar into two half-width pairs before Pippenger. A true sign
/// is positive, which matches the arkworks GLV convention.
fn msm_pippenger_glv(bases: &[G1Affine], exps: &[Fr]) -> Result<G1Affine, AltBn128BatchError> {
    validate_equal_lengths(bases.len(), exps.len())?;
    let capacity = 2usize
        .checked_mul(bases.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut glv_bases = Vec::with_capacity(capacity);
    let mut glv_scalars = Vec::with_capacity(capacity);
    for (base, exp) in bases.iter().zip(exps) {
        let ((sgn1, k1), (sgn2, k2)) =
            scalar_decomposition(exp).ok_or(AltBn128BatchError::BackendInvariant)?;
        let psi = G1Config::endomorphism_affine(base);
        glv_bases.push(if sgn1 { *base } else { base.neg() });
        glv_scalars.push(k1);
        glv_bases.push(if sgn2 { psi } else { psi.neg() });
        glv_scalars.push(k2);
    }
    Ok(G1Projective::msm_unchecked(&glv_bases, &glv_scalars).into_affine())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::{G1_BYTES, SCALAR_BYTES, parse_g1},
            test_utils::{
                be_add_one, fq_modulus_be, fr_bytes, fr_modulus_be, g1_bytes, random_g1, rng,
            },
        },
        ark_bn254::{Fq, Fr, G1Affine, G1Projective},
        ark_ff::{One, UniformRand, Zero},
        ark_std::rand::Rng,
    };

    // the byte-oriented bodies below drive the typed entry point through a
    // zero-cost cast; whole-element inputs only, matching the syscall boundary
    fn msm(points: &[u8], scalars: &[u8]) -> Result<[u8; G1_BYTES], AltBn128BatchError> {
        alt_bn128_g1_msm(
            Version::V0,
            bytemuck::cast_slice(points),
            bytemuck::cast_slice(scalars),
        )
        .map(|point| point.0)
    }

    fn random_input(rng: &mut ark_std::rand::rngs::StdRng, n: usize) -> (Vec<u8>, Vec<u8>) {
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for _ in 0..n {
            points.extend_from_slice(&g1_bytes(&random_g1(rng)));
            scalars.extend_from_slice(&fr_bytes(&Fr::rand(rng)));
        }
        (points, scalars)
    }

    #[test]
    fn test_msm_matches_naive_sum() {
        let mut rng = rng();
        for n in [1usize, 2, 3, 17, 64] {
            let (points, scalars) = random_input(&mut rng, n);
            // independent reference: plain per-term multiply-and-add, no MSM
            let mut expected = G1Projective::zero();
            for (p, s) in points
                .chunks_exact(G1_BYTES)
                .zip(scalars.chunks_exact(SCALAR_BYTES))
            {
                expected +=
                    crate::encoding::parse_g1(p).unwrap() * crate::encoding::parse_fr(s).unwrap();
            }
            assert_eq!(
                msm(&points, &scalars).unwrap(),
                g1_bytes(&expected.into_affine()),
                "n = {n}"
            );
        }
    }

    #[test]
    fn test_band_matches_library_over_edge_lattice() {
        // pool of edge and random points/scalars strided through every
        // position across rounds; sizes cover the band ends, both internal
        // K-band boundaries, and the walk's degenerate shapes
        let mut rng = rng();
        let g = G1Affine::generator();
        let mut points = vec![G1Affine::zero(), g, -g];
        let mut scalars = vec![Fr::zero(), Fr::from(1u64), -Fr::from(1u64)];
        for _ in 0..24 {
            points.push(random_g1(&mut rng));
            scalars.push(Fr::rand(&mut rng));
        }
        for n in [1usize, 2, 3, 4, 5, 8, 15, 16, 17, 31, 32, 33, 63, 64] {
            for round in 0..6 {
                let bases: Vec<G1Affine> = (0..n)
                    .map(|k| points[(round * 7 + k * 3 + n) % points.len()])
                    .collect();
                let exps: Vec<Fr> = (0..n)
                    .map(|k| scalars[(round * 5 + k * 11 + n) % scalars.len()])
                    .collect();
                let expected: G1Projective = bases.iter().zip(&exps).map(|(b, e)| *b * *e).sum();
                assert_eq!(
                    msm_band_strauss(&bases, &exps).unwrap(),
                    expected.into_affine(),
                    "n = {n}, round = {round}"
                );
            }
            // degenerate lattices: all infinity, all zero scalars
            assert_eq!(
                msm_band_strauss(&vec![G1Affine::zero(); n], &vec![Fr::one(); n]).unwrap(),
                G1Affine::zero()
            );
            assert_eq!(
                msm_band_strauss(&vec![g; n], &vec![Fr::zero(); n]).unwrap(),
                G1Affine::zero()
            );
        }
    }

    #[test]
    fn test_walk_chain_count_only_reassociates() {
        let mut rng = rng();
        for n in [3usize, 7, 16, 33] {
            let bases: Vec<G1Affine> = (0..n).map(|_| random_g1(&mut rng)).collect();
            let exps: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let (chains, walk_top) = build_band_chains(&bases, &exps).unwrap();
            let one = strauss_walk::<1>(&chains, walk_top).unwrap();
            assert_eq!(
                strauss_walk::<2>(&chains, walk_top).unwrap(),
                one,
                "n = {n}"
            );
            assert_eq!(
                strauss_walk::<4>(&chains, walk_top).unwrap(),
                one,
                "n = {n}"
            );
        }
    }

    #[test]
    fn test_walk_rejects_zero_accumulators() {
        assert_eq!(
            strauss_walk::<0>(&[], 0),
            Err(AltBn128BatchError::BackendInvariant)
        );
    }

    #[test]
    fn test_pippenger_glv_matches_library() {
        let mut rng = rng();
        for n in [65usize, 96] {
            let mut bases: Vec<G1Affine> = (0..n).map(|_| random_g1(&mut rng)).collect();
            let mut exps: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            bases[7] = G1Affine::zero();
            exps[11] = Fr::zero();
            exps[12] = -Fr::one();
            assert_eq!(
                msm_pippenger_glv(&bases, &exps),
                Ok(G1Projective::msm_unchecked(&bases, &exps).into_affine()),
                "n = {n}"
            );
        }
    }

    #[test]
    fn test_msm_n1_matches_solana_bn254_mul() {
        let mut rng = rng();
        let point = random_g1(&mut rng);
        let scalar = Fr::rand(&mut rng);
        let mut group_op_input = [0u8; 96];
        group_op_input[..64].copy_from_slice(&g1_bytes(&point));
        group_op_input[64..].copy_from_slice(&fr_bytes(&scalar));
        let expected =
            solana_bn254::prelude::alt_bn128_g1_multiplication_be(&group_op_input).unwrap();
        let ours = msm(&g1_bytes(&point), &fr_bytes(&scalar)).unwrap();
        assert_eq!(ours.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_msm_linearity() {
        let mut rng = rng();
        let (points_a, scalars_a) = random_input(&mut rng, 5);
        let (points_b, scalars_b) = random_input(&mut rng, 3);
        let joined_points = [points_a.clone(), points_b.clone()].concat();
        let joined_scalars = [scalars_a.clone(), scalars_b.clone()].concat();
        let sum_a = parse_g1(&msm(&points_a, &scalars_a).unwrap()).unwrap();
        let sum_b = parse_g1(&msm(&points_b, &scalars_b).unwrap()).unwrap();
        let joined = parse_g1(&msm(&joined_points, &joined_scalars).unwrap()).unwrap();
        assert_eq!(joined, (sum_a + sum_b).into_affine());
    }

    #[test]
    fn test_msm_accepts_infinity_point() {
        let mut rng = rng();
        let (mut points, scalars) = random_input(&mut rng, 3);
        let without_middle = parse_g1(
            &msm(
                &[&points[..G1_BYTES], &points[2 * G1_BYTES..]].concat(),
                &[&scalars[..SCALAR_BYTES], &scalars[2 * SCALAR_BYTES..]].concat(),
            )
            .unwrap(),
        )
        .unwrap();
        points[G1_BYTES..2 * G1_BYTES].copy_from_slice(&[0u8; G1_BYTES]);
        assert_eq!(
            msm(&points, &scalars).unwrap(),
            g1_bytes(&without_middle),
            "an infinity base must contribute nothing"
        );
    }

    #[test]
    fn test_msm_result_infinity_is_all_zeros() {
        let mut rng = rng();
        let point = random_g1(&mut rng);
        // [1]P + [r-1]P = [r]P = infinity
        let points = [g1_bytes(&point), g1_bytes(&point)].concat();
        let scalars = [fr_bytes(&Fr::one()), fr_bytes(&(-Fr::one()))].concat();
        assert_eq!(msm(&points, &scalars).unwrap(), [0u8; G1_BYTES]);
    }

    #[test]
    fn test_msm_accepts_scalar_r_minus_one() {
        let mut rng = rng();
        let point = random_g1(&mut rng);
        let result = msm(&g1_bytes(&point), &fr_bytes(&(-Fr::one()))).unwrap();
        assert_eq!(result, g1_bytes(&(-point)));
    }

    #[test]
    fn test_msm_rejects_empty() {
        assert_eq!(msm(&[], &[]), Err(AltBn128BatchError::ZeroInput));
    }

    #[test]
    fn test_msm_rejects_count_mismatch() {
        let mut rng = rng();
        let (points, scalars) = random_input(&mut rng, 3);
        assert_eq!(
            msm(&points, &scalars[..2 * SCALAR_BYTES]),
            Err(AltBn128BatchError::LengthMismatch)
        );
        assert_eq!(msm(&[], &scalars), Err(AltBn128BatchError::LengthMismatch));
    }

    #[test]
    fn test_msm_rejects_over_cap() {
        let n = MSM_MAX_POINTS + 1;
        // all-infinity points are cheap to build and valid, so the cap is the
        // only thing rejecting this input
        let points = vec![0u8; n * G1_BYTES];
        let scalars = vec![0u8; n * SCALAR_BYTES];
        assert_eq!(msm(&points, &scalars), Err(AltBn128BatchError::CapExceeded));
        assert!(
            msm(
                &points[..G1_BYTES * MSM_MAX_POINTS],
                &scalars[..SCALAR_BYTES * MSM_MAX_POINTS]
            )
            .is_ok()
        );
    }

    #[test]
    fn test_msm_rejects_off_curve_point_at_any_position() {
        let mut rng = rng();
        for position in [0usize, 3, 7] {
            let (mut points, scalars) = random_input(&mut rng, 8);
            let good = parse_g1(&points[position * G1_BYTES..(position + 1) * G1_BYTES]).unwrap();
            let off_curve = G1Affine::new_unchecked(good.x, good.y + Fq::one());
            points[position * G1_BYTES..(position + 1) * G1_BYTES]
                .copy_from_slice(&g1_bytes(&off_curve));
            assert_eq!(
                msm(&points, &scalars),
                Err(AltBn128BatchError::NotOnCurve),
                "position {position}"
            );
        }
    }

    #[test]
    fn test_msm_rejects_noncanonical_coordinate() {
        let mut rng = rng();
        let mut plus_one = fq_modulus_be();
        be_add_one(&mut plus_one);
        for bad in [fq_modulus_be(), plus_one, [0xffu8; 32]] {
            for slot in [0usize, 32] {
                let (mut points, scalars) = random_input(&mut rng, 2);
                points[slot..slot + 32].copy_from_slice(&bad);
                assert_eq!(
                    msm(&points, &scalars),
                    Err(AltBn128BatchError::NonCanonical)
                );
            }
        }
    }

    #[test]
    fn test_msm_rejects_scalar_ge_r() {
        let mut rng = rng();
        let mut plus_one = fr_modulus_be();
        be_add_one(&mut plus_one);
        for bad in [fr_modulus_be(), plus_one, [0xffu8; 32]] {
            let (points, mut scalars) = random_input(&mut rng, 2);
            scalars[SCALAR_BYTES..].copy_from_slice(&bad);
            assert_eq!(
                msm(&points, &scalars),
                Err(AltBn128BatchError::NonCanonical)
            );
        }
    }

    #[test]
    fn test_msm_validates_points_before_scalars() {
        // a bad point and a bad scalar in one call: the points array is
        // validated first, pinning the cross-array order
        let mut rng = rng();
        let (mut points, mut scalars) = random_input(&mut rng, 2);
        let good = parse_g1(&points[G1_BYTES..]).unwrap();
        points[G1_BYTES..].copy_from_slice(&g1_bytes(&G1Affine::new_unchecked(
            good.x,
            good.y + Fq::one(),
        )));
        scalars[..SCALAR_BYTES].copy_from_slice(&fr_modulus_be());
        assert_eq!(msm(&points, &scalars), Err(AltBn128BatchError::NotOnCurve));
    }

    #[test]
    fn test_msm_noncanonical_beats_not_on_curve() {
        // 2^256 - 1 is both non-canonical and (after any reduction) off-curve;
        // the canonical check must fire first
        let mut rng = rng();
        let (mut points, scalars) = random_input(&mut rng, 1);
        points[..32].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(
            msm(&points, &scalars),
            Err(AltBn128BatchError::NonCanonical)
        );
    }

    #[test]
    fn test_msm_total_on_random_bytes_and_deterministic() {
        let mut rng = rng();
        for _ in 0..2_000 {
            let n = rng.gen_range(1..8usize);
            let mut points = vec![0u8; n * G1_BYTES];
            let mut scalars = vec![0u8; n * SCALAR_BYTES];
            rng.fill(&mut points[..]);
            rng.fill(&mut scalars[..]);
            // must never panic; random coordinates are almost surely rejected
            let first = msm(&points, &scalars);
            assert_eq!(first, msm(&points, &scalars), "must be deterministic");
        }
    }

    #[test]
    fn test_msm_total_on_bit_flips_of_valid_input() {
        let mut rng = rng();
        let (points, scalars) = random_input(&mut rng, 2);
        for byte in 0..points.len() {
            for bit in [0u8, 4] {
                let mut mutated = points.clone();
                mutated[byte] ^= 1 << bit;
                let first = msm(&mutated, &scalars);
                assert_eq!(first, msm(&mutated, &scalars));
            }
        }
    }
}
