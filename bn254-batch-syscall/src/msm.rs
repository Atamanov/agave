//! G1 multi-scalar multiplication via mcl's `mulVec` (GLV-split Strauss for
//! small n, Pippenger buckets for large n, dispatched internally).
//!
//! The n == 1 case needs no dedicated arm: `mulVec` at one point measured
//! the same time as `mclBnG1_mul` (bn254-mcl-sys perf probe).

use {
    crate::{
        Version,
        encoding::{MSM_MAX_POINTS, parse_fr, serialize_g1},
        pod::{PodG1Point, PodScalar},
        validation::AltBn128BatchError,
    },
    solana_bn254_mcl_sys::api,
};

/// Multi-scalar multiplication in G1: sum of scalars[i] * points[i].
///
/// Validation order per point: canonical coordinates (< p), on-curve; G1 has
/// cofactor 1 so on-curve implies subgroup membership. The points array is
/// validated before the scalars array. The result serializes infinity as
/// all-zeros. Element widths are fixed by the pod types, so a malformed length
/// cannot reach here; it faults at the syscall boundary instead.
pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    if points.len() != scalars.len() {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    if points.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if points.len() > MSM_MAX_POINTS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut bases = Vec::with_capacity(points.len());
    for point in points {
        bases.push(point.to_mcl()?);
    }
    let mut exponents = Vec::with_capacity(scalars.len());
    for scalar in scalars {
        exponents.push(parse_fr(&scalar.0)?);
    }

    let sum = api::g1_mul_vec(&mut bases, &exponents);
    Ok(PodG1Point(serialize_g1(&sum)))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::{G1_BYTES, SCALAR_BYTES},
            test_utils::{
                be_add_one, fq_modulus_be, fr_bytes, fr_modulus_be, g1_bytes, random_g1, rng,
            },
        },
        ark_bn254::{Fq, Fr, G1Affine, G1Projective},
        ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM},
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
        let mut points = Vec::with_capacity(n * G1_BYTES);
        let mut scalars = Vec::with_capacity(n * SCALAR_BYTES);
        for _ in 0..n {
            points.extend_from_slice(&g1_bytes(&random_g1(rng)));
            scalars.extend_from_slice(&fr_bytes(&Fr::rand(rng)));
        }
        (points, scalars)
    }

    fn msm_oracle(bases: &[G1Affine], exps: &[Fr]) -> [u8; G1_BYTES] {
        // independent reference: plain per-term multiply-and-add, no MSM
        let mut expected = G1Projective::zero();
        for (p, s) in bases.iter().zip(exps) {
            expected += *p * *s;
        }
        g1_bytes(&expected.into_affine())
    }

    #[test]
    fn test_msm_matches_naive_sum() {
        let mut rng = rng();
        for n in [1usize, 2, 3, 17, 64] {
            let (points, scalars) = random_input(&mut rng, n);
            let bases: Vec<G1Affine> = points
                .chunks_exact(G1_BYTES)
                .map(|p| crate::encoding::ark_g1_unchecked(p.try_into().unwrap()))
                .collect();
            let exps: Vec<Fr> = scalars
                .chunks_exact(SCALAR_BYTES)
                .map(|s| crate::encoding::ark_fr(s).unwrap())
                .collect();
            assert_eq!(
                msm(&points, &scalars).unwrap(),
                msm_oracle(&bases, &exps),
                "n = {n}"
            );
        }
    }

    #[test]
    fn test_msm_matches_naive_over_edge_lattice() {
        // pool of edge and random points/scalars strided through every
        // position across rounds; sizes cover any internal dispatch
        // boundaries and the degenerate shapes
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
                let point_bytes: Vec<u8> = bases.iter().flat_map(g1_bytes).collect();
                let scalar_bytes: Vec<u8> = exps.iter().flat_map(fr_bytes).collect();
                assert_eq!(
                    msm(&point_bytes, &scalar_bytes).unwrap(),
                    msm_oracle(&bases, &exps),
                    "n = {n}, round = {round}"
                );
            }
            // degenerate lattices: all infinity, all zero scalars
            assert_eq!(
                msm(
                    &vec![0u8; n * G1_BYTES],
                    &Vec::from_iter(std::iter::repeat_n(fr_bytes(&Fr::one()), n).flatten())
                )
                .unwrap(),
                [0u8; G1_BYTES]
            );
            assert_eq!(
                msm(
                    &Vec::from_iter(std::iter::repeat_n(g1_bytes(&g), n).flatten()),
                    &vec![0u8; n * SCALAR_BYTES]
                )
                .unwrap(),
                [0u8; G1_BYTES]
            );
        }
    }

    #[test]
    fn test_msm_large_matches_library() {
        let mut rng = rng();
        for n in [65usize, 96] {
            let mut bases: Vec<G1Affine> = (0..n).map(|_| random_g1(&mut rng)).collect();
            let mut exps: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            bases[7] = G1Affine::zero();
            exps[11] = Fr::zero();
            exps[12] = -Fr::one();
            let point_bytes: Vec<u8> = bases.iter().flat_map(g1_bytes).collect();
            let scalar_bytes: Vec<u8> = exps.iter().flat_map(fr_bytes).collect();
            assert_eq!(
                msm(&point_bytes, &scalar_bytes).unwrap(),
                g1_bytes(&G1Projective::msm_unchecked(&bases, &exps).into_affine()),
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
        let sum_a = crate::encoding::ark_g1_unchecked(&msm(&points_a, &scalars_a).unwrap());
        let sum_b = crate::encoding::ark_g1_unchecked(&msm(&points_b, &scalars_b).unwrap());
        assert_eq!(
            msm(&joined_points, &joined_scalars).unwrap(),
            g1_bytes(&(sum_a + sum_b).into_affine())
        );
    }

    #[test]
    fn test_msm_accepts_infinity_point() {
        let mut rng = rng();
        let (mut points, scalars) = random_input(&mut rng, 3);
        let without_middle = msm(
            &[&points[..G1_BYTES], &points[2 * G1_BYTES..]].concat(),
            &[&scalars[..SCALAR_BYTES], &scalars[2 * SCALAR_BYTES..]].concat(),
        )
        .unwrap();
        points[G1_BYTES..2 * G1_BYTES].copy_from_slice(&[0u8; G1_BYTES]);
        assert_eq!(
            msm(&points, &scalars).unwrap(),
            without_middle,
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
            let good = crate::encoding::ark_g1_unchecked(
                points[position * G1_BYTES..(position + 1) * G1_BYTES]
                    .try_into()
                    .unwrap(),
            );
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
        let good = crate::encoding::ark_g1_unchecked(points[G1_BYTES..].try_into().unwrap());
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
