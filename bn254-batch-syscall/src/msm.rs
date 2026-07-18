//! G1 multi-scalar multiplication with GLV halving and a Strauss-Shamir band.
//!
//! Every scalar is GLV-split k = k1 + lambda*k2 (arith::glv), turning each
//! term into two half-width chains over P and psi(P). For n <= 64 one
//! Strauss-Shamir walk shares a single ~128-step doubling run across all
//! chains, which beats Pippenger's bucket overhead at these sizes (measured
//! -37% at the zolana msm@50 cell); larger n keeps the library's serial
//! Pippenger over the 2n half-width pairs. psi tables are the elementwise psi
//! image of the P tables, so the endo half never pays curve ops.

use {
    crate::{
        Version,
        arith::glv::{HALF_WNAF_MAX, half_to_u128, scalar_decomposition, wnaf_u128},
        encoding::MSM_MAX_POINTS,
        pod::{PodG1Point, PodScalar},
        validation::AltBn128BatchError,
    },
    ark_bn254::{Fr, G1Affine, G1Projective, g1::Config as G1Config},
    ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, scalar_mul::glv::GLVConfig},
    ark_ff::{AdditiveGroup, Zero},
};

/// Largest n served by the shared-doubling Strauss band: measurement raised
/// it to 64 so the zolana msm@50 cell rides the shared doubling run; above
/// it Pippenger's buckets amortize better.
const STRAUSS_BAND_MAX: usize = 64;

/// Walk-accumulator chain count: measurement settled K = 1
/// across the whole band (the serial double chain already hides the add
/// latency, so extra chains only re-pay doubles). The walk stays generic over
/// K because the reassociation proof tests instantiate K = 2 and 4.
const K_BAND: usize = 1;

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
        bases.push(point.to_affine()?);
    }
    let mut exponents: Vec<Fr> = Vec::with_capacity(scalars.len());
    for scalar in scalars {
        exponents.push(scalar.to_fr()?);
    }

    // both arms compute the same group element as the naive sum, so the
    // dispatch cannot change a byte; small n rides the band walk as its
    // degenerate 2- and 4-chain shapes
    let sum = if bases.len() <= STRAUSS_BAND_MAX {
        msm_band_strauss(&bases, &exponents)
    } else {
        msm_pippenger_glv(&bases, &exponents)
    };
    Ok(PodG1Point::from(&sum))
}

/// A band-walk digit stream: the owning point's index (the chain-partition
/// key), the wNAF digits, and the signed effective table.
type BandChain = (usize, [i8; HALF_WNAF_MAX], [G1Affine; 4]);

/// GLV-split chain build for the band walk: each non-zero base builds ONE
/// odd-multiples table {1, 3, 5, 7}P, ALL P tables share ONE
/// `normalize_batch` inversion, the psi tables are the elementwise psi image
/// of the normalized entries (psi(jP) = j*psi(P) for any group
/// endomorphism), and signs come free by affine negation after the map.
/// Each chain with a nonzero half-scalar carries its w = 4 wNAF digits
/// (w = 5 measured slower than w = 4 for this band). Returns the
/// chains and the MSB walk height; empty chains iff every term drops.
/// n <= STRAUSS_BAND_MAX bounds the tables to at most 128 chains and 192
/// normalized odd multiples (~49KB, comfortably L2-resident).
fn build_band_chains(bases: &[G1Affine], exps: &[Fr]) -> (Vec<BandChain>, usize) {
    let mut split = Vec::with_capacity(bases.len());
    for (base, exp) in bases.iter().zip(exps) {
        if base.is_zero() {
            continue;
        }
        let ((sgn1, k1), (sgn2, k2)) = scalar_decomposition(exp);
        let (k1, k2) = (half_to_u128(&k1), half_to_u128(&k2));
        if k1 == 0 && k2 == 0 {
            continue;
        }
        split.push((*base, (sgn1, k1), (sgn2, k2)));
    }
    if split.is_empty() {
        return (Vec::new(), 0);
    }
    // {3, 5, 7}P per base via one double + adds; no intermediate can be
    // infinity (G1 order is prime, bases are non-zero), so one shared
    // inversion covers every table
    let mut odd = Vec::with_capacity(3 * split.len());
    for (b, _, _) in &split {
        let two_b = b.into_group().double();
        let p3 = two_b + *b;
        let p5 = p3 + two_b;
        let p7 = p5 + two_b;
        odd.extend_from_slice(&[p3, p5, p7]);
    }
    let odd = G1Projective::normalize_batch(&odd);
    let mut walk_top = 0;
    let mut chains = Vec::with_capacity(2 * split.len());
    for (i, (b, half1, half2)) in split.iter().enumerate() {
        let table_p = [*b, odd[3 * i], odd[3 * i + 1], odd[3 * i + 2]];
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
                table = table.map(|p| -p);
            }
            let (digits, top) = wnaf_u128(k);
            walk_top = walk_top.max(top);
            chains.push((i, digits, table));
        }
    }
    (chains, walk_top)
}

/// MSB-aligned walk over K independent accumulator chains, digit streams
/// partitioned by point index mod K: every step doubles all K accumulators,
/// each nonzero digit mixed-adds its table entry into its stream's
/// accumulator, and the K accumulators are summed after the walk. The same
/// table entries are added for every K, so by group associativity the total
/// is the same group element; K = 1 is the plain single-accumulator walk.
fn strauss_walk<const K: usize>(chains: &[BandChain], walk_top: usize) -> G1Projective {
    let mut accs = [G1Projective::zero(); K];
    for i in (0..=walk_top).rev() {
        for acc in accs.iter_mut() {
            acc.double_in_place();
        }
        for (point, digits, table) in chains {
            let d = digits[i];
            if d > 0 {
                accs[point % K] += table[(d / 2) as usize];
            } else if d < 0 {
                accs[point % K] -= table[(-d / 2) as usize];
            }
        }
    }
    let mut total = accs[0];
    for acc in &accs[1..] {
        total += acc;
    }
    total
}

/// The n <= STRAUSS_BAND_MAX arm: shared-doubling Strauss-Shamir over the
/// GLV half-scalar chains.
fn msm_band_strauss(bases: &[G1Affine], exps: &[Fr]) -> G1Affine {
    let (chains, walk_top) = build_band_chains(bases, exps);
    if chains.is_empty() {
        return G1Affine::zero();
    }
    strauss_walk::<K_BAND>(&chains, walk_top).into_affine()
}

/// The large-n arm: GLV split k = k1 + lambda*k2 (sign true = positive,
/// matching the library's `glv_mul_projective`), psi(P) = lambda*P, so each
/// term becomes two half-width pairs and the library's serial Pippenger
/// runs one window count fewer over 2n points. Any valid
/// split sums to the same group element.
fn msm_pippenger_glv(bases: &[G1Affine], exps: &[Fr]) -> G1Affine {
    let mut glv_bases = Vec::with_capacity(2 * bases.len());
    let mut glv_scalars = Vec::with_capacity(2 * bases.len());
    for (base, exp) in bases.iter().zip(exps) {
        let ((sgn1, k1), (sgn2, k2)) = scalar_decomposition(exp);
        let psi = G1Config::endomorphism_affine(base);
        glv_bases.push(if sgn1 { *base } else { -*base });
        glv_scalars.push(k1);
        glv_bases.push(if sgn2 { psi } else { -psi });
        glv_scalars.push(k2);
    }
    G1Projective::msm_unchecked(&glv_bases, &glv_scalars).into_affine()
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
        let mut points = Vec::with_capacity(n * G1_BYTES);
        let mut scalars = Vec::with_capacity(n * SCALAR_BYTES);
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
                    msm_band_strauss(&bases, &exps),
                    expected.into_affine(),
                    "n = {n}, round = {round}"
                );
            }
            // degenerate lattices: all infinity, all zero scalars
            assert_eq!(
                msm_band_strauss(&vec![G1Affine::zero(); n], &vec![Fr::one(); n]),
                G1Affine::zero()
            );
            assert_eq!(
                msm_band_strauss(&vec![g; n], &vec![Fr::zero(); n]),
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
            let (chains, walk_top) = build_band_chains(&bases, &exps);
            let one = strauss_walk::<1>(&chains, walk_top);
            assert_eq!(strauss_walk::<2>(&chains, walk_top), one, "n = {n}");
            assert_eq!(strauss_walk::<4>(&chains, walk_top), one, "n = {n}");
        }
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
                G1Projective::msm_unchecked(&bases, &exps).into_affine(),
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
