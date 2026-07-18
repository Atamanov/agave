#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Seeded differential battery: every public op against an arkworks generic
//! oracle, across every internal dispatch boundary (Strauss band ends, walk
//! K-bands, Miller chunk width, inversion chain splits) and the scalar
//! representation edges 0, 1, r-1, 2^64, 2^128. The fingerprint test pins
//! wire behavior against the committed golden constant; this battery pins
//! the same behavior against independently computed values, so a porting
//! bug shows up as a named op and size instead of a hash mismatch.

use {
    ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM, pairing::Pairing},
    ark_ff::{BigInt, BigInteger, One, PrimeField, UniformRand, Zero, batch_inversion},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{
        AltBn128BatchError, PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, Version,
        alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    },
};

/// Every size class the msm dispatch distinguishes: band ends 1/2, the
/// internal K-band boundaries 16/17, the band top 64, the Pippenger entry
/// 65, and deep Pippenger sizes up to the cap.
const MSM_SIZES: [usize; 17] = [
    1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 63, 64, 65, 96, 256, 1024, 2048,
];

/// Scalar representation edges: identity, unit, r-1, and both limb
/// boundaries the GLV split and wNAF walk fold.
fn edge_scalars() -> [Fr; 5] {
    [
        Fr::zero(),
        Fr::one(),
        -Fr::one(),
        Fr::from(1u128 << 64),
        Fr::from(BigInt::new([0, 0, 1, 0])), // 2^128
    ]
}

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn pod_fr(s: &Fr) -> PodScalar {
    PodScalar::from(s)
}

fn pod_g1(p: &G1Affine) -> PodG1Point {
    PodG1Point::from(p)
}

fn pod_g2(p: &G2Affine) -> PodG2Point {
    let mut out = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        for (slot, coord) in [x.c1, x.c0, y.c1, y.c0].iter().enumerate() {
            out[slot * 32..(slot + 1) * 32].copy_from_slice(&coord.into_bigint().to_bytes_be());
        }
    }
    PodG2Point(out)
}

fn pod_pair(g1: &G1Affine, g2: &G2Affine) -> PodG1G2Pair {
    PodG1G2Pair {
        g1: pod_g1(g1),
        g2: pod_g2(g2),
    }
}

/// Deterministic on-curve G2 point outside the r-order subgroup (the twist
/// cofactor is ~2^254, so small-x points almost surely qualify).
fn non_subgroup_g2() -> G2Affine {
    for k in 0u64.. {
        let x = Fq2::new(Fq::from(k), Fq::zero());
        if let Some(point) = G2Affine::get_point_from_x_unchecked(x, true) {
            assert!(point.is_on_curve());
            if !point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
    }
    unreachable!("BN254 twist has non-subgroup points with small x");
}

#[test]
fn test_msm_matches_arkworks_across_dispatch_sizes() {
    let mut rng = rng(0xd1ff_0001);
    // fixed pool strided per size: cheap to build, still lands edge scalars
    // and infinity bases at varying positions of every arm
    let pool: Vec<G1Affine> = (0..64)
        .map(|_| (G1Projective::generator() * Fr::rand(&mut rng)).into_affine())
        .collect();
    for n in MSM_SIZES {
        let mut bases: Vec<G1Affine> = (0..n).map(|i| pool[(i * 7 + n) % pool.len()]).collect();
        let mut scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        bases[n / 2] = G1Affine::zero();
        for (k, edge) in edge_scalars().into_iter().enumerate() {
            scalars[(k * 5 + 1) % n] = edge;
        }
        let expected = G1Projective::msm(&bases, &scalars).unwrap().into_affine();
        let points: Vec<PodG1Point> = bases.iter().map(pod_g1).collect();
        let pods: Vec<PodScalar> = scalars.iter().map(pod_fr).collect();
        let got = alt_bn128_g1_msm(Version::V0, &points, &pods).unwrap();
        assert_eq!(got, pod_g1(&expected), "msm mismatch at n = {n}");
    }
}

#[test]
fn test_msm_edge_scalars_single_term() {
    let mut rng = rng(0xd1ff_0002);
    let base = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
    for edge in edge_scalars() {
        let got = alt_bn128_g1_msm(Version::V0, &[pod_g1(&base)], &[pod_fr(&edge)]).unwrap();
        let expected = (base * edge).into_affine();
        assert_eq!(got, pod_g1(&expected), "edge scalar {edge}");
    }
    // all-edge vector plus an infinity base through the band arm
    let mut bases: Vec<G1Affine> = edge_scalars()
        .iter()
        .map(|e| (G1Projective::generator() * (*e + Fr::from(3u64))).into_affine())
        .collect();
    bases[2] = G1Affine::zero();
    let scalars = edge_scalars();
    let expected = G1Projective::msm(&bases, &scalars).unwrap().into_affine();
    let points: Vec<PodG1Point> = bases.iter().map(pod_g1).collect();
    let pods: Vec<PodScalar> = scalars.iter().map(pod_fr).collect();
    let got = alt_bn128_g1_msm(Version::V0, &points, &pods).unwrap();
    assert_eq!(got, pod_g1(&expected));
}

/// n pairs over a shared G2 whose pairing product is the identity.
fn telescoping_pairs(rng: &mut StdRng, n: usize) -> Vec<PodG1G2Pair> {
    let p = G1Projective::generator();
    let q = (G2Projective::generator() * Fr::rand(rng)).into_affine();
    let mut sum = Fr::zero();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n - 1 {
        let s = Fr::rand(rng);
        sum += s;
        out.push(pod_pair(&(p * s).into_affine(), &q));
    }
    out.push(pod_pair(&(p * (-sum)).into_affine(), &q));
    out
}

#[test]
fn test_pairing_verdict_matches_multi_pairing() {
    let mut rng = rng(0xd1ff_0003);
    // telescoping accepts across the Miller chunk boundary and at the full
    // cap (8 exact chunks); a sign flip must flip the verdict, matching the
    // multi_pairing oracle either way
    for n in [2usize, 3, 31, 32, 33, 256] {
        let pairs = telescoping_pairs(&mut rng, n);
        assert_eq!(
            alt_bn128_pairing_check(Version::V0, &pairs),
            Ok(true),
            "telescoping n = {n}"
        );
        let mut flipped = pairs.clone();
        let g1 = flipped[0].g1.to_affine().unwrap();
        flipped[0].g1 = pod_g1(&(-g1));
        let oracle: Vec<(G1Affine, G2Affine)> = flipped
            .iter()
            .map(|p| (p.g1.to_affine().unwrap(), p.g2.to_affine().unwrap()))
            .collect();
        let (g1s, g2s): (Vec<_>, Vec<_>) = oracle.into_iter().unzip();
        let expected = Bn254::multi_pairing(g1s, g2s).0.is_one();
        assert!(!expected, "sign flip must break the identity");
        assert_eq!(
            alt_bn128_pairing_check(Version::V0, &flipped),
            Ok(expected),
            "flipped n = {n}"
        );
    }
}

#[test]
fn test_pairing_bilinearity_with_edge_scalars() {
    let mut rng = rng(0xd1ff_0004);
    let p = G1Projective::generator() * Fr::rand(&mut rng);
    let q = G2Projective::generator() * Fr::rand(&mut rng);
    for s in edge_scalars() {
        // e([s]P, Q) * e(-P, [s]Q) == 1; s == 0 degenerates to two skipped
        // infinity members and stays an accept
        let pairs = [
            pod_pair(&(p * s).into_affine(), &q.into_affine()),
            pod_pair(&(-p).into_affine(), &(q * s).into_affine()),
        ];
        assert_eq!(
            alt_bn128_pairing_check(Version::V0, &pairs),
            Ok(true),
            "edge scalar {s}"
        );
    }
}

#[test]
fn test_pairing_rejects_non_subgroup_g2_everywhere() {
    let mut rng = rng(0xd1ff_0005);
    let bad = non_subgroup_g2();
    let g1 = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
    for position in [0usize, 3, 7] {
        let mut pairs = telescoping_pairs(&mut rng, 8);
        pairs[position] = pod_pair(&g1, &bad);
        assert_eq!(
            alt_bn128_pairing_check(Version::V0, &pairs),
            Err(AltBn128BatchError::NotInSubgroup),
            "position {position}"
        );
    }
    // the partner of an infinity G1 is still validated
    let pairs = [pod_pair(&G1Affine::zero(), &bad)];
    assert_eq!(
        alt_bn128_pairing_check(Version::V0, &pairs),
        Err(AltBn128BatchError::NotInSubgroup)
    );
    // cancelling non-subgroup pairs must reject, not accept
    let pairs = [pod_pair(&g1, &bad), pod_pair(&g1, &(-bad))];
    assert_eq!(
        alt_bn128_pairing_check(Version::V0, &pairs),
        Err(AltBn128BatchError::NotInSubgroup)
    );
}

#[test]
fn test_fr_lincomb_matches_naive_loop() {
    let mut rng = rng(0xd1ff_0006);
    for n in MSM_SIZES {
        let mut a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        for (k, edge) in edge_scalars().into_iter().enumerate() {
            a[(k * 3 + 1) % n] = edge;
        }
        let expected: Fr = a.iter().zip(&b).map(|(x, y)| *x * y).sum();
        let ap: Vec<PodScalar> = a.iter().map(pod_fr).collect();
        let bp: Vec<PodScalar> = b.iter().map(pod_fr).collect();
        let got = alt_bn128_fr_lincomb(Version::V0, &ap, &bp).unwrap();
        assert_eq!(got, pod_fr(&expected), "lincomb mismatch at n = {n}");
    }
}

#[test]
fn test_fr_batch_invert_matches_arkworks() {
    let mut rng = rng(0xd1ff_0007);
    for n in MSM_SIZES {
        let mut a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        // nonzero edges only; zero is a rejected input, checked below
        for (k, edge) in edge_scalars().into_iter().skip(1).enumerate() {
            a[(k * 3 + 1) % n] = edge;
        }
        let mut expected = a.clone();
        batch_inversion(&mut expected);
        let ap: Vec<PodScalar> = a.iter().map(pod_fr).collect();
        let got = alt_bn128_fr_batch_invert(Version::V0, &ap).unwrap();
        let want: Vec<PodScalar> = expected.iter().map(pod_fr).collect();
        assert_eq!(got, want, "batch invert mismatch at n = {n}");
    }
    // zero rejects at every dispatch band (library, small chain, large chain)
    for n in [1usize, 8, 33, 64] {
        let mut a: Vec<PodScalar> = (0..n).map(|_| pod_fr(&Fr::rand(&mut rng))).collect();
        a[n - 1] = pod_fr(&Fr::zero());
        assert_eq!(
            alt_bn128_fr_batch_invert(Version::V0, &a),
            Err(AltBn128BatchError::ZeroInput),
            "n = {n}"
        );
    }
}
