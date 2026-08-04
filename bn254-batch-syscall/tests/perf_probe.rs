#![cfg(feature = "agave-unstable-api")]

//! Compare the selected backend with the former direct arkworks paths.
//!
//! This ignored test gives local ratios. Criterion results remain the source
//! for compute-unit prices.

use {
    ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM, pairing::Pairing},
    ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero, batch_inversion},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, Version, alt_bn128_fr_batch_invert,
        alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    },
    std::{
        ops::{Add, Div, Mul, Neg},
        time::{Duration, Instant},
    },
};

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Return round-robin medians so timing drift affects both paths.
fn median_ns(
    repetitions: usize,
    mut baseline: impl FnMut(),
    mut selected: impl FnMut(),
) -> (u64, u64) {
    assert!(repetitions > 0);
    let mut baseline_samples = Vec::with_capacity(repetitions);
    let mut selected_samples = Vec::with_capacity(repetitions);
    for _ in 0..repetitions {
        let start = Instant::now();
        baseline();
        baseline_samples.push(elapsed_ns(start));

        let start = Instant::now();
        selected();
        selected_samples.push(elapsed_ns(start));
    }
    baseline_samples.sort_unstable();
    selected_samples.sort_unstable();
    let middle = repetitions.checked_div(2).unwrap();
    (
        *baseline_samples.get(middle).unwrap(),
        *selected_samples.get(middle).unwrap(),
    )
}

fn report(label: &str, baseline: u64, selected: u64) {
    let baseline = Duration::from_nanos(baseline.max(1));
    let selected = Duration::from_nanos(selected);
    let ratio = selected.as_secs_f64().div(baseline.as_secs_f64());
    println!(
        "{label}: baseline {} ns, selected {} ns, ratio {ratio:.3}",
        baseline.as_nanos(),
        selected.as_nanos()
    );
}

fn pod_g2(point: &ark_bn254::G2Affine) -> PodG2Point {
    let mut output = PodG2Point([0u8; 128]);
    let Some((x, y)) = point.xy() else {
        return output;
    };
    for (slot, coordinate) in output.0.chunks_exact_mut(32).zip([x.c1, x.c0, y.c1, y.c0]) {
        slot.copy_from_slice(&coordinate.into_bigint().to_bytes_be());
    }
    output
}

#[test]
#[ignore = "local timing probe"]
fn selected_backend_ratios() {
    let mut rng = StdRng::seed_from_u64(0x9e7f);
    let generator = G1Projective::generator();

    let bases: Vec<G1Affine> = (0..50)
        .map(|_| generator.mul(Fr::rand(&mut rng)).into_affine())
        .collect();
    let exponents: Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();
    let points: Vec<PodG1Point> = bases.iter().map(PodG1Point::from).collect();
    let scalars: Vec<PodScalar> = exponents.iter().map(PodScalar::from).collect();
    let (baseline, selected) = median_ns(
        101,
        || {
            let parsed_bases: Vec<_> = points
                .iter()
                .map(|point| point.to_affine().unwrap())
                .collect();
            let parsed_scalars: Vec<_> = scalars
                .iter()
                .map(|scalar| scalar.to_fr().unwrap())
                .collect();
            let _ = core::hint::black_box(
                G1Projective::msm_unchecked(&parsed_bases, &parsed_scalars).into_affine(),
            );
        },
        || {
            core::hint::black_box(alt_bn128_g1_msm(Version::V0, &points, &scalars).unwrap());
        },
    );
    report("msm@50", baseline, selected);

    let q = G2Projective::generator()
        .mul(Fr::rand(&mut rng))
        .into_affine();
    let mut sum = Fr::zero();
    let mut g1_points = Vec::with_capacity(8);
    for _ in 0..7 {
        let scalar = Fr::rand(&mut rng);
        sum = sum.add(scalar);
        g1_points.push(generator.mul(scalar).into_affine());
    }
    g1_points.push(generator.mul(sum.neg()).into_affine());
    let q = pod_g2(&q);
    let pairs: Vec<_> = g1_points
        .iter()
        .map(|point| PodG1G2Pair {
            g1: PodG1Point::from(point),
            g2: q,
        })
        .collect();
    let (baseline, selected) = median_ns(
        21,
        || {
            let parsed: Vec<_> = pairs
                .iter()
                .map(|pair| (pair.g1.to_affine().unwrap(), pair.g2.to_affine().unwrap()))
                .collect();
            let (g1, g2): (Vec<_>, Vec<_>) = parsed.into_iter().unzip();
            core::hint::black_box(Bn254::multi_pairing(g1, g2).0.is_one());
        },
        || {
            core::hint::black_box(alt_bn128_pairing_check(Version::V0, &pairs).unwrap());
        },
    );
    report("pairing@8", baseline, selected);

    let a: Vec<PodScalar> = (0..2048)
        .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
        .collect();
    let b: Vec<PodScalar> = (0..2048)
        .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
        .collect();
    let (baseline, selected) = median_ns(
        201,
        || {
            let sum = a.iter().zip(&b).fold(Fr::zero(), |sum, (left, right)| {
                sum.add(left.to_fr().unwrap().mul(right.to_fr().unwrap()))
            });
            core::hint::black_box(PodScalar::from(&sum));
        },
        || {
            core::hint::black_box(alt_bn128_fr_lincomb(Version::V0, &a, &b).unwrap());
        },
    );
    report("fr_lincomb@2048", baseline, selected);

    let (baseline, selected) = median_ns(
        201,
        || {
            let mut values: Vec<_> = a.iter().map(|scalar| scalar.to_fr().unwrap()).collect();
            batch_inversion(&mut values);
            core::hint::black_box(values.iter().map(PodScalar::from).collect::<Vec<_>>());
        },
        || {
            core::hint::black_box(alt_bn128_fr_batch_invert(Version::V0, &a).unwrap());
        },
    );
    report("fr_batch_invert@2048", baseline, selected);
}
