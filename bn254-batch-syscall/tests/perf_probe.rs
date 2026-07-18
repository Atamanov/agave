#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Indicative perf probe, not a benchmark: times each op against the naive
//! arkworks path this crate previously shipped, on whatever machine runs it.
//! The consensus-relevant numbers come from the perf-harness on the x86-64-v2
//! reference box; run this only for a quick local sanity ratio:
//! `cargo test --release -p solana-bn254-batch-syscall \
//!   --features agave-unstable-api --test perf_probe -- --ignored --nocapture`

use {
    ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Projective},
    ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM, pairing::Pairing},
    ark_ff::{One, UniformRand, Zero, batch_inversion},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, Version, alt_bn128_fr_batch_invert,
        alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    },
    std::time::Instant,
};

/// Round-robin timed medians so drift hits both arms equally.
fn median_ns(reps: usize, mut old: impl FnMut(), mut new: impl FnMut()) -> (u64, u64) {
    let mut olds = Vec::with_capacity(reps);
    let mut news = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        old();
        olds.push(t.elapsed().as_nanos() as u64);
        let t = Instant::now();
        new();
        news.push(t.elapsed().as_nanos() as u64);
    }
    olds.sort_unstable();
    news.sort_unstable();
    (olds[reps / 2], news[reps / 2])
}

fn report(label: &str, old: u64, new: u64) {
    println!(
        "{label}: old {old} ns, new {new} ns, ratio {:.3}",
        new as f64 / old as f64
    );
}

#[test]
#[ignore = "indicative timing only; run release with --nocapture"]
fn perf_indicative() {
    let mut rng = StdRng::seed_from_u64(0x9e7f);
    let g = G1Projective::generator();

    // msm@50, the zolana anchor
    let bases: Vec<G1Affine> = (0..50)
        .map(|_| (g * Fr::rand(&mut rng)).into_affine())
        .collect();
    let exps: Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();
    let points: Vec<PodG1Point> = bases.iter().map(PodG1Point::from).collect();
    let scalars: Vec<PodScalar> = exps.iter().map(PodScalar::from).collect();
    let (old, new) = median_ns(
        101,
        || {
            let b: Vec<G1Affine> = points.iter().map(|p| p.to_affine().unwrap()).collect();
            let e: Vec<Fr> = scalars.iter().map(|s| s.to_fr().unwrap()).collect();
            let _ = core::hint::black_box(G1Projective::msm_unchecked(&b, &e).into_affine());
        },
        || {
            core::hint::black_box(alt_bn128_g1_msm(Version::V0, &points, &scalars).unwrap());
        },
    );
    report("msm@50", old, new);

    // pairing@8 (kept small so the probe stays quick)
    let q = (G2Projective::generator() * Fr::rand(&mut rng)).into_affine();
    let mut sum = Fr::zero();
    let mut pairs = Vec::new();
    for _ in 0..7 {
        let s = Fr::rand(&mut rng);
        sum += s;
        pairs.push((g * s).into_affine());
    }
    pairs.push((g * (-sum)).into_affine());
    let qb = {
        // big-endian wire encoding of q: x1 | x0 | y1 | y0
        let mut out = PodG2Point([0u8; 128]);
        use ark_ff::{BigInteger, PrimeField};
        let (x, y) = (q.x, q.y);
        for (slot, c) in [x.c1, x.c0, y.c1, y.c0].iter().enumerate() {
            out.0[slot * 32..(slot + 1) * 32].copy_from_slice(&c.into_bigint().to_bytes_be());
        }
        out
    };
    let wire: Vec<PodG1G2Pair> = pairs
        .iter()
        .map(|p| PodG1G2Pair {
            g1: PodG1Point::from(p),
            g2: qb,
        })
        .collect();
    let (old, new) = median_ns(
        21,
        || {
            let parsed: Vec<_> = wire
                .iter()
                .map(|p| (p.g1.to_affine().unwrap(), p.g2.to_affine().unwrap()))
                .collect();
            let (g1s, g2s): (Vec<_>, Vec<_>) = parsed.into_iter().unzip();
            core::hint::black_box(Bn254::multi_pairing(g1s, g2s).0.is_one());
        },
        || {
            core::hint::black_box(alt_bn128_pairing_check(Version::V0, &wire).unwrap());
        },
    );
    report("pairing@8", old, new);

    // fr ops @2048, the per-term slope anchor
    let a: Vec<PodScalar> = (0..2048)
        .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
        .collect();
    let b: Vec<PodScalar> = (0..2048)
        .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
        .collect();
    let (old, new) = median_ns(
        201,
        || {
            let mut acc = Fr::zero();
            for (x, y) in a.iter().zip(&b) {
                acc += x.to_fr().unwrap() * y.to_fr().unwrap();
            }
            core::hint::black_box(PodScalar::from(&acc));
        },
        || {
            core::hint::black_box(alt_bn128_fr_lincomb(Version::V0, &a, &b).unwrap());
        },
    );
    report("fr_lincomb@2048", old, new);

    let (old, new) = median_ns(
        201,
        || {
            let mut v: Vec<Fr> = a.iter().map(|s| s.to_fr().unwrap()).collect();
            batch_inversion(&mut v);
            core::hint::black_box(v.iter().map(PodScalar::from).collect::<Vec<_>>());
        },
        || {
            core::hint::black_box(alt_bn128_fr_batch_invert(Version::V0, &a).unwrap());
        },
    );
    report("fr_batch_invert@2048", old, new);
}
