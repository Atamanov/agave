//! Rough interleaved micro timings for the SoS kernel work. Run explicitly:
//! `cargo +1.97.1 test --release -p helios-bn254 sos_micro -- --ignored --nocapture`

use std::hint::black_box;
use std::ops::Mul;
use std::time::Instant;

use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::fp2_fast::{f2_from, f2_mul, f2_sqr};
use crate::fr::Fr;
use crate::g1::G1Projective;
use crate::g2::{G2Affine, G2Projective};
use crate::pairing::{final_exponentiation, miller_loop};
use crate::sos_tests::{random_fp2, random_fp6, random_fp12};

fn time_ns<F: FnMut()>(iters: u64, mut f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_nanos() as f64 / iters as f64
}

/// Interleave rounds of the measured closure, report the minimum round.
fn best_of<F: FnMut()>(rounds: u32, iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..rounds {
        best = best.min(time_ns(iters, &mut f));
    }
    best
}

#[test]
#[ignore = "manual field-op microbenchmark: cargo +1.97.1 test --release -p helios-bn254 sos_micro -- --ignored --nocapture"]
fn sos_micro_field_ops() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let a2 = f2_from(random_fp2(&mut rng));
    let b2 = f2_from(random_fp2(&mut rng));
    let a6 = random_fp6(&mut rng);
    let b6 = random_fp6(&mut rng);
    let a12 = random_fp12(&mut rng);
    let (c0, c3, c4) = (
        random_fp2(&mut rng),
        random_fp2(&mut rng),
        random_fp2(&mut rng),
    );

    const N: u64 = 200_000;
    const R: u32 = 5;

    // Dependency-chained: measures latency as seen by the pairing inner loop.
    let mut x = a2;
    let t = best_of(R, N, || x = f2_mul(black_box(x), black_box(b2)));
    black_box(x);
    println!("f2_mul          {t:8.2} ns");

    // Single-lane kernel pair (pre-dual path) for direct A/B.
    let mut x = a2;
    let t = best_of(R, N, || {
        use crate::fp::sos::{negp, sos2};
        let a = black_box(x);
        let b = black_box(b2);
        x = (
            sos2(&a.0, &b.0, &a.1, &negp(&b.1)),
            sos2(&a.0, &b.1, &a.1, &b.0),
        );
    });
    black_box(x);
    println!("f2_mul_2xsos2   {t:8.2} ns");

    let mut x = a2;
    let t = best_of(R, N, || {
        x = crate::fp2_fast::f2_mul_karatsuba(black_box(x), black_box(b2))
    });
    black_box(x);
    println!("f2_mul_karat    {t:8.2} ns");

    let mut x = a2;
    let t = best_of(R, N, || x = f2_sqr(black_box(x)));
    black_box(x);
    println!("f2_sqr          {t:8.2} ns");

    let mut x = a2;
    let t = best_of(R, N, || x = crate::fp2_fast::f2_sqr_lazy(black_box(x)));
    black_box(x);
    println!("f2_sqr_lazy     {t:8.2} ns");

    let mut x = a6;
    let t = best_of(R, N, || x = black_box(x) * black_box(b6));
    black_box(x);
    println!("fp6_mul         {t:8.2} ns");

    let mut x = a6;
    let t = best_of(R, N, || {
        x = black_box(x).mul_by_01(black_box(c0), black_box(c3))
    });
    black_box(x);
    println!("fp6_mul_by_01   {t:8.2} ns");

    let mut x = a12;
    let t = best_of(R, N / 4, || {
        x = black_box(x).mul_by_034(black_box(c0), black_box(c3), black_box(c4))
    });
    black_box(x);
    println!("fp12_mul_by_034 {t:8.2} ns");

    let mut x = a12;
    let t = best_of(R, N / 4, || x = black_box(x) * black_box(a12));
    black_box(x);
    println!("fp12_mul        {t:8.2} ns");

    let mut x = a12;
    let t = best_of(R, N / 4, || x = black_box(x).square());
    black_box(x);
    println!("fp12_square     {t:8.2} ns");

    let mut x = a12;
    let t = best_of(R, N / 4, || x = black_box(x).cyclotomic_square());
    black_box(x);
    println!("fp12_cyc_sq     {t:8.2} ns");
}

#[test]
#[ignore = "manual pairing-phase microbenchmark: cargo +1.97.1 test --release -p helios-bn254 sos_micro -- --ignored --nocapture"]
fn sos_micro_pairing() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let a = Fr::from_u64(rng.next_u64() | 1);
    let b = Fr::from_u64(rng.next_u64() | 1);
    let p = G1Projective::generator().mul(a).to_affine();
    let q = G2Projective::from(G2Affine::test_generator())
        .mul(b)
        .to_affine();

    let t = best_of(5, 200, || {
        black_box(miller_loop(black_box(&p), black_box(&q)));
    });
    println!("miller_loop     {:8.2} us", t / 1000.0);

    let f = miller_loop(&p, &q);
    let t = best_of(5, 200, || {
        black_box(final_exponentiation(black_box(&f)));
    });
    println!("final_exp       {:8.2} us", t / 1000.0);
}
