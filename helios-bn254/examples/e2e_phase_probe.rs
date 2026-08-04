//! Decompose the pairing n=1 end-to-end row into decode/validate/core phases.
use helios_bn254::pairing::{final_exponentiation, miller_loop, multi_pairing};
use helios_bn254::{Fp12, Fr, G1Projective, G2Projective, pairing_product_is_one};
use std::hint::black_box;
use std::ops::Mul;
use std::time::Instant;

fn time<R>(name: &str, iters: u32, mut f: impl FnMut() -> R) {
    for _ in 0..iters / 5 + 1 {
        black_box(f());
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    println!(
        "{name}: {:.2} us",
        t0.elapsed().as_secs_f64() * 1e6 / iters as f64
    );
}

fn main() {
    let g1 = G1Projective::generator()
        .mul(Fr::from_u64(0x1234_5678_9abc))
        .to_affine();
    let g2 = G2Projective::from(helios_bn254::G2Affine::test_generator())
        .mul(Fr::from_u64(0xdead_beef_cafe))
        .to_affine();

    let g1b = helios_bn254::G1Bytes::from_affine(&g1);
    let g2b = helios_bn254::G2Bytes::from_affine(&g2);
    let pair = helios_bn254::PairBytes { g1: g1b, g2: g2b };
    let pairs = [pair];

    time("e2e pairing_product_is_one n=1", 500, || {
        pairing_product_is_one(black_box(&pairs)).unwrap()
    });
    time("g1 decode+validate", 20000, || g1b.to_affine().unwrap());
    time("g2 decode+validate(subgroup)", 2000, || {
        g2b.to_affine().unwrap()
    });
    time("multi_pairing", 500, || {
        multi_pairing(black_box(&[(&g1, &g2)]))
    });
    time("miller_loop", 1000, || {
        miller_loop(black_box(&g1), black_box(&g2))
    });
    let ml = miller_loop(&g1, &g2);
    time("final_exponentiation", 1000, || {
        final_exponentiation(black_box(&ml))
    });
    let fe = final_exponentiation(&ml);
    time("fp12 == ONE compare", 100000, || {
        black_box(&fe) == &Fp12::ONE
    });
}
