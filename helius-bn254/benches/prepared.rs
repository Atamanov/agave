//! Prepared-operand costs for the stateless syscall tariff.
//!
//! Three UNMEASURED charge constants depend on these curves:
//! `alt_bn128_g2_prepare_base_cost` (g2_prepare standalone),
//! `alt_bn128_prepared_g2_restore_cost` (restore standalone), and
//! `alt_bn128_g2_line_prep_credit_cost` (full-vs-prepared delta per pair at
//! fixed total). Capture-host rules apply; see
//! research/bn254-decision-table-v2-20260804/CAPTURE-HOST-REQUIREMENTS.md.

use core::ops::Mul;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use helius_bn254::{
    Fr, G1Affine, G1Bytes, G1Projective, G2Affine, G2Bytes, G2Projective, PairBytes,
    PreparedG2Handle, PreparedPair, g2_prepare, pairing_check_prepared, pairing_product_is_one,
};

fn g1_bytes(k: u64) -> G1Bytes {
    G1Bytes::from_affine(
        &G1Projective::from(G1Affine::generator())
            .mul(Fr::from_u64(k))
            .to_affine(),
    )
}

fn g2_bytes(k: u64) -> G2Bytes {
    G2Bytes::from_affine(
        &G2Projective::from(G2Affine::arkworks_generator())
            .mul(Fr::from_u64(k))
            .to_affine(),
    )
}

fn bench_prepare_and_restore(c: &mut Criterion) {
    let source = g2_bytes(7);
    c.bench_function("g2_prepare", |ben| {
        ben.iter(|| g2_prepare(black_box(&source)).unwrap());
    });

    let wire = g2_prepare(&source).unwrap().to_scalar_bytes();
    c.bench_function("prepared_g2_restore", |ben| {
        ben.iter(|| PreparedG2Handle::from_scalar_bytes(black_box(&wire)).unwrap());
    });
}

fn bench_mixed_splits(c: &mut Criterion) {
    let mut group = c.benchmark_group("pairing_mixed");
    for &(full, prepared) in &[
        (1usize, 2usize),
        (1, 3),
        (3, 0),
        (0, 3),
        (5, 3),
        (2, 6),
        (0, 8),
        (8, 8),
    ] {
        let total = full + prepared;
        let all_pairs: Vec<PairBytes> = (0..total)
            .map(|i| PairBytes {
                g1: g1_bytes(i as u64 + 2),
                g2: g2_bytes(i as u64 + 3),
            })
            .collect();
        let handles: Vec<PreparedG2Handle> = all_pairs[full..]
            .iter()
            .map(|pair| g2_prepare(&pair.g2).unwrap())
            .collect();

        group.bench_function(format!("full{full}_prepared{prepared}"), |ben| {
            ben.iter_batched(
                || (),
                |()| {
                    let prepared_pairs: Vec<PreparedPair> = all_pairs[full..]
                        .iter()
                        .zip(&handles)
                        .map(|(pair, handle)| PreparedPair {
                            g1: pair.g1,
                            g2: handle,
                        })
                        .collect();
                    pairing_check_prepared(black_box(&all_pairs[..full]), &prepared_pairs).unwrap()
                },
                BatchSize::SmallInput,
            );
        });
        group.bench_function(format!("allfull{total}"), |ben| {
            ben.iter(|| pairing_product_is_one(black_box(&all_pairs)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_prepare_and_restore, bench_mixed_splits);
criterion_main!(benches);
