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

fn make_pairs(total: usize) -> Vec<PairBytes> {
    (0..total)
        .map(|i| PairBytes {
            g1: g1_bytes(i as u64 + 2),
            g2: g2_bytes(i as u64 + 3),
        })
        .collect()
}

const SPLITS: &[(usize, usize)] = &[
    (1, 2),
    (1, 3),
    (3, 0),
    (0, 3),
    (5, 3),
    (2, 6),
    (0, 8),
    (8, 8),
];

fn bench_mixed_splits(c: &mut Criterion) {
    let mut group = c.benchmark_group("pairing_mixed");
    let mut baselines = std::collections::HashSet::new();
    for &(full, prepared) in SPLITS {
        let total = full + prepared;
        let all_pairs = make_pairs(total);
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
        if baselines.insert(total) {
            group.bench_function(format!("allfull{total}"), |ben| {
                ben.iter(|| pairing_product_is_one(black_box(&all_pairs)).unwrap());
            });
        }
    }
    group.finish();
}

/// Registered-vs-full splits so the account-backed registry credit
/// (`alt_bn128_g2_subgroup_check_cost`) gets a measured basis too.
fn bench_registered_splits(c: &mut Criterion) {
    use helius_bn254::{RegisteredG2, RegisteredG2Pair, pairing_product_registered};

    let mut group = c.benchmark_group("pairing_registered");
    for &(full, registered) in SPLITS {
        if registered == 0 {
            continue;
        }
        let all_pairs = make_pairs(full + registered);
        let entries: Vec<RegisteredG2> = all_pairs[full..]
            .iter()
            .map(|pair| RegisteredG2::validate_for_registry(&pair.g2).unwrap())
            .collect();
        group.bench_function(format!("full{full}_registered{registered}"), |ben| {
            ben.iter_batched(
                || {
                    all_pairs[full..]
                        .iter()
                        .zip(&entries)
                        .map(|(pair, entry)| RegisteredG2Pair {
                            g1: pair.g1,
                            g2: entry.clone(),
                        })
                        .collect::<Vec<_>>()
                },
                |registered_pairs| {
                    pairing_product_registered(black_box(&all_pairs[..full]), &registered_pairs)
                        .unwrap()
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_prepare_and_restore,
    bench_mixed_splits,
    bench_registered_splits
);
criterion_main!(benches);
