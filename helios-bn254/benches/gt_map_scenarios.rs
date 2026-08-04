//! Native calibration for the requested GT-map verification shapes.
//!
//! The timed region is the complete checked byte facade: canonical G1/G2
//! decode, curve/subgroup validation, heterogeneous multi-pairing, one final
//! exponentiation, and canonical 384-byte GT encoding. Fixtures use a distinct
//! random G2 per pair so the common-Q fast path cannot collapse the scenario.

use std::time::Duration;

use ark_bn254::{Fq, Fr, G1Projective as ArkG1Projective, G2Projective as ArkG2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use helios_bn254::{
    G1Bytes, G2Bytes, PairBytes, ScalarBytes, TrustedGt, pairing_map, pairing_product_is_one,
    trusted_gt_multiexp,
};
use rand::{SeedableRng, rngs::StdRng};

const SEED: u64 = 0x6670_3132_5f6d_6170;
const POOL_SIZE: usize = 24;

// Groth16 omits the trusted alpha-beta target from the dynamic map, hence
// n + 2k raw pairs. Distinct-SRS PLONK emits two pairs per SRS cluster from the
// already-frozen joint fold. These are pairing-leg shapes, not full verifier
// transaction timings.
const SCENARIOS: &[(&str, usize, usize)] = &[
    ("groth16_5_same_vk_n5_k1", 7, 1),
    ("groth16_2_distinct_vk_n2_k2", 6, 2),
    ("groth16_3_distinct_vk_n3_k3", 9, 3),
    ("plonk_2_distinct_srs_k2", 4, 0),
    ("plonk_3_distinct_srs_k3", 6, 0),
];

fn field_be(value: Fq) -> [u8; 32] {
    let encoded = value.into_bigint().to_bytes_be();
    let mut output = [0u8; 32];
    output[32 - encoded.len()..].copy_from_slice(&encoded);
    output
}

fn g1_be(point: ArkG1Projective) -> G1Bytes {
    let mut output = [0u8; 64];
    if let Some((x, y)) = point.into_affine().xy() {
        output[..32].copy_from_slice(&field_be(x));
        output[32..].copy_from_slice(&field_be(y));
    }
    G1Bytes(output)
}

fn g2_be(point: ArkG2Projective) -> G2Bytes {
    let mut output = [0u8; 128];
    if let Some((x, y)) = point.into_affine().xy() {
        output[..32].copy_from_slice(&field_be(x.c1));
        output[32..64].copy_from_slice(&field_be(x.c0));
        output[64..96].copy_from_slice(&field_be(y.c1));
        output[96..].copy_from_slice(&field_be(y.c0));
    }
    G2Bytes(output)
}

fn scalar_be(value: Fr) -> ScalarBytes {
    let encoded = value.into_bigint().to_bytes_be();
    let mut output = [0u8; 32];
    output[32 - encoded.len()..].copy_from_slice(&encoded);
    ScalarBytes(output)
}

fn fixture_pool(pair_count: usize) -> Vec<Vec<PairBytes>> {
    let mut rng = StdRng::seed_from_u64(SEED ^ pair_count as u64);
    (0..POOL_SIZE)
        .map(|_| {
            (0..pair_count)
                .map(|_| PairBytes {
                    g1: g1_be(ArkG1Projective::rand(&mut rng)),
                    g2: g2_be(ArkG2Projective::rand(&mut rng)),
                })
                .collect()
        })
        .collect()
}

fn trusted_target_fixture(target_count: usize) -> (Vec<TrustedGt>, Vec<ScalarBytes>) {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x7472_7573_7465_6400 ^ target_count as u64);
    let mut targets = Vec::with_capacity(target_count);
    let mut exponents = Vec::with_capacity(target_count);
    for _ in 0..target_count {
        let pair = PairBytes {
            g1: g1_be(ArkG1Projective::rand(&mut rng)),
            g2: g2_be(ArkG2Projective::rand(&mut rng)),
        };
        targets.push(TrustedGt::from_pair(&pair).expect("registry fixture is valid"));
        exponents.push(scalar_be(Fr::rand(&mut rng)));
    }
    (targets, exponents)
}

fn bench_gt_map_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("helios_gt_map_scenarios_e2e");
    group.sample_size(40);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));

    for &(scenario, pair_count, target_count) in SCENARIOS {
        let pool = fixture_pool(pair_count);
        let (targets, exponents) = trusted_target_fixture(target_count);
        for pairs in &pool {
            pairing_map(pairs).expect("Ark-generated fixture is valid");
            pairing_product_is_one(pairs).expect("Ark-generated fixture is valid");
            trusted_gt_multiexp(&targets, &exponents)
                .expect("pre-registered target fixture is valid");
        }

        let mut map_cursor = 0usize;
        group.bench_function(BenchmarkId::new(scenario, "map"), |bencher| {
            bencher.iter(|| {
                let pairs = &pool[map_cursor];
                map_cursor = (map_cursor + 1) % POOL_SIZE;
                black_box(pairing_map(black_box(pairs)).expect("preflighted map fixture"))
            });
        });

        let mut check_cursor = 0usize;
        group.bench_function(BenchmarkId::new(scenario, "boolean"), |bencher| {
            bencher.iter(|| {
                let pairs = &pool[check_cursor];
                check_cursor = (check_cursor + 1) % POOL_SIZE;
                black_box(
                    pairing_product_is_one(black_box(pairs)).expect("preflighted boolean fixture"),
                )
            });
        });

        if target_count != 0 {
            group.bench_function(
                BenchmarkId::new(scenario, "trusted_gt_multiexp"),
                |bencher| {
                    bencher.iter(|| {
                        black_box(
                            trusted_gt_multiexp(black_box(&targets), black_box(&exponents))
                                .expect("preflighted registry target fixture"),
                        )
                    });
                },
            );

            let mut compare_cursor = 0usize;
            group.bench_function(
                BenchmarkId::new(scenario, "two_output_gt_compare"),
                |bencher| {
                    bencher.iter(|| {
                        let pairs = &pool[compare_cursor];
                        compare_cursor = (compare_cursor + 1) % POOL_SIZE;
                        let dynamic =
                            pairing_map(black_box(pairs)).expect("preflighted dynamic map fixture");
                        let expected =
                            trusted_gt_multiexp(black_box(&targets), black_box(&exponents))
                                .expect("preflighted registry target fixture");
                        black_box(dynamic.0 == expected.0)
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_gt_map_scenarios);
criterion_main!(benches);
