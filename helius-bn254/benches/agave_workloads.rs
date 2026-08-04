//! Helius timings over the exact deterministic fixtures used by Agave.
//!
//! Every row restarts `StdRng` with Agave's seed and performs the same direct
//! arkworks draws in the same order. Conversion to Helius's canonical byte or
//! typed representation happens before Criterion starts the timer.

use std::time::Duration;

use ark_bn254::{Fr as ArkFr, G1Projective as ArkG1Projective, G2Projective as ArkG2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use helius_bn254::{
    G1Bytes, G2Affine, G2Bytes, PairBytes, ScalarBytes, fr_batch_invert, fr_lincomb, g1_msm,
    pairing_product_is_one,
};
use rand::{SeedableRng, rngs::StdRng};

const SEED: u64 = 0x0a17_b428;
const FR_POOL_SIZE: usize = 32;
const PAIRING_POOL_SIZE: usize = 64;
const G2_SUBGROUP_POOL_SIZE: usize = 1024;

const MSM_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048];
const PAIRING_SIZES: &[usize] = &[1, 2, 3, 4, 8, 16];
const FR_SIZES: &[usize] = &[1, 16, 64, 256, 1024, 2048];

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

fn field_be<F: PrimeField>(value: F) -> [u8; 32] {
    let encoded = value.into_bigint().to_bytes_be();
    let mut output = [0_u8; 32];
    output[32 - encoded.len()..].copy_from_slice(&encoded);
    output
}

fn scalar_be(value: ArkFr) -> ScalarBytes {
    ScalarBytes(field_be(value))
}

fn g1_be(point: ArkG1Projective) -> G1Bytes {
    let mut output = [0_u8; 64];
    if let Some((x, y)) = point.into_affine().xy() {
        output[..32].copy_from_slice(&field_be(x));
        output[32..].copy_from_slice(&field_be(y));
    }
    G1Bytes(output)
}

fn g2_be(point: ArkG2Projective) -> G2Bytes {
    let mut output = [0_u8; 128];
    if let Some((x, y)) = point.into_affine().xy() {
        // Reversing Agave's 64-byte little-endian Fq2 chunks produces c1|c0.
        output[..32].copy_from_slice(&field_be(x.c1));
        output[32..64].copy_from_slice(&field_be(x.c0));
        output[64..96].copy_from_slice(&field_be(y.c1));
        output[96..].copy_from_slice(&field_be(y.c0));
    }
    G2Bytes(output)
}

struct MsmInput {
    points: Vec<G1Bytes>,
    scalars: Vec<ScalarBytes>,
}

/// Literal typed equivalent of Agave's `random_msm_be`: one fresh RNG per row,
/// followed by alternating G1 and Fr draws for every point in every pool item.
fn random_msm_pool(pool_size: usize, n: usize) -> Vec<MsmInput> {
    let mut rng = rng();
    (0..pool_size)
        .map(|_| {
            let mut points = Vec::with_capacity(n);
            let mut scalars = Vec::with_capacity(n);
            for _ in 0..n {
                points.push(g1_be(ArkG1Projective::rand(&mut rng)));
                scalars.push(scalar_be(ArkFr::rand(&mut rng)));
            }
            MsmInput { points, scalars }
        })
        .collect()
}

/// Literal typed equivalent of Agave's telescoping pairing fixture.
///
/// The G2 point is drawn before the G1 base. Scalars may be zero and the final
/// `-sum` may produce identity; no retry or nonzero substitution is permitted.
fn random_pairing_pool(pool_size: usize, n: usize) -> Vec<Vec<PairBytes>> {
    let mut rng = rng();
    (0..pool_size)
        .map(|_| {
            let q = g2_be(ArkG2Projective::rand(&mut rng));
            let p = ArkG1Projective::rand(&mut rng);
            let mut sum = ArkFr::from(0_u64);
            let mut pairs = Vec::with_capacity(n);
            for i in 0..n {
                let g1 = if n >= 2 && i == n - 1 {
                    p * (-sum)
                } else {
                    let scalar = ArkFr::rand(&mut rng);
                    sum += scalar;
                    p * scalar
                };
                pairs.push(PairBytes {
                    g1: g1_be(g1),
                    g2: q,
                });
            }
            pairs
        })
        .collect()
}

fn random_fr_pool(rng: &mut StdRng, pool_size: usize, n: usize) -> Vec<Vec<ScalarBytes>> {
    (0..pool_size)
        .map(|_| (0..n).map(|_| scalar_be(ArkFr::rand(rng))).collect())
        .collect()
}

/// Agave times typed subgroup arithmetic. Ark points are converted to the
/// equivalent Helius type once, outside the timed region.
fn random_g2_affine(pool_size: usize) -> Vec<G2Affine> {
    let mut rng = rng();
    (0..pool_size)
        .map(|_| {
            g2_be(ArkG2Projective::rand(&mut rng))
                .to_affine()
                .expect("Ark-generated G2 fixture is valid")
        })
        .collect()
}

fn configure_group(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    group.sample_size(30);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(5));
}

/// Profiling selects one benchmark after the executable has started. Criterion
/// still calls every registration function, so this opt-in filter avoids
/// constructing unrelated large row-local fixture pools.
fn fixture_selected(group: &str, n: usize) -> bool {
    let Ok(filter) = std::env::var("HELIUS_BENCH_FILTER") else {
        return true;
    };
    let id = format!("{group}/helius/{n}");
    if filter.contains("/helius/") {
        id == filter || id.ends_with(&filter)
    } else {
        id.contains(&filter)
    }
}

fn bench_g1_msm(c: &mut Criterion) {
    let mut group = c.benchmark_group("agave_bn254_g1_msm_e2e");
    configure_group(&mut group);

    for &n in MSM_SIZES {
        if !fixture_selected("agave_bn254_g1_msm_e2e", n) {
            continue;
        }
        let pool_size = (512 / n).clamp(4, 64);
        let pool = random_msm_pool(pool_size, n);
        for input in &pool {
            g1_msm(&input.points, &input.scalars).expect("valid deterministic MSM fixture");
        }

        group.throughput(Throughput::Elements(n as u64));
        let mut cursor = 0_usize;
        group.bench_with_input(BenchmarkId::new("helius", n), &n, |bencher, _| {
            bencher.iter(|| {
                let input = &pool[cursor];
                cursor = (cursor + 1) % pool_size;
                black_box(
                    g1_msm(black_box(&input.points), black_box(&input.scalars))
                        .expect("preflighted MSM fixture"),
                )
            });
        });
    }
    group.finish();
}

fn bench_pairing_product(c: &mut Criterion) {
    let mut group = c.benchmark_group("agave_bn254_pairing_product_e2e");
    configure_group(&mut group);

    for &n in PAIRING_SIZES {
        if !fixture_selected("agave_bn254_pairing_product_e2e", n) {
            continue;
        }
        let pool = random_pairing_pool(PAIRING_POOL_SIZE, n);
        for pairs in &pool {
            let verdict =
                pairing_product_is_one(pairs).expect("valid deterministic pairing fixture");
            assert_eq!(verdict, n >= 2, "Agave telescoping pairing fixture");
        }

        group.throughput(Throughput::Elements(n as u64));
        let mut cursor = 0_usize;
        group.bench_with_input(BenchmarkId::new("helius", n), &n, |bencher, _| {
            bencher.iter(|| {
                let pairs = &pool[cursor];
                cursor = (cursor + 1) % PAIRING_POOL_SIZE;
                black_box(
                    pairing_product_is_one(black_box(pairs)).expect("preflighted pairing fixture"),
                )
            });
        });
    }
    group.finish();
}

fn bench_g2_subgroup_check(c: &mut Criterion) {
    const GROUP: &str = "agave_bn254_g2_subgroup_arithmetic";
    if let Ok(filter) = std::env::var("HELIUS_BENCH_FILTER")
        && !filter.contains(GROUP)
        && !filter.contains("g2_subgroup")
    {
        return;
    }

    let points = random_g2_affine(G2_SUBGROUP_POOL_SIZE);
    assert!(
        points
            .iter()
            .all(G2Affine::is_in_correct_subgroup_assuming_on_curve)
    );

    let mut group = c.benchmark_group(GROUP);
    configure_group(&mut group);
    let mut cursor = 0_usize;
    group.bench_function("helius/point", |bencher| {
        bencher.iter(|| {
            let point = &points[cursor];
            cursor = (cursor + 1) % G2_SUBGROUP_POOL_SIZE;
            black_box(point.is_in_correct_subgroup_assuming_on_curve())
        });
    });
    group.finish();
}

fn bench_fr_lincomb(c: &mut Criterion) {
    let mut group = c.benchmark_group("agave_bn254_fr_lincomb_e2e");
    configure_group(&mut group);

    for &n in FR_SIZES {
        if !fixture_selected("agave_bn254_fr_lincomb_e2e", n) {
            continue;
        }
        // Agave draws the complete a pool before the complete b pool.
        let mut rng = rng();
        let coefficients = random_fr_pool(&mut rng, FR_POOL_SIZE, n);
        let values = random_fr_pool(&mut rng, FR_POOL_SIZE, n);
        for (a, b) in coefficients.iter().zip(&values) {
            fr_lincomb(a, b).expect("valid deterministic lincomb fixture");
        }

        group.throughput(Throughput::Elements(n as u64));
        let mut cursor = 0_usize;
        group.bench_with_input(BenchmarkId::new("helius", n), &n, |bencher, _| {
            bencher.iter(|| {
                let i = cursor;
                cursor = (cursor + 1) % FR_POOL_SIZE;
                black_box(
                    fr_lincomb(black_box(&coefficients[i]), black_box(&values[i]))
                        .expect("preflighted lincomb fixture"),
                )
            });
        });
    }
    group.finish();
}

fn bench_fr_batch_invert(c: &mut Criterion) {
    let mut group = c.benchmark_group("agave_bn254_fr_batch_invert_e2e");
    configure_group(&mut group);

    for &n in FR_SIZES {
        if !fixture_selected("agave_bn254_fr_batch_invert_e2e", n) {
            continue;
        }
        let mut rng = rng();
        let values = random_fr_pool(&mut rng, FR_POOL_SIZE, n);
        for input in &values {
            let output = fr_batch_invert(input).expect("valid deterministic inversion fixture");
            assert_eq!(output.len(), n);
        }

        group.throughput(Throughput::Elements(n as u64));
        let mut cursor = 0_usize;
        group.bench_with_input(BenchmarkId::new("helius", n), &n, |bencher, _| {
            bencher.iter(|| {
                let input = &values[cursor];
                cursor = (cursor + 1) % FR_POOL_SIZE;
                black_box(fr_batch_invert(black_box(input)).expect("preflighted inversion fixture"))
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_g1_msm,
    bench_pairing_product,
    bench_g2_subgroup_check,
    bench_fr_lincomb,
    bench_fr_batch_invert,
);
criterion_main!(benches);
