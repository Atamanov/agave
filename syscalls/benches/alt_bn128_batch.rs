// Prices the two alt_bn128 batch syscalls. CU = criterion 95%-CI upper bound /
// 33 ns per CU; the fitted constants land in `execution_budget.rs`. MSM sweeps
// one size per log2 bucket so the discount table sees the whole Pippenger
// curve; the pairing check sweeps small n for the base + per_pair fit; the G2
// subgroup check is timed standalone so its surcharge stays a separate constant.
#![allow(clippy::arithmetic_side_effects)]

use {
    ark_bn254::{Fr, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{Field, UniformRand},
    ark_serialize::{CanonicalSerialize, Compress},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    criterion::{BenchmarkId, Criterion, criterion_group, criterion_main},
    solana_bn254_batch_syscall::{
        Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm,
        alt_bn128_pairing_check,
    },
};

const SEED: u64 = 0xa17b428;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

// arkworks serializes little-endian; the syscalls read big-endian, so every
// field element is reversed within its 32-byte limb.
fn reverse_chunks(le: &[u8], chunk: usize) -> Vec<u8> {
    le.chunks_exact(chunk)
        .flat_map(|c| c.iter().rev().copied())
        .collect()
}

fn g1_le(p: G1Projective) -> [u8; 64] {
    let mut buf = [0u8; 64];
    if let Some((x, y)) = p.into_affine().xy() {
        x.serialize_with_mode(&mut buf[..32], Compress::No).unwrap();
        y.serialize_with_mode(&mut buf[32..], Compress::No).unwrap();
    }
    buf
}

fn g2_le(p: G2Projective) -> [u8; 128] {
    let mut buf = [0u8; 128];
    if let Some((x, y)) = p.into_affine().xy() {
        x.serialize_with_mode(&mut buf[..64], Compress::No).unwrap();
        y.serialize_with_mode(&mut buf[64..], Compress::No).unwrap();
    }
    buf
}

fn fr_le(s: Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    s.serialize_uncompressed(&mut buf[..]).unwrap();
    buf
}

struct MsmPool {
    points: Vec<Vec<u8>>,
    scalars: Vec<Vec<u8>>,
}

// `pool_size` MSM inputs of `n` points: n * 64 BE G1 bytes and n * 32 BE
// scalar bytes each, the wire format of `sol_alt_bn128_g1_msm`.
fn random_msm_be(pool_size: usize, n: usize) -> MsmPool {
    let mut r = rng();
    let mut pool = MsmPool {
        points: Vec::with_capacity(pool_size),
        scalars: Vec::with_capacity(pool_size),
    };
    for _ in 0..pool_size {
        let mut points = Vec::with_capacity(n * 64);
        let mut scalars = Vec::with_capacity(n * 32);
        for _ in 0..n {
            points.extend_from_slice(&reverse_chunks(&g1_le(G1Projective::rand(&mut r)), 32));
            scalars.extend_from_slice(&reverse_chunks(&fr_le(Fr::rand(&mut r)), 32));
        }
        pool.points.push(points);
        pool.scalars.push(scalars);
    }
    pool
}

// `pool_size` BE pairing inputs of `n` real pairs (n * 192 bytes) whose
// product is the GT identity for n >= 2: pair i is ([a_i]P, [s_i]Q) with the
// last a_n chosen so sum a_i s_i = 0. Every G2 is a DISTINCT multiple of Q,
// which is the worst case the price must cover: a backend may fold pairs
// sharing one G2 encoding by bilinearity, and shared-Q fixtures would let
// that optimization masquerade as a near-zero per-pair cost. n == 1 is one
// random pair (verdict false, same work).
fn random_pairing_check_be(pool_size: usize, n: usize) -> Vec<Vec<u8>> {
    let mut r = rng();
    let mut pool = Vec::with_capacity(pool_size);
    for _ in 0..pool_size {
        let p = G1Projective::rand(&mut r);
        let q = G2Projective::rand(&mut r);
        let mut acc = Fr::from(0u64);
        let mut bytes = Vec::with_capacity(n * 192);
        for i in 0..n {
            let s = Fr::rand(&mut r);
            let a = if n >= 2 && i == n - 1 {
                // closes sum a_i s_i = 0; s is invertible with probability
                // 1 - 1/q, and rand never returns zero in practice
                -acc * s.inverse().expect("random s is nonzero")
            } else {
                let a = Fr::rand(&mut r);
                acc += a * s;
                a
            };
            bytes.extend_from_slice(&reverse_chunks(&g1_le(p * a), 32));
            bytes.extend_from_slice(&reverse_chunks(&g2_le(q * s), 64));
        }
        pool.push(bytes);
    }
    pool
}

fn random_g2_affine(pool_size: usize) -> Vec<G2Affine> {
    let mut r = rng();
    (0..pool_size)
        .map(|_| G2Projective::rand(&mut r).into_affine())
        .collect()
}

// `pool_size` arrays of `n` BE scalars each. All draws share one rng stream, so
// a and b arrays for lincomb are distinct.
fn random_fr_be(rng: &mut StdRng, pool_size: usize, n: usize) -> Vec<Vec<u8>> {
    (0..pool_size)
        .map(|_| {
            let mut v = Vec::with_capacity(n * 32);
            for _ in 0..n {
                v.extend_from_slice(&reverse_chunks(&fr_le(Fr::rand(rng)), 32));
            }
            v
        })
        .collect()
}

fn bench_fr_lincomb(c: &mut Criterion) {
    const NS: &[usize] = &[1, 16, 64, 256, 1024, 2048];
    const POOL: usize = 32;

    let mut group = c.benchmark_group("BN254 Fr lincomb");
    group.sample_size(20);
    for &n in NS {
        let mut r = rng();
        let a = random_fr_be(&mut r, POOL, n);
        let b = random_fr_be(&mut r, POOL, n);
        for (x, y) in a.iter().zip(&b) {
            alt_bn128_fr_lincomb(
                Version::V0,
                bytemuck::cast_slice(x),
                bytemuck::cast_slice(y),
            )
            .expect("valid lincomb fixture");
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |bencher, _| {
            bencher.iter(|| {
                let r = alt_bn128_fr_lincomb(
                    Version::V0,
                    bytemuck::cast_slice(&a[i]),
                    bytemuck::cast_slice(&b[i]),
                )
                .unwrap();
                i = (i + 1) % POOL;
                r
            })
        });
    }
    group.finish();
}

fn bench_fr_batch_invert(c: &mut Criterion) {
    const NS: &[usize] = &[1, 16, 64, 256, 1024, 2048];
    const POOL: usize = 32;

    let mut group = c.benchmark_group("BN254 Fr batch invert");
    group.sample_size(20);
    for &n in NS {
        let mut r = rng();
        let a = random_fr_be(&mut r, POOL, n);
        for x in &a {
            alt_bn128_fr_batch_invert(Version::V0, bytemuck::cast_slice(x))
                .expect("valid batch-invert fixture");
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |bencher, _| {
            bencher.iter(|| {
                let r =
                    alt_bn128_fr_batch_invert(Version::V0, bytemuck::cast_slice(&a[i])).unwrap();
                i = (i + 1) % POOL;
                r
            })
        });
    }
    group.finish();
}

fn bench_g1_msm(c: &mut Criterion) {
    // 12 sizes, one per log2 bucket over the 1..=2048 cap
    const NS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048];

    let mut group = c.benchmark_group("BN254 G1 MSM");
    group.sample_size(20);
    for &n in NS {
        let pool_size = (512 / n).clamp(4, 64);
        let pool = random_msm_be(pool_size, n);
        for (points, scalars) in pool.points.iter().zip(pool.scalars.iter()) {
            alt_bn128_g1_msm(
                Version::V0,
                bytemuck::cast_slice(points),
                bytemuck::cast_slice(scalars),
            )
            .expect("valid msm fixture");
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |b, _| {
            b.iter(|| {
                let r = alt_bn128_g1_msm(
                    Version::V0,
                    bytemuck::cast_slice(&pool.points[i]),
                    bytemuck::cast_slice(&pool.scalars[i]),
                )
                .unwrap();
                i = (i + 1) % pool_size;
                r
            })
        });
    }
    group.finish();
}

fn bench_pairing_check(c: &mut Criterion) {
    const NS: &[usize] = &[1, 2, 3, 4, 8, 16];
    const POOL: usize = 64;

    let mut group = c.benchmark_group("BN254 Pairing check");
    for &n in NS {
        let pool = random_pairing_check_be(POOL, n);
        for pairs in &pool {
            let verdict = alt_bn128_pairing_check(Version::V0, bytemuck::cast_slice(pairs))
                .expect("valid fixture");
            assert_eq!(verdict, n >= 2, "telescoping inputs must pair to identity");
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |b, _| {
            b.iter(|| {
                let r =
                    alt_bn128_pairing_check(Version::V0, bytemuck::cast_slice(&pool[i])).unwrap();
                i = (i + 1) % POOL;
                r
            })
        });
    }
    group.finish();
}

// prices the standalone `alt_bn128_g2_subgroup_check_cost` component
fn bench_g2_subgroup_check(c: &mut Criterion) {
    const POOL: usize = 1024;

    let points = random_g2_affine(POOL);
    for point in &points {
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
    }
    let mut group = c.benchmark_group("BN254 G2 subgroup check");
    let mut i = 0usize;
    group.bench_function("point", |b| {
        b.iter(|| {
            let r = points[i].is_in_correct_subgroup_assuming_on_curve();
            i = (i + 1) % POOL;
            r
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_g1_msm,
    bench_pairing_check,
    bench_g2_subgroup_check,
    bench_fr_lincomb,
    bench_fr_batch_invert,
);
criterion_main!(benches);
