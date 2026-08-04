// Fit CU prices from the upper 95 percent confidence bound at 33 ns per CU.
// The G2 subgroup check stays separate because the runtime charges it once per point.

use {
    ark_bn254::{Fr, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{FftField, Field, UniformRand, Zero},
    ark_serialize::{CanonicalSerialize, Compress},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    criterion::{BenchmarkId, Criterion, criterion_group, criterion_main},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodPlonkReductionContext, PodPlonkReductionInput, PodScalar, TrustedGt,
        Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm,
        alt_bn128_pairing_check, alt_bn128_pairing_map, alt_bn128_plonk_batch_reduce,
        trusted_gt_from_pair, trusted_gt_multiexp,
    },
};

const SEED: u64 = 0xa17b428;

fn advance(index: usize, len: usize) -> usize {
    if index == len.saturating_sub(1) {
        0
    } else {
        index.saturating_add(1)
    }
}

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

fn random_msm_be(pool_size: usize, n: usize) -> MsmPool {
    let mut r = rng();
    let mut pool = MsmPool {
        points: Vec::with_capacity(pool_size),
        scalars: Vec::with_capacity(pool_size),
    };
    for _ in 0..pool_size {
        let mut points = Vec::with_capacity(n.saturating_mul(64));
        let mut scalars = Vec::with_capacity(n.saturating_mul(32));
        for _ in 0..n {
            points.extend_from_slice(&reverse_chunks(&g1_le(G1Projective::rand(&mut r)), 32));
            scalars.extend_from_slice(&reverse_chunks(&fr_le(Fr::rand(&mut r)), 32));
        }
        pool.points.push(points);
        pool.scalars.push(scalars);
    }
    pool
}

// Each G2 encoding is distinct so shared-key folding cannot hide pairing work.
fn random_pairing_check_be(pool_size: usize, n: usize) -> Vec<Vec<u8>> {
    let mut r = rng();
    let mut pool = Vec::with_capacity(pool_size);
    for _ in 0..pool_size {
        let p = G1Projective::rand(&mut r);
        let q = G2Projective::rand(&mut r);
        let mut acc = Fr::from(0u64);
        let mut bytes = Vec::with_capacity(n.saturating_mul(192));
        for i in 0..n {
            let s = random_nonzero_fr(&mut r);
            let a = if n >= 2 && i == n.saturating_sub(1) {
                core::ops::Mul::mul(
                    core::ops::Neg::neg(acc),
                    s.inverse().expect("random_nonzero_fr excludes zero"),
                )
            } else {
                let a = Fr::rand(&mut r);
                core::ops::AddAssign::add_assign(&mut acc, core::ops::Mul::mul(a, s));
                a
            };
            bytes.extend_from_slice(&reverse_chunks(&g1_le(core::ops::Mul::mul(p, a)), 32));
            bytes.extend_from_slice(&reverse_chunks(&g2_le(core::ops::Mul::mul(q, s)), 64));
        }
        pool.push(bytes);
    }
    pool
}

fn random_nonzero_fr(rng: &mut StdRng) -> Fr {
    loop {
        let value = Fr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

fn random_g2_affine(pool_size: usize) -> Vec<G2Affine> {
    let mut r = rng();
    (0..pool_size)
        .map(|_| G2Projective::rand(&mut r).into_affine())
        .collect()
}

fn random_fr_be(rng: &mut StdRng, pool_size: usize, n: usize) -> Vec<Vec<u8>> {
    (0..pool_size)
        .map(|_| {
            let mut v = Vec::with_capacity(n.saturating_mul(32));
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
                i = advance(i, POOL);
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
                i = advance(i, POOL);
                r
            })
        });
    }
    group.finish();
}

fn bench_plonk_batch_reduce(c: &mut Criterion) {
    const NS: &[usize] = &[1, 2, 4, 5, 8, 16, 32];
    const POOL: usize = 32;

    let omega = Fr::get_root_of_unity(8).unwrap();
    let context = PodPlonkReductionContext {
        domain_size_be: 8u64.to_be_bytes(),
        num_public_inputs_be: 1u32.to_be_bytes(),
        reserved: [0u8; 4],
        omega: PodScalar::from(&omega),
        k1: PodScalar::from(&Fr::from(2u64)),
        k2: PodScalar::from(&Fr::from(3u64)),
    };
    let mut group = c.benchmark_group("BN254 PLONK batch scalar reduce");
    group.sample_size(20);
    for &n in NS {
        let mut r = rng();
        let mut input_pool = Vec::with_capacity(POOL);
        let mut public_pool = Vec::with_capacity(POOL);
        for _ in 0..POOL {
            let inputs = (0..n)
                .map(|_| {
                    let challenges = core::array::from_fn(|_| {
                        reverse_chunks(&fr_le(Fr::rand(&mut r)), 32)
                            .try_into()
                            .unwrap()
                    });
                    let evaluations = core::array::from_fn(|_| PodScalar::from(&Fr::rand(&mut r)));
                    PodPlonkReductionInput {
                        challenge_digests: challenges,
                        evaluations,
                        rho: PodScalar::from(&Fr::rand(&mut r)),
                    }
                })
                .collect::<Vec<_>>();
            let public_inputs = (0..n)
                .map(|_| PodScalar::from(&Fr::rand(&mut r)))
                .collect::<Vec<_>>();
            input_pool.push(inputs);
            public_pool.push(public_inputs);
        }
        for (inputs, public_inputs) in input_pool.iter().zip(&public_pool) {
            alt_bn128_plonk_batch_reduce(Version::V0, &context, inputs, public_inputs)
                .expect("valid PLONK scalar fixture");
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |bencher, _| {
            bencher.iter(|| {
                let out = alt_bn128_plonk_batch_reduce(
                    Version::V0,
                    &context,
                    &input_pool[i],
                    &public_pool[i],
                )
                .unwrap();
                i = advance(i, POOL);
                out
            })
        });
    }
    group.finish();
}

fn bench_g1_msm(c: &mut Criterion) {
    // One size in each price bucket checks the complete MSM discount table.
    // Includes 7 and 10, which the earlier capture skipped and the table needs.
    const NS: &[usize] = &[
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 36, 54, 64, 128, 256, 512, 1024, 2048,
    ];

    let mut group = c.benchmark_group("BN254 G1 MSM");
    group.sample_size(20);
    for &n in NS {
        let pool_size = 512usize
            .checked_div(n)
            .expect("benchmark sizes are nonzero")
            .clamp(4, 64);
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
                i = advance(i, pool_size);
                r
            })
        });
    }
    group.finish();
}

fn bench_pairing_check(c: &mut Criterion) {
    // Every pair count the decision table charges, plus 16 to pin the second
    // IFMA lane. Do not thin this list: the schedule is fitted to it.
    const NS: &[usize] = &[1, 2, 3, 4, 6, 7, 8, 9, 12, 16];
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
                i = advance(i, POOL);
                r
            })
        });
    }
    group.finish();
}

fn bench_pairing_map(c: &mut Criterion) {
    // Every pair count the decision table charges, plus 16 to pin the second
    // IFMA lane. Do not thin this list: the schedule is fitted to it.
    const NS: &[usize] = &[1, 2, 3, 4, 6, 7, 8, 9, 12, 16];
    const POOL: usize = 64;

    let mut group = c.benchmark_group("BN254 Pairing map");
    for &n in NS {
        let pool = random_pairing_check_be(POOL, n);
        for pairs in &pool {
            let gt = alt_bn128_pairing_map(Version::V0, bytemuck::cast_slice(pairs))
                .expect("valid fixture");
            assert_eq!(
                gt == solana_bn254_batch_syscall::PodGtElement::identity(),
                n >= 2,
                "telescoping inputs must map to identity"
            );
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("BE", n), &n, |b, _| {
            b.iter(|| {
                let r = alt_bn128_pairing_map(Version::V0, bytemuck::cast_slice(&pool[i])).unwrap();
                i = advance(i, POOL);
                r
            })
        });
    }
    group.finish();
}

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
            i = advance(i, POOL);
            r
        })
    });
    group.finish();
}

/// Isolates the final exponentiation the runtime charges as a pairing's base
/// cost. Measured as the difference a Miller loop alone cannot show: map one
/// pair, then exponentiate. Reported standalone so the base term is auditable.
fn bench_final_exponentiation(c: &mut Criterion) {
    const POOL: usize = 64;

    let pool = random_pairing_check_be(POOL, 1);
    let mut group = c.benchmark_group("BN254 final exponentiation");
    let mut i = 0usize;
    group.bench_function("one", |b| {
        b.iter(|| {
            let r = alt_bn128_pairing_map(Version::V0, bytemuck::cast_slice(&pool[i])).unwrap();
            i = advance(i, POOL);
            r
        })
    });
    group.finish();
}

/// GT multiexponentiation over authenticated targets. No prior capture exists
/// for this operation on any x86 host, so the runtime schedule is a
/// placeholder until this group lands.
fn bench_trusted_gt_multiexp(c: &mut Criterion) {
    const NS: &[usize] = &[1, 2, 3, 4];
    const POOL: usize = 32;

    let mut group = c.benchmark_group("BN254 trusted GT multiexp");
    for &n in NS {
        let mut targets: Vec<Vec<TrustedGt>> = Vec::with_capacity(POOL);
        let mut exps: Vec<Vec<PodScalar>> = Vec::with_capacity(POOL);
        let mut r = rng();
        for bytes in random_pairing_check_be(POOL, n) {
            let pairs: &[PodG1G2Pair] = bytemuck::cast_slice(&bytes);
            targets.push(
                pairs
                    .iter()
                    .map(|pair| trusted_gt_from_pair(pair).expect("valid fixture"))
                    .collect(),
            );
            let mut scalars = Vec::with_capacity(n.saturating_mul(32));
            for _ in 0..n {
                scalars.extend_from_slice(&reverse_chunks(&fr_le(Fr::rand(&mut r)), 32));
            }
            exps.push(bytemuck::cast_slice::<u8, PodScalar>(&scalars).to_vec());
        }
        let mut i = 0usize;
        group.bench_with_input(BenchmarkId::new("targets", n), &n, |b, _| {
            b.iter(|| {
                let r = trusted_gt_multiexp(&targets[i], &exps[i]);
                i = advance(i, POOL);
                r
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_g1_msm,
    bench_pairing_check,
    bench_pairing_map,
    bench_g2_subgroup_check,
    bench_final_exponentiation,
    bench_trusted_gt_multiexp,
    bench_fr_lincomb,
    bench_fr_batch_invert,
    bench_plonk_batch_reduce,
);
criterion_main!(benches);
