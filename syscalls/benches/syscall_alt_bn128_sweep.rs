//! `sol_alt_bn128_group_op` multiplication under adversarial scalars.
//!
//! A flat price has to cover the slowest scalar, and a backend with GLV
//! decomposition runs `r - 1` fast. Two scalars extend the fixed-cost sweep:
//! a seeded full-domain scalar and the GLV lattice corner `(r - 1) / 2`, whose
//! Babai halves are both full length.

#[macro_use]
mod common;

use {
    ark_bn254::{Fr, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{Field, PrimeField},
    common::{bn254::*, *},
    criterion::{criterion_group, criterion_main},
    hex_literal::hex,
    solana_bn254::versioned::{
        alt_bn128_versioned_g1_multiplication, alt_bn128_versioned_g2_multiplication,
        VersionedG1Multiplication, VersionedG2Multiplication, ALT_BN128_G1_MUL_BE,
        ALT_BN128_G1_MUL_LE, ALT_BN128_G1_POINT_SIZE, ALT_BN128_G2_MUL_BE, ALT_BN128_G2_MUL_LE,
        ALT_BN128_G2_POINT_SIZE,
    },
    solana_syscalls::SyscallAltBn128,
    std::hint::black_box,
};

const INPUT_VA: u64 = va(0);
const RESULT_VA: u64 = va(1);

/// SHA-256 of `agave rows mul sweep v1`, reduced into the scalar field.
const SEEDED_SCALAR_BYTES: [u8; 32] =
    hex!("f63071dbb450de8bfb8c36906646fdda326bf3a5862a349c47e17a24b8abc7eb");

struct Case {
    name: String,
    group_op: u64,
    input: Vec<u8>,
    output_len: usize,
    primitive: Box<dyn Fn(&[u8])>,
}

fn scalars() -> [(&'static str, Fr); 2] {
    let seeded = Fr::from_be_bytes_mod_order(&SEEDED_SCALAR_BYTES);
    let glv_corner = -Fr::from(2u64).inverse().expect("two is invertible");
    [("khw128", seeded), ("kglvcorner", glv_corner)]
}

fn build_cases() -> Vec<Case> {
    let p1 = G1Affine::generator();
    let q1 = G2Affine::generator();
    let mut cases = Vec::new();

    for le in [false, true] {
        let tag = if le { "le" } else { "be" };
        for (sname, scalar) in &scalars() {
            let mut input = Vec::new();
            input.extend_from_slice(&g1_bytes(&p1, le));
            input.extend_from_slice(&fr_bytes(scalar, le));
            cases.push(Case {
                name: format!("g1_mul_{tag}_{sname}"),
                group_op: if le {
                    ALT_BN128_G1_MUL_LE
                } else {
                    ALT_BN128_G1_MUL_BE
                },
                input,
                output_len: ALT_BN128_G1_POINT_SIZE,
                primitive: Box::new(move |i| {
                    black_box(
                        alt_bn128_versioned_g1_multiplication(
                            VersionedG1Multiplication::V1,
                            i,
                            endian(le),
                        )
                        .unwrap(),
                    );
                }),
            });

            let mut input = Vec::new();
            input.extend_from_slice(&g2_bytes(&q1, le));
            input.extend_from_slice(&fr_bytes(scalar, le));
            cases.push(Case {
                name: format!("g2_mul_{tag}_{sname}"),
                group_op: if le {
                    ALT_BN128_G2_MUL_LE
                } else {
                    ALT_BN128_G2_MUL_BE
                },
                input,
                output_len: ALT_BN128_G2_POINT_SIZE,
                primitive: Box::new(move |i| {
                    black_box(
                        alt_bn128_versioned_g2_multiplication(
                            VersionedG2Multiplication::V0,
                            i,
                            endian(le),
                        )
                        .unwrap(),
                    );
                }),
            });
        }
    }

    cases
}

fn bench_case(c: &mut Criterion, case: &Case) {
    let mut group = c.benchmark_group(format!("alt_bn128_sweep_{}", case.name));
    configure(&mut group);
    group.bench_function("primitive", |b| {
        b.iter(|| (case.primitive)(black_box(case.input.as_slice())))
    });
    group.finish();

    let mut result = vec![0u8; case.output_len];
    let input_len = case.input.len() as u64;
    let config = Config::default();

    prepare_mockup!(invoke_context, SVMFeatureSet::all_enabled());
    let memory_mapping = unsafe {
        MemoryMapping::new(
            vec![
                MemoryRegion::new(bytes_of_slice(case.input.as_slice()), INPUT_VA),
                MemoryRegion::new(bytes_of_slice_mut(result.as_mut_slice()), RESULT_VA),
            ],
            &config,
            SBPFVersion::V3,
        )
        .unwrap()
    };
    invoke_context
        .memory_contexts
        .mock_set_mapping_abi_v1(memory_mapping);

    let cu = charged_cu!(
        invoke_context,
        SyscallAltBn128::rust(
            &mut invoke_context,
            case.group_op,
            INPUT_VA,
            input_len,
            RESULT_VA,
            0
        )
    );
    eprintln!("alt_bn128 sweep_{} -> {cu} CU", case.name);

    invoke_context.compute_meter.mock_set_remaining(u64::MAX);

    let mut group = c.benchmark_group(format!("alt_bn128_sweep_{}", case.name));
    configure(&mut group);
    group.throughput(Throughput::Elements(cu));
    group.bench_function("syscall", |b| {
        b.iter(|| {
            black_box(
                SyscallAltBn128::rust(
                    &mut invoke_context,
                    black_box(case.group_op),
                    black_box(INPUT_VA),
                    black_box(input_len),
                    black_box(RESULT_VA),
                    0,
                )
                .unwrap(),
            )
        })
    });
    group.finish();
}

fn bench_sweep(c: &mut Criterion) {
    for case in &build_cases() {
        bench_case(c, case);
    }
}

criterion_group!(benches, bench_sweep);
criterion_main!(benches);
