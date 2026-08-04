//! Paired release harness for the native assembly and portable Montgomery
//! leaves (Apple AArch64 hand leaf or generated x86-64 ADX leaf).
//!
//! This lives beside the private backends so the benchmark compares the exact
//! production entry points without making either implementation public.  It is
//! ignored by default: `scripts/run_backend_compare.sh` supplies a fresh output
//! path, records build provenance, and validates the resulting JSONL.

use std::fs::OpenOptions;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
use super::aarch64 as native;
use super::portable;
#[cfg(helius_mont4_x86_64_adx)]
use super::x86_64 as native;
use crate::consts::{MONT_R2, P};
use crate::limb;

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
const TARGET: &str = "aarch64-apple-darwin";
#[cfg(helius_mont4_x86_64_adx)]
const TARGET: &str = "x86_64-unknown-linux-gnu";

const SCHEMA: &str = "helius-bn254-backend-compare-v1";
const DEFAULT_SAMPLES: usize = 30;
const DEFAULT_ITERATIONS: usize = 1_000_000;
const DEFAULT_WARMUP_ITERATIONS: usize = 100_000;
const DEFAULT_POOL_SIZE: usize = 2_048;
const POOL_SEED: u64 = 0xd1b5_4a32_d192_ed03;

#[derive(Clone, Copy)]
enum Backend {
    NativeAsm,
    PortableRust,
}

impl Backend {
    const fn name(self) -> &'static str {
        match self {
            Self::NativeAsm => "native_asm",
            Self::PortableRust => "portable_rust",
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    IndependentMul,
    DependentMul,
    DependentSquare,
    IndependentSquare,
}

impl Operation {
    const ALL: [Self; 4] = [
        Self::IndependentMul,
        Self::DependentMul,
        Self::DependentSquare,
        Self::IndependentSquare,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::IndependentMul => "independent_mul",
            Self::DependentMul => "dependent_mul",
            Self::DependentSquare => "dependent_square",
            Self::IndependentSquare => "independent_square",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::IndependentMul => 0,
            Self::DependentMul => 1,
            Self::DependentSquare => 2,
            Self::IndependentSquare => 3,
        }
    }
}

struct Pools {
    left: Vec<[u64; 4]>,
    right: Vec<[u64; 4]>,
}

struct Measurement {
    backend: Backend,
    order: usize,
    elapsed: Duration,
    checksum: u64,
}

fn configured_usize(name: &str, default: usize, minimum: usize) -> usize {
    let Some(value) = std::env::var_os(name) else {
        return default;
    };
    let printable = value
        .to_str()
        .unwrap_or_else(|| panic!("{name} must be valid UTF-8"));
    let parsed = printable
        .parse::<usize>()
        .unwrap_or_else(|_| panic!("{name} must be an unsigned integer"));
    assert!(parsed >= minimum, "{name} must be at least {minimum}");
    parsed
}

#[inline]
fn next_u64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn next_nonzero_residue(state: &mut u64) -> [u64; 4] {
    loop {
        let value = core::array::from_fn(|_| next_u64(state));
        if !limb::is_zero(&value) && !limb::gte(&value, &P) {
            return value;
        }
    }
}

fn to_shared_montgomery(raw: [u64; 4], context: &str) -> [u64; 4] {
    let native_value = native::mont_mul(&raw, &MONT_R2);
    let portable_value = portable::mont_mul(&raw, &MONT_R2);
    assert_eq!(
        native_value, portable_value,
        "backend conversion mismatch: {context}"
    );
    assert!(
        !limb::gte(&native_value.0, &P),
        "unreduced conversion: {context}"
    );
    native_value.0
}

fn build_pools(size: usize) -> Pools {
    assert!(
        size.is_power_of_two(),
        "HELIUS_BACKEND_POOL_SIZE must be a power of two"
    );
    assert!(
        size <= 1 << 20,
        "HELIUS_BACKEND_POOL_SIZE is unreasonably large"
    );

    let p_minus_one = limb::sub_noborrow(&P, &[1, 0, 0, 0]);
    let p_minus_two = limb::sub_noborrow(&P, &[2, 0, 0, 0]);
    let edge_left = [[1, 0, 0, 0], p_minus_one, p_minus_two, MONT_R2];
    let edge_right = [p_minus_one, [2, 0, 0, 0], MONT_R2, [1, 0, 0, 0]];

    let mut state = POOL_SEED;
    let mut left = Vec::with_capacity(size);
    let mut right = Vec::with_capacity(size);
    for index in 0..size {
        let raw_left = edge_left
            .get(index)
            .copied()
            .unwrap_or_else(|| next_nonzero_residue(&mut state));
        let raw_right = edge_right
            .get(index)
            .copied()
            .unwrap_or_else(|| next_nonzero_residue(&mut state));
        left.push(to_shared_montgomery(raw_left, "left pool"));
        right.push(to_shared_montgomery(raw_right, "right pool"));
    }
    Pools { left, right }
}

#[inline(always)]
fn checksum_limb(checksum: u64, limb: u64) -> u64 {
    checksum
        .rotate_left(9)
        .wrapping_add(limb)
        .wrapping_mul(0x9e37_79b1_85eb_ca87)
}

#[inline]
fn finish_checksum(mut checksum: u64, value: [u64; 4]) -> u64 {
    for limb in value {
        checksum = checksum_limb(checksum, limb);
    }
    checksum
}

macro_rules! define_backend_runners {
    (
        $independent:ident,
        $dependent_mul:ident,
        $dependent_square:ident,
        $independent_square:ident,
        $mul:path,
        $square:path
    ) => {
        #[inline(never)]
        fn $independent(pools: &Pools, iterations: usize, rotation: usize) -> u64 {
            let mask = pools.left.len() - 1;
            let mut left_index = rotation & mask;
            let mut right_index = rotation.wrapping_mul(29).wrapping_add(17) & mask;
            let mut checksum = 0x243f_6a88_85a3_08d3;
            for iteration in 0..iterations {
                let product = ($mul)(
                    black_box(&pools.left[left_index]),
                    black_box(&pools.right[right_index]),
                );
                checksum = checksum_limb(checksum, black_box(product.0[iteration & 3]));
                left_index = left_index.wrapping_add(1) & mask;
                right_index = right_index.wrapping_add(17) & mask;
            }
            black_box(checksum)
        }

        #[inline(never)]
        fn $dependent_mul(pools: &Pools, iterations: usize, rotation: usize) -> u64 {
            let mask = pools.left.len() - 1;
            let mut value = pools.left[rotation & mask];
            let mut right_index = rotation.wrapping_mul(29).wrapping_add(17) & mask;
            for _ in 0..iterations {
                value = black_box(($mul)(
                    black_box(&value),
                    black_box(&pools.right[right_index]),
                ))
                .0;
                right_index = right_index.wrapping_add(17) & mask;
            }
            black_box(finish_checksum(0x1319_8a2e_0370_7344, value))
        }

        #[inline(never)]
        fn $dependent_square(pools: &Pools, iterations: usize, rotation: usize) -> u64 {
            let mask = pools.left.len() - 1;
            let mut value = pools.left[rotation & mask];
            for _ in 0..iterations {
                value = black_box(($square)(black_box(&value))).0;
            }
            black_box(finish_checksum(0xa409_3822_299f_31d0, value))
        }

        #[inline(never)]
        fn $independent_square(pools: &Pools, iterations: usize, rotation: usize) -> u64 {
            let mask = pools.left.len() - 1;
            let mut index = rotation & mask;
            let mut checksum = 0x082e_fa98_ec4e_6c89;
            for iteration in 0..iterations {
                let square = ($square)(black_box(&pools.left[index]));
                checksum = checksum_limb(checksum, black_box(square.0[iteration & 3]));
                index = index.wrapping_add(1) & mask;
            }
            black_box(checksum)
        }
    };
}

define_backend_runners!(
    native_independent_mul,
    native_dependent_mul,
    native_dependent_square,
    native_independent_square,
    native::mont_mul,
    native::mont_sqr
);
define_backend_runners!(
    portable_independent_mul,
    portable_dependent_mul,
    portable_dependent_square,
    portable_independent_square,
    portable::mont_mul,
    portable::mont_sqr
);

fn run(
    backend: Backend,
    operation: Operation,
    pools: &Pools,
    iterations: usize,
    rotation: usize,
) -> u64 {
    match (backend, operation) {
        (Backend::NativeAsm, Operation::IndependentMul) => {
            native_independent_mul(pools, iterations, rotation)
        }
        (Backend::NativeAsm, Operation::DependentMul) => {
            native_dependent_mul(pools, iterations, rotation)
        }
        (Backend::NativeAsm, Operation::DependentSquare) => {
            native_dependent_square(pools, iterations, rotation)
        }
        (Backend::NativeAsm, Operation::IndependentSquare) => {
            native_independent_square(pools, iterations, rotation)
        }
        (Backend::PortableRust, Operation::IndependentMul) => {
            portable_independent_mul(pools, iterations, rotation)
        }
        (Backend::PortableRust, Operation::DependentMul) => {
            portable_dependent_mul(pools, iterations, rotation)
        }
        (Backend::PortableRust, Operation::DependentSquare) => {
            portable_dependent_square(pools, iterations, rotation)
        }
        (Backend::PortableRust, Operation::IndependentSquare) => {
            portable_independent_square(pools, iterations, rotation)
        }
    }
}

fn measure(
    backend: Backend,
    order: usize,
    operation: Operation,
    pools: &Pools,
    iterations: usize,
    rotation: usize,
) -> Measurement {
    let started = Instant::now();
    let checksum = run(backend, operation, pools, iterations, rotation);
    let elapsed = started.elapsed();
    assert!(!elapsed.is_zero(), "timer resolution was insufficient");
    Measurement {
        backend,
        order,
        elapsed,
        checksum,
    }
}

fn sample_rotation(sample: usize, operation: Operation, pool_size: usize) -> usize {
    sample
        .wrapping_mul(0x9e37)
        .wrapping_add(operation.index().wrapping_mul(0x7f4a))
        & (pool_size - 1)
}

fn preflight(pools: &Pools, iterations: usize) {
    for index in 0..pools.left.len() {
        assert_eq!(
            native::mont_mul(&pools.left[index], &pools.right[index]),
            portable::mont_mul(&pools.left[index], &pools.right[index]),
            "multiply preflight {index}"
        );
        assert_eq!(
            native::mont_sqr(&pools.left[index]),
            portable::mont_sqr(&pools.left[index]),
            "square preflight {index}"
        );
    }

    let chain_iterations = iterations.min(pools.left.len().saturating_mul(2));
    for operation in Operation::ALL {
        for rotation in [0, pools.left.len() / 3, pools.left.len() - 1] {
            assert_eq!(
                run(
                    Backend::NativeAsm,
                    operation,
                    pools,
                    chain_iterations,
                    rotation,
                ),
                run(
                    Backend::PortableRust,
                    operation,
                    pools,
                    chain_iterations,
                    rotation,
                ),
                "{} chain preflight at rotation {rotation}",
                operation.name()
            );
        }
    }
}

fn write_metadata(
    output: &mut impl Write,
    samples: usize,
    warmup_iterations: usize,
    iterations: usize,
    pool_size: usize,
) {
    writeln!(
        output,
        concat!(
            "{{\"schema\":\"{}\",\"type\":\"metadata\",",
            "\"target\":\"{}\",\"profile\":\"release\",",
            "\"sample_count\":{},\"warmup_iterations\":{},\"iterations\":{},",
            "\"pool_size\":{},\"seed\":\"0x{:016x}\",",
            "\"pool_generator\":\"xorshift64-rejection-canonical-v1\",",
            "\"order_policy\":\"alternating-by-sample-and-operation\",",
            "\"operations\":[\"independent_mul\",\"dependent_mul\",",
            "\"dependent_square\",\"independent_square\"],",
            "\"backends\":[\"native_asm\",\"portable_rust\"]}}"
        ),
        SCHEMA, TARGET, samples, warmup_iterations, iterations, pool_size, POOL_SEED,
    )
    .expect("write backend comparison metadata");
}

fn write_measurement(
    output: &mut impl Write,
    operation: Operation,
    sample: usize,
    iterations: usize,
    measurement: &Measurement,
) {
    writeln!(
        output,
        concat!(
            "{{\"schema\":\"{}\",\"type\":\"sample\",\"operation\":\"{}\",",
            "\"backend\":\"{}\",\"sample\":{},\"order\":{},\"iterations\":{},",
            "\"elapsed_ns\":{},\"checksum\":\"{:016x}\"}}"
        ),
        SCHEMA,
        operation.name(),
        measurement.backend.name(),
        sample,
        measurement.order,
        iterations,
        measurement.elapsed.as_nanos(),
        measurement.checksum,
    )
    .expect("write backend comparison sample");
}

#[test]
#[ignore = "release-only paired performance harness; use scripts/run_backend_compare.sh"]
fn paired_backend_compare() {
    assert!(
        !black_box(cfg!(debug_assertions)),
        "backend comparison must be compiled with --release"
    );
    let samples = configured_usize("HELIUS_BACKEND_SAMPLES", DEFAULT_SAMPLES, 30);
    let iterations = configured_usize("HELIUS_BACKEND_ITERATIONS", DEFAULT_ITERATIONS, 10_000);
    let warmup_iterations = configured_usize(
        "HELIUS_BACKEND_WARMUP_ITERATIONS",
        DEFAULT_WARMUP_ITERATIONS,
        1,
    );
    let pool_size = configured_usize("HELIUS_BACKEND_POOL_SIZE", DEFAULT_POOL_SIZE, 256);
    let output_path = std::env::var_os("HELIUS_BACKEND_OUTPUT")
        .expect("HELIUS_BACKEND_OUTPUT must name a fresh JSONL file");

    let pools = build_pools(pool_size);
    preflight(&pools, iterations);

    // Warm both instruction streams and data paths with identical work before
    // measuring. Reversing this order per operation avoids one fixed winner.
    for operation in Operation::ALL {
        let rotation = sample_rotation(usize::MAX / 2, operation, pool_size);
        let first = if operation.index() & 1 == 0 {
            Backend::NativeAsm
        } else {
            Backend::PortableRust
        };
        let second = match first {
            Backend::NativeAsm => Backend::PortableRust,
            Backend::PortableRust => Backend::NativeAsm,
        };
        let first_checksum = run(first, operation, &pools, warmup_iterations, rotation);
        let second_checksum = run(second, operation, &pools, warmup_iterations, rotation);
        assert_eq!(
            first_checksum,
            second_checksum,
            "{} warmup",
            operation.name()
        );
    }

    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .expect("HELIUS_BACKEND_OUTPUT must be a creatable, nonexistent file");
    let mut output = BufWriter::new(output);
    write_metadata(
        &mut output,
        samples,
        warmup_iterations,
        iterations,
        pool_size,
    );

    for operation in Operation::ALL {
        for sample in 0..samples {
            let rotation = sample_rotation(sample, operation, pool_size);
            let native_first = (sample + operation.index()) & 1 == 0;
            let first_backend = if native_first {
                Backend::NativeAsm
            } else {
                Backend::PortableRust
            };
            let second_backend = if native_first {
                Backend::PortableRust
            } else {
                Backend::NativeAsm
            };
            let first = measure(first_backend, 0, operation, &pools, iterations, rotation);
            let second = measure(second_backend, 1, operation, &pools, iterations, rotation);
            assert_eq!(
                first.checksum,
                second.checksum,
                "{} sample {sample}",
                operation.name()
            );
            write_measurement(&mut output, operation, sample, iterations, &first);
            write_measurement(&mut output, operation, sample, iterations, &second);
        }
    }
    output.flush().expect("flush backend comparison JSONL");
}
