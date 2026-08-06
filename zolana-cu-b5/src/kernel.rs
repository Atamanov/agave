//! Syscall shims installed under the unmodified shielded-pool program.
//!
//! Two of them shadow a stock syscall by name. LiteSVM keys its syscall
//! registry by the hash of the name, so the fork drops the shadowed stock entry
//! instead of registering a second one; see this crate's `[patch.crates-io]`.
//!
//! [`B5GroupOp`] is the measurement. It keeps the `sol_alt_bn128_group_op` ABI
//! byte for byte, so the program binary and its sBPF trace are unchanged, and
//! routes the arithmetic through the B5 kernel while charging the fitted B5
//! schedule. The guest cannot tell the difference except in what it is billed.
//!
//! The hash shims charge exactly what the runtime charges and exist only to
//! read the per-slice lengths, which live in guest memory and therefore never
//! appear in a register trace.

use std::sync::atomic::{AtomicU64, Ordering};

use bytemuck::try_cast_slice;
use solana_bn254_batch_syscall::{
    alt_bn128_g1_msm, alt_bn128_pairing_check, PodG1G2Pair, PodG1Point, PodPairingResult, PodScalar,
    Version, G1_BYTES, PAIR_BYTES, SCALAR_BYTES,
};
use solana_program_runtime::{
    invoke_context::InvokeContext,
    solana_sbpf::{
        declare_builtin_function,
        memory_region::{AccessType, MemoryMapping},
    },
};

// ---------------------------------------------------------------------------
// The fitted B5 schedule.
//
// Mirrors `program-runtime/src/execution_budget.rs` in this worktree, which the
// harness cannot link because LiteSVM already links `solana-program-runtime`
// from crates.io. `b5_schedule_matches_the_worktree` reads that file back, so a
// drift there fails the test rather than silently repricing a measurement.
// ---------------------------------------------------------------------------

pub const B5_MSM_BASE_CU: u64 = 583;
pub const B5_MSM_PER_POINT_CU: u64 = 364;
pub const B5_PAIRING_BASE_CU: u64 = 6_105;
pub const B5_PAIRING_PER_PAIR_CU: u64 = 4_350;
pub const B5_PAIRING_LANE_BASE_CU: u64 = 4_655;
pub const B5_PAIRING_LANE_CU: u64 = 22_505;
pub const B5_PAIRING_LANE_REM_CU: u64 = 5_865;
pub const PAIRING_LANE_WIDTH: u64 = 8;

/// Stock prices for the ops the B5 schedule does not restate.
pub const STOCK_G1_ADD_CU: u64 = 334;
pub const SHA256_BASE_CU: u64 = 85;
pub const SHA256_BYTE_CU: u64 = 1;
pub const MEM_OP_BASE_CU: u64 = 10;

pub fn b5_msm_cu(points: u64) -> u64 {
    // The B5 MSM is linear over the measured range, so the bucketed discount
    // the B1 Pippenger schedule carried is absent here by design.
    B5_MSM_BASE_CU.saturating_add(B5_MSM_PER_POINT_CU.saturating_mul(points))
}

pub fn b5_pairing_cu(pairs: u64) -> u64 {
    let lanes = pairs.saturating_div(PAIRING_LANE_WIDTH);
    let remainder = pairs.saturating_sub(lanes.saturating_mul(PAIRING_LANE_WIDTH));
    if lanes == 0 {
        B5_PAIRING_BASE_CU.saturating_add(B5_PAIRING_PER_PAIR_CU.saturating_mul(remainder))
    } else {
        B5_PAIRING_LANE_BASE_CU
            .saturating_add(B5_PAIRING_LANE_CU.saturating_mul(lanes))
            .saturating_add(B5_PAIRING_LANE_REM_CU.saturating_mul(remainder))
    }
}

/// Agave 4.1 stock schedule, for the side the B5 run is compared against.
pub fn stock_group_op_cu(op: u64, input_size: u64) -> u64 {
    const LE_FLAG: u64 = 0x80;
    match op & !LE_FLAG {
        0 | 1 => 334,
        2 => 3_840,
        3 => {
            let pairs = input_size / PAIR_BYTES as u64;
            36_364 + 12_121 * pairs.saturating_sub(1) + SHA256_BASE_CU + input_size + 32
        }
        4 | 5 => 535,
        6 => 15_670,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Observation counters. One process runs one configuration, and the driver
// resets them immediately before the transaction under measurement.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct Observed {
    pub pairing_cu: u64,
    pub hash_calls: u64,
    pub hash_slices: u64,
    pub hash_cu: u64,
}

static PAIRING_CALLS: AtomicU64 = AtomicU64::new(0);
static PAIRING_PAIRS: AtomicU64 = AtomicU64::new(0);
static PAIRING_CU: AtomicU64 = AtomicU64::new(0);
static OTHER_CALLS: AtomicU64 = AtomicU64::new(0);
static OTHER_CU: AtomicU64 = AtomicU64::new(0);
static HASH_CALLS: AtomicU64 = AtomicU64::new(0);
static HASH_SLICES: AtomicU64 = AtomicU64::new(0);
static HASH_CU: AtomicU64 = AtomicU64::new(0);

const COUNTERS: [&AtomicU64; 8] = [
    &PAIRING_CALLS,
    &PAIRING_PAIRS,
    &PAIRING_CU,
    &OTHER_CALLS,
    &OTHER_CU,
    &HASH_CALLS,
    &HASH_SLICES,
    &HASH_CU,
];

pub fn reset_observations() {
    for counter in COUNTERS {
        counter.store(0, Ordering::Relaxed);
    }
}

pub fn observations() -> Observed {
    Observed {
        pairing_cu: PAIRING_CU.load(Ordering::Relaxed),
        hash_calls: HASH_CALLS.load(Ordering::Relaxed),
        hash_slices: HASH_SLICES.load(Ordering::Relaxed),
        hash_cu: HASH_CU.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// Memory helpers.
// ---------------------------------------------------------------------------

type SyscallResult = Result<u64, Box<dyn std::error::Error>>;

fn load<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a [u8], Box<dyn std::error::Error>> {
    let host: u64 = Result::from(memory_mapping.map(AccessType::Load, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts(host as *const u8, len as usize) })
}

#[allow(clippy::mut_from_ref)]
fn store<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a mut [u8], Box<dyn std::error::Error>> {
    let host: u64 = Result::from(memory_mapping.map(AccessType::Store, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts_mut(host as *mut u8, len as usize) })
}

fn one_scalar() -> PodScalar {
    let mut bytes = [0u8; SCALAR_BYTES];
    bytes[SCALAR_BYTES - 1] = 1;
    PodScalar(bytes)
}

// ---------------------------------------------------------------------------
// The measured shim.
// ---------------------------------------------------------------------------

declare_builtin_function!(
    /// `sol_alt_bn128_group_op` served by the B5 kernel and charged the fitted
    /// B5 schedule.
    ///
    /// Only the three big-endian ops a Groth16 verifier issues are served, and
    /// an unexpected op fails the run rather than falling back to a stock price
    /// that would be invisible in the total. A G1 addition keeps its stock
    /// charge: the B5 schedule prices an MSM and a pairing check, and states no
    /// tariff for a bare addition.
    B5GroupOp,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        group_op: u64,
        input_addr: u64,
        input_size: u64,
        result_addr: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        const G1_ADD_BE: u64 = 0;
        const G1_MUL_BE: u64 = 2;
        const PAIRING_BE: u64 = 3;

        match group_op {
            PAIRING_BE => {
                let pairs = input_size / PAIR_BYTES as u64;
                let cost = b5_pairing_cu(pairs);
                invoke_context.compute_meter.consume_checked(cost)?;
                PAIRING_CALLS.fetch_add(1, Ordering::Relaxed);
                PAIRING_PAIRS.fetch_add(pairs, Ordering::Relaxed);
                PAIRING_CU.fetch_add(cost, Ordering::Relaxed);

                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                let input = load(memory_mapping, input_addr, input_size)?.to_vec();
                let pairs: &[PodG1G2Pair] = try_cast_slice(&input)
                    .map_err(|error| format!("pair cast failed: {error}"))?;
                let verdict = alt_bn128_pairing_check(Version::V0, pairs)
                    .map_err(|error| format!("b5 pairing check: {error:?}"))?;
                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                store(memory_mapping, result_addr, 32)?
                    .copy_from_slice(&PodPairingResult::from_verdict(verdict).0);
                Ok(0)
            }
            G1_MUL_BE => {
                let cost = b5_msm_cu(1);
                invoke_context.compute_meter.consume_checked(cost)?;
                OTHER_CALLS.fetch_add(1, Ordering::Relaxed);
                OTHER_CU.fetch_add(cost, Ordering::Relaxed);

                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                let input = load(memory_mapping, input_addr, input_size)?.to_vec();
                let (point, scalar) = input.split_at(G1_BYTES);
                let point = PodG1Point(point.try_into().map_err(|_| "g1 mul point width")?);
                let scalar = PodScalar(scalar.try_into().map_err(|_| "g1 mul scalar width")?);
                let result = alt_bn128_g1_msm(Version::V0, &[point], &[scalar])
                    .map_err(|error| format!("b5 g1 mul: {error:?}"))?;
                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                store(memory_mapping, result_addr, G1_BYTES as u64)?.copy_from_slice(&result.0);
                Ok(0)
            }
            G1_ADD_BE => {
                invoke_context.compute_meter.consume_checked(STOCK_G1_ADD_CU)?;
                OTHER_CALLS.fetch_add(1, Ordering::Relaxed);
                OTHER_CU.fetch_add(STOCK_G1_ADD_CU, Ordering::Relaxed);

                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                let input = load(memory_mapping, input_addr, input_size)?.to_vec();
                let (left, right) = input.split_at(G1_BYTES);
                let points = [
                    PodG1Point(left.try_into().map_err(|_| "g1 add left width")?),
                    PodG1Point(right.try_into().map_err(|_| "g1 add right width")?),
                ];
                let result = alt_bn128_g1_msm(Version::V0, &points, &[one_scalar(); 2])
                    .map_err(|error| format!("b5 g1 add: {error:?}"))?;
                let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
                store(memory_mapping, result_addr, G1_BYTES as u64)?.copy_from_slice(&result.0);
                Ok(0)
            }
            other => Err(format!("group op {other} has no B5 mapping").into()),
        }
    }
);

// ---------------------------------------------------------------------------
// Price-neutral hash observers.
// ---------------------------------------------------------------------------

/// Charge and hash one `SyscallHash` call, reproducing the runtime's schedule.
///
/// The per-slice term is `max(mem_op_base_cost, byte_cost * len / 2)`, and the
/// integer division is the runtime's, not a rounding choice made here. Getting
/// this wrong shows up as the stock configuration failing to reproduce the
/// published total, which is why the driver runs an unshimmed control.
fn hash_syscall<H: sha2::Digest>(
    invoke_context: &mut InvokeContext<'_, '_>,
    vals_addr: u64,
    vals_len: u64,
    result_addr: u64,
) -> SyscallResult {
    invoke_context
        .compute_meter
        .consume_checked(SHA256_BASE_CU)?;
    HASH_CALLS.fetch_add(1, Ordering::Relaxed);
    HASH_CU.fetch_add(SHA256_BASE_CU, Ordering::Relaxed);

    let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
    let descriptors = load(memory_mapping, vals_addr, vals_len.saturating_mul(16))?.to_vec();
    let mut hasher = H::new();
    for descriptor in descriptors.chunks_exact(16) {
        let ptr = u64::from_le_bytes(descriptor[..8].try_into().expect("8 bytes"));
        let len = u64::from_le_bytes(descriptor[8..].try_into().expect("8 bytes"));
        let cost = MEM_OP_BASE_CU.max(SHA256_BYTE_CU.saturating_mul(len / 2));
        let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
        let bytes = load(memory_mapping, ptr, len)?.to_vec();
        invoke_context.compute_meter.consume_checked(cost)?;
        HASH_SLICES.fetch_add(1, Ordering::Relaxed);
        HASH_CU.fetch_add(cost, Ordering::Relaxed);
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    let memory_mapping = invoke_context.memory_contexts.memory_mapping_mut()?;
    store(memory_mapping, result_addr, digest.len() as u64)?.copy_from_slice(&digest);
    Ok(0)
}

declare_builtin_function!(
    ObservedSha256,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        hash_syscall::<sha2::Sha256>(invoke_context, vals_addr, vals_len, result_addr)
    }
);

declare_builtin_function!(
    ObservedKeccak256,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        hash_syscall::<sha3::Keccak256>(invoke_context, vals_addr, vals_len, result_addr)
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    const BUDGET: &str = include_str!("../../program-runtime/src/execution_budget.rs");

    fn fitted(field: &str) -> u64 {
        let needle = format!("{field}: ");
        let line = BUDGET
            .lines()
            .find(|line| line.trim_start().starts_with(&needle))
            .unwrap_or_else(|| panic!("{field} is absent from execution_budget.rs"));
        line.trim()
            .trim_start_matches(&needle)
            .trim_end_matches(',')
            .replace('_', "")
            .parse()
            .expect("a decimal constant")
    }

    /// A constant copied here that drifts in the worktree would reprice every
    /// B5 figure with nothing to show for it.
    #[test]
    fn b5_schedule_matches_the_worktree() {
        assert_eq!(fitted("alt_bn128_g1_msm_base_cost"), B5_MSM_BASE_CU);
        assert_eq!(fitted("alt_bn128_g1_msm_per_point_cost"), B5_MSM_PER_POINT_CU);
        assert_eq!(fitted("alt_bn128_pairing_check_base_cost"), B5_PAIRING_BASE_CU);
        assert_eq!(
            fitted("alt_bn128_pairing_check_per_pair_cost"),
            B5_PAIRING_PER_PAIR_CU
        );
        assert_eq!(
            fitted("alt_bn128_pairing_check_lane_base_cost"),
            B5_PAIRING_LANE_BASE_CU
        );
        assert_eq!(fitted("alt_bn128_pairing_check_lane_cost"), B5_PAIRING_LANE_CU);
        assert_eq!(
            fitted("alt_bn128_pairing_check_lane_rem_cost"),
            B5_PAIRING_LANE_REM_CU
        );
        assert_eq!(fitted("alt_bn128_g1_addition_cost"), STOCK_G1_ADD_CU);
        assert_eq!(fitted("sha256_base_cost"), SHA256_BASE_CU);
        assert_eq!(fitted("sha256_byte_cost"), SHA256_BYTE_CU);
        assert_eq!(fitted("mem_op_base_cost"), MEM_OP_BASE_CU);
    }

    /// The shapes this campaign measures never fill a lane, and the two regimes
    /// meet where they should.
    #[test]
    fn pairing_regimes_agree_at_the_lane_boundary() {
        assert_eq!(b5_pairing_cu(2), 6_105 + 8_700);
        assert_eq!(b5_pairing_cu(4), 6_105 + 17_400);
        assert_eq!(b5_pairing_cu(8), 4_655 + 22_505);
        assert_eq!(b5_msm_cu(1), 947);
    }
}
