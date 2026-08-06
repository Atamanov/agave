//! Research-only syscall-boundary observations compatible with the campaign
//! RawEvent adapter. Shapes are ordered and bounded; overflow is a hard error.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const NONE: u64 = u64::MAX;
const MAX_EVENTS: usize = 64;

macro_rules! event_storage {
    ($count:ident, $overflow:ident, $($events:ident),+ $(,)?) => {
        static $count: AtomicU64 = AtomicU64::new(0);
        static $overflow: AtomicBool = AtomicBool::new(false);
        $(
            static $events: [AtomicU64; MAX_EVENTS] =
                [const { AtomicU64::new(NONE) }; MAX_EVENTS];
        )+
    };
}

event_storage!(MSM_CALLS, MSM_OVERFLOW, MSM_POINTS);
event_storage!(
    PAIRING_CHECK_CALLS,
    PAIRING_CHECK_OVERFLOW,
    PAIRING_CHECK_PAIRS,
    PAIRING_CHECK_NONIDENTITY,
);
event_storage!(
    PAIRING_MAP_CALLS,
    PAIRING_MAP_OVERFLOW,
    PAIRING_MAP_PAIRS,
    PAIRING_MAP_NONIDENTITY,
);
event_storage!(
    REGISTERED_CALLS,
    REGISTERED_OVERFLOW,
    REGISTERED_FULL,
    REGISTERED_IDS,
    REGISTERED_NONIDENTITY,
);
event_storage!(GT_CALLS, GT_OVERFLOW, GT_TARGETS, GT_NONTRIVIAL,);
event_storage!(FR_LINCOMB_CALLS, FR_LINCOMB_OVERFLOW, FR_LINCOMB_TERMS);
event_storage!(
    PLONK_REDUCE_CALLS,
    PLONK_REDUCE_OVERFLOW,
    PLONK_REDUCE_CONTEXTS,
    PLONK_REDUCE_PROOFS,
    PLONK_REDUCE_PUBLICS,
);

static REGISTRY_INIT_G2: AtomicU64 = AtomicU64::new(0);
static REGISTRY_INIT_GT: AtomicU64 = AtomicU64::new(0);
static REGISTRY_G2_SUBGROUP_PREPARES: AtomicU64 = AtomicU64::new(0);
static REGISTRY_G2_LINE_PREPARES: AtomicU64 = AtomicU64::new(0);
static SUBGROUP_PROBES: AtomicU64 = AtomicU64::new(0);
static FINAL_EXP_PROBES: AtomicU64 = AtomicU64::new(0);
static IFMA_BATCH8_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static IFMA_MIXED_BATCH8_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static LEGACY_G1_MUL: AtomicU64 = AtomicU64::new(0);
static LEGACY_G1_ADD: AtomicU64 = AtomicU64::new(0);

pub fn reset() {
    reset_stream(&MSM_CALLS, &MSM_OVERFLOW, &[&MSM_POINTS]);
    reset_stream(
        &PAIRING_CHECK_CALLS,
        &PAIRING_CHECK_OVERFLOW,
        &[&PAIRING_CHECK_PAIRS, &PAIRING_CHECK_NONIDENTITY],
    );
    reset_stream(
        &PAIRING_MAP_CALLS,
        &PAIRING_MAP_OVERFLOW,
        &[&PAIRING_MAP_PAIRS, &PAIRING_MAP_NONIDENTITY],
    );
    reset_stream(
        &REGISTERED_CALLS,
        &REGISTERED_OVERFLOW,
        &[&REGISTERED_FULL, &REGISTERED_IDS, &REGISTERED_NONIDENTITY],
    );
    reset_stream(&GT_CALLS, &GT_OVERFLOW, &[&GT_TARGETS, &GT_NONTRIVIAL]);
    reset_stream(
        &FR_LINCOMB_CALLS,
        &FR_LINCOMB_OVERFLOW,
        &[&FR_LINCOMB_TERMS],
    );
    reset_stream(
        &PLONK_REDUCE_CALLS,
        &PLONK_REDUCE_OVERFLOW,
        &[
            &PLONK_REDUCE_CONTEXTS,
            &PLONK_REDUCE_PROOFS,
            &PLONK_REDUCE_PUBLICS,
        ],
    );
    REGISTRY_INIT_G2.store(0, Ordering::SeqCst);
    REGISTRY_INIT_GT.store(0, Ordering::SeqCst);
    REGISTRY_G2_SUBGROUP_PREPARES.store(0, Ordering::SeqCst);
    REGISTRY_G2_LINE_PREPARES.store(0, Ordering::SeqCst);
    SUBGROUP_PROBES.store(0, Ordering::SeqCst);
    FINAL_EXP_PROBES.store(0, Ordering::SeqCst);
    IFMA_BATCH8_DISPATCHES.store(0, Ordering::SeqCst);
    IFMA_MIXED_BATCH8_DISPATCHES.store(0, Ordering::SeqCst);
    LEGACY_G1_MUL.store(0, Ordering::SeqCst);
    LEGACY_G1_ADD.store(0, Ordering::SeqCst);
}

fn reset_stream(count: &AtomicU64, overflow: &AtomicBool, streams: &[&[AtomicU64; MAX_EVENTS]]) {
    count.store(0, Ordering::SeqCst);
    overflow.store(false, Ordering::SeqCst);
    for stream in streams {
        for event in *stream {
            event.store(NONE, Ordering::SeqCst);
        }
    }
}

fn event_count(count: &AtomicU64, overflow: &AtomicBool, name: &str) -> usize {
    assert!(!overflow.load(Ordering::SeqCst), "{name} observer overflow");
    let count = count.load(Ordering::SeqCst) as usize;
    assert!(count <= MAX_EVENTS, "{name} observer overflow");
    count
}

fn read_stream2(
    count: &AtomicU64,
    overflow: &AtomicBool,
    first: &[AtomicU64; MAX_EVENTS],
    second: &[AtomicU64; MAX_EVENTS],
    name: &str,
) -> Vec<(u64, u64)> {
    (0..event_count(count, overflow, name))
        .map(|index| {
            let a = first[index].load(Ordering::SeqCst);
            let b = second[index].load(Ordering::SeqCst);
            assert!(a != NONE && b != NONE, "missing {name} observer event");
            (a, b)
        })
        .collect()
}

pub fn observed_g1_msm_point_count_list() -> Vec<u64> {
    (0..event_count(&MSM_CALLS, &MSM_OVERFLOW, "G1 MSM"))
        .map(|index| {
            let value = MSM_POINTS[index].load(Ordering::SeqCst);
            assert_ne!(value, NONE, "missing G1 MSM observer event");
            value
        })
        .collect()
}

pub fn observed_pairing_check_shapes() -> Vec<(u64, u64)> {
    read_stream2(
        &PAIRING_CHECK_CALLS,
        &PAIRING_CHECK_OVERFLOW,
        &PAIRING_CHECK_PAIRS,
        &PAIRING_CHECK_NONIDENTITY,
        "pairing check",
    )
}

pub fn observed_pairing_check_shape() -> Option<(u64, u64)> {
    observed_pairing_check_shapes().last().copied()
}

pub fn observed_pairing_map_shapes() -> Vec<(u64, u64)> {
    read_stream2(
        &PAIRING_MAP_CALLS,
        &PAIRING_MAP_OVERFLOW,
        &PAIRING_MAP_PAIRS,
        &PAIRING_MAP_NONIDENTITY,
        "pairing map",
    )
}

pub fn observed_pairing_map_shape() -> Option<(u64, u64)> {
    observed_pairing_map_shapes().last().copied()
}

pub fn observed_registered_pairing_shapes() -> Vec<(u64, u64, u64)> {
    (0..event_count(
        &REGISTERED_CALLS,
        &REGISTERED_OVERFLOW,
        "registered pairing",
    ))
        .map(|index| {
            let full = REGISTERED_FULL[index].load(Ordering::SeqCst);
            let registered = REGISTERED_IDS[index].load(Ordering::SeqCst);
            let nonidentity = REGISTERED_NONIDENTITY[index].load(Ordering::SeqCst);
            assert!(
                full != NONE && registered != NONE && nonidentity != NONE,
                "missing registered pairing observer event"
            );
            (full, registered, nonidentity)
        })
        .collect()
}

pub fn observed_registered_pairing_shape() -> Option<(u64, u64, u64)> {
    observed_registered_pairing_shapes().last().copied()
}

pub fn observed_registry_init_shape() -> (u64, u64) {
    (
        REGISTRY_INIT_G2.load(Ordering::SeqCst),
        REGISTRY_INIT_GT.load(Ordering::SeqCst),
    )
}

/// Actual registered-G2 validation and line-schedule preparations.
pub fn observed_registry_g2_preparation_calls() -> (u64, u64) {
    (
        REGISTRY_G2_SUBGROUP_PREPARES.load(Ordering::SeqCst),
        REGISTRY_G2_LINE_PREPARES.load(Ordering::SeqCst),
    )
}

pub fn observed_gt_multiexp_shapes() -> Vec<(u64, u64)> {
    read_stream2(
        &GT_CALLS,
        &GT_OVERFLOW,
        &GT_TARGETS,
        &GT_NONTRIVIAL,
        "GT multiexp",
    )
}

pub fn observed_gt_multiexp_shape() -> Option<(u64, u64)> {
    observed_gt_multiexp_shapes().last().copied()
}

/// Shapes of every atomic multi-VK PLONK reduction, as (contexts, proofs, publics).
pub fn observed_snarkjs_plonk_multi_vk_shapes() -> Vec<(u64, u64, u64)> {
    (0..event_count(
        &PLONK_REDUCE_CALLS,
        &PLONK_REDUCE_OVERFLOW,
        "PLONK multi-VK reduce",
    ))
        .map(|index| {
            (
                PLONK_REDUCE_CONTEXTS[index].load(Ordering::SeqCst),
                PLONK_REDUCE_PROOFS[index].load(Ordering::SeqCst),
                PLONK_REDUCE_PUBLICS[index].load(Ordering::SeqCst),
            )
        })
        .collect()
}

pub fn observed_fr_lincomb_term_counts() -> Vec<u64> {
    (0..event_count(&FR_LINCOMB_CALLS, &FR_LINCOMB_OVERFLOW, "Fr lincomb"))
        .map(|index| {
            let value = FR_LINCOMB_TERMS[index].load(Ordering::SeqCst);
            assert_ne!(value, NONE, "missing Fr lincomb observer event");
            value
        })
        .collect()
}

pub fn observed_standalone_probe_calls() -> (u64, u64) {
    (
        SUBGROUP_PROBES.load(Ordering::SeqCst),
        FINAL_EXP_PROBES.load(Ordering::SeqCst),
    )
}

/// Number of successful pairing calls whose validated nonidentity shape
/// selected the linked Helius AVX-512 IFMA batch8 path.
pub fn observed_ifma_batch8_dispatches() -> u64 {
    IFMA_BATCH8_DISPATCHES.load(Ordering::SeqCst)
}

/// Successful authenticated mixed-pairing calls that selected batch8.
pub fn observed_ifma_mixed_batch8_dispatches() -> u64 {
    IFMA_MIXED_BATCH8_DISPATCHES.load(Ordering::SeqCst)
}

pub fn observed_legacy_group_ops() -> (u64, u64) {
    (
        LEGACY_G1_MUL.load(Ordering::SeqCst),
        LEGACY_G1_ADD.load(Ordering::SeqCst),
    )
}

fn reserve(count: &AtomicU64, overflow: &AtomicBool) -> Option<usize> {
    let index = count.fetch_add(1, Ordering::SeqCst) as usize;
    if index < MAX_EVENTS {
        Some(index)
    } else {
        overflow.store(true, Ordering::SeqCst);
        None
    }
}

pub(crate) fn record_msm(points: usize) {
    if let Some(index) = reserve(&MSM_CALLS, &MSM_OVERFLOW) {
        MSM_POINTS[index].store(points as u64, Ordering::SeqCst);
    }
}

// Hash syscalls are deliberately absent here. This observer sees only calls the
// guest makes into this crate; `sol_keccak256` and `sol_sha256` go straight to
// the runtime, so they are observed from the VM register trace instead.

pub(crate) fn record_fr_lincomb(terms: usize) {
    if let Some(index) = reserve(&FR_LINCOMB_CALLS, &FR_LINCOMB_OVERFLOW) {
        FR_LINCOMB_TERMS[index].store(terms as u64, Ordering::SeqCst);
    }
}

pub(crate) fn record_snarkjs_plonk_multi_vk_reduce(contexts: usize, proofs: usize, publics: usize) {
    if let Some(index) = reserve(&PLONK_REDUCE_CALLS, &PLONK_REDUCE_OVERFLOW) {
        PLONK_REDUCE_CONTEXTS[index].store(contexts as u64, Ordering::SeqCst);
        PLONK_REDUCE_PROOFS[index].store(proofs as u64, Ordering::SeqCst);
        PLONK_REDUCE_PUBLICS[index].store(publics as u64, Ordering::SeqCst);
    }
}

pub(crate) fn record_pairing_check(pairs: usize, nonidentity: usize) {
    if let Some(index) = reserve(&PAIRING_CHECK_CALLS, &PAIRING_CHECK_OVERFLOW) {
        PAIRING_CHECK_PAIRS[index].store(pairs as u64, Ordering::SeqCst);
        PAIRING_CHECK_NONIDENTITY[index].store(nonidentity as u64, Ordering::SeqCst);
    }
}

pub(crate) fn record_pairing_map(pairs: usize, nonidentity: usize) {
    if let Some(index) = reserve(&PAIRING_MAP_CALLS, &PAIRING_MAP_OVERFLOW) {
        PAIRING_MAP_PAIRS[index].store(pairs as u64, Ordering::SeqCst);
        PAIRING_MAP_NONIDENTITY[index].store(nonidentity as u64, Ordering::SeqCst);
    }
}

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) fn record_registered(full: usize, registered: usize, nonidentity: usize) {
    if let Some(index) = reserve(&REGISTERED_CALLS, &REGISTERED_OVERFLOW) {
        REGISTERED_FULL[index].store(full as u64, Ordering::SeqCst);
        REGISTERED_IDS[index].store(registered as u64, Ordering::SeqCst);
        REGISTERED_NONIDENTITY[index].store(nonidentity as u64, Ordering::SeqCst);
    }
}

pub fn record_registry_init(g2: usize, gt: usize) {
    REGISTRY_INIT_G2.fetch_add(g2 as u64, Ordering::SeqCst);
    REGISTRY_INIT_GT.fetch_add(gt as u64, Ordering::SeqCst);
}

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) fn record_registry_g2_preparation() {
    REGISTRY_G2_SUBGROUP_PREPARES.fetch_add(1, Ordering::SeqCst);
    REGISTRY_G2_LINE_PREPARES.fetch_add(1, Ordering::SeqCst);
}

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) fn record_gt_multiexp(exponents: &[crate::PodScalar]) {
    if let Some(index) = reserve(&GT_CALLS, &GT_OVERFLOW) {
        let mut one = [0u8; 32];
        one[31] = 1;
        GT_TARGETS[index].store(exponents.len() as u64, Ordering::SeqCst);
        GT_NONTRIVIAL[index].store(
            exponents
                .iter()
                .filter(|exponent| exponent.0 != [0u8; 32] && exponent.0 != one)
                .count() as u64,
            Ordering::SeqCst,
        );
    }
}

pub(crate) fn record_subgroup_probe() {
    SUBGROUP_PROBES.fetch_add(1, Ordering::SeqCst);
}

pub(crate) fn record_final_exp_probe() {
    FINAL_EXP_PROBES.fetch_add(1, Ordering::SeqCst);
}

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) fn record_ifma_batch8_dispatch() {
    IFMA_BATCH8_DISPATCHES.fetch_add(1, Ordering::SeqCst);
}

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) fn record_ifma_mixed_batch8_dispatch() {
    IFMA_MIXED_BATCH8_DISPATCHES.fetch_add(1, Ordering::SeqCst);
}

pub fn record_legacy_group_ops(g1_mul: usize, g1_add: usize) {
    LEGACY_G1_MUL.fetch_add(g1_mul as u64, Ordering::SeqCst);
    LEGACY_G1_ADD.fetch_add(g1_add as u64, Ordering::SeqCst);
}

pub(crate) fn nonidentity_pairs(pairs: &[crate::PodG1G2Pair]) -> usize {
    pairs
        .iter()
        .filter(|pair| {
            pair.g1.0.iter().any(|byte| *byte != 0) && pair.g2.0.iter().any(|byte| *byte != 0)
        })
        .count()
}
