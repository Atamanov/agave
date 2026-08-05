//! Pins the BN254 charge schedule against the measurements it was fitted to.
//!
//! The decision table is a pure tariff: given a syscall shape, the charge is
//! deterministic on any host. These tests are the contract that makes the table
//! reproducible, so a schedule edit that breaks them must restate the evidence.

use solana_program_runtime::execution_budget::SVMTransactionExecutionCost;

/// Ryzen 9 9900X, `ceil(max of two process mean CI95 upper bounds / 33)`.
/// Source: research/bn254-decision-table-v2-20260804/B5-CHARGE-SCHEDULE.md
const MEASURED_PAIRING: &[(u64, u64)] = &[
    (1, 10_454),
    (2, 14_795),
    (3, 19_148),
    (4, 23_473),
    (6, 32_205),
    (7, 36_537),
    (8, 27_159),
    (9, 33_025),
    (12, 50_617),
    (16, 49_664),
];

const MEASURED_MSM: &[(u64, u64)] = &[
    (1, 929),
    (2, 1_311),
    (3, 1_653),
    (4, 2_019),
    (5, 2_387),
    (6, 2_750),
    (7, 3_109),
    (8, 3_470),
    (9, 3_806),
    (10, 4_162),
    (16, 6_295),
    (32, 12_057),
    (36, 13_451),
    (54, 19_850),
];

const MEASURED_GT_MULTIEXP: &[(u64, u64)] = &[(1, 5_663), (2, 7_830), (3, 9_961), (4, 12_084)];

const MEASURED_FR_LINCOMB: &[(u64, u64)] = &[
    (1, 2),
    (16, 10),
    (64, 37),
    (256, 154),
    (1024, 636),
    (2048, 1_268),
];

const MEASURED_FR_BATCH_INVERT: &[(u64, u64)] = &[
    (1, 16),
    (16, 41),
    (64, 123),
    (256, 445),
    (1024, 1_731),
    (2048, 3_446),
];

/// Public inputs held at one, which is what every zolana verifying key declares.
const MEASURED_PLONK_REDUCE: &[(u64, u64)] = &[
    (1, 195),
    (2, 257),
    (4, 381),
    (5, 442),
    (8, 626),
    (16, 1_178),
    (32, 2_301),
];

fn pairing_charge(cost: &SVMTransactionExecutionCost, pairs: u64) -> u64 {
    cost.alt_bn128_pairing_cost(pairs, 0)
}

fn msm_charge(cost: &SVMTransactionExecutionCost, points: u64) -> u64 {
    cost.alt_bn128_g1_msm_base_cost + cost.alt_bn128_g1_msm_per_point_cost * points
}

fn brackets(label: &str, measured: &[(u64, u64)], bound_per_mille: u64, charge: impl Fn(u64) -> u64) {
    for &(shape, measured) in measured {
        let charged = charge(shape);
        assert!(
            charged >= measured,
            "{label} {shape}: charged {charged} is below the measured {measured}"
        );
        assert!(
            charged * 1_000 <= measured * bound_per_mille,
            "{label} {shape}: charged {charged} exceeds the measured {measured} \
             by more than {}%",
            (bound_per_mille - 1_000) as f64 / 10.0
        );
    }
}

#[test]
fn pairing_schedule_brackets_every_measured_shape() {
    let cost = SVMTransactionExecutionCost::default();
    brackets("pairs", MEASURED_PAIRING, 1_005, |n| pairing_charge(&cost, n));
}

/// Eight pairs cost less than six because the 8-wide IFMA kernel takes any
/// group of eight. A schedule linear in pair count cannot express this, and
/// would misprice every batch shape.
#[test]
fn a_full_lane_is_cheaper_than_a_shorter_scalar_run() {
    let cost = SVMTransactionExecutionCost::default();
    assert!(pairing_charge(&cost, 8) < pairing_charge(&cost, 7));
    assert!(pairing_charge(&cost, 16) < pairing_charge(&cost, 15));
}

/// A pair left over after a full lane costs more than a pair in a call that
/// never filled one. Collapsing the two regimes into one per-pair term is what
/// the old single-regime fit did, and it overcharged the sub-lane shapes by a
/// quarter.
#[test]
fn the_two_pairing_regimes_are_priced_apart() {
    let cost = SVMTransactionExecutionCost::default();
    assert!(
        cost.alt_bn128_pairing_check_lane_rem_cost > cost.alt_bn128_pairing_check_per_pair_cost
    );
    assert!(cost.alt_bn128_pairing_check_lane_base_cost < cost.alt_bn128_pairing_check_base_cost);
}

#[test]
fn msm_schedule_brackets_every_measured_point() {
    let cost = SVMTransactionExecutionCost::default();
    brackets("points", MEASURED_MSM, 1_020, |n| msm_charge(&cost, n));
}

/// The B5 MSM is linear over the measured range. A bucketed discount belongs to
/// B1 Pippenger and would undercharge here.
#[test]
fn msm_schedule_is_linear() {
    let cost = SVMTransactionExecutionCost::default();
    let step = msm_charge(&cost, 2) - msm_charge(&cost, 1);
    for points in 2..64 {
        assert_eq!(
            msm_charge(&cost, points + 1) - msm_charge(&cost, points),
            step
        );
    }
}

#[test]
fn gt_multiexp_schedule_brackets_every_measured_target_count() {
    let cost = SVMTransactionExecutionCost::default();
    brackets("targets", MEASURED_GT_MULTIEXP, 1_005, |t| {
        cost.alt_bn128_gt_multiexp_base_cost + cost.alt_bn128_gt_multiexp_per_target_cost * t
    });
}

/// Integer CU granularity, not the fit, sets the floor on these two: a term
/// costs well under one CU, so the schedule cannot track the curve closely.
#[test]
fn scalar_field_schedules_bracket_every_measured_length() {
    let cost = SVMTransactionExecutionCost::default();
    brackets("lincomb terms", MEASURED_FR_LINCOMB, 1_760, |n| {
        cost.alt_bn128_fr_lincomb_base_cost + cost.alt_bn128_fr_lincomb_per_term_cost * n
    });
    brackets("invert terms", MEASURED_FR_BATCH_INVERT, 1_195, |n| {
        cost.alt_bn128_fr_batch_invert_base_cost + cost.alt_bn128_fr_batch_invert_per_term_cost * n
    });
}

#[test]
fn plonk_reduce_schedule_brackets_every_measured_proof_count() {
    let cost = SVMTransactionExecutionCost::default();
    brackets("proofs", MEASURED_PLONK_REDUCE, 1_075, |n| {
        cost.alt_bn128_plonk_batch_reduce_base_cost
            + cost.alt_bn128_plonk_batch_reduce_per_proof_cost * n
            + cost.alt_bn128_plonk_batch_reduce_per_lagrange_cost * n
    });
}

/// Registering a verifying key is worth paying for only if verifying against it
/// is cheaper than verifying with full pairs. The saving is the subgroup check
/// the registry authenticated once, and it must scale with registered pairs.
#[test]
fn a_registered_pair_is_cheaper_than_a_full_pair() {
    let cost = SVMTransactionExecutionCost::default();
    for total in 1..24u64 {
        let full_only = cost.alt_bn128_pairing_cost(total, 0);
        for registered in 1..=total {
            let mixed = cost.alt_bn128_pairing_cost(total - registered, registered);
            assert!(
                mixed < full_only,
                "{total} pairs with {registered} registered: {mixed} is not below {full_only}"
            );
            assert_eq!(
                full_only - mixed,
                cost.alt_bn128_g2_subgroup_check_cost * registered
            );
        }
    }
}

/// UNMEASURED against the kernel this schedule prices. The capture times
/// arkworks' subgroup check standalone, which is not the code a pairing runs, so
/// crediting that number would undercharge every registered pair. The value is
/// held at the prior schedule's until a full-versus-registered differential at a
/// fixed pair count lands.
///
/// This test exists to fail when that differential lands. Delete it in the same
/// change.
#[test]
fn unmeasured_g2_subgroup_credit() {
    let cost = SVMTransactionExecutionCost::default();
    assert_eq!(cost.alt_bn128_g2_subgroup_check_cost, 1_612);
}
