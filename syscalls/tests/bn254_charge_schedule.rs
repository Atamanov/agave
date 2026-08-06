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

/// Registered-versus-full at a fixed pair count, same host and same selection
/// rule. `(full, registered, measured)`.
const MEASURED_REGISTERED: &[(u64, u64, u64)] = &[
    (1, 2, 13_154),
    (1, 3, 14_766),
    (0, 3, 10_696),
    (5, 3, 23_426),
    (2, 6, 20_166),
    (0, 8, 18_020),
    (8, 8, 39_646),
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

fn brackets(
    label: &str,
    measured: &[(u64, u64)],
    bound_per_mille: u64,
    charge: impl Fn(u64) -> u64,
) {
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
    brackets("pairs", MEASURED_PAIRING, 1_005, |n| {
        pairing_charge(&cost, n)
    });
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

#[test]
fn registered_pairing_schedule_brackets_every_measured_split() {
    let cost = SVMTransactionExecutionCost::default();
    for &(full, registered, measured) in MEASURED_REGISTERED {
        let charged = cost.alt_bn128_pairing_cost(full, registered);
        assert!(
            charged >= measured,
            "{full}+{registered}: charged {charged} is below the measured {measured}"
        );
        assert!(
            charged * 1_000 <= measured * 1_070,
            "{full}+{registered}: charged {charged} exceeds the measured {measured}              by more than 7%"
        );
    }
}

/// Registering a verifying key is worth paying for only if verifying against it
/// is cheaper than verifying with full pairs, and the saving must scale with
/// registered pairs at a fixed total.
#[test]
fn a_registered_pair_is_cheaper_than_a_full_pair() {
    let cost = SVMTransactionExecutionCost::default();
    for total in 1..24u64 {
        let full_only = cost.alt_bn128_pairing_cost(total, 0);
        let credit = if total < 8 {
            cost.alt_bn128_registered_pair_scalar_credit_cost
        } else {
            cost.alt_bn128_registered_pair_lane_credit_cost
        };
        for registered in 1..=total {
            let mixed = cost.alt_bn128_pairing_cost(total - registered, registered);
            assert!(
                mixed < full_only,
                "{total} pairs with {registered} registered: {mixed} is not below {full_only}"
            );
            assert_eq!(full_only - mixed, credit * registered);
        }
    }
}

/// Ryzen 9 9900X IFMA capture, 2026-08-05, agent-mail prepared-tariff-bench:
/// net per-prepared-pair saving `(allfull(total) - mixed) / prepared` in CU
/// at 33 ns/CU. Regime is decided by `total / 8`.
const MEASURED_PREPARED_SAVING: &[(u64, u64, u64)] = &[
    // (full, prepared, measured net saving per prepared pair). The 552
    // single-process figure once recorded for (5, 3) was process noise; the
    // two-process re-run puts that shape at 1,091.
    (1, 2, 2_270),
    (1, 3, 2_317),
    (0, 3, 2_387),
    (5, 3, 1_091),
    (2, 6, 899),
    (0, 8, 983),
    (8, 8, 792),
];

/// Mirrors `alt_bn128_pairing_cost_prepared`: full price for every pair,
/// minus a regime-split measured NET credit per prepared pair.
fn prepared_pairing_charge(cost: &SVMTransactionExecutionCost, full: u64, prepared: u64) -> u64 {
    let pairs = full + prepared;
    let credit = if pairs < 8 {
        cost.alt_bn128_prepared_pair_scalar_credit_cost
    } else {
        cost.alt_bn128_prepared_pair_lane_credit_cost
    };
    pairing_charge(cost, pairs) - credit * prepared
}

/// The credit never exceeds the measured saving in its regime, so the
/// prepared schedule never charges below what the syscall would cost as
/// plain full pairs minus real work saved.
#[test]
fn prepared_credit_stays_within_the_measured_saving() {
    let cost = SVMTransactionExecutionCost::default();
    for &(full, prepared, measured_saving) in MEASURED_PREPARED_SAVING {
        let credit = if full + prepared < 8 {
            cost.alt_bn128_prepared_pair_scalar_credit_cost
        } else {
            cost.alt_bn128_prepared_pair_lane_credit_cost
        };
        assert!(
            credit <= measured_saving,
            "full {full} prepared {prepared}: credit {credit} exceeds measured {measured_saving}"
        );
    }
}

/// A prepared pair must stay cheaper than a full pair in both regimes, and
/// the charge must stay above base so no shape goes free. The lane-regime
/// credit must be below the sub-lane credit: the 8-wide kernel means a
/// prepared pair saves preparation, not lane time.
#[test]
fn prepared_charge_is_positive_and_regime_ordered() {
    let cost = SVMTransactionExecutionCost::default();
    assert!(
        cost.alt_bn128_prepared_pair_lane_credit_cost
            < cost.alt_bn128_prepared_pair_scalar_credit_cost
    );
    assert!(
        cost.alt_bn128_prepared_pair_scalar_credit_cost
            < cost.alt_bn128_pairing_check_per_pair_cost
    );
    for total in 1..24u64 {
        for prepared in 1..=total.min(16) {
            let full = total - prepared;
            let mixed = prepared_pairing_charge(&cost, full, prepared);
            assert!(mixed < pairing_charge(&cost, total));
            assert!(mixed >= cost.alt_bn128_pairing_check_base_cost);
        }
    }
}

/// MEASURED credits (capture above); the prepare base stays a deliberate
/// overcharge (whole op measured at 2,656 CU vs the 4,888 composite charge).
/// This test exists to fail when the schedule is re-fitted, so a change
/// cannot land without restating the evidence.
#[test]
fn prepared_operand_schedule_is_pinned() {
    let cost = SVMTransactionExecutionCost::default();
    assert_eq!(cost.alt_bn128_prepared_pair_scalar_credit_cost, 2_200);
    assert_eq!(cost.alt_bn128_prepared_pair_lane_credit_cost, 750);
    assert_eq!(cost.alt_bn128_g2_prepare_base_cost, 700);
    // Mirrors the charge site: the per-pair price is all-in, so no separate
    // subgroup term is added.
    let prepare_charge =
        cost.alt_bn128_g2_prepare_base_cost + cost.alt_bn128_pairing_check_per_pair_cost;
    // Measured whole-op cost on the capture host.
    assert!(prepare_charge >= 2_656);
}

/// A registered pair saves over twice as much below one lane as above it, for
/// the same reason the price itself splits: past a full lane the pair still
/// occupies lane time and only its preparation is skipped. One credit would
/// either overcredit the lane shapes or throw away half the sub-lane saving.
#[test]
fn the_two_registered_credits_are_priced_apart() {
    let cost = SVMTransactionExecutionCost::default();
    assert!(
        cost.alt_bn128_registered_pair_scalar_credit_cost
            > 2 * cost.alt_bn128_registered_pair_lane_credit_cost
    );
}
