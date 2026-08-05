//! Pins the BN254 charge schedule against the measurements it was fitted to.
//!
//! The decision table is a pure tariff: given a syscall shape, the charge is
//! deterministic on any host. These tests are the contract that makes the table
//! reproducible, so a schedule edit that breaks them must restate the evidence.

use solana_program_runtime::execution_budget::SVMTransactionExecutionCost;

/// Threadripper 9970X, `ceil(max of two process mean CI95 upper bounds / 33)`.
/// Source: research/bn254-decision-table-v2-20260804/B5-CHARGE-SCHEDULE.md
const MEASURED_PAIRING: &[(u64, u64)] = &[
    (1, 8_829),
    (2, 12_398),
    (3, 15_956),
    (4, 19_586),
    (6, 26_856),
    (7, 30_487),
    (8, 22_427),
    (9, 27_263),
    (12, 41_731),
    (16, 41_033),
];

const MEASURED_MSM: &[(u64, u64)] = &[
    (1, 745),
    (2, 1_050),
    (3, 1_349),
    (4, 1_645),
    (5, 1_933),
    (6, 2_227),
    (8, 2_810),
    (9, 3_105),
    (16, 5_138),
    (32, 9_816),
    (36, 10_946),
    (54, 16_251),
];

/// Mirrors `alt_bn128_pairing_cost` for full pairs. Kept here deliberately: if
/// the syscall changes shape, this must be updated on purpose, not implicitly.
fn pairing_charge(cost: &SVMTransactionExecutionCost, pairs: u64) -> u64 {
    let lanes = pairs / 8;
    let remainder = pairs % 8;
    cost.alt_bn128_pairing_check_base_cost
        + cost.alt_bn128_pairing_check_lane_cost * lanes
        + cost.alt_bn128_pairing_check_per_pair_cost * remainder
}

/// A registered pair is credited the subgroup check it skips.
fn registered_pairing_charge(
    cost: &SVMTransactionExecutionCost,
    full: u64,
    registered: u64,
) -> u64 {
    pairing_charge(cost, full + registered) - cost.alt_bn128_g2_subgroup_check_cost * registered
}

fn msm_charge(cost: &SVMTransactionExecutionCost, points: u64) -> u64 {
    cost.alt_bn128_g1_msm_base_cost + cost.alt_bn128_g1_msm_per_point_cost * points
}

#[test]
fn pairing_schedule_never_charges_below_measurement() {
    let cost = SVMTransactionExecutionCost::default();
    for &(pairs, measured) in MEASURED_PAIRING {
        let charged = pairing_charge(&cost, pairs);
        assert!(
            charged >= measured,
            "{pairs} pairs: charged {charged} is below the measured {measured}"
        );
    }
}

#[test]
fn pairing_schedule_overcharge_stays_within_the_fitted_bound() {
    let cost = SVMTransactionExecutionCost::default();
    for &(pairs, measured) in MEASURED_PAIRING {
        let charged = pairing_charge(&cost, pairs);
        assert!(
            charged * 1_000 <= measured * 1_115,
            "{pairs} pairs: charged {charged} exceeds the measured {measured} by more than 11.5%"
        );
    }
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

#[test]
fn msm_schedule_brackets_every_measured_point() {
    let cost = SVMTransactionExecutionCost::default();
    for &(points, measured) in MEASURED_MSM {
        let charged = msm_charge(&cost, points);
        assert!(
            charged >= measured,
            "{points} points: charged {charged} is below the measured {measured}"
        );
        assert!(
            charged * 1_000 <= measured * 1_020,
            "{points} points: charged {charged} exceeds the measured {measured} by more than 2%"
        );
    }
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

/// Registering a verifying key is worth paying for only if verifying against it
/// is cheaper than verifying with full pairs. The saving is the subgroup check
/// the registry authenticated once, and it must scale with registered pairs.
#[test]
fn a_registered_pair_is_cheaper_than_a_full_pair() {
    let cost = SVMTransactionExecutionCost::default();
    for total in 1..24u64 {
        let full_only = registered_pairing_charge(&cost, total, 0);
        for registered in 1..=total {
            let mixed = registered_pairing_charge(&cost, total - registered, registered);
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

/// Ryzen 9 9900X IFMA capture, 2026-08-05, agent-mail prepared-tariff-bench:
/// net per-prepared-pair saving `(allfull(total) - mixed) / prepared` in CU
/// at 33 ns/CU. Regime is decided by `total / 8`.
const MEASURED_PREPARED_SAVING: &[(u64, u64, u64)] = &[
    // (full, prepared, measured net saving per prepared pair)
    (1, 2, 2_270),
    (1, 3, 2_317),
    (0, 3, 2_387),
    (5, 3, 552),
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
/// overcharge (whole op measured at 2,656 CU vs the 6,500 composite charge).
/// This test exists to fail when the schedule is re-fitted, so a change
/// cannot land without restating the evidence.
#[test]
fn prepared_operand_schedule_is_pinned() {
    let cost = SVMTransactionExecutionCost::default();
    assert_eq!(cost.alt_bn128_prepared_pair_scalar_credit_cost, 2_200);
    assert_eq!(cost.alt_bn128_prepared_pair_lane_credit_cost, 500);
    assert_eq!(cost.alt_bn128_g2_prepare_base_cost, 700);
    let prepare_charge = cost.alt_bn128_g2_prepare_base_cost
        + cost.alt_bn128_pairing_check_per_pair_cost
        + cost.alt_bn128_g2_subgroup_check_cost;
    // Measured whole-op cost on the capture host.
    assert!(prepare_charge >= 2_656);
}

/// PROVISIONAL. No x86 measurement exists for GT multiexponentiation. These
/// values are ~5x the only calibration we have (arm64 p50 9.1k / 19.0k / 34.3k
/// CU at 1 / 2 / 3 targets), held high so the schedule stays safe until an x86
/// IFMA capture replaces them.
///
/// This test exists to fail when someone lands the real numbers, so the
/// placeholder cannot survive unnoticed. Delete it in the same change.
#[test]
fn provisional_gt_multiexp_schedule() {
    let cost = SVMTransactionExecutionCost::default();
    assert_eq!(cost.alt_bn128_gt_multiexp_base_cost, 50_000);
    assert_eq!(cost.alt_bn128_gt_multiexp_per_target_cost, 20_000);
}
