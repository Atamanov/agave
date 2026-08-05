//! Renders the syscall-core half of the decision table straight from the
//! committed runtime charge schedule.
//!
//! Charged CU is a tariff, so every value here is identical on every host and
//! needs no measurement. What it does NOT include is the guest-side sBPF
//! residual, which only a LiteSVM run can supply. Cells are therefore a lower
//! bound on the transaction, and the full table adds the residual per cell.

use {
    solana_bn254_decision_bench::{ColumnId, OperationTrace, RowId, expected_trace},
    solana_program_runtime::execution_budget::SVMTransactionExecutionCost,
};

/// The stock `alt_bn128_group_op` pairing charge, which is consensus today and
/// not part of the batch schedule.
fn stock_pairing(pairs: u64) -> u64 {
    36_364 + 12_121 * pairs.saturating_sub(1) + 85 + 192 * pairs + 32
}

fn batch_pairing(cost: &SVMTransactionExecutionCost, full: u64, registered: u64) -> u64 {
    let pairs = full + registered;
    cost.alt_bn128_pairing_check_base_cost
        + cost.alt_bn128_pairing_check_lane_cost * (pairs / 8)
        + cost.alt_bn128_pairing_check_per_pair_cost * (pairs % 8)
        - cost.alt_bn128_g2_subgroup_check_cost * registered
}

fn core_cu(cost: &SVMTransactionExecutionCost, column: ColumnId, trace: &OperationTrace) -> u64 {
    let stock = matches!(column, ColumnId::Current | ColumnId::CurrentFp12);
    let mut cu = 0u64;
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        let each = if stock {
            stock_pairing(call.pairs.into())
        } else {
            batch_pairing(cost, call.full_pairs.into(), call.registered_pairs.into())
        };
        cu += u64::from(call.calls) * each;
    }
    for call in &trace.msm_calls {
        cu += u64::from(call.calls)
            * (cost.alt_bn128_g1_msm_base_cost
                + cost.alt_bn128_g1_msm_per_point_cost * u64::from(call.points));
    }
    for call in &trace.gt_target_multiexp_calls {
        cu += u64::from(call.calls)
            * (cost.alt_bn128_gt_multiexp_base_cost
                + cost.alt_bn128_gt_multiexp_per_target_cost * u64::from(call.targets));
    }
    cu
}

fn main() {
    let cost = SVMTransactionExecutionCost::default();
    println!("# BN254 decision table, syscall core\n");
    println!("Charged CU from the committed runtime schedule. Host-independent.");
    println!("Excludes the guest-side sBPF residual, so each cell is a lower bound.\n");
    print!("| Scenario |");
    for column in ColumnId::ALL {
        print!(" {} |", column.label());
    }
    println!("\n|---|{}", "---:|".repeat(ColumnId::ALL.len()));
    for row in RowId::ALL {
        print!("| {} |", row.label());
        for column in ColumnId::ALL {
            print!(" {} |", core_cu(&cost, column, &expected_trace(row, column)));
        }
        println!();
    }
    println!(
        "\nGT multiexp is provisional at {} + {}t and inflates the fold-all column \
         on multi-key rows.",
        cost.alt_bn128_gt_multiexp_base_cost, cost.alt_bn128_gt_multiexp_per_target_cost
    );
}
