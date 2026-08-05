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
    std::{collections::BTreeMap, path::PathBuf},
};

/// Guest-side sBPF CU per cell, measured by the collector. A cell absent here
/// has no measurement and is reported as core-only, never silently as a total.
fn residuals() -> BTreeMap<String, u64> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("research/bn254-decision-table-v2-20260804/residuals.json");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().trim_matches('"');
            if let Ok(cu) = value.trim().parse::<u64>() {
                out.insert(key.to_owned(), cu);
            }
        }
    }
    out
}

fn key(row: RowId, column: ColumnId) -> String {
    let r = format!("{row:?}");
    let c = format!("{column:?}");
    fn snake(s: &str) -> String {
        let mut out = String::new();
        for (i, ch) in s.chars().enumerate() {
            if ch.is_uppercase() && i > 0 {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        }
        out
    }
    format!("{}/{}", snake(&r), snake(&c))
}

/// The stock `alt_bn128_group_op` pairing charge, which is consensus today and
/// not part of the batch schedule.
fn stock_pairing(pairs: u64) -> u64 {
    36_364 + 12_121 * pairs.saturating_sub(1) + 85 + 192 * pairs + 32
}

fn core_cu(cost: &SVMTransactionExecutionCost, column: ColumnId, trace: &OperationTrace) -> u64 {
    let stock = matches!(column, ColumnId::Current | ColumnId::CurrentFp12);
    let mut cu = 0u64;
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        let each = if stock {
            stock_pairing(call.pairs.into())
        } else {
            cost.alt_bn128_pairing_cost(call.full_pairs.into(), call.registered_pairs.into())
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
    let residual = residuals();
    println!("# BN254 decision table, transaction CU\n");
    println!("Syscall core from the committed runtime schedule, plus the measured");
    println!("guest-side sBPF residual. Core is a tariff and is identical on every host.\n");
    println!("A cell shown as `N +?` has no residual measurement and is core only, so it");
    println!("is a lower bound. See CAPTURE-HOST-REQUIREMENTS.md for why.\n");
    print!("| Scenario |");
    for column in ColumnId::ALL {
        print!(" {} |", column.label());
    }
    println!("\n|---|{}", "---:|".repeat(ColumnId::ALL.len()));
    for row in RowId::ALL {
        print!("| {} |", row.label());
        for column in ColumnId::ALL {
            let core = core_cu(&cost, column, &expected_trace(row, column));
            match residual.get(&key(row, column)) {
                Some(r) => print!(" {} |", core + r),
                None => print!(" {core} +? |"),
            }
        }
        println!();
    }
    let measured = RowId::ALL
        .iter()
        .flat_map(|row| ColumnId::ALL.iter().map(move |c| key(*row, *c)))
        .filter(|k| residual.contains_key(k))
        .count();
    println!("\n{measured} of 30 cells carry a measured residual.");
    println!(
        "The batch columns price the AVX-512 IFMA kernel. A validator without \
         avx512ifma cannot reach these charges, so adopting them raises the \
         hardware floor above docs/src/operations/requirements.md."
    );
}
