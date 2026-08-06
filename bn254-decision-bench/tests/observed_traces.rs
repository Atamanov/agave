//! Compares the operation trace the guest really executed against the trace the
//! published table prices.
//!
//! `expected_trace` prices all 30 cells. Without this comparison a guest whose
//! syscall shape drifts from the model keeps the model's price.

use {
    solana_bn254_decision_bench::{
        ColumnId, ResidualCuContract, RowId, SCHEMA_PREFIX, expected_trace,
    },
    std::{collections::BTreeMap, path::PathBuf},
};

fn research_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("research/bn254-decision-table-v2-20260804")
}

fn observed() -> ResidualCuContract {
    let path = research_dir().join("observed-traces.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} is missing ({error}). Regenerate it with \
             bash bn254-decision-bench/collect-residuals.sh",
            path.display()
        )
    });
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not a residual contract: {error}", path.display()))
}

#[test]
fn every_observed_trace_equals_the_priced_trace() {
    let contract = observed();
    assert_eq!(
        contract.schema,
        format!("{SCHEMA_PREFIX}.residual-cu-contract.v1")
    );
    let cells: BTreeMap<_, _> = contract
        .cells
        .iter()
        .map(|cell| ((cell.row_id, cell.column_id), cell))
        .collect();
    assert_eq!(
        cells.len(),
        contract.cells.len(),
        "observed-traces.json repeats a cell identity"
    );

    let mut disagreements = Vec::new();
    for row in RowId::ALL {
        for column in ColumnId::ALL {
            let Some(cell) = cells.get(&(row, column)) else {
                disagreements.push(format!("{row:?}/{column:?}: no observed cell"));
                continue;
            };
            assert_eq!(
                cell.source, "observed_in_tree_host_non_core",
                "{row:?}/{column:?} was not observed in the host runtime"
            );
            let expected = expected_trace(row, column);
            if cell.observed_trace != expected {
                disagreements.push(format!(
                    "{row:?}/{column:?}\n    observed {}\n    expected {}",
                    serde_json::to_string(&cell.observed_trace).expect("trace serializes"),
                    serde_json::to_string(&expected).expect("trace serializes"),
                ));
            }
        }
    }
    assert!(
        disagreements.is_empty(),
        "{} of 30 cells are priced with a shape the guest does not execute. \
         Decide whether the guest or the model is wrong before changing either.\n  {}",
        disagreements.len(),
        disagreements.join("\n  ")
    );
}

/// The renderer reads residuals.json, the trace check reads observed-traces.json.
/// They come from one collector run and must not drift apart.
#[test]
fn residuals_json_agrees_with_the_observed_cells() {
    let residuals: BTreeMap<String, u64> = serde_json::from_str(
        &std::fs::read_to_string(research_dir().join("residuals.json"))
            .expect("residuals.json must be committed"),
    )
    .expect("residuals.json is a map of cell key to CU");

    let snake = |value: serde_json::Value| {
        value
            .as_str()
            .expect("identities serialize as snake_case strings")
            .to_owned()
    };
    for cell in &observed().cells {
        let key = format!(
            "{}/{}",
            snake(serde_json::to_value(cell.row_id).expect("row id serializes")),
            snake(serde_json::to_value(cell.column_id).expect("column id serializes")),
        );
        assert_eq!(
            residuals.get(&key),
            Some(&cell.non_core_transaction_cu),
            "{key}: residuals.json disagrees with the observed cell"
        );
    }
    assert_eq!(residuals.len(), 30, "residuals.json must hold 30 cells");
}

/// Catches drift between the renderer's charge and the residual subtractor's.
///
///     syscall_cu(trace) + non_core_transaction_cu == transaction_cu
///
/// Both have disagreed here: the pairing overhead was double counted, and the
/// G1 mul/add work was dropped entirely.
///
/// It proves less than that identity suggests. The residual is defined as
/// `metered - modeled`, so the equation reduces to the two copies of the model
/// agreeing with each other, and both can be wrong together. What rules that
/// out is `the_stock_pairing_charge_matches_the_runtime_budget`, which prices
/// the same formula from the runtime's own fields. It also covers only the ten
/// stock cells, because the batch columns are the schedule under test rather
/// than a charge LiteSVM already meters.
#[test]
fn stock_priced_cells_reconstruct_the_metered_transaction() {
    use solana_bn254_decision_bench::syscall_cu;
    use solana_program_runtime::execution_budget::SVMTransactionExecutionCost;

    let contract = observed();
    let cost = SVMTransactionExecutionCost::default();
    let mut checked = 0usize;
    for cell in &contract.cells {
        if !matches!(cell.column_id, ColumnId::Current | ColumnId::CurrentFp12) {
            continue;
        }
        // Older captures predate the field; they cannot be checked, not silently passed.
        assert_ne!(
            cell.transaction_cu, 0,
            "{:?}/{:?} has no metered total; re-run collect-residuals.sh",
            cell.row_id, cell.column_id
        );
        let syscall = syscall_cu(&cost, cell.column_id, &cell.observed_trace);
        assert_eq!(
            syscall + cell.non_core_transaction_cu,
            cell.transaction_cu,
            "{:?}/{:?}: syscall {} + residual {} != metered {}",
            cell.row_id,
            cell.column_id,
            syscall,
            cell.non_core_transaction_cu,
            cell.transaction_cu
        );
        checked += 1;
    }
    assert_eq!(checked, 10, "both stock columns on all five rows");
}

/// Prices the baseline from the runtime's own budget fields instead of the
/// bench's copy of them. Without this the reconstruction above compares one
/// model against itself.
///
/// The syscall charges the group op once per pair, then adds the input and
/// output bytes the way `SyscallHash` does, so a change to any of the four
/// fields must move the baseline column.
#[test]
fn the_stock_pairing_charge_matches_the_runtime_budget() {
    use {
        solana_bn254_decision_bench::stock_group_op_pairing_cu,
        solana_program_runtime::execution_budget::SVMTransactionExecutionCost,
    };

    let cost = SVMTransactionExecutionCost::default();
    for pairs in 1u64..=16 {
        let from_budget = cost
            .alt_bn128_pairing_one_pair_cost_first
            .saturating_add(
                cost.alt_bn128_pairing_one_pair_cost_other
                    .saturating_mul(pairs.saturating_sub(1)),
            )
            .saturating_add(cost.sha256_base_cost)
            .saturating_add(192 * pairs)
            .saturating_add(32);
        assert_eq!(
            stock_group_op_pairing_cu(pairs),
            from_budget,
            "baseline pairing charge for {pairs} pairs left the runtime schedule"
        );
    }
}
