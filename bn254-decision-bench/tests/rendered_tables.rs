//! Pins the rendered tables against the committed markdown.
//!
//! A hand-edited table fails here. That is the whole point: the published
//! numbers must come from the schedule and the op contract, never from a
//! keyboard.

use std::{path::PathBuf, process::Command};

fn research_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("research/bn254-decision-table-v2-20260804")
}

fn render(example: &str) -> String {
    let out = Command::new(env!("CARGO"))
        .args(["run", "-q", "-p", "solana-bn254-decision-bench", "--example", example])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("workspace root"))
        .output()
        .unwrap_or_else(|error| panic!("could not run {example}: {error}"));
    assert!(out.status.success(), "{example} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("renderer emits utf8")
}

fn assert_matches_committed(example: &str, file: &str) {
    let committed = std::fs::read_to_string(research_dir().join(file))
        .unwrap_or_else(|error| panic!("{file} must be committed: {error}"));
    assert_eq!(
        render(example).trim(),
        committed.trim(),
        "{file} differs from `cargo run --example {example}`. Regenerate it, do not edit it."
    );
}

#[test]
fn transaction_table_matches_the_committed_markdown() {
    assert_matches_committed("render_core_table", "TRANSACTION-TABLE.md");
}

#[test]
fn operations_table_matches_the_committed_markdown() {
    assert_matches_committed("render_ops_table", "OPERATIONS-TABLE.md");
}

/// A pairing term must keep its call count apart from its per-call width.
/// The two were once multiplied together, which printed five calls of four
/// pairs as twenty pairs and hid which tariff the row was charged on.
#[test]
fn a_pairing_term_reports_calls_and_width_separately() {
    let table = std::fs::read_to_string(research_dir().join("OPERATIONS-TABLE.md"))
        .expect("OPERATIONS-TABLE.md must be committed");

    assert!(
        table.contains("5\u{d7}4ML"),
        "the baseline row runs five pairing calls of four pairs and must say so"
    );
    assert!(
        !table.contains(" 20ML"),
        "20ML is the product of five calls and four pairs, not a shape the runtime charges"
    );
    // A padded lane is the whole reason the notation carries a width.
    assert!(
        table.contains("1\u{d7}8ML[1L]"),
        "a lane-filling call must show one call of the full lane width"
    );
    assert!(
        table.contains("1\u{d7}9ML[1L+1]"),
        "a call past a lane boundary must show the remainder it pays for"
    );
    // A superscript beside a count reads as arithmetic on that count.
    assert!(
        !table.contains('\u{2078}'),
        "lane width belongs in the bracket, not in a superscript next to a number"
    );
}

/// A charged family must appear in the operations that explain the charge.
///
/// Decompression and the stock G1 ops were each priced in every cell and shown
/// in none, the second of them worth 248,436 CU on one baseline cell. Checking
/// the two by name would leave the next omission to be found by an auditor, so
/// this walks the families instead.
#[test]
fn every_charged_family_appears_in_the_operations_table() {
    use solana_bn254_decision_bench::{ColumnId, RowId, expected_trace, syscall_families};

    let table = std::fs::read_to_string(research_dir().join("OPERATIONS-TABLE.md"))
        .expect("OPERATIONS-TABLE.md must be committed");
    let cost = solana_program_runtime::execution_budget::SVMTransactionExecutionCost::default();

    for row in RowId::ALL {
        let line = table
            .lines()
            .find(|line| line.starts_with(&format!("| {} |", row.label())))
            .unwrap_or_else(|| panic!("{} has no row", row.label()));
        for (index, column) in ColumnId::ALL.into_iter().enumerate() {
            let cell = line.split('|').nth(index.saturating_add(2)).expect("cell");
            let families = syscall_families(&cost, column, &expected_trace(row, column));
            for (charge, token) in [
                (families.decompress, "DEC("),
                (families.stock_g1, "G1"),
                (families.msm, "MSM("),
                (families.gt, "GT("),
                (families.reduce, "RED("),
                (families.lincomb, "LC("),
                (families.hash, "H("),
            ] {
                assert!(
                    charge == 0 || cell.contains(token),
                    "{}/{} charges {charge} CU of {token} and does not show it",
                    row.label(),
                    column.label(),
                );
            }
        }
    }
}

/// Poseidon is imported from a measurement of another program, so it must stay
/// outside the cells and outside the syscall share. Both would price work no
/// guest here runs.
#[test]
fn poseidon_is_reported_beside_the_cells_and_never_inside_them() {
    let ops = std::fs::read_to_string(research_dir().join("OPERATIONS-TABLE.md"))
        .expect("OPERATIONS-TABLE.md must be committed");
    let (cells, poseidon) = ops
        .split_once("## Poseidon")
        .expect("the operations table must carry the Poseidon section");

    assert!(
        !cells.contains("PO"),
        "no cell runs a Poseidon call, so no cell may carry one"
    );
    assert!(poseidon.contains("45588"), "the one-leg measurement must be published");
    assert!(
        poseidon.contains("Aggregation stops at 3 legs"),
        "a reader must learn that four and five legs do not exist"
    );

    let structure = std::fs::read_to_string(research_dir().join("STRUCTURE-TABLE.md"))
        .expect("STRUCTURE-TABLE.md must be committed");
    assert!(
        !structure.to_lowercase().contains("poseidon"),
        "borrowed work must not move the syscall share"
    );
}

/// The file carrying the syscall-share claim was the one table with no golden
/// test, so a hand-edited share passed the suite.
#[test]
fn structure_table_matches_the_committed_markdown() {
    assert_matches_committed("render_structure_table", "STRUCTURE-TABLE.md");
}

/// Without measurements the renderer must abort. It used to emit a table of
/// `?` cells and exit zero, which reads as a rendered table.
#[test]
fn the_structure_renderer_refuses_to_render_without_residuals() {
    let out = Command::new(env!("CARGO"))
        .args(["run", "-q", "-p", "solana-bn254-decision-bench", "--example", "render_structure_table"])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().expect("workspace root"))
        .env("BN254_RESIDUALS", research_dir().join("residuals.json.absent"))
        .output()
        .expect("renderer runs");
    assert!(!out.status.success(), "renderer must fail with no residuals.json");
}
