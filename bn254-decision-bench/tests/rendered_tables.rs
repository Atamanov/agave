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
        table.contains("1\u{d7}8ML\u{2078}"),
        "a lane-filling call must show one call of the full lane width"
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
