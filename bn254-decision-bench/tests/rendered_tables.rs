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
fn core_table_matches_the_committed_markdown() {
    assert_matches_committed("render_core_table", "CORE-TABLE.md");
}

#[test]
fn operations_table_matches_the_committed_markdown() {
    assert_matches_committed("render_ops_table", "OPERATIONS-TABLE.md");
}
