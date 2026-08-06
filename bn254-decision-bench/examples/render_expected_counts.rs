//! Emits the operation-count contract from the in-code matrix.
//!
//! The file used to be maintained by hand, so a model change left it stale and
//! the only signal was a test failure with no way to regenerate. The pipeline
//! writes it, the test still compares it to the matrix, and the observed-trace
//! test compares the matrix to what the guests really do.

use solana_bn254_decision_bench::builtin_expected_counts;

fn main() {
    let contract = builtin_expected_counts();
    println!(
        "{}",
        serde_json::to_string_pretty(&contract).expect("contract serializes")
    );
}
