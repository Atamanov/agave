fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&solana_bn254_decision_bench::builtin_expected_counts())
            .expect("expected-count contract is serializable")
    );
}
