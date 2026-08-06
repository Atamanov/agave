//! Renders the operations table in the published notation.
//!
//! Pure op counts from the expected-count contract, so there is nothing
//! measured here and nothing host-dependent. `tests/contracts.rs` already pins
//! that contract against measured traces, which is what makes this table
//! trustworthy rather than merely self-consistent.

use solana_bn254_decision_bench::{ColumnId, OperationTrace, RowId, expected_trace};

/// ML live Miller pair · pML prepared pair · SC G2 subgroup check ·
/// FE final exponentiation · kMSM(np) k MSM syscalls over n points · CMP FP12
/// identity compare. A superscript 8 marks a call the 8-wide IFMA kernel takes.
fn notation(column: ColumnId, trace: &OperationTrace) -> String {
    let mut parts = Vec::new();
    let mut live = 0u32;
    let mut prepared = 0u32;
    let mut lane_wide = false;
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        live = live.saturating_add(call.full_pairs.saturating_mul(call.calls));
        prepared = prepared.saturating_add(call.registered_pairs.saturating_mul(call.calls));
        lane_wide |= call.pairs >= 8;
    }
    let mark = if lane_wide { "\u{2078}" } else { "" };
    if live > 0 {
        parts.push(format!("{live}ML{mark}"));
    }
    if prepared > 0 {
        parts.push(format!("{prepared}pML{mark}"));
    }
    if trace.g2_subgroup_checks > 0 {
        parts.push(format!("{}SC", trace.g2_subgroup_checks));
    }
    if trace.final_exponentiations > 0 {
        let n = trace.final_exponentiations;
        parts.push(if n == 1 { "FE".to_owned() } else { format!("{n}FE") });
    }
    let calls: u32 = trace.msm_calls.iter().map(|c| c.calls).sum();
    let points: u32 = trace.msm_calls.iter().map(|c| c.points.saturating_mul(c.calls)).sum();
    if calls > 0 {
        parts.push(format!("{calls}MSM({points}p)"));
    }
    for call in &trace.gt_target_multiexp_calls {
        parts.push(format!("GT({}t)", call.targets));
    }
    for call in &trace.plonk_multi_vk_reduce_calls {
        parts.push(format!("RED({}c/{}p)", call.contexts, call.proofs));
    }
    let lincombs: u32 = trace.fr_lincomb_calls.iter().map(|c| c.calls).sum();
    let terms: u32 = trace
        .fr_lincomb_calls
        .iter()
        .map(|c| c.terms.saturating_mul(c.calls))
        .sum();
    if lincombs > 0 {
        parts.push(format!("{lincombs}LC({terms}t)"));
    }
    if trace.hash_syscalls.calls > 0 {
        parts.push(format!(
            "{}H({}s)",
            trace.hash_syscalls.calls, trace.hash_syscalls.slices
        ));
    }
    if matches!(column, ColumnId::CurrentFp12 | ColumnId::BatchFp12B5) {
        parts.push("CMP".to_owned());
    }
    if parts.is_empty() {
        "—".to_owned()
    } else {
        parts.join(" + ")
    }
}

fn main() {
    println!("# BN254 decision table, operations per transaction\n");
    println!(
        "ML live Miller pair · pML prepared pair (lines cached, subgroup paid at \
         registration) · SC G2 subgroup check · FE final exponentiation · \
         kMSM(np) k MSM syscalls over n points · GT(t) target multiexp \u{b7} RED(c/p) PLONK multi-VK reduction over c contexts and p proofs \u{b7} kLC(nt) k scalar inner products over n terms \u{b7} kH(ns) k hash syscalls over n slices · CMP FP12 \
         identity compare. \u{2078} marks a call the 8-wide IFMA kernel takes.\n"
    );
    print!("| Scenario |");
    for column in ColumnId::ALL {
        print!(" {} |", column.label());
    }
    println!("\n|---|{}", "---|".repeat(ColumnId::ALL.len()));
    for row in RowId::ALL {
        print!("| {} |", row.label());
        for column in ColumnId::ALL {
            print!(" {} |", notation(column, &expected_trace(row, column)));
        }
        println!();
    }
}
