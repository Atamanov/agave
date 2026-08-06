//! Renders the operations table in the published notation.
//!
//! Pure op counts from the expected-count contract, so there is nothing
//! measured here and nothing host-dependent. `tests/contracts.rs` already pins
//! that contract against measured traces, which is what makes this table
//! trustworthy rather than merely self-consistent.

use {
    solana_bn254_decision_bench::{ColumnId, OperationTrace, RowId, expected_trace},
    solana_program_runtime::execution_budget::ALT_BN128_PAIRING_LANE_WIDTH,
};

/// Narrowed once so the notation cannot claim a lane the tariff does not charge.
const LANE_WIDTH: u32 = ALT_BN128_PAIRING_LANE_WIDTH as u32;

/// ML live Miller pair · pML prepared pair · SC G2 subgroup check ·
/// FE final exponentiation · kMSM(np) k MSM syscalls over n points · CMP FP12
/// identity compare. A superscript 8 marks a call the 8-wide IFMA kernel takes.
///
/// A pairing term keeps its call count and its per-call width apart. Collapsing
/// them into one product hides the regime: five calls of four pairs and one
/// call of twenty pairs are the same product and nothing like the same charge.
fn notation(column: ColumnId, trace: &OperationTrace) -> String {
    let mut parts = Vec::new();
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        let width = match (call.full_pairs, call.registered_pairs) {
            (live, 0) => format!("{live}ML"),
            (0, prepared) => format!("{prepared}pML"),
            // Lanes come off the whole call, so a mixed call cannot attribute
            // them to the live or the prepared half.
            (live, prepared) => format!("({live}ML+{prepared}pML)"),
        };
        let (lanes, remainder) = (call.pairs / LANE_WIDTH, call.pairs % LANE_WIDTH);
        let lane_split = match (lanes, remainder) {
            (0, _) => String::new(),
            (lanes, 0) => format!("[{lanes}L]"),
            (lanes, remainder) => format!("[{lanes}L+{remainder}]"),
        };
        parts.push(format!("{}\u{d7}{width}{lane_split}", call.calls));
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
        "c\u{d7}pML reads as c pairing calls of p live Miller pairs each, never as \
         the product \u{b7} pML prepared pair (lines cached, subgroup paid at \
         registration) \u{b7} SC G2 subgroup check \u{b7} FE final exponentiation \u{b7} \
         kMSM(np) k MSM syscalls over n points \u{b7} GT(t) target multiexp \u{b7} RED(c/p) PLONK multi-VK reduction over c contexts and p proofs \u{b7} kLC(nt) k scalar inner products over n terms \u{b7} kH(ns) k hash syscalls over n slices \u{b7} CMP FP12 \
         identity compare.\n"
    );
    println!(
        "[nL+r] is how one call is charged, n full {LANE_WIDTH}-wide IFMA lanes plus r \
         pairs left over. No bracket means the call never fills a lane and every \
         pair is charged singly. A remainder pair costs more than a pair inside a \
         lane, which is why {LANE_WIDTH} pairs cost less than 7 and why a call is padded \
         to a lane boundary where that is cheaper.\n"
    );
    println!(
        "Padding is why a call can carry more pairs than another and still charge \
         less. Compare [1L] against a bare 7ML.\n"
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
