//! Renders the operations table in the published notation.
//!
//! Pure op counts from the expected-count contract, so there is nothing
//! measured here and nothing host-dependent. `tests/contracts.rs` already pins
//! that contract against measured traces, which is what makes this table
//! trustworthy rather than merely self-consistent.

use {
    solana_bn254_decision_bench::{ColumnId, OperationTrace, RowId, expected_trace},
    solana_program_runtime::execution_budget::{
        ALT_BN128_PAIRING_LANE_WIDTH, SVMTransactionExecutionCost,
    },
};

/// Narrowed once so the notation cannot claim a lane the tariff does not charge.
const LANE_WIDTH: u32 = ALT_BN128_PAIRING_LANE_WIDTH as u32;

#[derive(serde::Deserialize)]
struct PoseidonMeasurement {
    arity: u64,
    unsupported_above_legs: u32,
    unsupported_reason: String,
    #[serde(rename = "measured")]
    rows: Vec<PoseidonRow>,
}

#[derive(serde::Deserialize)]
struct PoseidonRow {
    legs: u32,
    calls: u64,
    cu: u64,
    statement_compression_calls: u64,
    state_machine_calls: u64,
}

fn poseidon_measurement() -> PoseidonMeasurement {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("research/bn254-decision-table-v2-20260804/zolana-poseidon.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be committed: {error}", path.display()));
    serde_json::from_str(&text).expect("poseidon measurement parses")
}

/// ML live Miller pair · pML prepared pair · SC G2 subgroup check ·
/// FE final exponentiation · kMSM(np) k MSM syscalls over n points · CMP FP12
/// identity compare. A superscript 8 marks a call the 8-wide IFMA kernel takes.
///
/// A pairing term keeps its call count and its per-call width apart. Collapsing
/// them into one product hides the regime: five calls of four pairs and one
/// call of twenty pairs are the same product and nothing like the same charge.
fn notation(column: ColumnId, trace: &OperationTrace) -> String {
    let mut parts = Vec::new();
    // One G2 point is the dearest single charge in the grid, so it cannot be
    // priced in the cells and absent from the operations that explain them.
    match (trace.g1_decompressions, trace.g2_decompressions) {
        (0, 0) => {}
        (g1, 0) => parts.push(format!("DEC({g1}G1)")),
        (0, g2) => parts.push(format!("DEC({g2}G2)")),
        (g1, g2) => parts.push(format!("DEC({g1}G1+{g2}G2)")),
    }
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
    // Priced in every cell that carries them, and the largest single term in
    // the PLONK baseline. An operation the table charges must be an operation
    // the table shows.
    if trace.stock_g1_additions > 0 {
        parts.push(format!("{}G1add", trace.stock_g1_additions));
    }
    if trace.stock_g1_multiplications > 0 {
        parts.push(format!("{}G1mul", trace.stock_g1_multiplications));
    }
    if trace.final_exponentiations > 0 {
        let n = trace.final_exponentiations;
        parts.push(if n == 1 { "FE".to_owned() } else { format!("{n}FE") });
    }
    // MSM charges its base once per call, so call widths cannot be summed into
    // one figure. Eight calls totalling thirteen points cost 9,396 CU where one
    // call of thirteen points costs 5,315.
    let mut widths: Vec<u32> = Vec::new();
    for call in &trace.msm_calls {
        for _ in 0..call.calls {
            widths.push(call.points);
        }
    }
    if !widths.is_empty() {
        widths.sort_unstable();
        let mut runs: Vec<String> = Vec::new();
        let mut index = 0;
        while index < widths.len() {
            let width = widths[index];
            let count = widths[index..].iter().take_while(|w| **w == width).count();
            runs.push(if count == 1 {
                format!("MSM({width}p)")
            } else {
                format!("{count}\u{d7}MSM({width}p)")
            });
            index = index.saturating_add(count);
        }
        parts.push(runs.join("+"));
    }
    for call in &trace.gt_target_multiexp_calls {
        parts.push(format!("GT({}t)", call.targets));
    }
    for call in &trace.plonk_multi_vk_reduce_calls {
        // Public inputs drive both the Lagrange term and the transcript term,
        // so a reader cannot reproduce the charge without them.
        let shape = format!("RED({}c/{}p/{}i)", call.contexts, call.proofs, call.public_inputs);
        parts.push(if call.calls == 1 { shape } else { format!("{}\u{d7}{shape}", call.calls) });
    }
    let mut lincombs: Vec<u32> = Vec::new();
    for call in &trace.fr_lincomb_calls {
        for _ in 0..call.calls {
            lincombs.push(call.terms);
        }
    }
    if !lincombs.is_empty() {
        lincombs.sort_unstable();
        let mut runs: Vec<String> = Vec::new();
        let mut index = 0;
        while index < lincombs.len() {
            let terms = lincombs[index];
            let count = lincombs[index..].iter().take_while(|t| **t == terms).count();
            runs.push(if count == 1 {
                format!("LC({terms}t)")
            } else {
                format!("{count}\u{d7}LC({terms}t)")
            });
            index = index.saturating_add(count);
        }
        parts.push(runs.join("+"));
    }
    if trace.hash_syscalls.calls > 0 {
        // The byte term is the largest part of the hash charge and was invisible.
        parts.push(format!(
            "{}H({}s,{}b)",
            trace.hash_syscalls.calls, trace.hash_syscalls.slices, trace.hash_syscalls.byte_cu
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
        "DEC(nG1+mG2) wire point decompression, paid by every column because a \
         deployment of any of them receives the same compressed proof \u{b7} \
         c\u{d7}pML reads as c pairing calls of p live Miller pairs each, never as \
         the product \u{b7} nG1add and nG1mul stock group ops, which the unbatched \
         path uses to build its public-input commitment \u{b7} \
         pML prepared pair (lines cached, subgroup paid at \
         registration) \u{b7} SC G2 subgroup check \u{b7} FE final exponentiation \u{b7} \
         c\u{d7}MSM(np) c MSM calls of n points each, listed by width because the \
         base is charged per call \u{b7} GT(t) target multiexp \u{b7} RED(c/p/i) PLONK multi-VK reduction over c contexts, p proofs and i public inputs \u{b7} c\u{d7}LC(nt) c inner products of n terms each \u{b7} kH(ns,mb) k hash syscalls over n slices carrying m CU of byte charge \u{b7} nFE n final exponentiations \u{b7} CMP FP12 \
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

    render_poseidon();
}

/// Poseidon sits beside verification rather than inside it.
///
/// None of the thirty cells above executes a Poseidon call, so these counts are
/// imported from a measurement of the real zolana program and are reported on
/// their own. Folding them into a cell would price work the guest never ran,
/// and folding them into the syscall share would lift every column by the same
/// borrowed constant.
fn render_poseidon() {
    let measured = poseidon_measurement();
    let cost = SVMTransactionExecutionCost::default();
    let arity = measured.arity;
    let per_call = cost.poseidon_cost(arity).expect("arity is in range");

    println!("\n## Poseidon, the application work beside verification\n");
    println!(
        "Measured on the unmodified zolana shielded pool, every call at arity {arity} \
         and so {per_call} CU. No cell above runs one."
    );
    println!(
        "\nThe split is a partition. Statement compression folds the public statement \
         into the single field element the verifier consumes, so it holds for any \
         column keeping that convention and moves if the convention does. The rest is \
         tree, nullifier and hash-chain work that no choice of pairing kernel touches.\n"
    );
    println!("| Legs | Calls | CU | Statement compression | State machine |");
    println!("|---:|---:|---:|---:|---:|");
    for row in &measured.rows {
        assert_eq!(
            row.statement_compression_calls.saturating_add(row.state_machine_calls),
            row.calls,
            "the two-way split must partition the measured calls"
        );
        assert_eq!(
            row.cu,
            row.calls.saturating_mul(per_call),
            "measured CU must be the runtime charge"
        );
        println!(
            "| {} | {} | {} | {} calls, {} CU | {} calls, {} CU |",
            row.legs,
            row.calls,
            row.cu,
            row.statement_compression_calls,
            row.statement_compression_calls.saturating_mul(per_call),
            row.state_machine_calls,
            row.state_machine_calls.saturating_mul(per_call),
        );
    }
    println!(
        "\nAggregation stops at {} legs. {}\n",
        measured.unsupported_above_legs, measured.unsupported_reason
    );
    println!(
        "Per-leg growth is not constant, so no row is extrapolated. The tree append \
         costs what the leaf index makes it cost, not what the leg count does."
    );
}
