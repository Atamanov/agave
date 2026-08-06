//! Three-bucket rollup and the tables that support it.

use std::collections::BTreeMap;

use crate::{
    bn254_syscall_total, is_bn254_name, other_syscall_counts, poseidon_summary, reconcile,
    FunctionMap, InvocationTrace, PoseidonSummary, Reconciliation, SyscallPricer,
};

/// The split the campaign asks for. `syscall` and `sbpf_total` are measured;
/// the two sBPF sub-buckets depend on which instructions count as
/// BN254-adjacent, so both a static and a dynamic rule are carried.
#[derive(Clone, Debug)]
pub struct Buckets {
    pub transaction_cu: u64,
    pub sbpf_total: u64,
    pub syscall_bn254_cu: u64,
    /// Poseidon is syscall CU too, kept apart from BN254 so the BN254 ratio
    /// cannot be flattered by hashing that no BN254 syscall can absorb.
    pub poseidon: PoseidonSummary,
    pub residual_cu: i64,
    /// sBPF instructions in functions whose own name is BN254 work.
    pub bn254_sbpf_static: u64,
    /// sBPF instructions executed with a BN254 frame anywhere on the stack.
    /// Adds shared helpers (memcpy, core slice code) called from the verifier.
    pub bn254_sbpf_dynamic: u64,
}

impl Buckets {
    /// `syscall / (syscall + BN254-adjacent sBPF)` under the dynamic rule,
    /// which is the larger of the two sBPF numbers and therefore the more
    /// conservative ceiling.
    pub fn syscall_share_of_bn254_work(&self) -> f64 {
        let denominator = self.syscall_bn254_cu + self.bn254_sbpf_dynamic;
        if denominator == 0 {
            return 0.0;
        }
        self.syscall_bn254_cu as f64 / denominator as f64
    }

    /// Program work that BN254 can never absorb: total sBPF minus the
    /// BN254-adjacent part, under the dynamic rule.
    pub fn non_bn254_sbpf(&self) -> u64 {
        self.sbpf_total.saturating_sub(self.bn254_sbpf_dynamic)
    }

    /// Residual with Poseidon removed, since Poseidon is now its own line.
    pub fn other_syscall_cu(&self) -> i64 {
        self.residual_cu - self.poseidon.total_cu as i64
    }
}

pub fn buckets(
    transaction_cu: u64,
    traces: &[InvocationTrace],
    map: &FunctionMap,
    pricer: SyscallPricer,
) -> Buckets {
    let Reconciliation {
        sbpf_instructions,
        bn254_syscall_cu,
        residual_cu,
        ..
    } = reconcile(transaction_cu, traces, pricer);

    let mut bn254_sbpf_static = 0u64;
    for trace in traces {
        for (pc, count) in &trace.pc_counts {
            if map.lookup(*pc).is_some_and(|s| is_bn254_name(&s.name)) {
                bn254_sbpf_static += count;
            }
        }
    }
    let bn254_sbpf_dynamic: u64 = traces
        .iter()
        .map(|trace| trace.bn254_subtree_instructions)
        .sum();

    Buckets {
        transaction_cu,
        sbpf_total: sbpf_instructions,
        syscall_bn254_cu: bn254_syscall_cu,
        poseidon: poseidon_summary(traces),
        residual_cu,
        bn254_sbpf_static,
        bn254_sbpf_dynamic,
    }
}

/// Flat per-function instruction counts across all invocations, biggest first.
pub fn flat_profile(traces: &[InvocationTrace], map: &FunctionMap) -> Vec<(String, u64, bool)> {
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for trace in traces {
        for (pc, count) in &trace.pc_counts {
            *totals.entry(map.name(*pc)).or_insert(0) += count;
        }
    }
    let mut rows: Vec<(String, u64, bool)> = totals
        .into_iter()
        .map(|(name, count)| {
            let bn254 = is_bn254_name(&name);
            (name, count, bn254)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows
}

/// Inclusive cost of each frame, biggest first. Useful for finding the roots
/// of a subtree; the numbers overlap by construction.
pub fn inclusive_profile(traces: &[InvocationTrace], map: &FunctionMap) -> Vec<(String, u64)> {
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for trace in traces {
        for (entry_pc, count) in &trace.inclusive_by_entry {
            let slot = totals.entry(map.name(*entry_pc)).or_insert(0);
            *slot = (*slot).max(*count);
        }
    }
    let mut rows: Vec<(String, u64)> = totals.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    rows
}

pub fn render(
    label: &str,
    transaction_cu: u64,
    traces: &[InvocationTrace],
    map: &FunctionMap,
    pricer: SyscallPricer,
) -> String {
    use std::fmt::Write;

    let buckets = buckets(transaction_cu, traces, map, pricer);
    let (_, bn254_by_name) = bn254_syscall_total(traces, pricer);
    let others = other_syscall_counts(traces, pricer);
    let mut out = String::new();

    let _ = writeln!(out, "\n=== {label} ===");
    let _ = writeln!(out, "invocations traced        {}", traces.len());
    for trace in traces {
        let _ = writeln!(
            out,
            "  program {}  sbpf {:>8}  syscalls {:>4}  max depth {:>3}  version {}{}",
            bs58(&trace.program_id),
            trace.instructions,
            trace.syscalls.len(),
            trace.max_stack_depth,
            trace.sbpf_version,
            if trace.stack_reconstruction_failed {
                "  STACK WALK FAILED"
            } else {
                ""
            }
        );
    }

    let _ = writeln!(out, "\n-- reconciliation --");
    let _ = writeln!(out, "transaction CU            {:>10}", buckets.transaction_cu);
    let _ = writeln!(out, "sBPF instructions         {:>10}", buckets.sbpf_total);
    let _ = writeln!(out, "BN254 syscall CU          {:>10}", buckets.syscall_bn254_cu);
    let _ = writeln!(out, "residual (other syscalls) {:>10}", buckets.residual_cu);

    let _ = writeln!(out, "\n-- BN254 syscalls --");
    for (name, (count, cu)) in &bn254_by_name {
        let _ = writeln!(out, "  {name:<44} x{count:<4} {cu:>8} CU");
    }
    let _ = writeln!(out, "  per call (r1 selects the op, r3 is the input size):");
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let Some(cu) = pricer(event) else { continue };
        let _ = writeln!(
            out,
            "    {:<40} r1={:<4} r3={:<6} {:>8} CU  from {}",
            event.name,
            event.args[0],
            event.args[2],
            cu,
            truncate(&map.name(event.caller_entry_pc), 70)
        );
    }
    let _ = writeln!(
        out,
        "\n-- other syscalls (all inside the residual; CU shown where registers determine it) --"
    );
    let mut priced_other = 0u64;
    for (name, count) in &others {
        let cu: u64 = traces
            .iter()
            .flat_map(|trace| trace.syscalls.iter())
            .filter(|event| &event.name == name)
            .filter_map(crate::other_syscall_cu)
            .sum();
        priced_other += cu;
        if cu > 0 {
            let _ = writeln!(out, "  {name:<44} x{count:<4} {cu:>8} CU");
        } else {
            let _ = writeln!(out, "  {name:<44} x{count:<4}        ? CU");
        }
    }
    let _ = writeln!(
        out,
        "  {:<44}        {:>8} CU accounted, {} unaccounted",
        "total",
        priced_other,
        buckets.residual_cu - priced_other as i64
    );

    let poseidon = &buckets.poseidon;
    let _ = writeln!(out, "\n-- Poseidon syscall (own family, own line) --");
    let _ = writeln!(
        out,
        "  calls {}  CU {}  ({:.1}% of the transaction)",
        poseidon.calls,
        poseidon.total_cu,
        100.0 * poseidon.total_cu as f64 / buckets.transaction_cu.max(1) as f64
    );
    for (arity, count) in &poseidon.by_arity {
        let _ = writeln!(
            out,
            "    arity {arity:>2}  x{count:<4} {:>8} CU  (61*{arity}^2+542 each)",
            count * crate::poseidon_cu(*arity)
        );
    }
    let mut by_caller: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let Some(arity) = crate::poseidon_arity(event) else {
            continue;
        };
        let slot = by_caller
            .entry(map.name(event.caller_entry_pc))
            .or_insert((0, 0));
        slot.0 += 1;
        slot.1 += crate::poseidon_cu(arity);
    }
    let mut callers: Vec<(String, (u64, u64))> = by_caller.into_iter().collect();
    callers.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    for (name, (count, cu)) in callers {
        let _ = writeln!(out, "    x{count:<4} {cu:>8} CU  from {}", truncate(&name, 96));
    }

    let _ = writeln!(out, "\n-- buckets --");
    let total = buckets.transaction_cu.max(1) as f64;
    let pct = |value: u64| 100.0 * value as f64 / total;
    let _ = writeln!(
        out,
        "  a. syscall, BN254                {:>9}  {:>5.1}%",
        buckets.syscall_bn254_cu,
        pct(buckets.syscall_bn254_cu)
    );
    let _ = writeln!(
        out,
        "  a2. syscall, Poseidon            {:>9}  {:>5.1}%",
        poseidon.total_cu,
        pct(poseidon.total_cu)
    );
    let _ = writeln!(
        out,
        "  b. BN254-adjacent sBPF (dynamic) {:>9}  {:>5.1}%",
        buckets.bn254_sbpf_dynamic,
        pct(buckets.bn254_sbpf_dynamic)
    );
    let _ = writeln!(
        out,
        "     BN254-adjacent sBPF (static)  {:>9}  {:>5.1}%",
        buckets.bn254_sbpf_static,
        pct(buckets.bn254_sbpf_static)
    );
    let _ = writeln!(
        out,
        "  c. non-BN254 program sBPF        {:>9}  {:>5.1}%",
        buckets.non_bn254_sbpf(),
        pct(buckets.non_bn254_sbpf())
    );
    let _ = writeln!(
        out,
        "  d. other syscalls + overhead     {:>9}  {:>5.1}%",
        buckets.other_syscall_cu(),
        100.0 * buckets.other_syscall_cu() as f64 / total
    );
    let _ = writeln!(
        out,
        "\n  syscall / (syscall + BN254-adjacent sBPF) = {:.1}%",
        100.0 * buckets.syscall_share_of_bn254_work()
    );
    let _ = writeln!(
        out,
        "  BN254 reachable ceiling (a + b) / transaction = {:.1}%",
        100.0 * (buckets.syscall_bn254_cu + buckets.bn254_sbpf_dynamic) as f64 / total
    );

    let _ = writeln!(out, "\n-- top functions by exclusive sBPF CU --");
    for (name, count, bn254) in flat_profile(traces, map).into_iter().take(40) {
        let _ = writeln!(
            out,
            "  {:>8}  {}  {}",
            count,
            if bn254 { "BN254" } else { "     " },
            truncate(&name, 110)
        );
    }

    let _ = writeln!(out, "\n-- top frames by inclusive sBPF CU --");
    for (name, count) in inclusive_profile(traces, map).into_iter().take(25) {
        let _ = writeln!(out, "  {:>8}  {}", count, truncate(&name, 110));
    }

    out
}

fn truncate(name: &str, width: usize) -> String {
    if name.len() <= width {
        name.to_string()
    } else {
        format!("{}...", &name[..width])
    }
}

fn bs58(bytes: &[u8; 32]) -> String {
    solana_pubkey::Pubkey::new_from_array(*bytes).to_string()
}
