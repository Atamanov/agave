//! Where a transaction's compute units actually go.
//!
//! A column named after a syscall should spend most of its budget inside that
//! syscall. When it does not, the column is measuring the guest-side wrapper
//! and the optimization it claims to evaluate is barely exercised. This table
//! exists so that fact is a published number rather than something a reader has
//! to derive from two files.

use {
    solana_bn254_decision_bench::{
        ColumnId, CostSplit, MIN_SYSCALL_SHARE_PER_MILLE, RowId, SYSCALL_BEARING_COLUMNS,
        cost_split, expected_trace, syscall_families,
    },
    solana_program_runtime::execution_budget::SVMTransactionExecutionCost,
    std::{collections::BTreeMap, path::PathBuf},
};

/// A missing or unparsable residual file must abort. Rendering `?` cells at exit
/// zero once let a table advertise a share it had not measured.
fn residuals() -> BTreeMap<String, u64> {
    let path = std::env::var_os("BN254_RESIDUALS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .join("research/bn254-decision-table-v2-20260804/residuals.json")
        });
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must exist, run the pipeline first: {error}", path.display()));
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim().trim_end_matches(',');
        if let Some((key, value)) = line.split_once(':') {
            if let Ok(cu) = value.trim().parse::<u64>() {
                out.insert(key.trim().trim_matches('"').to_owned(), cu);
            }
        }
    }
    out
}

fn key(row: RowId, column: ColumnId) -> String {
    fn snake(s: &str) -> String {
        let mut out = String::new();
        for (i, ch) in s.chars().enumerate() {
            if ch.is_uppercase() && i > 0 {
                out.push('_');
            }
            out.extend(ch.to_lowercase());
        }
        out
    }
    format!("{}/{}", snake(&format!("{row:?}")), snake(&format!("{column:?}")))
}

fn main() {
    let cost = SVMTransactionExecutionCost::default();
    let residual = residuals();
    let mut breaches = Vec::new();

    println!("# BN254 decision table, where the compute units go\n");
    println!("Syscall CU is the charge a validator meters. sBPF is everything the");
    println!("guest program spends preparing it. A syscall column whose share is low");
    println!("is measuring its own wrapper.\n");
    print!("| Scenario |");
    for column in ColumnId::ALL {
        print!(" {} |", column.label());
    }
    println!("\n|---|{}", "---:|".repeat(ColumnId::ALL.len()));

    let mut without_hash = Vec::new();

    for row in RowId::ALL {
        print!("| {} |", row.label());
        for column in ColumnId::ALL {
            let name = key(row, column);
            let r = residual
                .get(&name)
                .unwrap_or_else(|| panic!("{name} has no measured residual"));
            let split = cost_split(&cost, row, column, *r);
            let share = split.syscall_share_per_mille();
            if SYSCALL_BEARING_COLUMNS.contains(&column) && share < MIN_SYSCALL_SHARE_PER_MILLE {
                breaches.push((row, column, share));
            }
            let hash = syscall_families(&cost, column, &expected_trace(row, column)).hash;
            if SYSCALL_BEARING_COLUMNS.contains(&column) {
                without_hash.push((
                    row,
                    column,
                    hash,
                    share,
                    CostSplit {
                        syscall: split.syscall.saturating_sub(hash),
                        sbpf: split.sbpf.saturating_add(hash),
                    }
                    .syscall_share_per_mille(),
                ));
            }
            print!(" {} / {} = {}.{}% |", split.syscall, split.sbpf, share / 10, share % 10);
        }
        println!();
    }

    println!("\nEach cell is `syscall CU / sBPF CU = syscall share`.");
    println!(
        "\nA syscall-bearing column below {}.{}% is reported as a structural breach.",
        MIN_SYSCALL_SHARE_PER_MILLE / 10,
        MIN_SYSCALL_SHARE_PER_MILLE % 10
    );
    println!("\n## What the hash syscalls contribute\n");
    println!("`sol_keccak256` and `sol_sha256` are metered syscall charges, so they");
    println!("belong in the numerator. They are also the one family that moved from");
    println!("the residual without any program changing, so the share is given both");
    println!("ways. The second number is what the cell reads if the hash charge is");
    println!("returned to the guest side.\n");
    println!("| Scenario | Column | Hash CU | Share | Share with hash as sBPF |");
    println!("|---|---|---:|---:|---:|");
    let mut floor = 1_000u64;
    for (row, column, hash, share, bare) in &without_hash {
        println!(
            "| {} | {} | {} | {}.{}% | {}.{}% |",
            row.label(),
            column.label(),
            hash,
            share / 10,
            share % 10,
            bare / 10,
            bare % 10
        );
        floor = floor.min(*bare);
    }
    println!(
        "\nThe lowest syscall-bearing share is {}.{}% once the hash charge is returned to the guest side.",
        floor / 10,
        floor % 10
    );

    if breaches.is_empty() {
        println!("\nNo breach.");
    } else {
        println!("\n## Structural breaches\n");
        for (row, column, share) in &breaches {
            println!(
                "- **{} / {}** spends only {}.{}% of its budget in the syscall it is named after.",
                row.label(),
                column.label(),
                share / 10,
                share % 10
            );
        }
    }
}
