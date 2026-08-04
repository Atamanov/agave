use {
    crate::{Error, model::*},
    std::collections::BTreeMap,
};

fn pairing_calls(calls: &[PairingCall]) -> String {
    if calls.is_empty() {
        return "—".to_owned();
    }
    calls
        .iter()
        .map(|call| {
            if call.registered_pairs == 0 {
                format!("{}×{} full", call.calls, call.pairs)
            } else {
                format!(
                    "{}×{} ({} full + {} registered)",
                    call.calls, call.pairs, call.full_pairs, call.registered_pairs
                )
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn msm_calls(calls: &[MsmCall]) -> String {
    if calls.is_empty() {
        return "—".to_owned();
    }
    calls
        .iter()
        .flat_map(|call| std::iter::repeat_n(call.points.to_string(), call.calls as usize))
        .collect::<Vec<_>>()
        .join(", ")
}

fn total_pairing_pairs(trace: &OperationTrace) -> u32 {
    trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.pairs.saturating_mul(call.calls))
        .sum()
}

fn saving(
    row: RowId,
    column: ColumnId,
    current: &OperationTrace,
    candidate: &OperationTrace,
    batch_b5: &OperationTrace,
) -> String {
    let current_pairs = total_pairing_pairs(current);
    let candidate_pairs = total_pairing_pairs(candidate);
    match column {
        ColumnId::Current => "baseline: Agave's current independent verifier".to_owned(),
        ColumnId::BatchB5 => format!(
            "folds {} independent checks into one: pair terms {}→{}, FE {}→{}, subgroup {}→{}; folded MSM sequence is shown",
            row.proof_count(),
            current_pairs,
            candidate_pairs,
            current.final_exponentiations,
            candidate.final_exponentiations,
            current.g2_subgroup_checks,
            candidate.g2_subgroup_checks,
        ),
        ColumnId::RegistryB5 => format!(
            "same one check and identical MSM sequence as B5; authenticated VK G2 entries remove hot subgroup checks {}→{} and live line preparation",
            batch_b5.g2_subgroup_checks, candidate.g2_subgroup_checks,
        ),
        ColumnId::RecursionB5 => format!(
            "replaces the inner verifications with one outer six-pair B5 check: pair terms {}→6, FE {}→1, subgroup {}→6; the outer gamma MSM size is in the sequence",
            current_pairs, current.final_exponentiations, current.g2_subgroup_checks,
        ),
        ColumnId::CurrentFp12 if row.is_groth16() => format!(
            "authenticated alpha-beta target removes one pair per proof while staying independent: pair terms {}→{}, subgroup {}→{}; FE stays {}; no MSM",
            current_pairs,
            candidate_pairs,
            current.g2_subgroup_checks,
            candidate.g2_subgroup_checks,
            candidate.final_exponentiations,
        ),
        ColumnId::CurrentFp12 => {
            "operation counts match Current; the Fp12 map is compared with the canonical GT identity, so any saving is the directly measured map-vs-check cost, not a count reduction".to_owned()
        }
        ColumnId::BatchFp12B5 if row.is_groth16() => {
            let target = if row.vk_count() == 1 {
                "direct authenticated target comparison".to_owned()
            } else {
                format!(
                    "authenticated combination of {} VK targets",
                    row.vk_count()
                )
            };
            format!(
                "one folded map removes the alpha-beta pair for each VK: B5 pair terms {}→{}; FE stays 1, subgroup {}→{}; {}",
                total_pairing_pairs(batch_b5),
                candidate_pairs,
                batch_b5.g2_subgroup_checks,
                candidate.g2_subgroup_checks,
                target,
            )
        }
        ColumnId::BatchFp12B5 => {
            "same folded MSM and two pair terms as B5, but returns Fp12 for comparison with the canonical GT identity; any saving is the directly measured map-vs-check cost".to_owned()
        }
    }
}

fn shape_text(shape: &BTreeMap<String, u64>) -> String {
    shape
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn render_report(result: &CampaignResult) -> Result<String, Error> {
    let cells: BTreeMap<_, _> = result
        .cells
        .iter()
        .map(|cell| ((cell.row_id, cell.column_id), cell))
        .collect();
    if cells.len() != RowId::ALL.len().saturating_mul(ColumnId::ALL.len()) {
        return Err(Error::Contract(
            "report requires exactly one result for every 5 x 6 cell".to_owned(),
        ));
    }

    let mut markdown = String::from("# BN254 decision table\n\n");
    markdown.push_str("## 1. Full-transaction decision table\n\n");
    if result
        .cells
        .iter()
        .any(|cell| cell.measurement_kind == MeasurementKind::DeterministicFullTransactionEstimate)
    {
        markdown.push_str("Values are measurement-derived proposed exact-shape deterministic full-transaction CU estimates: exact syscall shapes use fresh upper-95% host timings converted with Agave's conventional 33 ns/CU basis, plus a transaction-observed non-core residual. They are not validator-fleet-calibrated consensus prices.\n\n");
    } else {
        markdown.push_str("Values are directly observed full-transaction CU.\n\n");
    }
    markdown.push_str("The lowest value in each scenario row is bold.\n\n");
    markdown.push_str("| Scenario |");
    for column in ColumnId::ALL {
        markdown.push_str(&format!(" {} CU |", column.label()));
    }
    markdown.push_str("\n|---|");
    for _ in ColumnId::ALL {
        markdown.push_str("---:|");
    }
    markdown.push('\n');
    for row in RowId::ALL {
        let minimum = ColumnId::ALL
            .iter()
            .map(|column| cells[&(row, *column)].transaction_cu)
            .min()
            .expect("every report row has six cells");
        markdown.push_str(&format!("| {} |", row.label()));
        for column in ColumnId::ALL {
            let cell = cells[&(row, column)];
            if cell.transaction_cu == minimum {
                markdown.push_str(&format!(" **{}** |", cell.transaction_cu));
            } else {
                markdown.push_str(&format!(" {} |", cell.transaction_cu));
            }
        }
        markdown.push('\n');
    }

    markdown.push_str("\n## 2. Pairing, MSM, final-exponentiation, and subgroup-check counts\n\n");
    markdown.push_str("Counting rule: Agave's current syscall and every full-pair batch/map variant deserialize each full G2 with validation, so every full pair contributes one subgroup check; every pairing check or map contains one final exponentiation. Authenticated registry G2 entries skip subgroup validation and line preparation only on the hot path.\n\n");
    markdown.push_str("| Scenario | Variant | Pairing checks | Pairing maps | MSM point sequence | Final exponentiations | G2 subgroup checks | Where the saving is |\n");
    markdown.push_str("|---|---|---|---|---|---:|---:|---|\n");
    for row in RowId::ALL {
        let current = &cells[&(row, ColumnId::Current)].trace;
        for column in ColumnId::ALL {
            let trace = &cells[&(row, column)].trace;
            let explanation = saving(
                row,
                column,
                current,
                trace,
                &cells[&(row, ColumnId::BatchB5)].trace,
            );
            markdown.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                row.label(),
                column.label(),
                pairing_calls(&trace.pairing_checks),
                pairing_calls(&trace.pairing_maps),
                msm_calls(&trace.msm_calls),
                trace.final_exponentiations,
                trace.g2_subgroup_checks,
                explanation,
            ));
        }
    }

    markdown.push_str("\n## 3. Exact-shape operation costs\n\n");
    markdown.push_str("All CU values below come from direct exact-shape upper-95% timing measurements divided by Agave's fixed conventional 33 ns/CU basis. This is proposed pricing, not validator-fleet calibration; interpolation and ratio substitution are rejected. Full pairing/map costs already contain their final exponentiation and full-input subgroup checks, so the standalone rows are diagnostics and are not added again.\n\n");
    markdown
        .push_str("| Pricing family | Operation | Exact shape | CU | Upper 95% ns | Samples |\n");
    markdown.push_str("|---|---|---|---:|---:|---:|\n");
    let mut entries = result.tariff.entries.iter().collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        (
            entry.pricing_id.as_str(),
            entry.operation,
            shape_text(&entry.shape),
        )
    });
    for entry in entries {
        markdown.push_str(&format!(
            "| {} | {:?} | {} | {} | {:.3} | {} |\n",
            entry.pricing_id,
            entry.operation,
            shape_text(&entry.shape),
            entry.cu,
            entry.measurement.upper_95_ns,
            entry.measurement.sample_count,
        ));
    }
    Ok(markdown)
}
