use {
    crate::{Error, model::*},
    std::collections::BTreeSet,
};

fn msm(points: &[u32]) -> Vec<MsmCall> {
    points.iter().copied().map(MsmCall::one).collect()
}

fn trace(
    pairing_checks: Vec<PairingCall>,
    pairing_maps: Vec<PairingCall>,
    msm_calls: Vec<MsmCall>,
    gt_target_multiexp_calls: Vec<GtTargetMultiexpCall>,
) -> OperationTrace {
    let final_exponentiations = pairing_checks
        .iter()
        .chain(&pairing_maps)
        .map(|call| call.calls)
        .sum();
    let g2_subgroup_checks = pairing_checks
        .iter()
        .chain(&pairing_maps)
        .map(|call| call.full_pairs.saturating_mul(call.calls))
        .sum();
    OperationTrace {
        pairing_checks,
        pairing_maps,
        msm_calls,
        gt_target_multiexp_calls,
        final_exponentiations,
        g2_subgroup_checks,
        stock_g1_additions: 0,
        stock_g1_multiplications: 0,
        fr_lincomb_calls: Vec::new(),
        plonk_multi_vk_reduce_calls: Vec::new(),
        keccak_calls: Vec::new(),
    }
}

/// The batch columns hand the whole reduction to the runtime. One call per
/// transaction, one context and one proof per verifying key, one public input
/// each, which is what every zolana verifying key declares.
fn with_multi_vk_reduce(mut trace: OperationTrace, n: u32) -> OperationTrace {
    trace.plonk_multi_vk_reduce_calls = vec![PlonkMultiVkReduceCall {
        contexts: n,
        proofs: n,
        public_inputs: n,
        calls: 1,
    }];
    trace
}

/// The BSB22 hash-to-field reduction, one three-term inner product per outer
/// proof. It replaced an ark-ff byte-at-a-time loop that cost 75,000 CU.
///
/// The outer verification is itself a one-proof fold, so it also carries the
/// fold's own inner products: one negation plus one per public-input column,
/// and the outer statement width is the gamma MSM slot.
fn with_bsb22_reduction(mut trace: OperationTrace) -> OperationTrace {
    let gamma_width = trace
        .msm_calls
        .get(2)
        .map(|call| call.points)
        .unwrap_or_default();
    let mut calls = vec![FrLincombCall::one(3)];
    calls.extend(core::iter::repeat_n(FrLincombCall::one(1), gamma_width as usize));
    trace.fr_lincomb_calls = calls;
    trace
}

/// Inner products the batched fold hands to the runtime, per verifying key.
///
/// Each proof of a key needs its randomizer negated, one term each. A key with
/// several proofs then folds `-sum r` and each public-input column across them,
/// so those widen to the proof count; a key with a single proof reuses the
/// negation and its one column stays one term. Every zolana verifying key
/// declares one public input.
fn with_fp12_fold_lincombs(mut trace: OperationTrace, proofs: u32, keys: u32) -> OperationTrace {
    // A shared key runs the same_vk fold: one negation per proof, then a single
    // inner product across them per public-input column. Distinct keys run the
    // guest's own fp12 fold, where each key holds one proof, so its negation,
    // its column and its running sum are all one term.
    trace.fr_lincomb_calls = if keys == 1 {
        // Order matters: the derivation runs before the fold. It contributes the
        // affine coefficient and the sum-to-one check, and the fold re-checks
        // the invariant, so three n-term folds precede the per-proof negations.
        // A single proof needs none of them: the sum short-circuits and the
        // tail is empty.
        let mut calls = Vec::new();
        if proofs > 1 {
            calls.extend(core::iter::repeat_n(FrLincombCall::one(proofs), 3));
        }
        calls.extend(core::iter::repeat_n(FrLincombCall::one(1), proofs as usize));
        calls.push(FrLincombCall::one(proofs));
        calls
    } else {
        vec![FrLincombCall::one(1); 3 * proofs as usize]
    };
    trace
}

fn with_fold_lincombs(mut trace: OperationTrace, proofs: u32, keys: u32) -> OperationTrace {
    const PUBLIC_INPUT_COLUMNS: u32 = 1;
    let per_key = proofs.checked_div(keys).unwrap_or_default();
    let mut calls = Vec::new();
    for _ in 0..keys {
        for _ in 0..per_key {
            calls.push(FrLincombCall::one(1));
        }
        if per_key > 1 {
            calls.push(FrLincombCall::one(per_key));
        }
        for _ in 0..PUBLIC_INPUT_COLUMNS {
            calls.push(FrLincombCall::one(per_key));
        }
    }
    trace.fr_lincomb_calls = calls;
    trace
}

/// The unbatched columns build their public-input commitment with stock G1
/// operations. Counts come from the observer, never from a guess: the
/// `observed_traces` test fails if the model and the guest disagree.
fn with_stock_g1(mut trace: OperationTrace, additions: u32, multiplications: u32) -> OperationTrace {
    trace.stock_g1_additions = additions;
    trace.stock_g1_multiplications = multiplications;
    trace
}

fn groth_msm(row: RowId, column: ColumnId) -> Vec<MsmCall> {
    // The registry variant reuses the exact B5 fold and replaces only the
    // fixed-G2 suffix at the pairing boundary. It must never grow a second,
    // registry-specific G1 fold.
    let column = if column == ColumnId::RegistryB5 {
        ColumnId::BatchB5
    } else {
        column
    };
    let points: &[u32] = match (row, column) {
        (RowId::Groth16N5SameVk, ColumnId::BatchB5) => &[1, 1, 1, 1, 1, 1, 2, 5],
        (RowId::Groth16N2DistinctVk, ColumnId::BatchB5) => &[1, 1, 1, 2, 1, 1, 2, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::BatchB5) => &[1, 1, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1],
        (RowId::Groth16N5SameVk, ColumnId::RecursionB5) => &[1, 1, 9, 1, 1, 1],
        (RowId::Groth16N2DistinctVk, ColumnId::RecursionB5) => &[1, 1, 6, 1, 1, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::RecursionB5) => &[1, 1, 7, 1, 1, 1],
        (RowId::Groth16N5SameVk, ColumnId::BatchFp12B5) => &[1, 1, 1, 1, 1, 2, 5],
        (RowId::Groth16N2DistinctVk, ColumnId::BatchFp12B5) => &[1, 2, 1, 2, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::BatchFp12B5) => &[1, 1, 2, 1, 2, 1, 2, 1],
        (_, ColumnId::Current | ColumnId::CurrentFp12) => &[],
        _ => unreachable!("Groth16 MSM matrix is exhaustive"),
    };
    msm(points)
}

pub fn expected_trace(row: RowId, column: ColumnId) -> OperationTrace {
    if row.is_groth16() {
        let n = row.proof_count();
        let k = row.vk_count();
        return match column {
            ColumnId::Current => with_stock_g1(
                trace(vec![PairingCall::full(4, n)], vec![], vec![], vec![]),
                n,
                n,
            ),
            ColumnId::BatchB5 => with_fold_lincombs(
                trace(
                    vec![PairingCall::full(
                        n.saturating_add(3u32.saturating_mul(k)),
                        1,
                    )],
                    vec![],
                    groth_msm(row, column),
                    vec![],
                ),
                n,
                k,
            ),
            ColumnId::RegistryB5 => with_fold_lincombs(
                trace(
                    vec![PairingCall::registered(n, 3u32.saturating_mul(k))],
                    vec![],
                    groth_msm(row, column),
                    vec![],
                ),
                n,
                k,
            ),
            ColumnId::RecursionB5 => with_bsb22_reduction(trace(
                vec![PairingCall::full(6, 1)],
                vec![],
                groth_msm(row, column),
                vec![],
            )),
            // This is deliberately n independent current-verifier maps. It is
            // not the batched FP12 fold and therefore has no MSM syscall.
            ColumnId::CurrentFp12 => with_stock_g1(
                trace(vec![], vec![PairingCall::full(3, n)], vec![], vec![]),
                n,
                n,
            ),
            ColumnId::BatchFp12B5 => {
                let gt_target_multiexp_calls = if k > 1 {
                    vec![GtTargetMultiexpCall {
                        targets: k,
                        nontrivial_exponents: k.saturating_sub(1),
                        calls: 1,
                    }]
                } else {
                    vec![]
                };
                with_fp12_fold_lincombs(
                    trace(
                        vec![],
                        vec![PairingCall::full(
                            n.saturating_add(2u32.saturating_mul(k)),
                            1,
                        )],
                        groth_msm(row, column),
                        gt_target_multiexp_calls,
                    ),
                    n,
                    k,
                )
            }
        };
    }

    let n = row.proof_count();
    let folded_msm = || msm(&[2u32.saturating_mul(n), 18u32.saturating_mul(n)]);
    match column {
        ColumnId::Current => with_stock_g1(
            trace(vec![PairingCall::full(2, n)], vec![], vec![], vec![]),
            18u32.saturating_mul(n),
            20u32.saturating_mul(n),
        ),
        ColumnId::BatchB5 => {
            with_multi_vk_reduce(trace(vec![PairingCall::full(2, 1)], vec![], folded_msm(), vec![]), n)
        }
        ColumnId::RegistryB5 => with_multi_vk_reduce(
            trace(
                vec![PairingCall::registered(0, 2)],
                vec![],
                folded_msm(),
                vec![],
            ),
            n,
        ),
        ColumnId::RecursionB5 => {
            let outer_msm: &[u32] = match row {
                RowId::PlonkN2DistinctVkSharedSrs => &[1, 1, 7, 1, 1, 1],
                RowId::PlonkN3DistinctVkSharedSrs => &[1, 1, 10, 1, 1, 1],
                _ => unreachable!("PLONK recursion rows are exhaustive"),
            };
            with_bsb22_reduction(trace(
                vec![PairingCall::full(6, 1)],
                vec![],
                msm(outer_msm),
                vec![],
            ))
        }
        // As above, preserve one independent current-verifier map per proof.
        ColumnId::CurrentFp12 => with_stock_g1(
            trace(vec![], vec![PairingCall::full(2, n)], vec![], vec![]),
            18u32.saturating_mul(n),
            20u32.saturating_mul(n),
        ),
        ColumnId::BatchFp12B5 => {
            with_multi_vk_reduce(trace(vec![], vec![PairingCall::full(2, 1)], folded_msm(), vec![]), n)
        }
    }
}

pub fn builtin_expected_counts() -> ExpectedCountContract {
    ExpectedCountContract {
        schema: format!("{SCHEMA_PREFIX}.expected-counts.v1"),
        contract_id: "bn254-corrected-six-columns-counts-20260805".to_owned(),
        cells: RowId::ALL
            .into_iter()
            .flat_map(|row_id| {
                ColumnId::ALL
                    .into_iter()
                    .map(move |column_id| ExpectedCell {
                        row_id,
                        column_id,
                        trace: expected_trace(row_id, column_id),
                    })
            })
            .collect(),
    }
}

pub fn validate_trace_consistency(trace: &OperationTrace, label: &str) -> Result<(), Error> {
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        if call.calls == 0 || call.pairs == 0 {
            return Err(Error::Contract(format!(
                "{label}: pairing calls and pairs must be nonzero"
            )));
        }
        if call.pairs != call.full_pairs.saturating_add(call.registered_pairs) {
            return Err(Error::Contract(format!(
                "{label}: total pairs do not equal full plus registered pairs"
            )));
        }
    }
    if trace
        .pairing_maps
        .iter()
        .any(|call| call.registered_pairs != 0)
    {
        return Err(Error::Contract(format!(
            "{label}: pairing-map registry inputs are not part of this campaign"
        )));
    }
    if trace
        .msm_calls
        .iter()
        .any(|call| call.calls == 0 || call.points == 0)
    {
        return Err(Error::Contract(format!(
            "{label}: MSM calls and points must be nonzero"
        )));
    }
    if trace.gt_target_multiexp_calls.iter().any(|call| {
        call.calls == 0 || call.targets < 2 || call.nontrivial_exponents >= call.targets
    }) {
        return Err(Error::Contract(format!(
            "{label}: GT target multiexp shape is invalid"
        )));
    }
    let expected_final_exponentiations: u32 = trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.calls)
        .sum();
    if trace.final_exponentiations != expected_final_exponentiations {
        return Err(Error::Contract(format!(
            "{label}: final-exponentiation count is {}, expected {expected_final_exponentiations}",
            trace.final_exponentiations
        )));
    }
    let expected_subgroup_checks: u32 = trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.full_pairs.saturating_mul(call.calls))
        .sum();
    if trace.g2_subgroup_checks != expected_subgroup_checks {
        return Err(Error::Contract(format!(
            "{label}: subgroup-check count is {}, expected {expected_subgroup_checks}",
            trace.g2_subgroup_checks
        )));
    }
    Ok(())
}

pub fn validate_expected_counts(contract: &ExpectedCountContract) -> Result<(), Error> {
    let expected = builtin_expected_counts();
    if contract.schema != expected.schema {
        return Err(Error::Contract(format!(
            "expected-count schema must be {}",
            expected.schema
        )));
    }
    if contract.contract_id != expected.contract_id {
        return Err(Error::Contract(
            "expected-count contract id is not the corrected six-column contract".to_owned(),
        ));
    }
    if contract.cells.len() != RowId::ALL.len().saturating_mul(ColumnId::ALL.len()) {
        return Err(Error::Contract(
            "expected-count contract must contain exactly 5 x 6 cells".to_owned(),
        ));
    }
    let mut identities = BTreeSet::new();
    for cell in &contract.cells {
        if !identities.insert((cell.row_id, cell.column_id)) {
            return Err(Error::Contract(format!(
                "duplicate expected-count cell {:?}/{:?}",
                cell.row_id, cell.column_id
            )));
        }
        validate_trace_consistency(
            &cell.trace,
            &format!("expected {:?}/{:?}", cell.row_id, cell.column_id),
        )?;
    }
    if contract != &expected {
        return Err(Error::Contract(
            "expected-count contract differs from the built-in corrected matrix".to_owned(),
        ));
    }
    Ok(())
}

/// Rejects a document that names a retired B1 column or a derived, rather than
/// measured, value.
///
/// Matching is on whole identifiers. A substring match rejected every real
/// document: `fp12_b5` occurs inside the live column id `batch_fp12_b5`, and
/// `ratio` occurs inside `operation`, a key in every tariff entry. That made
/// the entire campaign entrypoint unreachable, and with it the fixture seal,
/// the tariff attestation and the observed-versus-expected trace comparison.
/// The published tables came from the renderer path instead, which performs
/// none of those checks.
pub fn reject_deprecated_or_derived_json(raw: &str, label: &str) -> Result<(), Error> {
    const FORBIDDEN: &[&str] = &[
        "batch_b1",
        "registry_b1",
        "fp12_b1",
        "fp12_b5",
        "ratio",
        "ratio_scaled",
        "substituted",
        "interpolated",
        "derived_cu",
    ];
    let lowered = raw.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    let boundary = |index: usize| {
        bytes
            .get(index)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
    };
    for token in FORBIDDEN {
        for (start, _) in lowered.match_indices(token) {
            let before_ok = start
                .checked_sub(1)
                .is_none_or(&boundary);
            let after_ok = start
                .checked_add(token.len())
                .is_none_or(&boundary);
            if before_ok && after_ok {
                return Err(Error::Contract(format!(
                    "{label} contains forbidden legacy/derived token `{token}`"
                )));
            }
        }
    }
    Ok(())
}
