use {
    solana_bn254_decision_bench::{
        B5Attestation, CampaignMode, CampaignSpec, Cli, ColumnId, ExactMeasurement,
        ExactShapeTariff, ExecutionRequest, ExpectedCountContract, FixtureManifest,
        FixtureProvenance, FixtureRow, HostCapabilities, MeasurementKind, MsmCall, OperationKind,
        OutputPaths, PinnedFile, RowId, SCHEMA_PREFIX, TariffEntry,
        TariffSourceConfig, TransactionExecutor, TransactionMeasurement, builtin_expected_counts,
        expected_trace, render_report, run_campaign,
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
    },
    tempfile::TempDir,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn measurement() -> ExactMeasurement {
    ExactMeasurement {
        method: "measured_exact_shape".to_owned(),
        sample_count: 20,
        upper_95_ns: 3_300.0,
        ns_per_cu: 33.0,
        command: "taskset -c 7 cargo bench exact-shape".to_owned(),
    }
}

fn pairing_shape(call: &solana_bn254_decision_bench::PairingCall) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("pairs".to_owned(), u64::from(call.pairs)),
        ("full_pairs".to_owned(), u64::from(call.full_pairs)),
        (
            "registered_pairs".to_owned(),
            u64::from(call.registered_pairs),
        ),
    ])
}

fn unit_shape() -> BTreeMap<String, u64> {
    BTreeMap::from([("count".to_owned(), 1)])
}

fn push_entry(
    entries: &mut Vec<TariffEntry>,
    keys: &mut BTreeSet<(String, OperationKind, String)>,
    pricing_id: &str,
    operation: OperationKind,
    shape: BTreeMap<String, u64>,
) {
    let key = (
        pricing_id.to_owned(),
        operation,
        serde_json::to_string(&shape).unwrap(),
    );
    if keys.insert(key) {
        entries.push(TariffEntry {
            pricing_id: pricing_id.to_owned(),
            operation,
            shape,
            cu: 100,
            measurement: measurement(),
        });
    }
}

fn complete_tariff() -> ExactShapeTariff {
    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    for row in RowId::ALL {
        for column in ColumnId::ALL {
            let trace = expected_trace(row, column);
            for call in &trace.pairing_checks {
                let operation = if call.registered_pairs == 0 {
                    OperationKind::PairingCheck
                } else {
                    OperationKind::RegisteredPairingCheck
                };
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    operation,
                    pairing_shape(call),
                );
            }
            for call in &trace.pairing_maps {
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    OperationKind::PairingMap,
                    pairing_shape(call),
                );
            }
            for call in &trace.msm_calls {
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    OperationKind::G1Msm,
                    BTreeMap::from([("points".to_owned(), u64::from(call.points))]),
                );
            }
            for call in &trace.gt_target_multiexp_calls {
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    OperationKind::GtTargetMultiexp,
                    BTreeMap::from([
                        (
                            "nontrivial_exponents".to_owned(),
                            u64::from(call.nontrivial_exponents),
                        ),
                        ("targets".to_owned(), u64::from(call.targets)),
                    ]),
                );
            }
            if trace.final_exponentiations > 0 {
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    OperationKind::FinalExponentiation,
                    unit_shape(),
                );
            }
            if trace.g2_subgroup_checks > 0 {
                push_entry(
                    &mut entries,
                    &mut keys,
                    column.pricing_id(),
                    OperationKind::G2SubgroupCheck,
                    unit_shape(),
                );
            }
        }
    }
    for pricing_id in ["b1", "b2", "b3", "b4"] {
        push_entry(
            &mut entries,
            &mut keys,
            pricing_id,
            OperationKind::FinalExponentiation,
            unit_shape(),
        );
    }
    ExactShapeTariff {
        schema: format!("{SCHEMA_PREFIX}.exact-shape-tariff.v1"),
        tariff_id: "unit-test-exact-shapes".to_owned(),
        coverage: "exact_no_interpolation".to_owned(),
        b5_attestation: B5Attestation {
            backend_id: "helius-b5".to_owned(),
            architecture: "x86_64".to_owned(),
            cpu_model: "AMD Ryzen Threadripper PRO 9975WX".to_owned(),
            logical_cpu_count: 64,
            timing_cpu_affinity: "linux logical CPU 0 via taskset -c".to_owned(),
            rustflags: "-C target-cpu=native -C target-feature=+avx512f,+avx512ifma".to_owned(),
            avx512ifma_build_enabled: true,
            avx512ifma_runtime_detected: true,
            ifma_batch8_dispatches: 1,
            ifma_mixed_batch8_dispatches: 1,
            measured_on_host: true,
            validator_fleet_calibrated: false,
            cu_conversion_assumption:
                "Agave conventional conversion assumption: 1 CU = 33ns; not validator-fleet calibrated"
                    .to_owned(),
            timing_executable_sha256: digest('6'),
            observer_executable_sha256: digest('7'),
            source_revision: digest('a'),
            captured_at_utc: "2026-08-05T12:00:00Z".to_owned(),
        },
        entries,
    }
}

fn fixture_bundle() -> (TempDir, PathBuf, FixtureManifest) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("fixture-manifest.json");
    let artifact_root = temp.path().join("artifacts");
    fs::create_dir(&artifact_root).unwrap();
    let mut source_artifacts = Vec::new();
    let rows = RowId::ALL
        .into_iter()
        .enumerate()
        .map(|(index, row_id)| {
            let path = format!("fixture-{index}.bin");
            let bytes = format!("canonical fixture {index}").into_bytes();
            fs::write(artifact_root.join(&path), &bytes).unwrap();
            let sha256 = hex::encode(solana_sha256_hasher::hash(&bytes).to_bytes());
            source_artifacts.push(serde_json::json!({
                "path": path.clone(),
                "bytes": bytes.len(),
                "sha256": sha256.clone(),
                "origin": "unit-test source flow",
            }));
            FixtureRow {
                row_id,
                fixture_id: format!("fixture-{index}"),
                source_record_ids: vec![format!("fixture-{index}")],
                classification: "unit-test fixture".to_owned(),
                files: vec![PinnedFile {
                    path,
                    sha256,
                    size_bytes: bytes.len() as u64,
                    origin: "unit-test source flow".to_owned(),
                }],
            }
        })
        .collect();
    let source_manifest_path = artifact_root.join("source-manifest.json");
    let source_manifest = serde_json::json!({
        "zolana_commit": digest('e'),
        "groth16": (0..5).map(|index| serde_json::json!({"id": format!("fixture-{index}")})).collect::<Vec<_>>(),
        "plonk_test_exceptions": [],
        "artifacts": source_artifacts,
    });
    let source_bytes = serde_json::to_vec_pretty(&source_manifest).unwrap();
    fs::write(&source_manifest_path, &source_bytes).unwrap();
    let manifest = FixtureManifest {
        schema: format!("{SCHEMA_PREFIX}.fixture-manifest.v1"),
        fixture_set_id: "unit-test-fixtures".to_owned(),
        artifact_root: "artifacts".to_owned(),
        provenance: FixtureProvenance {
            source_manifest_path: "artifacts/source-manifest.json".to_owned(),
            source_manifest_sha256: hex::encode(
                solana_sha256_hasher::hash(&source_bytes).to_bytes(),
            ),
            zolana_revision: digest('e'),
        },
        rows,
    };
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    (temp, manifest_path, manifest)
}

struct ExactMock;

impl TransactionExecutor for ExactMock {
    fn execute(
        &mut self,
        request: &ExecutionRequest,
    ) -> Result<TransactionMeasurement, solana_bn254_decision_bench::Error> {
        Ok(TransactionMeasurement {
            schema: format!("{SCHEMA_PREFIX}.transaction-measurement.v1"),
            campaign_id: request.campaign_id.clone(),
            row_id: request.row_id,
            column_id: request.column_id,
            algorithm_id: request.algorithm_id.clone(),
            backend_id: request.backend_id.clone(),
            pricing_id: request.pricing_id.clone(),
            fixture_set_id: request.fixture_set_id.clone(),
            tariff_sha256: request.tariff_sha256.clone(),
            measurement_kind: MeasurementKind::FullTransaction,
            transaction_cu: 100_000u64
                .saturating_add(u64::from(request.row_id.proof_count()).saturating_mul(1_000))
                .saturating_add(request.column_id as u64),
            transaction_succeeded: true,
            setup_excluded: true,
            pricing_basis: solana_bn254_decision_bench::PricingBasis::CurrentRuntimeMeasured,
            operation_trace_source: "runtime_observer".to_owned(),
            program_sha256: digest('b'),
            runtime_revision: digest('c'),
            transaction_log_sha256: digest('d'),
            trace: expected_trace(request.row_id, request.column_id),
            estimate_breakdown: None,
        })
    }
}

fn draft_spec() -> CampaignSpec {
    CampaignSpec {
        schema: format!("{SCHEMA_PREFIX}.campaign.v1"),
        campaign_id: "unit-test-campaign".to_owned(),
        mode: CampaignMode::Draft,
        fixture_manifest: "fixture-manifest.json".to_owned(),
        expected_counts: "expected-counts.json".to_owned(),
        tariff_source: TariffSourceConfig::Pinned {
            path: "tariff.json".to_owned(),
        },
        executor: solana_bn254_decision_bench::ExecutorConfig::Measurements {
            path: "measurements.json".to_owned(),
        },
    }
}

fn run_valid_campaign(
    mode: CampaignMode,
    host: HostCapabilities,
) -> Result<solana_bn254_decision_bench::CampaignResult, solana_bn254_decision_bench::Error> {
    let (_temp, manifest_path, manifest) = fixture_bundle();
    let mut spec = draft_spec();
    spec.mode = mode;
    run_campaign(
        &spec,
        &manifest_path,
        &manifest,
        &builtin_expected_counts(),
        &complete_tariff(),
        &digest('1'),
        &digest('2'),
        &digest('3'),
        &mut ExactMock,
        &host,
    )
}

#[test]
fn count_contract_covers_every_cell_exactly_once() {
    let contract = builtin_expected_counts();
    assert_eq!(contract.cells.len(), 30);
    let identities: BTreeSet<_> = contract
        .cells
        .iter()
        .map(|cell| (cell.row_id, cell.column_id))
        .collect();
    assert_eq!(identities.len(), 30);
}

/// Total Miller-loop pairs a trace runs, however the calls are grouped.
fn total_pairs(trace: &solana_bn254_decision_bench::OperationTrace) -> u32 {
    trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.pairs.saturating_mul(call.calls))
        .sum()
}

fn registered_pairs(trace: &solana_bn254_decision_bench::OperationTrace) -> u32 {
    trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.registered_pairs.saturating_mul(call.calls))
        .sum()
}

/// Pairs one Groth16 or PLONK proof needs on the stock path.
fn pairs_per_proof(row: RowId) -> u32 {
    if row.is_groth16() { 4 } else { 2 }
}

/// Current verifies each proof on its own: nothing is shared, so every count
/// scales with the proof count and no batching syscall is reached.
#[test]
fn current_column_is_n_independent_verifications() {
    for row in RowId::ALL {
        let n = row.proof_count();
        let trace = expected_trace(row, ColumnId::Current);
        assert_eq!(trace.final_exponentiations, n, "{row:?}");
        assert!(trace.msm_calls.is_empty(), "{row:?}");
        assert!(trace.gt_target_multiexp_calls.is_empty(), "{row:?}");
        assert!(trace.pairing_maps.is_empty(), "{row:?}");
        assert_eq!(registered_pairs(&trace), 0, "{row:?}");
        assert_eq!(
            trace.pairing_checks,
            vec![solana_bn254_decision_bench::PairingCall::full(
                pairs_per_proof(row),
                n
            )],
            "{row:?}"
        );
        assert_eq!(total_pairs(&trace), pairs_per_proof(row) * n, "{row:?}");
    }
}

/// Batching collapses N independent checks into one, so exactly one final
/// exponentiation is shared and no call runs more pairs than the independent
/// path would.
///
/// Pair count itself only drops where the statements share structure: a shared
/// verifying key folds its alpha/beta and gamma pairs, and PLONK folds its
/// openings. Groth16 rows over distinct keys keep all 4n pairs and win on the
/// shared final exponentiation and on lane packing alone. Asserting a strict
/// drop everywhere would encode a saving this column does not make.
#[test]
fn batch_column_folds_into_one_final_exponentiation() {
    for row in RowId::ALL {
        let current = expected_trace(row, ColumnId::Current);
        let trace = expected_trace(row, ColumnId::BatchB5);
        assert_eq!(trace.final_exponentiations, 1, "{row:?}");
        assert!(
            current.final_exponentiations > 1,
            "{row:?}: every row must have more than one proof to fold"
        );
        assert_eq!(registered_pairs(&trace), 0, "{row:?}");
        assert!(!trace.msm_calls.is_empty(), "{row:?}");
        assert_eq!(
            trace.pairing_checks.iter().map(|call| call.calls).sum::<u32>(),
            1,
            "{row:?}: batching must reach exactly one pairing syscall"
        );
        assert!(
            total_pairs(&trace) <= total_pairs(&current),
            "{row:?}: batching must never run more pairs than verifying each proof alone"
        );
    }
}

/// Where the pair count does fold, and why. A shared key folds its fixed pairs
/// across proofs; PLONK folds every proof into one two-pair opening check.
/// Groth16 over distinct keys cannot fold either, which is what makes the
/// registry and Fp12 columns worth measuring on those rows.
#[test]
fn pair_folding_happens_only_where_the_statements_share_structure() {
    for row in RowId::ALL {
        let current = total_pairs(&expected_trace(row, ColumnId::Current));
        let batch = total_pairs(&expected_trace(row, ColumnId::BatchB5));
        let shares_structure = !row.is_groth16() || row.vk_count() == 1;
        if shares_structure {
            assert!(batch < current, "{row:?}: {batch} !< {current}");
        } else {
            assert_eq!(
                batch, current,
                "{row:?}: distinct Groth16 keys have no pairs to fold"
            );
        }
    }
}

/// Registration moves the fixed-G2 boundary off the hot path. It does not
/// change how many pairs the Miller loop runs, only who paid for their subgroup
/// check and line preparation, so the fold must be identical to plain batching.
#[test]
fn registry_column_reuses_the_fold_and_only_moves_the_g2_boundary() {
    for row in RowId::ALL {
        let batch = expected_trace(row, ColumnId::BatchB5);
        let registry = expected_trace(row, ColumnId::RegistryB5);
        assert_eq!(registry.final_exponentiations, 1, "{row:?}");
        assert_eq!(registry.msm_calls, batch.msm_calls, "{row:?}");
        assert_eq!(total_pairs(&registry), total_pairs(&batch), "{row:?}");
        assert!(
            registered_pairs(&registry) > 0,
            "{row:?}: a registry column with no registered pair is just batching"
        );
        assert!(
            registry.g2_subgroup_checks < batch.g2_subgroup_checks,
            "{row:?}: registered pairs must skip subgroup checks the batch pays"
        );
    }
}

/// Recursion replaces N inner verifications with one outer proof, so its
/// pairing work is the same on every row. That independence is the claim the
/// column makes; row-by-row pinning cannot express it.
#[test]
fn recursion_column_costs_the_same_pairing_work_on_every_row() {
    let mut shapes: Vec<_> = RowId::ALL
        .iter()
        .map(|row| {
            let trace = expected_trace(*row, ColumnId::RecursionB5);
            assert_eq!(trace.final_exponentiations, 1, "{row:?}");
            assert_eq!(registered_pairs(&trace), 0, "{row:?}");
            (trace.pairing_checks.clone(), trace.g2_subgroup_checks)
        })
        .collect();
    shapes.dedup();
    assert_eq!(
        shapes.len(),
        1,
        "recursion must not vary its pairing shape by row: {shapes:?}"
    );
    let (checks, subgroup_checks) = shapes.into_iter().next().expect("one shape");
    assert_eq!(
        checks,
        vec![solana_bn254_decision_bench::PairingCall::full(6, 1)]
    );
    assert_eq!(subgroup_checks, 6);

    // One outer Groth16/BSB22 verification is six MSM calls. Five are single
    // points; only the gamma slot carries the outer public inputs, so that is
    // the one place the inner count may show up. A seventh call, or a second
    // wide slot, would mean the column stopped verifying one outer proof.
    for row in RowId::ALL {
        let msm = expected_trace(row, ColumnId::RecursionB5).msm_calls;
        assert_eq!(msm.len(), 6, "{row:?}: {msm:?}");
        let points: Vec<u32> = msm.iter().map(|call| call.points).collect();
        assert!(msm.iter().all(|call| call.calls == 1), "{row:?}");
        assert_eq!(
            [points[0], points[1], points[3], points[4], points[5]],
            [1, 1, 1, 1, 1],
            "{row:?}: only the gamma slot may widen"
        );
        assert!(points[2] >= row.proof_count(), "{row:?}: {points:?}");
    }

    // The gamma slot is monotone in the inner count within a proof system.
    for rows in RowId::ALL.windows(2) {
        let [lower, higher] = rows else { continue };
        if lower.is_groth16() != higher.is_groth16() || lower.proof_count() >= higher.proof_count()
        {
            continue;
        }
        let gamma = |row: RowId| expected_trace(row, ColumnId::RecursionB5).msm_calls[2].points;
        assert!(
            gamma(*lower) <= gamma(*higher),
            "{lower:?} -> {higher:?}: the outer statement must not shrink as inner proofs are added"
        );
    }
}

/// Current + Fp12 keeps the per-proof independence of Current and only swaps
/// the finalizer, so it maps once per proof and never reaches an MSM syscall.
#[test]
fn current_fp12_column_stays_independent_per_proof() {
    for row in RowId::ALL {
        let n = row.proof_count();
        let trace = expected_trace(row, ColumnId::CurrentFp12);
        assert!(trace.pairing_checks.is_empty(), "{row:?}");
        assert!(trace.msm_calls.is_empty(), "{row:?}");
        assert_eq!(trace.pairing_maps.len(), 1, "{row:?}");
        assert_eq!(trace.pairing_maps[0].calls, n, "{row:?}");
        assert_eq!(
            trace.pairing_maps[0].pairs,
            if row.is_groth16() { 3 } else { 2 },
            "{row:?}"
        );
        assert_eq!(trace.final_exponentiations, n, "{row:?}");
        assert_eq!(
            trace.g2_subgroup_checks,
            if row.is_groth16() { 3u32 } else { 2 }.saturating_mul(n),
            "{row:?}"
        );
    }
}

/// Batching + Fp12 folds like Batching and finishes with one map. Distinct
/// verifying keys leave one GT target each to fold; a shared key leaves none.
#[test]
fn batch_fp12_column_folds_once_and_charges_one_gt_target_per_distinct_key() {
    for row in RowId::ALL {
        let trace = expected_trace(row, ColumnId::BatchFp12B5);
        assert_eq!(trace.pairing_maps.len(), 1, "{row:?}");
        assert_eq!(trace.pairing_maps[0].calls, 1, "{row:?}");
        assert_eq!(trace.final_exponentiations, 1, "{row:?}");
        assert_eq!(registered_pairs(&trace), 0, "{row:?}");
        assert!(!trace.msm_calls.is_empty(), "{row:?}");
    }

    assert!(
        expected_trace(RowId::Groth16N5SameVk, ColumnId::BatchFp12B5)
            .gt_target_multiexp_calls
            .is_empty(),
        "one shared key leaves nothing to fold"
    );
    for (row, targets) in [
        (RowId::Groth16N2DistinctVk, 2),
        (RowId::Groth16N3DistinctVk, 3),
    ] {
        let calls = expected_trace(row, ColumnId::BatchFp12B5).gt_target_multiexp_calls;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].targets, targets);
        assert_eq!(calls[0].nontrivial_exponents, targets - 1);
    }
}

/// The table exists to rank these strategies. Pin the ranking itself, so an
/// edit that inverts it fails here instead of being published as a finding.
/// Pairing work is non-increasing left to right, and registration never changes
/// it at all.
#[test]
fn pairing_work_ranks_current_then_batch_then_registry() {
    for row in RowId::ALL {
        let current = total_pairs(&expected_trace(row, ColumnId::Current));
        let batch = total_pairs(&expected_trace(row, ColumnId::BatchB5));
        let registry = total_pairs(&expected_trace(row, ColumnId::RegistryB5));
        assert!(current >= batch, "{row:?}: {current} !>= {batch}");
        assert_eq!(batch, registry, "{row:?}: {batch} != {registry}");
    }
}

#[test]
fn checked_in_count_contract_matches_the_builtin_matrix() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../research/bn254-decision-table-v2-20260804/expected-counts.v1.json");
    let checked_in: ExpectedCountContract =
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(checked_in, builtin_expected_counts());
}

#[test]
fn campaign_template_requests_all_exact_fresh_pricing_jobs() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../research/bn254-decision-table-v2-20260804/campaign.template.json");
    let campaign: CampaignSpec = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let TariffSourceConfig::Fresh { jobs, .. } = campaign.tariff_source else {
        panic!("campaign template must measure a fresh exact-shape tariff");
    };
    let identities: BTreeSet<_> = jobs
        .iter()
        .map(|job| {
            (
                job.pricing_id.as_str(),
                job.backend_feature.as_str(),
                job.profile.as_str(),
            )
        })
        .collect();
    assert_eq!(identities.len(), 8);
    assert!(identities.contains(&("b5", "backend-b5-helius-ifma", "batch")));
    assert!(identities.contains(&("batch_fp12_b5", "backend-b5-helius-ifma", "batch")));
    assert!(identities.contains(&("current_fp12", "backend-b1-arkworks", "batch")));
}

#[test]
fn strict_real_fixture_manifest_preserves_all_exported_artifacts_and_provenance() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../research/bn254-decision-table-v2-20260804/fixture-manifest.real-20260805.json");
    let manifest: FixtureManifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let unique_files: BTreeSet<_> = manifest
        .rows
        .iter()
        .flat_map(|row| row.files.iter().map(|file| file.path.as_str()))
        .collect();
    assert_eq!(unique_files.len(), 60);
    assert_eq!(
        manifest.rows[0].source_record_ids.len(),
        5,
        "same-VK row must retain all five real source records"
    );
    for (row, combined) in [
        (RowId::Groth16N5SameVk, "rows/G5.bin"),
        (RowId::Groth16N2DistinctVk, "rows/G2.bin"),
        (RowId::Groth16N3DistinctVk, "rows/G3.bin"),
    ] {
        let fixture = manifest
            .rows
            .iter()
            .find(|fixture| fixture.row_id == row)
            .unwrap();
        assert!(fixture.files.iter().any(|file| file.path == combined));
    }

    run_campaign(
        &draft_spec(),
        &path,
        &manifest,
        &builtin_expected_counts(),
        &complete_tariff(),
        &digest('1'),
        &digest('2'),
        &digest('3'),
        &mut ExactMock,
        &HostCapabilities {
            architecture: "aarch64".to_owned(),
            cpu_model: "Apple test CPU".to_owned(),
            logical_cpu_count: 12,
            avx512ifma_runtime_detected: false,
        },
    )
    .unwrap();
}

#[test]
fn legacy_b1_aliases_and_ratio_fields_are_not_in_the_schema() {
    assert!(serde_json::from_str::<ColumnId>(r#""batch_b1""#).is_err());
    assert!(serde_json::from_str::<ColumnId>(r#""registry_b1""#).is_err());
    assert!(serde_json::from_str::<ColumnId>(r#""fp12_b1""#).is_err());
    let mut value = serde_json::to_value(complete_tariff().entries.remove(0)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("ratio".to_owned(), serde_json::json!(0.7));
    assert!(serde_json::from_value::<TariffEntry>(value).is_err());
}

#[test]
fn report_has_only_the_three_required_sections_and_renders_independent_fp12() {
    let result = run_valid_campaign(
        CampaignMode::Draft,
        HostCapabilities {
            architecture: "aarch64".to_owned(),
            cpu_model: "Apple test CPU".to_owned(),
            logical_cpu_count: 12,
            avx512ifma_runtime_detected: false,
        },
    )
    .unwrap();
    let markdown = render_report(&result).unwrap();
    assert_eq!(markdown.matches("\n## ").count(), 3);
    assert!(markdown.contains("## 1. Full-transaction decision table"));
    assert!(
        markdown.contains("## 2. Pairing, MSM, final-exponentiation, and subgroup-check counts")
    );
    assert!(markdown.contains("## 3. Exact-shape operation costs"));
    assert!(markdown.contains("Current + Fp12 | — | 5×3 full | — | 5 | 15"));
    assert!(!markdown.contains("batch_b1"));
    assert!(!markdown.contains("ratio-scaled"));
}

#[test]
fn final_campaign_hard_fails_without_local_x86_ifma() {
    let error = run_valid_campaign(
        CampaignMode::Final,
        HostCapabilities {
            architecture: "aarch64".to_owned(),
            cpu_model: "Apple test CPU".to_owned(),
            logical_cpu_count: 12,
            avx512ifma_runtime_detected: false,
        },
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires this exact x86_64 AVX512IFMA host")
    );
}

#[test]
fn cli_requires_the_public_flags_and_absolute_output() {
    let parsed = Cli::parse([
        OsString::from("--campaign"),
        OsString::from("campaign.json"),
        OsString::from("--output"),
        OsString::from("/tmp/bn254-output"),
    ])
    .unwrap();
    assert_eq!(parsed.campaign, PathBuf::from("campaign.json"));
    assert_eq!(parsed.output, PathBuf::from("/tmp/bn254-output"));
    assert!(
        Cli::parse([
            OsString::from("--campaign"),
            OsString::from("campaign.json"),
            OsString::from("--output"),
            OsString::from("relative"),
        ])
        .is_err()
    );
    let _: Option<OutputPaths> = None;
    let _: Option<MsmCall> = None;
}

/// The forbidden-token screen matched substrings, so `fp12_b5` inside the live
/// column id `batch_fp12_b5` and `ratio` inside `operation` rejected every real
/// document. That took the whole campaign entrypoint offline, and with it every
/// seal and trace check it performs.
#[test]
fn forbidden_token_screen_admits_the_documents_the_campaign_actually_reads() {
    use solana_bn254_decision_bench::reject_deprecated_or_derived_json as screen;

    for (label, raw) in [
        ("column id", r#"{"column_id":"batch_fp12_b5"}"#),
        ("pricing id", r#"{"pricing_id":"batch_fp12_b5"}"#),
        ("tariff key", r#"{"operation":"PairingCheck"}"#),
        ("both", r#"{"operation":"G1Msm","pricing_id":"batch_fp12_b5"}"#),
    ] {
        assert!(screen(raw, label).is_ok(), "{label} must be readable: {raw}");
    }

    for (label, raw) in [
        ("retired column", r#"{"column_id":"fp12_b5"}"#),
        ("retired b1", r#"{"column_id":"batch_b1"}"#),
        ("derived value", r#"{"derived_cu":1}"#),
        ("ratio field", r#"{"ratio":1.23}"#),
    ] {
        assert!(screen(raw, label).is_err(), "{label} must be rejected: {raw}");
    }
}

/// Every JSON document the campaign reads must survive its own screen. This is
/// the regression that the substring bug was: the committed files were
/// unreadable by the code meant to validate them.
#[test]
fn every_committed_campaign_document_passes_its_own_screen() {
    use solana_bn254_decision_bench::reject_deprecated_or_derived_json as screen;

    let research = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../research/bn254-decision-table-v2-20260804");
    for name in [
        "expected-counts.v1.json",
        "campaign.template.json",
        "fixture-manifest.real-20260805.json",
    ] {
        let path = research.join(name);
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        screen(&raw, name).unwrap_or_else(|e| panic!("{name} is unreadable by the campaign: {e}"));
    }
}
