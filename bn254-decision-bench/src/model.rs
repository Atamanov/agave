use {
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
};

pub const SCHEMA_PREFIX: &str = "helius.bn254-decision-table-v3";
pub const MAX_TRANSACTION_CU: u64 = 1_400_000;

/// The current-basis charge for one `alt_bn128_pairing_map` call.
///
/// The Fp12 finalizer is not the stock precompile - no stock op returns an Fp12
/// element - so the Current + Fp12 column cannot be priced at the stock
/// `group_op` rate. This is the price LiteSVM meters and the price the residual
/// subtracts; using anything else makes the cell reconstruct to a number the
/// runtime never charged.
pub fn current_pairing_map_cu(pairs: u64) -> u64 {
    const BASE: u64 = 17_246;
    const PER_PAIR: u64 = 5_741;
    const SUBGROUP: u64 = 3_595;
    BASE.saturating_add(PER_PAIR.saturating_add(SUBGROUP).saturating_mul(pairs))
}

/// The stock `alt_bn128_group_op` pairing charge, which is consensus today and
/// not part of the batch schedule.
///
/// The per-pair terms are not the whole charge: the syscall also adds
/// `sha256_base_cost`, the input byte count and the output size. The residual
/// subtractor once omitted those three, so they stayed inside the residual
/// while the renderer added them again, overstating every Current cell by
/// between 1,002 and 4,425 CU. One definition now serves both.
pub fn stock_group_op_pairing_cu(pairs: u64) -> u64 {
    const FIRST: u64 = 36_364;
    const OTHER: u64 = 12_121;
    const SHA256_BASE: u64 = 85;
    const ELEMENT_BYTES: u64 = 192;
    const OUTPUT_BYTES: u64 = 32;
    FIRST
        .saturating_add(OTHER.saturating_mul(pairs.saturating_sub(1)))
        .saturating_add(SHA256_BASE)
        .saturating_add(ELEMENT_BYTES.saturating_mul(pairs))
        .saturating_add(OUTPUT_BYTES)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowId {
    Groth16N5SameVk,
    Groth16N2DistinctVk,
    Groth16N3DistinctVk,
    PlonkN2DistinctVkSharedSrs,
    PlonkN3DistinctVkSharedSrs,
}

impl RowId {
    pub const ALL: [Self; 5] = [
        Self::Groth16N5SameVk,
        Self::Groth16N2DistinctVk,
        Self::Groth16N3DistinctVk,
        Self::PlonkN2DistinctVkSharedSrs,
        Self::PlonkN3DistinctVkSharedSrs,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Groth16N5SameVk => "5 real Zolana Groth16 proofs — same VK",
            Self::Groth16N2DistinctVk => "2 real Zolana Groth16 proofs — distinct VKs",
            Self::Groth16N3DistinctVk => "3 real Zolana Groth16 proofs — distinct VKs",
            Self::PlonkN2DistinctVkSharedSrs => {
                "2 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS"
            }
            Self::PlonkN3DistinctVkSharedSrs => {
                "3 PLONK proofs, zolana transact shapes — distinct VKs, shared SRS"
            }
        }
    }

    pub const fn proof_count(self) -> u32 {
        match self {
            Self::Groth16N5SameVk => 5,
            Self::Groth16N2DistinctVk | Self::PlonkN2DistinctVkSharedSrs => 2,
            Self::Groth16N3DistinctVk | Self::PlonkN3DistinctVkSharedSrs => 3,
        }
    }

    pub const fn vk_count(self) -> u32 {
        match self {
            Self::Groth16N5SameVk => 1,
            Self::Groth16N2DistinctVk | Self::PlonkN2DistinctVkSharedSrs => 2,
            Self::Groth16N3DistinctVk | Self::PlonkN3DistinctVkSharedSrs => 3,
        }
    }

    pub const fn is_groth16(self) -> bool {
        matches!(
            self,
            Self::Groth16N5SameVk | Self::Groth16N2DistinctVk | Self::Groth16N3DistinctVk
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColumnId {
    Current,
    BatchB5,
    RegistryB5,
    RecursionB5,
    CurrentFp12,
    BatchFp12B5,
}

impl ColumnId {
    pub const ALL: [Self; 6] = [
        Self::Current,
        Self::BatchB5,
        Self::RegistryB5,
        Self::RecursionB5,
        Self::CurrentFp12,
        Self::BatchFp12B5,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Current => "Current",
            Self::BatchB5 => "Batching syscalls (B5)",
            Self::RegistryB5 => "Batching + VK registry (B5)",
            Self::RecursionB5 => "Recursion over B5",
            Self::CurrentFp12 => "Current + Fp12",
            Self::BatchFp12B5 => "Batching + Fp12 (B5)",
        }
    }

    pub const fn backend_id(self) -> &'static str {
        match self {
            Self::Current => "agave-current",
            Self::CurrentFp12 => "current-fp12",
            Self::BatchFp12B5 => "helius-b5-fp12",
            Self::BatchB5 | Self::RegistryB5 | Self::RecursionB5 => "helius-b5",
        }
    }

    pub const fn pricing_id(self) -> &'static str {
        match self {
            Self::Current => "stock_current",
            Self::BatchB5 | Self::RegistryB5 | Self::RecursionB5 => "b5",
            Self::CurrentFp12 => "current_fp12",
            Self::BatchFp12B5 => "batch_fp12_b5",
        }
    }

    pub fn algorithm_id(self, row: RowId) -> &'static str {
        match (row.is_groth16(), self) {
            (true, Self::Current) => "groth16-current-independent-v1",
            (true, Self::BatchB5) => "groth16-batch-b5-v1",
            (true, Self::RegistryB5) => "groth16-batch-registry-b5-v1",
            (true, Self::RecursionB5) => "groth16-recursion-over-b5-v1",
            (true, Self::CurrentFp12) => "groth16-current-independent-fp12-v1",
            (true, Self::BatchFp12B5) => "groth16-batch-fp12-b5-v1",
            (false, Self::Current) => "plonk-current-independent-v1",
            (false, Self::BatchB5) => "plonk-batch-b5-v1",
            (false, Self::RegistryB5) => "plonk-batch-registry-b5-v1",
            (false, Self::RecursionB5) => "plonk-recursion-over-b5-v1",
            (false, Self::CurrentFp12) => "plonk-current-independent-fp12-v1",
            (false, Self::BatchFp12B5) => "plonk-batch-fp12-b5-v1",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairingCall {
    pub pairs: u32,
    pub full_pairs: u32,
    pub registered_pairs: u32,
    pub calls: u32,
}

impl PairingCall {
    pub const fn full(pairs: u32, calls: u32) -> Self {
        Self {
            pairs,
            full_pairs: pairs,
            registered_pairs: 0,
            calls,
        }
    }

    pub const fn registered(full_pairs: u32, registered_pairs: u32) -> Self {
        Self {
            pairs: full_pairs.saturating_add(registered_pairs),
            full_pairs,
            registered_pairs,
            calls: 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MsmCall {
    pub points: u32,
    pub calls: u32,
}

/// One `alt_bn128_fr_lincomb` call. The scalar syscalls were priced long before
/// any guest reached them; this is the first that does.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrLincombCall {
    pub terms: u32,
    pub calls: u32,
}

/// One atomic multi-VK snarkjs PLONK reduction. The runtime replays the whole
/// transcript and returns the MSM coefficients, so the guest does none of it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlonkMultiVkReduceCall {
    pub contexts: u32,
    pub proofs: u32,
    pub public_inputs: u32,
    pub calls: u32,
}

impl FrLincombCall {
    pub const fn one(terms: u32) -> Self {
        Self { terms, calls: 1 }
    }
}

impl MsmCall {
    pub const fn one(points: u32) -> Self {
        Self { points, calls: 1 }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GtTargetMultiexpCall {
    pub targets: u32,
    pub nontrivial_exponents: u32,
    pub calls: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTrace {
    pub pairing_checks: Vec<PairingCall>,
    pub pairing_maps: Vec<PairingCall>,
    pub msm_calls: Vec<MsmCall>,
    pub gt_target_multiexp_calls: Vec<GtTargetMultiexpCall>,
    pub final_exponentiations: u32,
    pub g2_subgroup_checks: u32,
    /// Stock `alt_bn128_group_op` G1 additions, used by the unbatched path to
    /// build the public-input commitment. The residual subtracts them, so the
    /// table has to charge them or the baseline is short by their whole cost.
    #[serde(default)]
    pub stock_g1_additions: u32,
    /// Stock `alt_bn128_group_op` G1 multiplications, same reason.
    #[serde(default)]
    pub stock_g1_multiplications: u32,
    /// Scalar inner products moved off the guest and into the runtime.
    #[serde(default)]
    pub fr_lincomb_calls: Vec<FrLincombCall>,
    /// The whole PLONK verifier reduction, moved into the runtime.
    #[serde(default)]
    pub plonk_multi_vk_reduce_calls: Vec<PlonkMultiVkReduceCall>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCell {
    pub row_id: RowId,
    pub column_id: ColumnId,
    pub trace: OperationTrace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCountContract {
    pub schema: String,
    pub contract_id: String,
    pub cells: Vec<ExpectedCell>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub origin: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProvenance {
    pub source_manifest_path: String,
    pub source_manifest_sha256: String,
    pub zolana_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRow {
    pub row_id: RowId,
    pub fixture_id: String,
    pub source_record_ids: Vec<String>,
    pub classification: String,
    pub files: Vec<PinnedFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureManifest {
    pub schema: String,
    pub fixture_set_id: String,
    pub artifact_root: String,
    pub provenance: FixtureProvenance,
    pub rows: Vec<FixtureRow>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignMode {
    Draft,
    Final,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutorConfig {
    InTreeLiteSvm,
    Command { argv: Vec<String> },
    Measurements { path: String },
    DeterministicEstimate { residual_contract: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TariffProbeJob {
    pub pricing_id: String,
    pub backend_feature: String,
    pub profile: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TariffSourceConfig {
    Pinned {
        path: String,
    },
    Fresh {
        tariff_id: String,
        samples: u64,
        ns_per_cu: f64,
        source_revision: String,
        captured_at_utc: String,
        jobs: Vec<TariffProbeJob>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSpec {
    pub schema: String,
    pub campaign_id: String,
    pub mode: CampaignMode,
    pub fixture_manifest: String,
    pub expected_counts: String,
    pub tariff_source: TariffSourceConfig,
    pub executor: ExecutorConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    PairingCheck,
    PairingMap,
    RegisteredPairingCheck,
    G1Msm,
    GtTargetMultiexp,
    FinalExponentiation,
    G2SubgroupCheck,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactMeasurement {
    pub method: String,
    pub sample_count: u64,
    pub upper_95_ns: f64,
    pub ns_per_cu: f64,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TariffEntry {
    pub pricing_id: String,
    pub operation: OperationKind,
    pub shape: BTreeMap<String, u64>,
    pub cu: u64,
    pub measurement: ExactMeasurement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct B5Attestation {
    pub backend_id: String,
    pub architecture: String,
    pub cpu_model: String,
    pub logical_cpu_count: u32,
    pub timing_cpu_affinity: String,
    pub rustflags: String,
    pub avx512ifma_build_enabled: bool,
    pub avx512ifma_runtime_detected: bool,
    pub ifma_batch8_dispatches: u64,
    pub ifma_mixed_batch8_dispatches: u64,
    pub measured_on_host: bool,
    pub validator_fleet_calibrated: bool,
    pub cu_conversion_assumption: String,
    pub timing_executable_sha256: String,
    pub observer_executable_sha256: String,
    pub source_revision: String,
    pub captured_at_utc: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactShapeTariff {
    pub schema: String,
    pub tariff_id: String,
    pub coverage: String,
    pub b5_attestation: B5Attestation,
    pub entries: Vec<TariffEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub schema: String,
    pub campaign_id: String,
    pub row_id: RowId,
    pub column_id: ColumnId,
    pub algorithm_id: String,
    pub backend_id: String,
    pub pricing_id: String,
    pub fixture_set_id: String,
    pub fixture_manifest_path: String,
    pub fixture: FixtureRow,
    pub tariff_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementKind {
    FullTransaction,
    DeterministicFullTransactionEstimate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingBasis {
    CurrentRuntimeMeasured,
    MeasurementDerivedProposedExactShape,
    /// Evaluated from the committed runtime charge schedule. The schedule is a
    /// tariff, so a cell priced this way is identical on every host, and the
    /// capture that fitted the constants is provenance rather than an input.
    RuntimeSchedule,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstimateComponent {
    pub pricing_id: String,
    pub operation: OperationKind,
    pub shape: BTreeMap<String, u64>,
    pub calls: u32,
    pub per_call_cu: u64,
    pub total_cu: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EstimateBreakdown {
    pub additive_core_components: Vec<EstimateComponent>,
    pub nested_diagnostic_components: Vec<EstimateComponent>,
    pub non_core_transaction_cu: u64,
    pub non_core_source: String,
    pub total_cu: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualCell {
    pub row_id: RowId,
    pub column_id: ColumnId,
    pub observed_trace: OperationTrace,
    pub non_core_transaction_cu: u64,
    /// Everything LiteSVM metered for the transaction, before any syscall
    /// charge was subtracted. For the stock-priced columns
    /// `syscall_cu + non_core_transaction_cu` must equal this exactly; a
    /// mismatch means the split double counts a charge or drops one.
    #[serde(default)]
    pub transaction_cu: u64,
    pub source: String,
    pub sample_count: u64,
    pub program_sha256: String,
    pub runtime_revision: String,
    pub transaction_log_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResidualCuContract {
    pub schema: String,
    pub contract_id: String,
    pub cells: Vec<ResidualCell>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionMeasurement {
    pub schema: String,
    pub campaign_id: String,
    pub row_id: RowId,
    pub column_id: ColumnId,
    pub algorithm_id: String,
    pub backend_id: String,
    pub pricing_id: String,
    pub fixture_set_id: String,
    pub tariff_sha256: String,
    pub measurement_kind: MeasurementKind,
    pub transaction_cu: u64,
    pub transaction_succeeded: bool,
    pub setup_excluded: bool,
    pub pricing_basis: PricingBasis,
    pub operation_trace_source: String,
    pub program_sha256: String,
    pub runtime_revision: String,
    pub transaction_log_sha256: String,
    pub trace: OperationTrace,
    pub estimate_breakdown: Option<EstimateBreakdown>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignResult {
    pub schema: String,
    pub campaign_id: String,
    pub fixture_manifest_sha256: String,
    pub expected_counts_sha256: String,
    pub exact_shape_tariff_sha256: String,
    pub rows: Vec<RowDescriptor>,
    pub columns: Vec<ColumnDescriptor>,
    pub cells: Vec<TransactionMeasurement>,
    pub tariff: ExactShapeTariff,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RowDescriptor {
    pub id: RowId,
    pub label: String,
    pub proof_count: u32,
    pub vk_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnDescriptor {
    pub id: ColumnId,
    pub label: String,
    pub backend_id: String,
    pub pricing_id: String,
}
