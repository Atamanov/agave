use {
    crate::{
        Error,
        contract::{validate_expected_counts, validate_trace_consistency},
        io::{
            read_bytes, read_json, resolve_reference, sha256_hex, validate_hex_digest, write_json,
            write_text,
        },
        model::*,
        report::render_report,
        tariff::{HostCapabilities, estimate_breakdown, validate_tariff, validate_tariff_coverage},
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        ffi::OsString,
        fs,
        io::Write,
        path::{Path, PathBuf},
        process::{Command, Stdio},
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cli {
    pub campaign: PathBuf,
    pub output: PathBuf,
}

impl Cli {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        let mut campaign = None;
        let mut output = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.to_str() {
                Some("--campaign") => {
                    let value = args
                        .next()
                        .ok_or_else(|| Error::Cli("--campaign requires a JSON path".to_owned()))?;
                    if campaign.replace(PathBuf::from(value)).is_some() {
                        return Err(Error::Cli("--campaign may appear only once".to_owned()));
                    }
                }
                Some("--output") => {
                    let value = args.next().ok_or_else(|| {
                        Error::Cli("--output requires an absolute directory".to_owned())
                    })?;
                    if output.replace(PathBuf::from(value)).is_some() {
                        return Err(Error::Cli("--output may appear only once".to_owned()));
                    }
                }
                Some("--help" | "-h") => {
                    return Err(Error::Cli(
                        "usage: decision_table --campaign CAMPAIGN.json --output ABS_DIR"
                            .to_owned(),
                    ));
                }
                _ => {
                    return Err(Error::Cli(format!(
                        "unknown argument `{}`",
                        arg.to_string_lossy()
                    )));
                }
            }
        }
        let campaign = campaign.ok_or_else(|| Error::Cli("missing --campaign".to_owned()))?;
        let output = output.ok_or_else(|| Error::Cli("missing --output".to_owned()))?;
        if !output.is_absolute() {
            return Err(Error::Cli("--output must be an absolute path".to_owned()));
        }
        Ok(Self { campaign, output })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputPaths {
    pub result_json: PathBuf,
    pub report_markdown: PathBuf,
    pub exact_shape_tariff_json: PathBuf,
}

pub trait TransactionExecutor {
    fn execute(&mut self, request: &ExecutionRequest) -> Result<TransactionMeasurement, Error>;
}

struct CommandExecutor {
    argv: Vec<String>,
}

impl TransactionExecutor for CommandExecutor {
    fn execute(&mut self, request: &ExecutionRequest) -> Result<TransactionMeasurement, Error> {
        let (program, args) = self.argv.split_first().ok_or_else(|| Error::Executor {
            row: format!("{:?}", request.row_id),
            column: format!("{:?}", request.column_id),
            message: "command executor argv is empty".to_owned(),
        })?;
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!("could not start `{program}`: {error}"),
            })?;
        let request_bytes = serde_json::to_vec(request).expect("request serialization cannot fail");
        child
            .stdin
            .take()
            .expect("piped stdin is present")
            .write_all(&request_bytes)
            .map_err(|error| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!("could not write executor request: {error}"),
            })?;
        let output = child.wait_with_output().map_err(|error| Error::Executor {
            row: format!("{:?}", request.row_id),
            column: format!("{:?}", request.column_id),
            message: format!("could not wait for executor: {error}"),
        })?;
        if !output.status.success() {
            return Err(Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!(
                    "adapter exited with {}; stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }
        serde_json::from_slice(&output.stdout).map_err(|error| Error::Executor {
            row: format!("{:?}", request.row_id),
            column: format!("{:?}", request.column_id),
            message: format!("adapter returned invalid strict measurement JSON: {error}"),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MeasurementBundle {
    schema: String,
    measurements: Vec<TransactionMeasurement>,
}

struct BundleExecutor {
    measurements: BTreeMap<(RowId, ColumnId), TransactionMeasurement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeFragment {
    schema: String,
    pricing_id: String,
    backend_feature: String,
    host_architecture: String,
    avx512ifma_compiled: bool,
    ifma_batch8_dispatches: u64,
    ifma_mixed_batch8_dispatches: u64,
    entries: Vec<TariffEntry>,
}

struct TariffArtifact {
    tariff: ExactShapeTariff,
    sha256: String,
    bytes: Vec<u8>,
}

struct DeterministicEstimateExecutor {
    residuals: BTreeMap<(RowId, ColumnId), ResidualCell>,
    tariff: ExactShapeTariff,
}

struct InTreeLiteSvmExecutor {
    collector_binary: PathBuf,
    workspace_root: PathBuf,
    program_dir: PathBuf,
    plonk_fixture_dir: PathBuf,
    runtime_revision: String,
    tariff: ExactShapeTariff,
    temporary_root: PathBuf,
}

impl Drop for InTreeLiteSvmExecutor {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temporary_root);
    }
}

impl TransactionExecutor for InTreeLiteSvmExecutor {
    fn execute(&mut self, request: &ExecutionRequest) -> Result<TransactionMeasurement, Error> {
        let mut child = Command::new(&self.collector_binary)
            .args([
                "--workspace-root",
                &self.workspace_root.display().to_string(),
                "--program-dir",
                &self.program_dir.display().to_string(),
                "--plonk-fixture-dir",
                &self.plonk_fixture_dir.display().to_string(),
                "--runtime-revision",
                &self.runtime_revision,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!("could not start sealed in-tree LiteSVM collector: {error}"),
            })?;
        child
            .stdin
            .take()
            .expect("piped collector stdin exists")
            .write_all(
                &serde_json::to_vec(request).expect("execution request serialization cannot fail"),
            )
            .map_err(|error| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!("could not write collector request: {error}"),
            })?;
        let output = child.wait_with_output().map_err(|error| Error::Executor {
            row: format!("{:?}", request.row_id),
            column: format!("{:?}", request.column_id),
            message: format!("could not wait for in-tree collector: {error}"),
        })?;
        if !output.status.success() {
            return Err(Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!(
                    "in-tree collector exited with {}; stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }
        let residual: ResidualCell =
            serde_json::from_slice(&output.stdout).map_err(|error| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: format!("collector returned invalid strict residual JSON: {error}"),
            })?;
        if residual.row_id != request.row_id
            || residual.column_id != request.column_id
            || residual.source != "observed_in_tree_host_non_core"
            || residual.sample_count != 2
            || residual.runtime_revision != self.runtime_revision
        {
            return Err(Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: "collector residual identity/provenance changed".to_owned(),
            });
        }
        let estimate = estimate_breakdown(
            &self.tariff,
            request.column_id,
            &residual.observed_trace,
            residual.non_core_transaction_cu,
            &residual.source,
        )?;
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
            measurement_kind: MeasurementKind::DeterministicFullTransactionEstimate,
            transaction_cu: estimate.total_cu,
            transaction_succeeded: true,
            setup_excluded: true,
            pricing_basis: PricingBasis::MeasurementDerivedProposedExactShape,
            operation_trace_source: "in_tree_host_observer".to_owned(),
            program_sha256: residual.program_sha256,
            runtime_revision: residual.runtime_revision,
            transaction_log_sha256: residual.transaction_log_sha256,
            trace: residual.observed_trace,
            estimate_breakdown: Some(estimate),
        })
    }
}

impl TransactionExecutor for DeterministicEstimateExecutor {
    fn execute(&mut self, request: &ExecutionRequest) -> Result<TransactionMeasurement, Error> {
        let residual = self
            .residuals
            .remove(&(request.row_id, request.column_id))
            .ok_or_else(|| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: "residual contract has no observed cell".to_owned(),
            })?;
        let estimate = estimate_breakdown(
            &self.tariff,
            request.column_id,
            &residual.observed_trace,
            residual.non_core_transaction_cu,
            &residual.source,
        )?;
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
            measurement_kind: MeasurementKind::DeterministicFullTransactionEstimate,
            transaction_cu: estimate.total_cu,
            transaction_succeeded: true,
            setup_excluded: true,
            pricing_basis: PricingBasis::MeasurementDerivedProposedExactShape,
            operation_trace_source: "in_tree_host_observer".to_owned(),
            program_sha256: residual.program_sha256,
            runtime_revision: residual.runtime_revision,
            transaction_log_sha256: residual.transaction_log_sha256,
            trace: residual.observed_trace,
            estimate_breakdown: Some(estimate),
        })
    }
}

impl TransactionExecutor for BundleExecutor {
    fn execute(&mut self, request: &ExecutionRequest) -> Result<TransactionMeasurement, Error> {
        self.measurements
            .remove(&(request.row_id, request.column_id))
            .ok_or_else(|| Error::Executor {
                row: format!("{:?}", request.row_id),
                column: format!("{:?}", request.column_id),
                message: "measurement bundle has no cell".to_owned(),
            })
    }
}

const REQUIRED_FRESH_TARIFF_JOBS: &[(&str, &str, &str)] = &[
    ("stock_current", "backend-b1-arkworks", "stock_current"),
    ("b1", "backend-b1-arkworks", "batch"),
    ("b2", "backend-b2-arkworks-optimized", "batch"),
    ("b3", "backend-b3-mcl", "batch"),
    ("b4", "backend-b4-helius", "batch"),
    ("b5", "backend-b5-helius-ifma", "batch"),
    ("current_fp12", "backend-b1-arkworks", "batch"),
    ("batch_fp12_b5", "backend-b5-helius-ifma", "batch"),
];

fn validate_fresh_tariff_jobs(jobs: &[TariffProbeJob]) -> Result<(), Error> {
    let actual: BTreeSet<_> = jobs
        .iter()
        .map(|job| {
            (
                job.pricing_id.as_str(),
                job.backend_feature.as_str(),
                job.profile.as_str(),
            )
        })
        .collect();
    let required: BTreeSet<_> = REQUIRED_FRESH_TARIFF_JOBS.iter().copied().collect();
    if jobs.len() != required.len() || actual != required {
        return Err(Error::Contract(format!(
            "fresh tariff jobs must be exactly {REQUIRED_FRESH_TARIFF_JOBS:?}; no pricing-family aliases are allowed"
        )));
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf, Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::Contract("decision benchmark has no workspace parent".to_owned()))
}

fn command_failure(label: &str, output: &std::process::Output) -> Error {
    Error::Contract(format!(
        "{label} failed with {}; stdout={}; stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn linux_affinity_cpu() -> Result<String, Error> {
    if env::consts::OS != "linux" {
        return Err(Error::Contract(
            "fresh tariff measurement requires Linux taskset CPU affinity".to_owned(),
        ));
    }
    let status = fs::read_to_string("/proc/self/status").map_err(|error| {
        Error::Contract(format!("could not read Linux CPU affinity mask: {error}"))
    })?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Contract("Linux Cpus_allowed_list is missing".to_owned()))?;
    let cpu = allowed
        .split(',')
        .next()
        .and_then(|range| range.split('-').next())
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| Error::Contract("Linux Cpus_allowed_list is invalid".to_owned()))?;
    Ok(cpu.to_owned())
}

fn run_pinned_probe(
    binary: &Path,
    args: &[&str],
    root: &Path,
    affinity_cpu: &str,
) -> Result<std::process::Output, Error> {
    Command::new("taskset")
        .args(["-c", affinity_cpu])
        .arg(binary)
        .args(args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            Error::Contract(format!(
                "could not execute CPU-pinned tariff probe on logical CPU {affinity_cpu}: {error}"
            ))
        })
}

fn measure_fresh_tariff(
    tariff_id: &str,
    samples: u64,
    ns_per_cu: f64,
    source_revision: &str,
    captured_at_utc: &str,
    jobs: &[TariffProbeJob],
    host: &HostCapabilities,
) -> Result<TariffArtifact, Error> {
    validate_fresh_tariff_jobs(jobs)?;
    if tariff_id.trim().is_empty()
        || samples != 20
        || ns_per_cu != 33.0
        || !is_revision(source_revision)
        || !captured_at_utc.starts_with("20")
        || !captured_at_utc.ends_with('Z')
    {
        return Err(Error::Contract(
            "fresh tariff metadata is incomplete: tariff_id, exactly 20 samples, the pinned Agave 33ns/CU conversion assumption, exact source revision, and UTC capture time are required"
                .to_owned(),
        ));
    }
    if host.architecture != "x86_64"
        || host.cpu_model == "unavailable"
        || host.logical_cpu_count == 0
        || !host.avx512ifma_runtime_detected
    {
        return Err(Error::Contract(format!(
            "fresh B5 tariff measurement requires x86_64 AVX512IFMA on this host; detected arch={} avx512ifma={}",
            host.architecture, host.avx512ifma_runtime_detected
        )));
    }

    let root = workspace_root()?;
    let affinity_cpu = linux_affinity_cpu()?;
    let git_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&root)
        .output()
        .map_err(|error| Error::Contract(format!("could not inspect Agave revision: {error}")))?;
    if !git_output.status.success() {
        return Err(command_failure("git rev-parse HEAD", &git_output));
    }
    let actual_revision = String::from_utf8_lossy(&git_output.stdout)
        .trim()
        .to_owned();
    if actual_revision != source_revision {
        return Err(Error::Contract(format!(
            "fresh tariff source_revision {source_revision} differs from checked-out Agave revision {actual_revision}"
        )));
    }
    let status_output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(&root)
        .output()
        .map_err(|error| Error::Contract(format!("could not inspect Agave worktree: {error}")))?;
    if !status_output.status.success() {
        return Err(command_failure("git status --porcelain", &status_output));
    }
    if !status_output.stdout.is_empty() {
        return Err(Error::Contract(format!(
            "fresh tariff cannot seal a dirty Agave worktree; git status --porcelain returned:\n{}",
            String::from_utf8_lossy(&status_output.stdout)
        )));
    }

    let temp_root = env::temp_dir().join(format!(
        "helius-bn254-decision-tariff-{}",
        std::process::id()
    ));
    if temp_root.exists() {
        return Err(Error::Contract(format!(
            "fresh tariff temporary build directory already exists: {}",
            temp_root.display()
        )));
    }
    fs::create_dir_all(&temp_root).map_err(|source| Error::Write {
        path: temp_root.clone(),
        source,
    })?;

    let mut features: BTreeSet<_> = jobs.iter().map(|job| job.backend_feature.clone()).collect();
    const B5_OBSERVER_FEATURES: &str = "backend-b5-helius-ifma,core-probe-observer";
    let inherited_rustflags = env::var("RUSTFLAGS").unwrap_or_default();
    let native_rustflags = format!("{inherited_rustflags} -C target-cpu=native");
    let b5_rustflags = format!("{native_rustflags} -C target-feature=+avx512f,+avx512ifma");
    features.insert(B5_OBSERVER_FEATURES.to_owned());
    let mut builds = Vec::with_capacity(features.len());
    for feature in features {
        let target_dir = temp_root.join(feature.replace(['-', ','], "_"));
        let mut command = Command::new(root.join("cargo"));
        command
            .args([
                "build",
                "--release",
                "-q",
                "-p",
                "solana-bn254-decision-bench",
                "--example",
                "core_tariff_probe",
                "--no-default-features",
                "--features",
                &feature,
            ])
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.env(
            "RUSTFLAGS",
            if feature.contains("backend-b5-helius-ifma") {
                &b5_rustflags
            } else {
                &native_rustflags
            },
        );
        let child = command.spawn().map_err(|error| {
            Error::Contract(format!("could not start fresh {feature} build: {error}"))
        })?;
        builds.push((feature, target_dir, child));
    }

    let mut binaries = BTreeMap::new();
    for (feature, target_dir, child) in builds {
        let output = child.wait_with_output().map_err(|error| {
            Error::Contract(format!("could not wait for fresh {feature} build: {error}"))
        })?;
        if !output.status.success() {
            return Err(command_failure(
                &format!("fresh {feature} tariff-probe build"),
                &output,
            ));
        }
        let binary = target_dir.join("release/examples/core_tariff_probe");
        if !binary.is_file() {
            return Err(Error::Contract(format!(
                "fresh {feature} tariff-probe binary is missing at {}",
                binary.display()
            )));
        }
        binaries.insert(feature, binary);
    }

    let mut entries = Vec::new();
    for job in jobs {
        let binary = &binaries[&job.backend_feature];
        let samples_arg = samples.to_string();
        let ns_per_cu_arg = ns_per_cu.to_string();
        let output = run_pinned_probe(
            binary,
            &[
                "--pricing-id",
                &job.pricing_id,
                "--profile",
                &job.profile,
                "--samples",
                &samples_arg,
                "--ns-per-cu",
                &ns_per_cu_arg,
            ],
            &root,
            &affinity_cpu,
        )?;
        if !output.status.success() {
            return Err(command_failure(
                &format!("fresh {} tariff probe", job.pricing_id),
                &output,
            ));
        }
        let mut fragment: ProbeFragment =
            serde_json::from_slice(&output.stdout).map_err(|source| Error::Json {
                path: binaries[&job.backend_feature].clone(),
                source,
            })?;
        if fragment.schema != format!("{SCHEMA_PREFIX}.core-tariff-fragment.v1")
            || fragment.pricing_id != job.pricing_id
            || fragment.backend_feature != job.backend_feature
            || fragment.host_architecture != host.architecture
            || fragment
                .entries
                .iter()
                .any(|entry| entry.pricing_id != job.pricing_id)
        {
            return Err(Error::Contract(format!(
                "fresh {} tariff fragment has mismatched identity, backend, host, or entry pricing",
                job.pricing_id
            )));
        }
        if job.backend_feature == "backend-b5-helius-ifma" {
            if !fragment.avx512ifma_compiled
                || fragment.ifma_batch8_dispatches != 0
                || fragment.ifma_mixed_batch8_dispatches != 0
            {
                return Err(Error::Contract(format!(
                    "fresh {} timing probe lacks compile-time IFMA or unexpectedly includes observer dispatches",
                    job.pricing_id
                )));
            }
        } else if fragment.avx512ifma_compiled
            || fragment.ifma_batch8_dispatches != 0
            || fragment.ifma_mixed_batch8_dispatches != 0
        {
            return Err(Error::Contract(format!(
                "non-B5 {} probe unexpectedly claims an IFMA dispatch attestation",
                job.pricing_id
            )));
        }
        let build_rustflags = if job.backend_feature == "backend-b5-helius-ifma" {
            &b5_rustflags
        } else {
            &native_rustflags
        };
        for entry in &mut fragment.entries {
            entry.measurement.command = format!(
                "taskset -c {affinity_cpu}; build_rustflags={build_rustflags:?}; {}",
                entry.measurement.command
            );
        }
        entries.extend(fragment.entries);
    }

    let attestation_binary = &binaries[B5_OBSERVER_FEATURES];
    let samples_arg = samples.to_string();
    let ns_per_cu_arg = ns_per_cu.to_string();
    let attestation_output = run_pinned_probe(
        attestation_binary,
        &[
            "--pricing-id",
            "b5_dispatch_attestation",
            "--profile",
            "attestation",
            "--samples",
            &samples_arg,
            "--ns-per-cu",
            &ns_per_cu_arg,
        ],
        &root,
        &affinity_cpu,
    )?;
    if !attestation_output.status.success() {
        return Err(command_failure(
            "fresh B5 observer-attestation probe",
            &attestation_output,
        ));
    }
    let attestation_fragment: ProbeFragment = serde_json::from_slice(&attestation_output.stdout)
        .map_err(|source| Error::Json {
            path: attestation_binary.clone(),
            source,
        })?;
    if attestation_fragment.schema != format!("{SCHEMA_PREFIX}.core-tariff-fragment.v1")
        || attestation_fragment.pricing_id != "b5_dispatch_attestation"
        || attestation_fragment.backend_feature != "backend-b5-helius-ifma"
        || attestation_fragment.host_architecture != host.architecture
        || !attestation_fragment.avx512ifma_compiled
        || attestation_fragment.ifma_batch8_dispatches == 0
        || attestation_fragment.ifma_mixed_batch8_dispatches == 0
        || !attestation_fragment.entries.is_empty()
    {
        return Err(Error::Contract(
            "fresh B5 observer binary did not attest compile-time IFMA plus ordinary 8-pair and mixed 5+3 batch8 dispatches"
                .to_owned(),
        ));
    }

    let tariff = ExactShapeTariff {
        schema: format!("{SCHEMA_PREFIX}.exact-shape-tariff.v1"),
        tariff_id: tariff_id.to_owned(),
        coverage: "exact_no_interpolation".to_owned(),
        b5_attestation: B5Attestation {
            backend_id: "helius-b5".to_owned(),
            architecture: host.architecture.clone(),
            cpu_model: host.cpu_model.clone(),
            logical_cpu_count: host.logical_cpu_count,
            timing_cpu_affinity: format!(
                "linux logical CPU {affinity_cpu} via taskset -c"
            ),
            rustflags: b5_rustflags,
            avx512ifma_build_enabled: attestation_fragment.avx512ifma_compiled,
            avx512ifma_runtime_detected: host.avx512ifma_runtime_detected,
            ifma_batch8_dispatches: attestation_fragment.ifma_batch8_dispatches,
            ifma_mixed_batch8_dispatches: attestation_fragment.ifma_mixed_batch8_dispatches,
            measured_on_host: true,
            validator_fleet_calibrated: false,
            cu_conversion_assumption:
                "Agave conventional conversion assumption: 1 CU = 33ns; not validator-fleet calibrated"
                    .to_owned(),
            timing_executable_sha256: sha256_hex(&read_bytes(&binaries["backend-b5-helius-ifma"])?),
            observer_executable_sha256: sha256_hex(&read_bytes(attestation_binary)?),
            source_revision: source_revision.to_owned(),
            captured_at_utc: captured_at_utc.to_owned(),
        },
        entries,
    };
    validate_tariff(&tariff, CampaignMode::Draft, host)?;
    let mut bytes = serde_json::to_vec_pretty(&tariff).map_err(|source| Error::Json {
        path: PathBuf::from("<fresh-exact-shape-tariff>"),
        source,
    })?;
    bytes.push(b'\n');
    let sha256 = sha256_hex(&bytes);
    fs::remove_dir_all(&temp_root).map_err(|source| Error::Write {
        path: temp_root,
        source,
    })?;
    Ok(TariffArtifact {
        tariff,
        sha256,
        bytes,
    })
}

fn load_tariff(
    campaign_path: &Path,
    source: &TariffSourceConfig,
    host: &HostCapabilities,
) -> Result<TariffArtifact, Error> {
    match source {
        TariffSourceConfig::Pinned { path } => {
            let path = resolve_reference(campaign_path, path)?;
            let bytes = read_bytes(&path)?;
            let (tariff, sha256) = read_json::<ExactShapeTariff>(&path, true)?;
            Ok(TariffArtifact {
                tariff,
                sha256,
                bytes,
            })
        }
        TariffSourceConfig::Fresh {
            tariff_id,
            samples,
            ns_per_cu,
            source_revision,
            captured_at_utc,
            jobs,
        } => measure_fresh_tariff(
            tariff_id,
            *samples,
            *ns_per_cu,
            source_revision,
            captured_at_utc,
            jobs,
            host,
        ),
    }
}

fn resolve_sealed_manifest_path(
    manifest_path: &Path,
    value: &str,
    label: &str,
) -> Result<std::path::PathBuf, Error> {
    let manifest_parent = fs::canonicalize(
        manifest_path.parent().unwrap_or_else(|| Path::new(".")),
    )
    .map_err(|error| {
        Error::Contract(format!(
            "cannot canonicalize fixture-manifest directory for {label}: {error}"
        ))
    })?;
    let supplied = Path::new(value);
    if value.is_empty()
        || (!supplied.is_absolute()
            && supplied
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_))))
    {
        return Err(Error::Contract(format!(
            "{label} must be a nonempty portable relative path or an absolute canonical path"
        )));
    }
    let candidate = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        manifest_parent.join(supplied)
    };
    let canonical = fs::canonicalize(&candidate).map_err(|error| {
        Error::Contract(format!(
            "cannot resolve sealed {label} {}: {error}",
            candidate.display()
        ))
    })?;
    if canonical != candidate
        || (!supplied.is_absolute() && !canonical.starts_with(&manifest_parent))
    {
        return Err(Error::Contract(format!(
            "sealed {label} must not traverse outside the bundle or pass through a symlink"
        )));
    }
    Ok(canonical)
}

fn validate_fixture_manifest(
    manifest_path: &Path,
    manifest: &FixtureManifest,
) -> Result<(), Error> {
    let expected_schema = format!("{SCHEMA_PREFIX}.fixture-manifest.v1");
    if manifest.schema != expected_schema {
        return Err(Error::Contract(format!(
            "fixture manifest schema must be {expected_schema}"
        )));
    }
    if manifest.fixture_set_id.trim().is_empty() {
        return Err(Error::Contract("fixture_set_id is empty".to_owned()));
    }
    let artifact_root = resolve_sealed_manifest_path(
        manifest_path,
        &manifest.artifact_root,
        "fixture artifact_root",
    )?;
    if !artifact_root.is_dir() {
        return Err(Error::Contract(
            "fixture artifact_root must resolve to a directory".to_owned(),
        ));
    }
    let source_manifest_path = resolve_sealed_manifest_path(
        manifest_path,
        &manifest.provenance.source_manifest_path,
        "source fixture manifest",
    )?;
    if source_manifest_path.parent() != Some(artifact_root.as_path())
        || !source_manifest_path.is_file()
    {
        return Err(Error::Contract(
            "source fixture manifest must be a canonical file directly under artifact_root"
                .to_owned(),
        ));
    }
    validate_hex_digest(
        &manifest.provenance.source_manifest_sha256,
        "source fixture manifest",
    )?;
    if !is_revision(&manifest.provenance.zolana_revision) {
        return Err(Error::Contract(
            "fixture source provenance is incomplete".to_owned(),
        ));
    }
    let source_bytes = read_bytes(&source_manifest_path)?;
    if sha256_hex(&source_bytes) != manifest.provenance.source_manifest_sha256 {
        return Err(Error::Contract(
            "source fixture manifest digest differs from its provenance seal".to_owned(),
        ));
    }
    let source: serde_json::Value =
        serde_json::from_slice(&source_bytes).map_err(|source| Error::Json {
            path: source_manifest_path.clone(),
            source,
        })?;
    if source
        .get("zolana_commit")
        .and_then(serde_json::Value::as_str)
        != Some(manifest.provenance.zolana_revision.as_str())
    {
        return Err(Error::Contract(
            "strict fixture provenance differs from the sealed source manifest".to_owned(),
        ));
    }
    let source_artifacts: BTreeMap<_, _> = source
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Contract("source fixture artifact list is missing".to_owned()))?
        .iter()
        .map(|artifact| {
            let path = artifact
                .get("path")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::Contract("source artifact path is missing".to_owned()))?;
            Ok((path, artifact))
        })
        .collect::<Result<_, Error>>()?;
    let source_record_ids: BTreeSet<_> = source
        .get("groth16")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            source
                .get("plonk_test_exceptions")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten(),
        )
        .filter_map(|record| record.get("id").and_then(serde_json::Value::as_str))
        .collect();
    if manifest.rows.len() != RowId::ALL.len() {
        return Err(Error::Contract(
            "fixture manifest must contain exactly the five decision rows".to_owned(),
        ));
    }
    let mut row_ids = BTreeSet::new();
    let mut fixture_ids = BTreeSet::new();
    for row in &manifest.rows {
        if !row_ids.insert(row.row_id) || !fixture_ids.insert(row.fixture_id.as_str()) {
            return Err(Error::Contract(
                "fixture manifest has duplicate row or fixture id".to_owned(),
            ));
        }
        if row.files.is_empty()
            || row.source_record_ids.is_empty()
            || row.classification.trim().is_empty()
        {
            return Err(Error::Contract(format!(
                "fixture {:?} has incomplete files/source classification",
                row.row_id
            )));
        }
        if row
            .source_record_ids
            .iter()
            .any(|id| !source_record_ids.contains(id.as_str()))
        {
            return Err(Error::Contract(format!(
                "fixture {:?} cites an unknown source record",
                row.row_id
            )));
        }
        let mut paths = BTreeSet::new();
        for file in &row.files {
            if !paths.insert(file.path.as_str()) {
                return Err(Error::Contract(format!(
                    "fixture {:?} repeats path {}",
                    row.row_id, file.path
                )));
            }
            validate_hex_digest(&file.sha256, &format!("fixture {}", file.path))?;
            if file.origin.trim().is_empty() {
                return Err(Error::Contract(format!(
                    "fixture {} has no origin provenance",
                    file.path
                )));
            }
            let relative = Path::new(&file.path);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(Error::Contract(format!(
                    "fixture path {} is not a portable relative path",
                    file.path
                )));
            }
            let source_artifact = source_artifacts.get(file.path.as_str()).ok_or_else(|| {
                Error::Contract(format!(
                    "fixture {} is absent from the sealed source manifest",
                    file.path
                ))
            })?;
            if source_artifact
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                != Some(file.size_bytes)
                || source_artifact
                    .get("sha256")
                    .and_then(serde_json::Value::as_str)
                    != Some(file.sha256.as_str())
                || source_artifact
                    .get("origin")
                    .and_then(serde_json::Value::as_str)
                    != Some(file.origin.as_str())
            {
                return Err(Error::Contract(format!(
                    "fixture {} differs from its source artifact record",
                    file.path
                )));
            }
            let resolved = artifact_root.join(relative);
            let canonical = fs::canonicalize(&resolved).map_err(|error| {
                Error::Contract(format!(
                    "cannot resolve sealed fixture {}: {error}",
                    resolved.display()
                ))
            })?;
            if canonical != resolved
                || !canonical.starts_with(&artifact_root)
                || !canonical.is_file()
            {
                return Err(Error::Contract(format!(
                    "fixture {} traverses outside artifact_root or passes through a symlink",
                    file.path
                )));
            }
            let bytes = read_bytes(&resolved)?;
            if bytes.len() as u64 != file.size_bytes {
                return Err(Error::Contract(format!(
                    "fixture {} size is {}, manifest pins {}",
                    resolved.display(),
                    bytes.len(),
                    file.size_bytes
                )));
            }
            let actual = sha256_hex(&bytes);
            if actual != file.sha256 {
                return Err(Error::Contract(format!(
                    "fixture {} SHA-256 is {actual}, manifest pins {}",
                    resolved.display(),
                    file.sha256
                )));
            }
        }
    }
    if row_ids != RowId::ALL.into_iter().collect() {
        return Err(Error::Contract(
            "fixture manifest row identities differ from the exact five-row contract".to_owned(),
        ));
    }
    Ok(())
}

fn is_revision(value: &str) -> bool {
    (40..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_measurement(
    measurement: &TransactionMeasurement,
    request: &ExecutionRequest,
    expected: &OperationTrace,
) -> Result<(), Error> {
    let label = format!("{:?}/{:?}", request.row_id, request.column_id);
    let expected_schema = format!("{SCHEMA_PREFIX}.transaction-measurement.v1");
    if measurement.schema != expected_schema
        || measurement.campaign_id != request.campaign_id
        || measurement.row_id != request.row_id
        || measurement.column_id != request.column_id
        || measurement.algorithm_id != request.algorithm_id
        || measurement.backend_id != request.backend_id
        || measurement.pricing_id != request.pricing_id
        || measurement.fixture_set_id != request.fixture_set_id
        || measurement.tariff_sha256 != request.tariff_sha256
    {
        return Err(Error::Contract(format!(
            "{label}: executor response identity/provenance differs from its request"
        )));
    }
    if measurement.transaction_cu == 0
        || measurement.transaction_cu > MAX_TRANSACTION_CU
        || !measurement.transaction_succeeded
        || !measurement.setup_excluded
    {
        return Err(Error::Contract(format!(
            "{label}: result is not a successful bounded full-transaction measurement or explicit estimate"
        )));
    }
    match measurement.measurement_kind {
        MeasurementKind::FullTransaction => {
            if measurement.operation_trace_source != "runtime_observer"
                || measurement.estimate_breakdown.is_some()
                || measurement.pricing_basis != PricingBasis::CurrentRuntimeMeasured
            {
                return Err(Error::Contract(format!(
                    "{label}: measured full transaction must use a runtime observer and no estimate breakdown"
                )));
            }
        }
        MeasurementKind::DeterministicFullTransactionEstimate => {
            let breakdown = measurement.estimate_breakdown.as_ref().ok_or_else(|| {
                Error::Contract(format!("{label}: estimate breakdown is missing"))
            })?;
            if measurement.operation_trace_source != "in_tree_host_observer"
                || breakdown.total_cu != measurement.transaction_cu
                || breakdown.non_core_source != "observed_in_tree_host_non_core"
                || measurement.pricing_basis != PricingBasis::MeasurementDerivedProposedExactShape
            {
                return Err(Error::Contract(format!(
                    "{label}: deterministic estimate provenance or total is invalid"
                )));
            }
        }
    }
    validate_hex_digest(&measurement.program_sha256, &format!("{label} program"))?;
    validate_hex_digest(
        &measurement.transaction_log_sha256,
        &format!("{label} transaction log"),
    )?;
    if !is_revision(&measurement.runtime_revision) {
        return Err(Error::Contract(format!(
            "{label}: runtime_revision must be a 40-64 character lowercase hex revision"
        )));
    }
    validate_trace_consistency(&measurement.trace, &label)?;
    if &measurement.trace != expected {
        return Err(Error::Contract(format!(
            "{label}: runtime operation trace differs from the machine-readable expected-count contract"
        )));
    }
    Ok(())
}

fn validate_residual_contract(contract: &ResidualCuContract) -> Result<(), Error> {
    let expected_schema = format!("{SCHEMA_PREFIX}.residual-cu-contract.v1");
    if contract.schema != expected_schema || contract.contract_id.trim().is_empty() {
        return Err(Error::Contract(format!(
            "residual contract must use schema {expected_schema} and a nonempty id"
        )));
    }
    if contract.cells.len() != RowId::ALL.len().saturating_mul(ColumnId::ALL.len()) {
        return Err(Error::Contract(
            "residual contract must contain all 5 x 6 observed cells".to_owned(),
        ));
    }
    let mut identities = BTreeSet::new();
    for cell in &contract.cells {
        let label = format!("residual {:?}/{:?}", cell.row_id, cell.column_id);
        if !identities.insert((cell.row_id, cell.column_id))
            || cell.source != "observed_in_tree_host_non_core"
            || cell.sample_count < 2
            || cell.observed_trace != crate::expected_trace(cell.row_id, cell.column_id)
        {
            return Err(Error::Contract(format!(
                "{label}: residual is duplicated, unobserved, or differs from the exact trace contract"
            )));
        }
        validate_hex_digest(&cell.program_sha256, &format!("{label} program"))?;
        validate_hex_digest(
            &cell.transaction_log_sha256,
            &format!("{label} transaction log"),
        )?;
        if !is_revision(&cell.runtime_revision) {
            return Err(Error::Contract(format!(
                "{label}: runtime revision is invalid"
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_campaign(
    spec: &CampaignSpec,
    fixture_manifest_path: &Path,
    fixture_manifest: &FixtureManifest,
    expected_counts: &ExpectedCountContract,
    tariff: &ExactShapeTariff,
    fixture_manifest_sha256: &str,
    expected_counts_sha256: &str,
    tariff_sha256: &str,
    executor: &mut dyn TransactionExecutor,
    host: &HostCapabilities,
) -> Result<CampaignResult, Error> {
    let expected_spec_schema = format!("{SCHEMA_PREFIX}.campaign.v1");
    if spec.schema != expected_spec_schema || spec.campaign_id.trim().is_empty() {
        return Err(Error::Contract(format!(
            "campaign must use schema {expected_spec_schema} and a nonempty id"
        )));
    }
    validate_fixture_manifest(fixture_manifest_path, fixture_manifest)?;
    validate_expected_counts(expected_counts)?;
    validate_tariff(tariff, spec.mode, host)?;

    let fixtures: BTreeMap<_, _> = fixture_manifest
        .rows
        .iter()
        .map(|row| (row.row_id, row.clone()))
        .collect();
    let expected: BTreeMap<_, _> = expected_counts
        .cells
        .iter()
        .map(|cell| ((cell.row_id, cell.column_id), cell.trace.clone()))
        .collect();
    let manifest_absolute =
        fs::canonicalize(fixture_manifest_path).map_err(|source| Error::Read {
            path: fixture_manifest_path.to_path_buf(),
            source,
        })?;

    let mut cells = Vec::with_capacity(RowId::ALL.len().saturating_mul(ColumnId::ALL.len()));
    for row_id in RowId::ALL {
        for column_id in ColumnId::ALL {
            let trace = &expected[&(row_id, column_id)];
            let label = format!("{row_id:?}/{column_id:?}");
            validate_tariff_coverage(tariff, column_id, trace, &label)?;
            let request = ExecutionRequest {
                schema: format!("{SCHEMA_PREFIX}.execution-request.v1"),
                campaign_id: spec.campaign_id.clone(),
                row_id,
                column_id,
                algorithm_id: column_id.algorithm_id(row_id).to_owned(),
                backend_id: column_id.backend_id().to_owned(),
                pricing_id: column_id.pricing_id().to_owned(),
                fixture_set_id: fixture_manifest.fixture_set_id.clone(),
                fixture_manifest_path: manifest_absolute.display().to_string(),
                fixture: fixtures[&row_id].clone(),
                tariff_sha256: tariff_sha256.to_owned(),
            };
            let measurement = executor.execute(&request)?;
            validate_measurement(&measurement, &request, trace)?;
            cells.push(measurement);
        }
    }

    Ok(CampaignResult {
        schema: format!("{SCHEMA_PREFIX}.canonical-result.v1"),
        campaign_id: spec.campaign_id.clone(),
        fixture_manifest_sha256: fixture_manifest_sha256.to_owned(),
        expected_counts_sha256: expected_counts_sha256.to_owned(),
        exact_shape_tariff_sha256: tariff_sha256.to_owned(),
        rows: RowId::ALL
            .into_iter()
            .map(|id| RowDescriptor {
                id,
                label: id.label().to_owned(),
                proof_count: id.proof_count(),
                vk_count: id.vk_count(),
            })
            .collect(),
        columns: ColumnId::ALL
            .into_iter()
            .map(|id| ColumnDescriptor {
                id,
                label: id.label().to_owned(),
                backend_id: id.backend_id().to_owned(),
                pricing_id: id.pricing_id().to_owned(),
            })
            .collect(),
        cells,
        tariff: tariff.clone(),
    })
}

fn run_required_command(command: &mut Command, label: &str) -> Result<std::process::Output, Error> {
    let output = command
        .output()
        .map_err(|error| Error::Contract(format!("could not start {label}: {error}")))?;
    if !output.status.success() {
        return Err(command_failure(label, &output));
    }
    Ok(output)
}

fn build_in_tree_litesvm_executor(
    tariff: ExactShapeTariff,
    mode: CampaignMode,
) -> Result<InTreeLiteSvmExecutor, Error> {
    let root = workspace_root()?;
    let revision_output = run_required_command(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root),
        "git rev-parse for in-tree collector",
    )?;
    let runtime_revision = String::from_utf8(revision_output.stdout)
        .map_err(|error| Error::Contract(format!("git revision is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if !is_revision(&runtime_revision) {
        return Err(Error::Contract(
            "in-tree collector runtime revision is not a full lowercase Git revision".to_owned(),
        ));
    }
    if tariff.b5_attestation.source_revision != runtime_revision {
        return Err(Error::Contract(format!(
            "in-tree collector HEAD {runtime_revision} differs from tariff source revision {}",
            tariff.b5_attestation.source_revision
        )));
    }
    if mode == CampaignMode::Final {
        let status = run_required_command(
            Command::new("git")
                .args(["status", "--porcelain", "--untracked-files=all"])
                .current_dir(&root),
            "git status for in-tree collector",
        )?;
        if !status.stdout.is_empty() {
            return Err(Error::Contract(format!(
                "final in-tree collector refuses a dirty worktree:\n{}",
                String::from_utf8_lossy(&status.stdout)
            )));
        }
    }

    let temporary_root = env::temp_dir().join(format!(
        "bn254-decision-in-tree-{}-{}",
        std::process::id(),
        runtime_revision
    ));
    if temporary_root.exists() {
        return Err(Error::Contract(format!(
            "in-tree collector temporary root already exists: {}",
            temporary_root.display()
        )));
    }
    let program_dir = temporary_root.join("programs");
    let collector_target = temporary_root.join("collector-target");
    fs::create_dir_all(&program_dir).map_err(|source| Error::Write {
        path: program_dir.clone(),
        source,
    })?;

    struct SbfBuild<'a> {
        label: &'a str,
        manifest: &'a str,
        features: Option<&'a str>,
    }
    let builds = [
        SbfBuild {
            label: "Groth16 direct decision guest",
            manifest: "bn254-decision-bench/sbf/groth16/Cargo.toml",
            features: None,
        },
        SbfBuild {
            label: "PLONK direct decision guest",
            manifest: "bn254-decision-bench/sbf/plonk-direct/Cargo.toml",
            features: None,
        },
        SbfBuild {
            label: "Groth16 recursion decision guest",
            manifest: "bn254-decision-bench/sbf/groth-recursion/Cargo.toml",
            features: Some("bpf-entrypoint,backend-b5-helius-ifma"),
        },
        SbfBuild {
            label: "PLONK recursion decision guest",
            manifest: "bn254-decision-bench/sbf/plonk-recursion/Cargo.toml",
            features: Some("bpf-entrypoint,backend-b5-helius-ifma"),
        },
    ];
    for build in builds {
        let mut command = Command::new(root.join("cargo-build-sbf"));
        command
            .args(["--tools-version", "v1.54", "--manifest-path"])
            .arg(root.join(build.manifest))
            .arg("--sbf-out-dir")
            .arg(&program_dir);
        if let Some(features) = build.features {
            command
                .arg("--no-default-features")
                .args(["--features", features]);
        }
        command.args(["--", "--locked"]).current_dir(&root);
        run_required_command(&mut command, build.label)?;
    }

    let expected_programs = [
        "bn254_decision_groth16_guest.so",
        "bn254_decision_plonk_direct_guest.so",
        "bn254_decision_groth_recursion_guest.so",
        "bn254_decision_plonk_recursion_guest.so",
    ];
    for name in expected_programs {
        let path = program_dir.join(name);
        let bytes = read_bytes(&path)?;
        if bytes.is_empty() {
            return Err(Error::Contract(format!(
                "fresh SBF artifact {} is empty",
                path.display()
            )));
        }
    }

    let plonk_fixture_dir = temporary_root.join("plonk-fixtures");
    let mut exporter = Command::new("cargo");
    exporter
        .args(["run", "--locked", "--manifest-path"])
        .arg(root.join("bn254-decision-bench/sbf/plonk-direct/Cargo.toml"))
        .args(["--example", "export_rows", "--", "--fixtures-root"])
        .arg(
            root.join(
                "research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions",
            ),
        )
        .arg("--output")
        .arg(&plonk_fixture_dir)
        .current_dir(&root);
    run_required_command(&mut exporter, "canonical PLONK account exporter")?;
    for name in ["manifest.json", "n2.bin", "n3.bin"] {
        let path = plonk_fixture_dir.join(name);
        if read_bytes(&path)?.is_empty() {
            return Err(Error::Contract(format!(
                "canonical PLONK exporter artifact {} is empty",
                path.display()
            )));
        }
    }

    let rustflags = "-C target-cpu=native -C target-feature=+avx512f,+avx512ifma";
    let mut collector_build = Command::new(root.join("cargo"));
    collector_build
        .args([
            "build",
            "--release",
            "--package",
            "solana-bn254-decision-collector",
            "--no-default-features",
            "--features",
            "backend-b5-helius-ifma",
        ])
        .env("CARGO_TARGET_DIR", &collector_target)
        .env("RUSTFLAGS", rustflags)
        .current_dir(&root);
    run_required_command(&mut collector_build, "B5 in-tree LiteSVM collector build")?;
    let collector_binary = collector_target
        .join("release")
        .join("solana-bn254-decision-collector");
    if read_bytes(&collector_binary)?.is_empty() {
        return Err(Error::Contract(
            "fresh B5 collector executable is empty".to_owned(),
        ));
    }

    Ok(InTreeLiteSvmExecutor {
        collector_binary,
        workspace_root: root,
        program_dir,
        plonk_fixture_dir,
        runtime_revision,
        tariff,
        temporary_root,
    })
}

pub fn run_cli(cli: Cli) -> Result<OutputPaths, Error> {
    fs::create_dir_all(&cli.output).map_err(|source| Error::Write {
        path: cli.output.clone(),
        source,
    })?;
    let mut existing = fs::read_dir(&cli.output).map_err(|source| Error::Read {
        path: cli.output.clone(),
        source,
    })?;
    if existing.next().is_some() {
        return Err(Error::Contract(format!(
            "output directory {} is not empty",
            cli.output.display()
        )));
    }

    let (spec, _) = read_json::<CampaignSpec>(&cli.campaign, true)?;
    if spec.mode == CampaignMode::Final && !matches!(spec.executor, ExecutorConfig::InTreeLiteSvm) {
        return Err(Error::Contract(
            "final campaigns require the embedded in-tree LiteSVM executor".to_owned(),
        ));
    }
    let fixture_path = resolve_reference(&cli.campaign, &spec.fixture_manifest)?;
    let expected_path = resolve_reference(&cli.campaign, &spec.expected_counts)?;
    let (fixture_manifest, fixture_sha256) = read_json(&fixture_path, true)?;
    let (expected_counts, expected_sha256) = read_json(&expected_path, true)?;
    let host = HostCapabilities::detect();
    let tariff_artifact = load_tariff(&cli.campaign, &spec.tariff_source, &host)?;
    let tariff = tariff_artifact.tariff;
    let tariff_sha256 = tariff_artifact.sha256;

    let mut executor: Box<dyn TransactionExecutor> = match &spec.executor {
        ExecutorConfig::InTreeLiteSvm => {
            Box::new(build_in_tree_litesvm_executor(tariff.clone(), spec.mode)?)
        }
        ExecutorConfig::Command { argv } => Box::new(CommandExecutor { argv: argv.clone() }),
        ExecutorConfig::Measurements { path } => {
            let path = resolve_reference(&cli.campaign, path)?;
            let (bundle, _) = read_json::<MeasurementBundle>(&path, true)?;
            let expected_schema = format!("{SCHEMA_PREFIX}.measurement-bundle.v1");
            if bundle.schema != expected_schema {
                return Err(Error::Contract(format!(
                    "measurement bundle schema must be {expected_schema}"
                )));
            }
            let mut measurements = BTreeMap::new();
            for measurement in bundle.measurements {
                let key = (measurement.row_id, measurement.column_id);
                if measurements.insert(key, measurement).is_some() {
                    return Err(Error::Contract(
                        "measurement bundle has duplicate cells".to_owned(),
                    ));
                }
            }
            if measurements.len() != RowId::ALL.len().saturating_mul(ColumnId::ALL.len()) {
                return Err(Error::Contract(
                    "measurement bundle must contain exactly 5 x 6 cells".to_owned(),
                ));
            }
            Box::new(BundleExecutor { measurements })
        }
        ExecutorConfig::DeterministicEstimate { residual_contract } => {
            let path = resolve_reference(&cli.campaign, residual_contract)?;
            let (contract, _) = read_json::<ResidualCuContract>(&path, true)?;
            validate_residual_contract(&contract)?;
            let residuals = contract
                .cells
                .into_iter()
                .map(|cell| ((cell.row_id, cell.column_id), cell))
                .collect();
            Box::new(DeterministicEstimateExecutor {
                residuals,
                tariff: tariff.clone(),
            })
        }
    };

    let result = run_campaign(
        &spec,
        &fixture_path,
        &fixture_manifest,
        &expected_counts,
        &tariff,
        &fixture_sha256,
        &expected_sha256,
        &tariff_sha256,
        executor.as_mut(),
        &host,
    )?;
    let report = render_report(&result)?;

    let result_json = cli.output.join("decision-table.canonical.json");
    let report_markdown = cli.output.join("REPORT.md");
    let exact_shape_tariff_json = cli.output.join("exact-shape-tariff.json");
    write_json(&result_json, &result)?;
    write_text(&report_markdown, &report)?;
    fs::write(&exact_shape_tariff_json, tariff_artifact.bytes).map_err(|source| Error::Write {
        path: exact_shape_tariff_json.clone(),
        source,
    })?;
    Ok(OutputPaths {
        result_json,
        report_markdown,
        exact_shape_tariff_json,
    })
}
