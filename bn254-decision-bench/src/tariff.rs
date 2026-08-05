use {
    crate::{Error, model::*},
    std::collections::{BTreeMap, BTreeSet},
};

const REQUIRED_PRICING_FAMILIES: &[&str] = &[
    "stock_current",
    "b1",
    "b2",
    "b3",
    "b4",
    "b5",
    "current_fp12",
    "batch_fp12_b5",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCapabilities {
    pub architecture: String,
    pub cpu_model: String,
    pub logical_cpu_count: u32,
    pub avx512ifma_runtime_detected: bool,
}

impl HostCapabilities {
    pub fn detect() -> Self {
        Self {
            architecture: std::env::consts::ARCH.to_owned(),
            cpu_model: detect_cpu_model(),
            logical_cpu_count: std::thread::available_parallelism()
                .ok()
                .and_then(|count| u32::try_from(count.get()).ok())
                .unwrap_or(0),
            avx512ifma_runtime_detected: runtime_has_avx512ifma(),
        }
    }
}

fn detect_cpu_model() -> String {
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(model) = cpuinfo.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| matches!(key.trim(), "model name" | "Hardware"))
                .map(|(_, value)| value.trim())
                .filter(|value| !value.is_empty())
        }) {
            return model.to_owned();
        }
    }
    if let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
    {
        if output.status.success() {
            let model = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !model.is_empty() {
                return model;
            }
        }
    }
    "unavailable".to_owned()
}

#[cfg(target_arch = "x86_64")]
fn runtime_has_avx512ifma() -> bool {
    std::arch::is_x86_feature_detected!("avx512ifma")
}

#[cfg(not(target_arch = "x86_64"))]
fn runtime_has_avx512ifma() -> bool {
    false
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_shape_keys(operation: OperationKind) -> &'static [&'static str] {
    match operation {
        OperationKind::PairingCheck
        | OperationKind::PairingMap
        | OperationKind::RegisteredPairingCheck => &["full_pairs", "pairs", "registered_pairs"],
        OperationKind::G1Msm => &["points"],
        OperationKind::GtTargetMultiexp => &["nontrivial_exponents", "targets"],
        OperationKind::FinalExponentiation | OperationKind::G2SubgroupCheck => &["count"],
    }
}

fn validate_shape(entry: &TariffEntry, label: &str) -> Result<(), Error> {
    let keys: Vec<_> = entry.shape.keys().map(String::as_str).collect();
    if keys != required_shape_keys(entry.operation) {
        return Err(Error::Contract(format!(
            "{label}: exact shape keys are {keys:?}, expected {:?}",
            required_shape_keys(entry.operation)
        )));
    }
    if entry.shape.values().any(|value| *value == 0) {
        match entry.operation {
            OperationKind::PairingCheck
            | OperationKind::PairingMap
            | OperationKind::RegisteredPairingCheck => {}
            _ => {
                return Err(Error::Contract(format!(
                    "{label}: exact shape values must be nonzero"
                )));
            }
        }
    }
    if matches!(
        entry.operation,
        OperationKind::PairingCheck
            | OperationKind::PairingMap
            | OperationKind::RegisteredPairingCheck
    ) {
        let pairs = entry.shape["pairs"];
        let full = entry.shape["full_pairs"];
        let registered = entry.shape["registered_pairs"];
        if pairs == 0 || pairs != full.saturating_add(registered) {
            return Err(Error::Contract(format!(
                "{label}: pairing shape must have nonzero pairs = full_pairs + registered_pairs"
            )));
        }
        if entry.operation == OperationKind::RegisteredPairingCheck && registered == 0 {
            return Err(Error::Contract(format!(
                "{label}: registered pairing tariff has no registered pairs"
            )));
        }
        if entry.operation != OperationKind::RegisteredPairingCheck && registered != 0 {
            return Err(Error::Contract(format!(
                "{label}: non-registry tariff includes registered pairs"
            )));
        }
    }
    if matches!(
        entry.operation,
        OperationKind::FinalExponentiation | OperationKind::G2SubgroupCheck
    ) && entry.shape["count"] != 1
    {
        return Err(Error::Contract(format!(
            "{label}: component tariffs must be measured per one operation"
        )));
    }
    if entry.operation == OperationKind::GtTargetMultiexp
        && (entry.shape["targets"] < 2
            || entry.shape["nontrivial_exponents"] >= entry.shape["targets"])
    {
        return Err(Error::Contract(format!(
            "{label}: GT target multiexp shape is invalid"
        )));
    }
    Ok(())
}

fn entry_key(entry: &TariffEntry) -> (String, OperationKind, String) {
    (
        entry.pricing_id.clone(),
        entry.operation,
        serde_json::to_string(&entry.shape).expect("BTreeMap serialization cannot fail"),
    )
}

fn find_entry<'a>(
    tariff: &'a ExactShapeTariff,
    pricing_id: &str,
    operation: OperationKind,
    shape: &BTreeMap<String, u64>,
) -> Option<&'a TariffEntry> {
    tariff.entries.iter().find(|entry| {
        entry.pricing_id == pricing_id && entry.operation == operation && &entry.shape == shape
    })
}

pub fn validate_tariff(
    tariff: &ExactShapeTariff,
    mode: CampaignMode,
    host: &HostCapabilities,
) -> Result<(), Error> {
    let expected_schema = format!("{SCHEMA_PREFIX}.exact-shape-tariff.v1");
    if tariff.schema != expected_schema {
        return Err(Error::Contract(format!(
            "tariff schema must be {expected_schema}"
        )));
    }
    // Two bases, and they validate differently. `exact_no_interpolation` is a
    // timing capture converted at 33 ns/CU, so it must prove where it ran.
    // `runtime_schedule` evaluates the committed charge constants, which are a
    // tariff and therefore host-independent: demanding an on-host x86
    // attestation of it would assert something untrue.
    let from_runtime_schedule = tariff.coverage == "runtime_schedule";
    if !from_runtime_schedule && tariff.coverage != "exact_no_interpolation" {
        return Err(Error::Contract(
            "tariff coverage must be exact_no_interpolation or runtime_schedule; ratios and interpolation are forbidden"
                .to_owned(),
        ));
    }
    if tariff.entries.is_empty() {
        return Err(Error::Contract(
            "tariff has no exact-shape entries".to_owned(),
        ));
    }

    let mut keys = BTreeSet::new();
    let mut pricing_families = BTreeSet::new();
    for (index, entry) in tariff.entries.iter().enumerate() {
        let label = format!("tariff entry {index}");
        validate_shape(entry, &label)?;
        if from_runtime_schedule {
            if entry.cu == 0
                || entry.measurement.method != "runtime_schedule"
                || entry.measurement.command.trim().is_empty()
            {
                return Err(Error::Contract(format!(
                    "{label}: a runtime-schedule tariff needs a positive charge and the expression that produced it"
                )));
            }
        } else if entry.cu == 0
            || entry.measurement.method != "measured_exact_shape"
            || entry.measurement.sample_count < 2
            || !entry.measurement.upper_95_ns.is_finite()
            || entry.measurement.upper_95_ns <= 0.0
            || entry.measurement.ns_per_cu != 33.0
            || entry.measurement.command.trim().is_empty()
        {
            return Err(Error::Contract(format!(
                "{label}: tariff must contain a positive, directly measured exact-shape sample"
            )));
        }
        if !keys.insert(entry_key(entry)) {
            return Err(Error::Contract(format!(
                "{label}: duplicate pricing/operation/shape tariff"
            )));
        }
        pricing_families.insert(entry.pricing_id.as_str());
    }
    for family in REQUIRED_PRICING_FAMILIES {
        if !pricing_families.contains(family) {
            return Err(Error::Contract(format!(
                "tariff is missing required pricing family `{family}`"
            )));
        }
    }

    let attestation = &tariff.b5_attestation;
    if from_runtime_schedule {
        // The schedule cites the capture that fitted it, and that capture ran
        // somewhere else. Requiring the on-host fields here would force the
        // file to claim this run measured them.
        if attestation.backend_id != "helius-b5"
            || attestation.source_revision.trim().is_empty()
            || attestation.validator_fleet_calibrated
        {
            return Err(Error::Contract(
                "a runtime-schedule tariff must name the B5 backend and the revision whose constants it read, and must not claim fleet calibration"
                    .to_owned(),
            ));
        }
        return Ok(());
    }
    if attestation.backend_id != "helius-b5"
        || attestation.architecture != "x86_64"
        || attestation.cpu_model.trim().is_empty()
        || attestation.cpu_model == "unavailable"
        || attestation.logical_cpu_count == 0
        || !attestation
            .timing_cpu_affinity
            .starts_with("linux logical CPU ")
        || !attestation.timing_cpu_affinity.ends_with(" via taskset -c")
        || !attestation.rustflags.contains("-C target-cpu=native")
        || !attestation.rustflags.contains("+avx512f,+avx512ifma")
        || !attestation.avx512ifma_build_enabled
        || !attestation.avx512ifma_runtime_detected
        || attestation.ifma_batch8_dispatches == 0
        || attestation.ifma_mixed_batch8_dispatches == 0
        || !attestation.measured_on_host
        || attestation.validator_fleet_calibrated
        || attestation.cu_conversion_assumption
            != "Agave conventional conversion assumption: 1 CU = 33ns; not validator-fleet calibrated"
        || !(40..=64).contains(&attestation.source_revision.len())
        || !is_lower_hex(&attestation.source_revision)
        || !attestation.captured_at_utc.starts_with("20")
        || !attestation.captured_at_utc.ends_with('Z')
    {
        return Err(Error::Contract(
            "B5 tariff lacks a complete x86_64 AVX512IFMA on-host attestation with the explicit non-calibrated 33ns/CU conversion assumption"
                .to_owned(),
        ));
    }
    crate::io::validate_hex_digest(
        &attestation.timing_executable_sha256,
        "B5 timing executable",
    )?;
    crate::io::validate_hex_digest(
        &attestation.observer_executable_sha256,
        "B5 observer executable",
    )?;
    if mode == CampaignMode::Final
        && (host.architecture != "x86_64"
            || !host.avx512ifma_runtime_detected
            || host.cpu_model != attestation.cpu_model
            || host.logical_cpu_count != attestation.logical_cpu_count)
    {
        return Err(Error::Contract(format!(
            "final B5 campaign requires this exact x86_64 AVX512IFMA host; detected arch={} cpu={:?} logical_cpus={} avx512ifma={}",
            host.architecture,
            host.cpu_model,
            host.logical_cpu_count,
            host.avx512ifma_runtime_detected
        )));
    }
    Ok(())
}

pub fn pairing_shape(call: &PairingCall) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("pairs".to_owned(), u64::from(call.pairs)),
        ("full_pairs".to_owned(), u64::from(call.full_pairs)),
        (
            "registered_pairs".to_owned(),
            u64::from(call.registered_pairs),
        ),
    ])
}

pub fn msm_shape(call: &MsmCall) -> BTreeMap<String, u64> {
    BTreeMap::from([("points".to_owned(), u64::from(call.points))])
}

pub fn gt_target_multiexp_shape(call: &GtTargetMultiexpCall) -> BTreeMap<String, u64> {
    BTreeMap::from([
        (
            "nontrivial_exponents".to_owned(),
            u64::from(call.nontrivial_exponents),
        ),
        ("targets".to_owned(), u64::from(call.targets)),
    ])
}

pub fn unit_shape() -> BTreeMap<String, u64> {
    BTreeMap::from([("count".to_owned(), 1)])
}

pub fn validate_tariff_coverage(
    tariff: &ExactShapeTariff,
    column: ColumnId,
    trace: &OperationTrace,
    label: &str,
) -> Result<(), Error> {
    let available: BTreeSet<_> = tariff.entries.iter().map(entry_key).collect();
    let pricing = column.pricing_id();
    let mut required = Vec::new();
    for call in &trace.pairing_checks {
        let operation = if call.registered_pairs == 0 {
            OperationKind::PairingCheck
        } else {
            OperationKind::RegisteredPairingCheck
        };
        required.push((operation, pairing_shape(call)));
    }
    for call in &trace.pairing_maps {
        required.push((OperationKind::PairingMap, pairing_shape(call)));
    }
    for call in &trace.msm_calls {
        required.push((OperationKind::G1Msm, msm_shape(call)));
    }
    for call in &trace.gt_target_multiexp_calls {
        required.push((
            OperationKind::GtTargetMultiexp,
            gt_target_multiexp_shape(call),
        ));
    }
    if trace.final_exponentiations > 0 {
        required.push((OperationKind::FinalExponentiation, unit_shape()));
    }
    if trace.g2_subgroup_checks > 0 {
        required.push((OperationKind::G2SubgroupCheck, unit_shape()));
    }

    for (operation, shape) in required {
        let key = (
            pricing.to_owned(),
            operation,
            serde_json::to_string(&shape).expect("BTreeMap serialization cannot fail"),
        );
        if !available.contains(&key) {
            return Err(Error::Contract(format!(
                "{label}: missing exact tariff for pricing={pricing} operation={operation:?} shape={shape:?}"
            )));
        }
    }
    Ok(())
}

pub fn estimate_breakdown(
    tariff: &ExactShapeTariff,
    column: ColumnId,
    trace: &OperationTrace,
    non_core_transaction_cu: u64,
    non_core_source: &str,
) -> Result<EstimateBreakdown, Error> {
    let pricing_id = column.pricing_id();
    let mut additive_shapes = Vec::new();
    for call in &trace.pairing_checks {
        additive_shapes.push((
            if call.registered_pairs == 0 {
                OperationKind::PairingCheck
            } else {
                OperationKind::RegisteredPairingCheck
            },
            pairing_shape(call),
            call.calls,
        ));
    }
    for call in &trace.pairing_maps {
        additive_shapes.push((OperationKind::PairingMap, pairing_shape(call), call.calls));
    }
    for call in &trace.msm_calls {
        additive_shapes.push((OperationKind::G1Msm, msm_shape(call), call.calls));
    }
    for call in &trace.gt_target_multiexp_calls {
        additive_shapes.push((
            OperationKind::GtTargetMultiexp,
            gt_target_multiexp_shape(call),
            call.calls,
        ));
    }

    let mut additive_core_components = Vec::new();
    let mut additive_total = 0u64;
    for (operation, shape, calls) in additive_shapes {
        let entry = find_entry(tariff, pricing_id, operation, &shape).ok_or_else(|| {
            Error::Contract(format!(
                "estimate lacks exact tariff for pricing={pricing_id} operation={operation:?} shape={shape:?}"
            ))
        })?;
        let total_cu = entry.cu.checked_mul(u64::from(calls)).ok_or_else(|| {
            Error::Contract("estimate component CU multiplication overflowed".to_owned())
        })?;
        additive_total = additive_total
            .checked_add(total_cu)
            .ok_or_else(|| Error::Contract("estimate core CU sum overflowed".to_owned()))?;
        additive_core_components.push(EstimateComponent {
            pricing_id: pricing_id.to_owned(),
            operation,
            shape,
            calls,
            per_call_cu: entry.cu,
            total_cu,
        });
    }

    let mut nested_diagnostic_components = Vec::new();
    for (operation, calls) in [
        (
            OperationKind::FinalExponentiation,
            trace.final_exponentiations,
        ),
        (OperationKind::G2SubgroupCheck, trace.g2_subgroup_checks),
    ] {
        if calls == 0 {
            continue;
        }
        let shape = unit_shape();
        let entry = find_entry(tariff, pricing_id, operation, &shape).ok_or_else(|| {
            Error::Contract(format!(
                "estimate lacks diagnostic tariff for pricing={pricing_id} operation={operation:?}"
            ))
        })?;
        let total_cu = entry.cu.checked_mul(u64::from(calls)).ok_or_else(|| {
            Error::Contract("estimate diagnostic CU multiplication overflowed".to_owned())
        })?;
        nested_diagnostic_components.push(EstimateComponent {
            pricing_id: pricing_id.to_owned(),
            operation,
            shape,
            calls,
            per_call_cu: entry.cu,
            total_cu,
        });
    }

    let total_cu = additive_total
        .checked_add(non_core_transaction_cu)
        .ok_or_else(|| Error::Contract("full transaction estimate CU overflowed".to_owned()))?;
    Ok(EstimateBreakdown {
        additive_core_components,
        nested_diagnostic_components,
        non_core_transaction_cu,
        non_core_source: non_core_source.to_owned(),
        total_cu,
    })
}
