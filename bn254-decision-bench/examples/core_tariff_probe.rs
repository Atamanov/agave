use {
    ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup, pairing::Pairing},
    ark_ff::{BigInteger, Field, PrimeField},
    serde::Serialize,
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, Version, alt_bn128_g1_msm,
        alt_bn128_pairing_check, alt_bn128_pairing_map, prepare_final_exponentiation_probe,
        prepare_g2_subgroup_probe, run_final_exponentiation_probe, run_g2_subgroup_probe,
    },
    solana_bn254_decision_bench::{ExactMeasurement, OperationKind, SCHEMA_PREFIX, TariffEntry},
    std::{collections::BTreeMap, env, hint::black_box, process::ExitCode, time::Instant},
};

#[cfg(feature = "core-probe-observer")]
use solana_bn254_batch_syscall::research_observer;

#[cfg(any(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma"))]
use {
    solana_bn254_batch_syscall::{PodG1RegisteredG2Pair, PodTrustedGtExponent},
    solana_pubkey::Pubkey,
    solana_syscalls::bn254_registry::{
        RegistryAccountView, pairing_check_registry_account, prepare_registry_account_bytes,
        registry_keyset_digest, trusted_gt_multiexp_registry_account,
    },
    std::collections::BTreeSet,
};

#[derive(Serialize)]
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

struct Args {
    pricing_id: String,
    profile: String,
    samples: usize,
    ns_per_cu: f64,
}

fn parse_args() -> Result<Args, String> {
    let mut pricing_id = None;
    let mut profile = None;
    let mut samples = 20usize;
    let mut ns_per_cu = 33.0f64;
    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--pricing-id" => pricing_id = Some(value),
            "--profile" => profile = Some(value),
            "--samples" => {
                samples = value.parse().map_err(|_| "invalid --samples")?;
            }
            "--ns-per-cu" => {
                ns_per_cu = value.parse().map_err(|_| "invalid --ns-per-cu")?;
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if samples != 20 || ns_per_cu != 33.0 {
        return Err(
            "samples must be exactly 20 and ns-per-cu must equal the pinned Agave 33ns/CU assumption"
                .to_owned(),
        );
    }
    let profile = profile.ok_or("missing --profile")?;
    if !matches!(profile.as_str(), "stock_current" | "batch" | "attestation") {
        return Err("--profile must be stock_current, batch, or attestation".to_owned());
    }
    Ok(Args {
        pricing_id: pricing_id.ok_or("missing --pricing-id")?,
        profile,
        samples,
        ns_per_cu,
    })
}

fn backend_feature() -> &'static str {
    if cfg!(feature = "backend-b1-arkworks") {
        "backend-b1-arkworks"
    } else if cfg!(feature = "backend-b2-arkworks-optimized") {
        "backend-b2-arkworks-optimized"
    } else if cfg!(feature = "backend-b3-mcl") {
        "backend-b3-mcl"
    } else if cfg!(feature = "backend-b4-helios") {
        "backend-b4-helios"
    } else if cfg!(feature = "backend-b5-helios-ifma") {
        "backend-b5-helios-ifma"
    } else {
        unreachable!("core-probe requires exactly one backend feature")
    }
}

fn fq(value: &ark_bn254::Fq) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32usize.saturating_sub(bytes.len())..].copy_from_slice(&bytes);
    out
}

fn g1(point: G1Affine) -> PodG1Point {
    if point.is_zero() {
        return PodG1Point([0; 64]);
    }
    let (x, y) = point.xy().expect("nonzero point has coordinates");
    let mut out = [0; 64];
    out[..32].copy_from_slice(&fq(&x));
    out[32..].copy_from_slice(&fq(&y));
    PodG1Point(out)
}

fn g2(point: G2Affine) -> PodG2Point {
    if point.is_zero() {
        return PodG2Point([0; 128]);
    }
    let (x, y) = point.xy().expect("nonzero point has coordinates");
    let mut out = [0; 128];
    out[..32].copy_from_slice(&fq(&x.c1));
    out[32..64].copy_from_slice(&fq(&x.c0));
    out[64..96].copy_from_slice(&fq(&y.c1));
    out[96..].copy_from_slice(&fq(&y.c0));
    PodG2Point(out)
}

fn scalar(value: Fr) -> PodScalar {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32usize.saturating_sub(bytes.len())..].copy_from_slice(&bytes);
    PodScalar(out)
}

fn pairing_fixture(count: usize) -> Vec<PodG1G2Pair> {
    assert!(count >= 2);
    let p = G1Projective::generator();
    let q = G2Projective::generator();
    let mut coefficient_sum = Fr::from(0u64);
    let mut pairs = Vec::with_capacity(count);
    for index in 0..count {
        let q_scalar = Fr::from(u64::try_from(index.saturating_add(2)).unwrap());
        let p_scalar = if index == count.saturating_sub(1) {
            -coefficient_sum * q_scalar.inverse().expect("q scalar is nonzero")
        } else {
            let p_scalar = Fr::from(u64::try_from(index.saturating_add(1)).unwrap());
            coefficient_sum += p_scalar * q_scalar;
            p_scalar
        };
        pairs.push(PodG1G2Pair {
            g1: g1((p * p_scalar).into_affine()),
            g2: g2((q * q_scalar).into_affine()),
        });
    }
    pairs
}

fn msm_fixture(count: usize) -> (Vec<PodG1Point>, Vec<PodScalar>) {
    let points = (0..count)
        .map(|index| {
            let value = Fr::from(u64::try_from(index.saturating_add(1)).unwrap());
            g1((G1Projective::generator() * value).into_affine())
        })
        .collect();
    let scalars = (0..count)
        .map(|index| scalar(Fr::from(u64::try_from(index.saturating_add(7)).unwrap())))
        .collect();
    (points, scalars)
}

fn measure<T>(samples: usize, mut operation: impl FnMut() -> T) -> (f64, u64) {
    for _ in 0..2 {
        black_box(operation());
    }
    let mut iterations = 1usize;
    loop {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(operation());
        }
        if start.elapsed().as_micros() >= 1_000 || iterations >= 1_024 {
            break;
        }
        iterations = iterations.saturating_mul(2);
    }
    let mut observations = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(operation());
        }
        observations.push(start.elapsed().as_nanos() as f64 / iterations as f64);
    }
    let sample_count = u64::try_from(observations.len()).expect("sample count fits u64");
    let mean = observations.iter().sum::<f64>() / observations.len() as f64;
    let variance = observations
        .iter()
        .map(|observation| {
            let delta = observation - mean;
            delta * delta
        })
        .sum::<f64>()
        / observations.len().saturating_sub(1) as f64;
    // Campaign parsing requires exactly 20 observations, hence df=19.
    let upper_95 = mean + 2.093 * (variance.sqrt() / (observations.len() as f64).sqrt());
    (upper_95, sample_count)
}

fn command() -> String {
    env::args().collect::<Vec<_>>().join(" ")
}

fn entry(
    args: &Args,
    operation: OperationKind,
    shape: BTreeMap<String, u64>,
    mut run: impl FnMut(),
) -> TariffEntry {
    let (upper_95_ns, sample_count) = measure(args.samples, &mut run);
    let cu = (upper_95_ns / args.ns_per_cu).ceil().max(1.0) as u64;
    TariffEntry {
        pricing_id: args.pricing_id.clone(),
        operation,
        shape,
        cu,
        measurement: ExactMeasurement {
            method: "measured_exact_shape".to_owned(),
            sample_count,
            upper_95_ns,
            ns_per_cu: args.ns_per_cu,
            command: command(),
        },
    }
}

fn pairing_shape(pairs: u64, full_pairs: u64, registered_pairs: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("pairs".to_owned(), pairs),
        ("full_pairs".to_owned(), full_pairs),
        ("registered_pairs".to_owned(), registered_pairs),
    ])
}

fn run_stock(args: &Args) -> Result<Vec<TariffEntry>, String> {
    let mut entries = Vec::new();
    for count in [2usize, 4] {
        let pairs = pairing_fixture(count);
        let bytes = bytemuck::cast_slice::<PodG1G2Pair, u8>(&pairs);
        solana_bn254::prelude::alt_bn128_pairing_be(bytes)
            .map_err(|error| format!("stock pairing fixture failed: {error:?}"))?;
        entries.push(entry(
            args,
            OperationKind::PairingCheck,
            pairing_shape(count as u64, count as u64, 0),
            || {
                solana_bn254::prelude::alt_bn128_pairing_be(black_box(bytes))
                    .expect("validated stock pairing fixture");
            },
        ));
    }

    let subgroup = G2Affine::generator();
    if !subgroup.is_in_correct_subgroup_assuming_on_curve() {
        return Err("stock subgroup fixture is not in the subgroup".to_owned());
    }
    entries.push(entry(
        args,
        OperationKind::G2SubgroupCheck,
        BTreeMap::from([("count".to_owned(), 1)]),
        || {
            black_box(subgroup.is_in_correct_subgroup_assuming_on_curve());
        },
    ));

    let fe_probe = Bn254::multi_miller_loop([G1Affine::generator()], [G2Affine::generator()]);
    let _ = Bn254::final_exponentiation(fe_probe.clone())
        .ok_or("stock final-exponentiation fixture failed")?;
    entries.push(entry(
        args,
        OperationKind::FinalExponentiation,
        BTreeMap::from([("count".to_owned(), 1)]),
        || {
            let _ = Bn254::final_exponentiation(black_box(fe_probe.clone()))
                .expect("validated stock final-exponentiation fixture");
        },
    ));
    Ok(entries)
}

fn validate_pairing_check(count: usize, pairs: &[PodG1G2Pair]) -> Result<(), String> {
    #[cfg(not(feature = "core-probe-observer"))]
    let _ = count;
    #[cfg(feature = "core-probe-observer")]
    research_observer::reset();
    if !alt_bn128_pairing_check(Version::V0, pairs).map_err(|error| error.to_string())? {
        return Err("pairing-check fixture is not the identity".to_owned());
    }
    #[cfg(feature = "core-probe-observer")]
    if research_observer::observed_pairing_check_shape() != Some((count as u64, count as u64)) {
        return Err("pairing-check observer shape mismatch".to_owned());
    }
    Ok(())
}

fn run_batch(args: &Args) -> Result<Vec<TariffEntry>, String> {
    let mut entries = Vec::new();
    for count in [2usize, 4, 6, 8, 12] {
        let pairs = pairing_fixture(count);
        validate_pairing_check(count, &pairs)?;
        entries.push(entry(
            args,
            OperationKind::PairingCheck,
            pairing_shape(count as u64, count as u64, 0),
            || {
                alt_bn128_pairing_check(Version::V0, black_box(&pairs))
                    .expect("validated pairing-check fixture");
            },
        ));
    }
    for count in [2usize, 3, 6, 7, 9] {
        let pairs = pairing_fixture(count);
        #[cfg(feature = "core-probe-observer")]
        research_observer::reset();
        alt_bn128_pairing_map(Version::V0, &pairs).map_err(|error| error.to_string())?;
        #[cfg(feature = "core-probe-observer")]
        if research_observer::observed_pairing_map_shape() != Some((count as u64, count as u64)) {
            return Err("pairing-map observer shape mismatch".to_owned());
        }
        entries.push(entry(
            args,
            OperationKind::PairingMap,
            pairing_shape(count as u64, count as u64, 0),
            || {
                alt_bn128_pairing_map(Version::V0, black_box(&pairs))
                    .expect("validated pairing-map fixture");
            },
        ));
    }
    for count in [1usize, 2, 4, 5, 6, 7, 9, 10, 36, 54] {
        let (points, scalars) = msm_fixture(count);
        #[cfg(feature = "core-probe-observer")]
        research_observer::reset();
        alt_bn128_g1_msm(Version::V0, &points, &scalars).map_err(|error| error.to_string())?;
        #[cfg(feature = "core-probe-observer")]
        if research_observer::observed_g1_msm_point_count_list() != [count as u64] {
            return Err("MSM observer shape mismatch".to_owned());
        }
        entries.push(entry(
            args,
            OperationKind::G1Msm,
            BTreeMap::from([("points".to_owned(), count as u64)]),
            || {
                alt_bn128_g1_msm(Version::V0, black_box(&points), black_box(&scalars))
                    .expect("validated MSM fixture");
            },
        ));
    }

    let subgroup = g2(G2Affine::generator());
    let subgroup_probe = prepare_g2_subgroup_probe(&subgroup).map_err(|error| error.to_string())?;
    #[cfg(feature = "core-probe-observer")]
    research_observer::reset();
    if !run_g2_subgroup_probe(&subgroup_probe).map_err(|error| error.to_string())? {
        return Err("standalone subgroup observer mismatch".to_owned());
    }
    #[cfg(feature = "core-probe-observer")]
    if research_observer::observed_standalone_probe_calls() != (1, 0) {
        return Err("standalone subgroup observer mismatch".to_owned());
    }
    entries.push(entry(
        args,
        OperationKind::G2SubgroupCheck,
        BTreeMap::from([("count".to_owned(), 1)]),
        || {
            run_g2_subgroup_probe(black_box(&subgroup_probe)).expect("validated subgroup fixture");
        },
    ));

    let fe_pairs = pairing_fixture(2);
    let fe_probe =
        prepare_final_exponentiation_probe(&fe_pairs).map_err(|error| error.to_string())?;
    #[cfg(feature = "core-probe-observer")]
    research_observer::reset();
    run_final_exponentiation_probe(&fe_probe).map_err(|error| error.to_string())?;
    #[cfg(feature = "core-probe-observer")]
    if research_observer::observed_standalone_probe_calls() != (0, 1) {
        return Err("standalone final-exponentiation observer mismatch".to_owned());
    }
    entries.push(entry(
        args,
        OperationKind::FinalExponentiation,
        BTreeMap::from([("count".to_owned(), 1)]),
        || {
            run_final_exponentiation_probe(black_box(&fe_probe))
                .expect("validated final-exponentiation fixture");
        },
    ));

    #[cfg(any(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma"))]
    add_helios_registry_entries(args, &mut entries)?;
    Ok(entries)
}

#[cfg(all(feature = "backend-b5-helios-ifma", feature = "core-probe-observer"))]
fn b5_dispatch_attestation() -> Result<(bool, u64, u64), String> {
    if !solana_bn254_batch_syscall::selected_backend_compiled_with_avx512_ifma() {
        return Err("B5 executable was not compiled with the Helios AVX512IFMA cfg".to_owned());
    }
    let pairs = pairing_fixture(8);
    research_observer::reset();
    if !alt_bn128_pairing_check(Version::V0, &pairs).map_err(|error| error.to_string())? {
        return Err("B5 dispatch-attestation fixture is not the identity".to_owned());
    }
    let dispatches = research_observer::observed_ifma_batch8_dispatches();
    if dispatches == 0 {
        return Err("B5 executable did not observe the >=8-pair IFMA batch8 path".to_owned());
    }

    let mixed_pairs = pairing_fixture(8);
    let full = &mixed_pairs[..5];
    let registered_sources: Vec<_> = mixed_pairs[5..].iter().map(|pair| pair.g2).collect();
    let consumer = [19u8; 32];
    let prepared = prepare_registry_account_bytes(
        consumer,
        registry_keyset_digest(&registered_sources, &[]),
        &registered_sources,
        &[],
    )
    .map_err(|error| error.to_string())?;
    let registered: Vec<_> = mixed_pairs[5..]
        .iter()
        .zip(&prepared.g2_ids)
        .map(|(pair, id)| PodG1RegisteredG2Pair {
            g1: pair.g1,
            g2_id: *id,
        })
        .collect();
    let account = RegistryAccountView {
        key: prepared.key,
        owner: Pubkey::new_from_array(consumer),
        data: &prepared.data,
        is_writable: false,
    };
    research_observer::reset();
    if !pairing_check_registry_account(consumer, account, full, &registered)
        .map_err(|error| error.to_string())?
    {
        return Err("B5 mixed dispatch-attestation fixture is not the identity".to_owned());
    }
    if research_observer::observed_registered_pairing_shape() != Some((5, 3, 8)) {
        return Err("B5 mixed dispatch-attestation shape is not 5+3".to_owned());
    }
    let mixed_dispatches = research_observer::observed_ifma_mixed_batch8_dispatches();
    if mixed_dispatches == 0 {
        return Err("B5 executable did not observe the mixed 5+3 IFMA batch8 path".to_owned());
    }
    Ok((true, dispatches, mixed_dispatches))
}

#[cfg(all(
    feature = "backend-b5-helios-ifma",
    not(feature = "core-probe-observer")
))]
fn b5_dispatch_attestation() -> Result<(bool, u64, u64), String> {
    let compiled = solana_bn254_batch_syscall::selected_backend_compiled_with_avx512_ifma();
    if !compiled {
        return Err("B5 executable was not compiled with the Helios AVX512IFMA cfg".to_owned());
    }
    Ok((compiled, 0, 0))
}

#[cfg(not(feature = "backend-b5-helios-ifma"))]
fn b5_dispatch_attestation() -> Result<(bool, u64, u64), String> {
    Ok((false, 0, 0))
}

#[cfg(any(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma"))]
fn add_helios_registry_entries(args: &Args, entries: &mut Vec<TariffEntry>) -> Result<(), String> {
    for (full_count, registered_count) in [(5usize, 3usize), (2, 6), (3, 9), (0, 2)] {
        let total = full_count.saturating_add(registered_count);
        let q_scalars: Vec<_> = (0..total)
            .map(|index| Fr::from(u64::try_from(index.saturating_add(2)).unwrap()))
            .collect();
        let mut weighted_sum = Fr::from(0u64);
        let mut coefficients = Vec::with_capacity(total);
        for (index, q_scalar) in q_scalars.iter().enumerate() {
            let coefficient = if index == total.saturating_sub(1) {
                -weighted_sum * q_scalar.inverse().expect("nonzero G2 scalar")
            } else {
                Fr::from(u64::try_from(index.saturating_add(1)).unwrap())
            };
            weighted_sum += coefficient * q_scalar;
            coefficients.push(coefficient);
        }
        assert_eq!(weighted_sum, Fr::from(0u64));
        let all_g2: Vec<_> = q_scalars
            .iter()
            .map(|q_scalar| g2((G2Projective::generator() * q_scalar).into_affine()))
            .collect();
        let distinct_g2: BTreeSet<_> = all_g2.iter().map(|point| point.0).collect();
        if distinct_g2.len() != total {
            return Err("registered-pairing fixture reused a G2 source".to_owned());
        }
        let full: Vec<_> = (0..full_count)
            .map(|index| PodG1G2Pair {
                g1: g1((G1Projective::generator() * coefficients[index]).into_affine()),
                g2: all_g2[index],
            })
            .collect();
        let consumer = [7u8; 32];
        let registered_g2_sources = &all_g2[full_count..];
        let prepared = prepare_registry_account_bytes(
            consumer,
            registry_keyset_digest(registered_g2_sources, &[]),
            registered_g2_sources,
            &[],
        )
        .map_err(|error| error.to_string())?;
        let registered: Vec<_> = (full_count..total)
            .enumerate()
            .map(|(registered_index, index)| PodG1RegisteredG2Pair {
                g1: g1((G1Projective::generator() * coefficients[index]).into_affine()),
                g2_id: prepared.g2_ids[registered_index],
            })
            .collect();
        let account = RegistryAccountView {
            key: prepared.key,
            owner: Pubkey::new_from_array(consumer),
            data: &prepared.data,
            is_writable: false,
        };
        #[cfg(feature = "core-probe-observer")]
        research_observer::reset();
        if !pairing_check_registry_account(consumer, account, &full, &registered)
            .map_err(|error| error.to_string())?
        {
            return Err("registered-pairing observer shape mismatch".to_owned());
        }
        #[cfg(feature = "core-probe-observer")]
        if research_observer::observed_registered_pairing_shape()
            != Some((full_count as u64, registered_count as u64, total as u64))
        {
            return Err("registered-pairing observer shape mismatch".to_owned());
        }
        entries.push(entry(
            args,
            OperationKind::RegisteredPairingCheck,
            pairing_shape(total as u64, full_count as u64, registered_count as u64),
            || {
                pairing_check_registry_account(
                    consumer,
                    black_box(account),
                    black_box(&full),
                    black_box(&registered),
                )
                .expect("validated account-backed registered-pairing fixture");
            },
        ));
    }

    for targets_count in [2usize, 3] {
        let sources: Vec<_> = (0..targets_count)
            .map(|index| PodG1G2Pair {
                g1: g1((G1Projective::generator()
                    * Fr::from(u64::try_from(index.saturating_add(1)).unwrap()))
                .into_affine()),
                g2: g2((G2Projective::generator()
                    * Fr::from(u64::try_from(index.saturating_add(2)).unwrap()))
                .into_affine()),
            })
            .collect();
        let consumer = [11u8; 32];
        let prepared = prepare_registry_account_bytes(
            consumer,
            registry_keyset_digest(&[], &sources),
            &[],
            &sources,
        )
        .map_err(|error| error.to_string())?;
        let operands: Vec<_> = (0..targets_count)
            .map(|index| PodTrustedGtExponent {
                target_id: prepared.gt_ids[index],
                exponent: scalar(if index == 0 {
                    Fr::from(1u64)
                } else {
                    Fr::from(u64::try_from(index.saturating_add(7)).unwrap())
                }),
            })
            .collect();
        let account = RegistryAccountView {
            key: prepared.key,
            owner: Pubkey::new_from_array(consumer),
            data: &prepared.data,
            is_writable: false,
        };
        #[cfg(feature = "core-probe-observer")]
        research_observer::reset();
        trusted_gt_multiexp_registry_account(consumer, account, &operands)
            .map_err(|error| error.to_string())?;
        #[cfg(feature = "core-probe-observer")]
        if research_observer::observed_gt_multiexp_shape()
            != Some((targets_count as u64, targets_count.saturating_sub(1) as u64))
        {
            return Err("GT target multiexp observer shape mismatch".to_owned());
        }
        entries.push(entry(
            args,
            OperationKind::GtTargetMultiexp,
            BTreeMap::from([
                (
                    "nontrivial_exponents".to_owned(),
                    targets_count.saturating_sub(1) as u64,
                ),
                ("targets".to_owned(), targets_count as u64),
            ]),
            || {
                trusted_gt_multiexp_registry_account(
                    consumer,
                    black_box(account),
                    black_box(&operands),
                )
                .expect("validated account-backed GT target multiexp fixture");
            },
        ));
    }
    Ok(())
}

fn run() -> Result<ProbeFragment, String> {
    let args = parse_args()?;
    let entries = match args.profile.as_str() {
        "stock_current" => run_stock(&args)?,
        "batch" => run_batch(&args)?,
        "attestation" => Vec::new(),
        _ => unreachable!("profile was validated"),
    };
    let (avx512ifma_compiled, ifma_batch8_dispatches, ifma_mixed_batch8_dispatches) =
        b5_dispatch_attestation()?;
    Ok(ProbeFragment {
        schema: format!("{SCHEMA_PREFIX}.core-tariff-fragment.v1"),
        pricing_id: args.pricing_id,
        backend_feature: backend_feature().to_owned(),
        host_architecture: env::consts::ARCH.to_owned(),
        avx512ifma_compiled,
        ifma_batch8_dispatches,
        ifma_mixed_batch8_dispatches,
        entries,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(fragment) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&fragment)
                    .expect("fragment serialization cannot fail")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("core tariff probe failed: {error}");
            ExitCode::FAILURE
        }
    }
}
