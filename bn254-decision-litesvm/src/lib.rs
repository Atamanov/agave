//! Reproducible LiteSVM installation for the BN254 decision campaign.
//!
//! Custom batch/registry syscalls use the same embedded current-pricing model
//! as Agave. The stock `sol_alt_bn128_group_op` remains installed by LiteSVM;
//! a read-only register-trace callback observes it without replacement.

mod stock_observer;

pub use stock_observer::{
    GroupOpKind, StockGroupOpEvent, StockGroupOpObservation, StockGroupOpObserver,
};

use {
    litesvm::LiteSVM,
    serde::{Deserialize, Serialize},
    solana_bn254_batch_syscall::{
        FQ12_BYTES, G1_BYTES, G2_BYTES, PAIR_BYTES, PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair,
        PodPairingResult, PodScalar, PodTrustedGtExponent, SCALAR_BYTES, Version, alt_bn128_g1_msm,
        alt_bn128_pairing_check, alt_bn128_pairing_map, research_observer as backend_observer,
    },
    solana_program_runtime::{
        invoke_context::InvokeContext,
        solana_sbpf::{
            declare_builtin_function,
            memory_region::{AccessType, MemoryMapping},
        },
    },
    solana_pubkey_v4::Pubkey as PubkeyV4,
    solana_syscalls::bn254_registry::{
        self as registry, REGISTRY_MAX_G2_ENTRIES, REGISTRY_MAX_GT_ENTRIES,
        REGISTRY_MAX_REGISTERED_PAIRS, RegistryAccountView, pairing_check_registry_account,
        prepare_registry_account_bytes, trusted_gt_multiexp_registry_account,
    },
    std::sync::OnceLock,
};

pub use registry::{
    REGISTRY_ABI_VERSION, REGISTRY_BACKEND_B5, REGISTRY_CURVE_BN254, REGISTRY_FROZEN,
    REGISTRY_G2_ENTRY_BYTES, REGISTRY_GT_ENTRY_BYTES, REGISTRY_HEADER_BYTES, REGISTRY_MAGIC,
    REGISTRY_PDA_SEED, REGISTRY_VERSION, pack_gt_multiexp_shape, pack_registered_pairing_shape,
    pack_registry_init_shape, registry_account_len, registry_address, registry_keyset_digest,
};
pub use solana_bn254_batch_syscall::selected_backend_compiled_with_avx512_ifma;

pub const CURRENT_MSM_BASE_CU: u64 = 100;
pub const CURRENT_MSM_PER_POINT_CU: u64 = 3_322;
pub const CURRENT_PAIRING_BASE_CU: u64 = 17_246;
pub const CURRENT_PAIRING_PER_PAIR_CU: u64 = 5_741;
pub const CURRENT_G2_SUBGROUP_CHECK_CU: u64 = 3_595;
pub const CURRENT_GROUP_OP_G1_ADD_CU: u64 = 334;
pub const CURRENT_GROUP_OP_G1_MUL_CU: u64 = 3_840;
pub const CURRENT_GROUP_OP_PAIRING_FIRST_CU: u64 = 36_364;
pub const CURRENT_GROUP_OP_PAIRING_OTHER_CU: u64 = 12_121;

const MSM_DISCOUNT_PER_THOUSAND: [u64; 12] =
    [1000, 636, 449, 320, 246, 199, 166, 131, 113, 98, 85, 79];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MsmObservation {
    pub points: u64,
    pub charged_cu: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PairingObservation {
    pub pairs: u64,
    pub nonidentity_pairs: u64,
    pub charged_cu: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisteredPairingObservation {
    pub full_pairs: u64,
    pub registered_pairs: u64,
    pub nonidentity_pairs: u64,
    pub charged_cu: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustedGtObservation {
    pub targets: u64,
    pub nontrivial_exponents: u64,
    pub charged_cu: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistryInitObservation {
    pub g2_entries: u64,
    pub gt_entries: u64,
    pub g2_subgroup_checks: u64,
    pub g2_line_preparations: u64,
    pub charged_cu: u64,
}

/// Strict, ordered syscall-boundary witness for one measured case.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObserverSnapshot {
    pub msm_calls: Vec<MsmObservation>,
    pub pairing_checks: Vec<PairingObservation>,
    pub pairing_maps: Vec<PairingObservation>,
    pub registered_pairing_checks: Vec<RegisteredPairingObservation>,
    pub trusted_gt_multiexps: Vec<TrustedGtObservation>,
    /// Setup is separate so hot-path totals can exclude it without inference.
    pub registry_init: RegistryInitObservation,
    pub standalone_subgroup_checks: u64,
    pub standalone_final_exponentiations: u64,
    pub legacy_g1_multiplications: u64,
    pub legacy_g1_additions: u64,
    pub ifma_batch8_dispatches: u64,
    pub ifma_mixed_batch8_dispatches: u64,
    pub stock_group_ops: StockGroupOpObservation,
}

pub fn current_msm_cu(points: u64) -> u64 {
    let discount = match points {
        0 => 1000,
        count => MSM_DISCOUNT_PER_THOUSAND[core::cmp::min(count.ilog2() as usize, 11)],
    };
    CURRENT_MSM_BASE_CU.saturating_add(
        CURRENT_MSM_PER_POINT_CU
            .saturating_mul(points)
            .saturating_mul(discount)
            .saturating_div(1000),
    )
}

pub fn current_pairing_cu(pairs: u64) -> u64 {
    CURRENT_PAIRING_BASE_CU.saturating_add(
        CURRENT_PAIRING_PER_PAIR_CU
            .saturating_add(CURRENT_G2_SUBGROUP_CHECK_CU)
            .saturating_mul(pairs),
    )
}

pub fn current_registered_pairing_cu(full: u64, registered: u64) -> u64 {
    CURRENT_PAIRING_BASE_CU
        .saturating_add(CURRENT_PAIRING_PER_PAIR_CU.saturating_mul(full.saturating_add(registered)))
        .saturating_add(CURRENT_G2_SUBGROUP_CHECK_CU.saturating_mul(full))
}

pub fn current_trusted_gt_multiexp_cu(targets: u64) -> u64 {
    CURRENT_PAIRING_BASE_CU.saturating_add(CURRENT_PAIRING_PER_PAIR_CU.saturating_mul(targets))
}

pub fn current_registry_init_cu(g2_entries: u64, gt_entries: u64) -> u64 {
    if g2_entries == 0 && gt_entries == 0 {
        return 0;
    }
    let per_validated_pair =
        CURRENT_PAIRING_PER_PAIR_CU.saturating_add(CURRENT_G2_SUBGROUP_CHECK_CU);
    per_validated_pair
        .saturating_mul(g2_entries)
        .saturating_add(CURRENT_PAIRING_BASE_CU)
        .saturating_add(per_validated_pair.saturating_mul(gt_entries))
}

pub fn current_stock_group_op_cu(event: &StockGroupOpEvent) -> u64 {
    match event.kind {
        GroupOpKind::G1Add => CURRENT_GROUP_OP_G1_ADD_CU,
        GroupOpKind::G1Mul => CURRENT_GROUP_OP_G1_MUL_CU,
        GroupOpKind::Pairing => event.pairing_elements.map_or(0, |pairs| {
            CURRENT_GROUP_OP_PAIRING_FIRST_CU.saturating_add(
                CURRENT_GROUP_OP_PAIRING_OTHER_CU.saturating_mul(pairs.saturating_sub(1)),
            )
        }),
    }
}

/// Sum every successfully observed custom event and every read-only observed
/// stock group-op event, including registry initialization.
pub fn current_embedded_core_cu(snapshot: &ObserverSnapshot) -> u64 {
    current_embedded_hot_core_cu(snapshot).saturating_add(snapshot.registry_init.charged_cu)
}

/// Current-pricing sum with one-time registry initialization excluded.
pub fn current_embedded_hot_core_cu(snapshot: &ObserverSnapshot) -> u64 {
    snapshot
        .msm_calls
        .iter()
        .map(|event| event.charged_cu)
        .chain(snapshot.pairing_checks.iter().map(|event| event.charged_cu))
        .chain(snapshot.pairing_maps.iter().map(|event| event.charged_cu))
        .chain(
            snapshot
                .registered_pairing_checks
                .iter()
                .map(|event| event.charged_cu),
        )
        .chain(
            snapshot
                .trusted_gt_multiexps
                .iter()
                .map(|event| event.charged_cu),
        )
        .chain(
            snapshot
                .stock_group_ops
                .events
                .iter()
                .map(current_stock_group_op_cu),
        )
        .fold(0u64, u64::saturating_add)
}

static STOCK_OBSERVER: OnceLock<StockGroupOpObserver> = OnceLock::new();

fn stock_observer() -> &'static StockGroupOpObserver {
    STOCK_OBSERVER.get_or_init(StockGroupOpObserver::default)
}

pub fn reset_observers() {
    backend_observer::reset();
    stock_observer().reset();
}

pub fn observer_snapshot() -> ObserverSnapshot {
    let registry_init_shape = backend_observer::observed_registry_init_shape();
    let registry_preparations = backend_observer::observed_registry_g2_preparation_calls();
    let standalone = backend_observer::observed_standalone_probe_calls();
    let legacy = backend_observer::observed_legacy_group_ops();
    ObserverSnapshot {
        msm_calls: backend_observer::observed_g1_msm_point_count_list()
            .into_iter()
            .map(|points| MsmObservation {
                points,
                charged_cu: current_msm_cu(points),
            })
            .collect(),
        pairing_checks: backend_observer::observed_pairing_check_shapes()
            .into_iter()
            .map(|(pairs, nonidentity_pairs)| PairingObservation {
                pairs,
                nonidentity_pairs,
                charged_cu: current_pairing_cu(pairs),
            })
            .collect(),
        pairing_maps: backend_observer::observed_pairing_map_shapes()
            .into_iter()
            .map(|(pairs, nonidentity_pairs)| PairingObservation {
                pairs,
                nonidentity_pairs,
                charged_cu: current_pairing_cu(pairs),
            })
            .collect(),
        registered_pairing_checks: backend_observer::observed_registered_pairing_shapes()
            .into_iter()
            .map(
                |(full_pairs, registered_pairs, nonidentity_pairs)| RegisteredPairingObservation {
                    full_pairs,
                    registered_pairs,
                    nonidentity_pairs,
                    charged_cu: current_registered_pairing_cu(full_pairs, registered_pairs),
                },
            )
            .collect(),
        trusted_gt_multiexps: backend_observer::observed_gt_multiexp_shapes()
            .into_iter()
            .map(|(targets, nontrivial_exponents)| TrustedGtObservation {
                targets,
                nontrivial_exponents,
                charged_cu: current_trusted_gt_multiexp_cu(targets),
            })
            .collect(),
        registry_init: RegistryInitObservation {
            g2_entries: registry_init_shape.0,
            gt_entries: registry_init_shape.1,
            g2_subgroup_checks: registry_preparations.0,
            g2_line_preparations: registry_preparations.1,
            charged_cu: current_registry_init_cu(registry_init_shape.0, registry_init_shape.1),
        },
        standalone_subgroup_checks: standalone.0,
        standalone_final_exponentiations: standalone.1,
        legacy_g1_multiplications: legacy.0,
        legacy_g1_additions: legacy.1,
        ifma_batch8_dispatches: backend_observer::observed_ifma_batch8_dispatches(),
        ifma_mixed_batch8_dispatches: backend_observer::observed_ifma_mixed_batch8_dispatches(),
        stock_group_ops: stock_observer().snapshot(),
    }
}

/// Construct a normal LiteSVM 0.12 environment and install all decision
/// syscalls after stock builtins and before default programs.
pub fn new_litesvm_with_decision_syscalls() -> LiteSVM {
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    let mut svm = with_decision_syscalls(
        LiteSVM::new_debuggable(true)
            .with_mainnet_features()
            .with_builtins(),
    )
    .with_lamports(1_000_000u64.wrapping_mul(LAMPORTS_PER_SOL))
    .with_sysvars()
    .with_feature_accounts()
    .with_default_programs()
    .with_sigverify(true)
    .with_blockhash_check(true);
    svm.set_invocation_inspect_callback(stock_observer().clone());
    svm
}

fn with_decision_syscalls(svm: LiteSVM) -> LiteSVM {
    svm.with_custom_syscall("sol_alt_bn128_g1_msm", SyscallG1Msm::vm)
        .with_custom_syscall("sol_alt_bn128_pairing_check", SyscallPairingCheck::vm)
        .with_custom_syscall("sol_alt_bn128_pairing_map", SyscallPairingMap::vm)
        .with_custom_syscall("sol_alt_bn128_vk_registry_init", SyscallVkRegistryInit::vm)
        .with_custom_syscall(
            "sol_alt_bn128_pairing_check_registered",
            SyscallPairingCheckRegistered::vm,
        )
        .with_custom_syscall(
            "sol_alt_bn128_trusted_gt_multiexp",
            SyscallTrustedGtMultiexp::vm,
        )
}

fn translate<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a [u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Load, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts(host_addr as *const u8, len as usize) })
}

#[allow(clippy::mut_from_ref)]
fn translate_mut<'a>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<&'a mut [u8], Box<dyn std::error::Error>> {
    let host_addr: u64 = Result::from(memory_mapping.map(AccessType::Store, vm_addr, len))?;
    Ok(unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, len as usize) })
}

fn pod_slice<T: bytemuck::Pod>(bytes: &[u8]) -> Result<&[T], Box<dyn std::error::Error>> {
    bytemuck::try_cast_slice(bytes).map_err(|error| format!("pod cast failed: {error}").into())
}

fn byte_len(count: u64, element_size: usize) -> Result<u64, Box<dyn std::error::Error>> {
    count
        .checked_mul(element_size as u64)
        .ok_or_else(|| "VM slice length overflow".into())
}

fn current_program_id(
    invoke_context: &InvokeContext,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    Ok(invoke_context
        .transaction_context
        .get_current_instruction_context()?
        .get_program_key()?
        .to_bytes())
}

#[derive(Clone, Copy)]
struct InitShape {
    g2_count: u16,
    gt_count: u16,
    account_index: u16,
}

fn unpack_init_shape(shape: u64) -> Option<InitShape> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some(InitShape {
        g2_count: shape as u16,
        gt_count: (shape >> 16) as u16,
        account_index: (shape >> 32) as u16,
    })
}

#[derive(Clone, Copy)]
struct RegisteredShape {
    full_count: u16,
    registered_count: u16,
    account_index: u16,
}

fn unpack_registered_shape(shape: u64) -> Option<RegisteredShape> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some(RegisteredShape {
        full_count: shape as u16,
        registered_count: (shape >> 16) as u16,
        account_index: (shape >> 32) as u16,
    })
}

fn unpack_gt_shape(shape: u64) -> Option<(u16, u16)> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some((shape as u16, (shape >> 32) as u16))
}

declare_builtin_function!(
    SyscallG1Msm,
    fn rust(
        invoke_context: &mut InvokeContext,
        num_points: u64,
        points_addr: u64,
        scalars_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(current_msm_cu(num_points))?;
        let points: &[PodG1Point] = pod_slice(translate(
            memory_mapping,
            points_addr,
            byte_len(num_points, G1_BYTES)?,
        )?)?;
        let scalars: &[PodScalar] = pod_slice(translate(
            memory_mapping,
            scalars_addr,
            byte_len(num_points, SCALAR_BYTES)?,
        )?)?;
        match alt_bn128_g1_msm(Version::V0, points, scalars) {
            Ok(result) => {
                translate_mut(memory_mapping, result_addr, G1_BYTES as u64)?
                    .copy_from_slice(&result.0);
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }
);

declare_builtin_function!(
    SyscallPairingCheck,
    fn rust(
        invoke_context: &mut InvokeContext,
        num_pairs: u64,
        pairs_addr: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(current_pairing_cu(num_pairs))?;
        let pairs: &[PodG1G2Pair] = pod_slice(translate(
            memory_mapping,
            pairs_addr,
            byte_len(num_pairs, PAIR_BYTES)?,
        )?)?;
        match alt_bn128_pairing_check(Version::V0, pairs) {
            Ok(verdict) => {
                translate_mut(memory_mapping, result_addr, 32)?
                    .copy_from_slice(&PodPairingResult::from_verdict(verdict).0);
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }
);

declare_builtin_function!(
    SyscallPairingMap,
    fn rust(
        invoke_context: &mut InvokeContext,
        num_pairs: u64,
        pairs_addr: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(current_pairing_cu(num_pairs))?;
        let pairs: &[PodG1G2Pair] = pod_slice(translate(
            memory_mapping,
            pairs_addr,
            byte_len(num_pairs, PAIR_BYTES)?,
        )?)?;
        match alt_bn128_pairing_map(Version::V0, pairs) {
            Ok(result) => {
                translate_mut(memory_mapping, result_addr, FQ12_BYTES as u64)?
                    .copy_from_slice(&result.0);
                Ok(0)
            }
            Err(_) => Ok(1),
        }
    }
);

declare_builtin_function!(
    SyscallVkRegistryInit,
    fn rust(
        invoke_context: &mut InvokeContext,
        packed_shape: u64,
        g2_sources_addr: u64,
        gt_sources_addr: u64,
        keyset_digest_addr: u64,
        registry_data_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let Some(shape) = unpack_init_shape(packed_shape) else {
            return Ok(1);
        };
        let g2_count = usize::from(shape.g2_count);
        let gt_count = usize::from(shape.gt_count);
        if g2_count > REGISTRY_MAX_G2_ENTRIES
            || gt_count > REGISTRY_MAX_GT_ENTRIES
            || g2_count.saturating_add(gt_count) == 0
        {
            return Ok(1);
        }
        invoke_context.consume_checked(current_registry_init_cu(
            u64::from(shape.g2_count),
            u64::from(shape.gt_count),
        ))?;
        let consumer = current_program_id(invoke_context)?;
        let g2_sources: Vec<solana_bn254_batch_syscall::PodG2Point> = if shape.g2_count == 0 {
            Vec::new()
        } else {
            pod_slice::<solana_bn254_batch_syscall::PodG2Point>(translate(
                memory_mapping,
                g2_sources_addr,
                byte_len(u64::from(shape.g2_count), G2_BYTES)?,
            )?)?
            .to_vec()
        };
        let gt_sources: Vec<PodG1G2Pair> = if shape.gt_count == 0 {
            Vec::new()
        } else {
            pod_slice::<PodG1G2Pair>(translate(
                memory_mapping,
                gt_sources_addr,
                byte_len(u64::from(shape.gt_count), PAIR_BYTES)?,
            )?)?
            .to_vec()
        };
        let keyset_digest: [u8; 32] = translate(memory_mapping, keyset_digest_addr, 32)?
            .try_into()
            .map_err(|_| "invalid keyset digest length")?;
        let Ok(prepared) =
            prepare_registry_account_bytes(consumer, keyset_digest, &g2_sources, &gt_sources)
        else {
            return Ok(1);
        };
        let expected_len = registry_account_len(g2_count, gt_count);
        let instruction = invoke_context
            .transaction_context
            .get_current_instruction_context()?;
        let Ok(account) = instruction.try_borrow_instruction_account(shape.account_index) else {
            return Ok(1);
        };
        if !account.is_writable()
            || account.get_owner().to_bytes() != consumer
            || account.get_key().to_bytes() != prepared.key.to_bytes()
            || account.get_data().len() != expected_len
            || account.get_data().iter().any(|byte| *byte != 0)
        {
            return Ok(1);
        }
        drop(account);
        let destination = translate_mut(memory_mapping, registry_data_addr, expected_len as u64)?;
        if destination.iter().any(|byte| *byte != 0) {
            return Ok(1);
        }
        destination.copy_from_slice(&prepared.data);
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallPairingCheckRegistered,
    fn rust(
        invoke_context: &mut InvokeContext,
        packed_shape: u64,
        full_addr: u64,
        registered_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let Some(shape) = unpack_registered_shape(packed_shape) else {
            return Ok(1);
        };
        let total = usize::from(shape.full_count)
            .checked_add(usize::from(shape.registered_count))
            .ok_or("pair count overflow")?;
        if total == 0
            || total > REGISTRY_MAX_REGISTERED_PAIRS
            || usize::from(shape.registered_count) > REGISTRY_MAX_G2_ENTRIES
        {
            return Ok(1);
        }
        invoke_context.consume_checked(current_registered_pairing_cu(
            u64::from(shape.full_count),
            u64::from(shape.registered_count),
        ))?;
        let full: &[PodG1G2Pair] = if shape.full_count == 0 {
            &[]
        } else {
            pod_slice(translate(
                memory_mapping,
                full_addr,
                byte_len(u64::from(shape.full_count), PAIR_BYTES)?,
            )?)?
        };
        let registered: &[PodG1RegisteredG2Pair] = if shape.registered_count == 0 {
            &[]
        } else {
            pod_slice(translate(
                memory_mapping,
                registered_addr,
                byte_len(
                    u64::from(shape.registered_count),
                    core::mem::size_of::<PodG1RegisteredG2Pair>(),
                )?,
            )?)?
        };
        let consumer = current_program_id(invoke_context)?;
        let instruction = invoke_context
            .transaction_context
            .get_current_instruction_context()?;
        let Ok(account) = instruction.try_borrow_instruction_account(shape.account_index) else {
            return Ok(1);
        };
        let view = RegistryAccountView {
            key: PubkeyV4::new_from_array(account.get_key().to_bytes()),
            owner: PubkeyV4::new_from_array(account.get_owner().to_bytes()),
            data: account.get_data(),
            is_writable: account.is_writable(),
        };
        let Ok(verdict) = pairing_check_registry_account(consumer, view, full, registered) else {
            return Ok(1);
        };
        drop(account);
        translate_mut(memory_mapping, result_addr, 32)?
            .copy_from_slice(&PodPairingResult::from_verdict(verdict).0);
        Ok(0)
    }
);

declare_builtin_function!(
    SyscallTrustedGtMultiexp,
    fn rust(
        invoke_context: &mut InvokeContext,
        packed_shape: u64,
        operands_addr: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let Some((target_count, account_index)) = unpack_gt_shape(packed_shape) else {
            return Ok(1);
        };
        if target_count == 0 || usize::from(target_count) > REGISTRY_MAX_GT_ENTRIES {
            return Ok(1);
        }
        invoke_context.consume_checked(current_trusted_gt_multiexp_cu(u64::from(target_count)))?;
        let operands: &[PodTrustedGtExponent] = pod_slice(translate(
            memory_mapping,
            operands_addr,
            byte_len(
                u64::from(target_count),
                core::mem::size_of::<PodTrustedGtExponent>(),
            )?,
        )?)?;
        let consumer = current_program_id(invoke_context)?;
        let instruction = invoke_context
            .transaction_context
            .get_current_instruction_context()?;
        let Ok(account) = instruction.try_borrow_instruction_account(account_index) else {
            return Ok(1);
        };
        let view = RegistryAccountView {
            key: PubkeyV4::new_from_array(account.get_key().to_bytes()),
            owner: PubkeyV4::new_from_array(account.get_owner().to_bytes()),
            data: account.get_data(),
            is_writable: account.is_writable(),
        };
        let Ok(result) = trusted_gt_multiexp_registry_account(consumer, view, operands) else {
            return Ok(1);
        };
        drop(account);
        translate_mut(memory_mapping, result_addr, FQ12_BYTES as u64)?.copy_from_slice(&result.0);
        Ok(0)
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_embedded_tariffs_are_pinned() {
        assert_eq!(current_msm_cu(1), 3_422);
        assert_eq!(current_pairing_cu(4), 17_246 + 9_336 * 4);
        assert_eq!(current_registered_pairing_cu(5, 3), 81_149);
        assert_eq!(current_trusted_gt_multiexp_cu(2), 28_728);
        assert_eq!(current_registry_init_cu(1, 1), 35_918);
    }

    #[test]
    fn setup_is_excluded_only_by_hot_total() {
        assert_eq!(current_embedded_core_cu(&ObserverSnapshot::default()), 0);
        let snapshot = ObserverSnapshot {
            registry_init: RegistryInitObservation {
                g2_entries: 1,
                gt_entries: 0,
                g2_subgroup_checks: 1,
                g2_line_preparations: 1,
                charged_cu: current_registry_init_cu(1, 0),
            },
            ..ObserverSnapshot::default()
        };
        assert_eq!(current_embedded_hot_core_cu(&snapshot), 0);
        assert_eq!(
            current_embedded_core_cu(&snapshot),
            current_registry_init_cu(1, 0)
        );
    }

    #[test]
    fn installer_constructs_without_replacing_stock_group_op() {
        reset_observers();
        let _svm = new_litesvm_with_decision_syscalls();
        assert!(observer_snapshot().stock_group_ops.events.is_empty());
    }
}
