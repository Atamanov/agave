//! The solana-target half of the crate: the same entry points, dispatched to
//! the runtime instead of computed here.
//!
//! Validation, caps, and the error taxonomy all live behind the syscall, which
//! reports any rejection as a nonzero return code. The distinctions the native
//! path draws are not recoverable here, so runtime failures surface as
//! `SyscallFailed`. Two-slice length mismatches are rejected locally before an
//! unsafe pointer crosses the syscall boundary.

use {
    crate::{
        Version,
        encoding::{
            plonk_reduction_output_count, plonk_reduction_shape,
            snarkjs_plonk_multi_vk_output_count, snarkjs_plonk_multi_vk_shape,
        },
        pod::{
            PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair, PodGtElement, PodPairingResult,
            PodPlonkReductionContext, PodPlonkReductionInput, PodScalar,
            PodSnarkjsPlonkMultiVkContext, PodSnarkjsPlonkMultiVkInput,
            PodSnarkjsPlonkReductionContext, PodSnarkjsPlonkReductionInput, PodTrustedGtExponent,
        },
        registry_abi::{
            REGISTRY_MAX_G2_ENTRIES, REGISTRY_MAX_GT_ENTRIES, REGISTRY_MAX_REGISTERED_PAIRS,
            pack_gt_multiexp_shape, pack_registered_pairing_shape, pack_registry_init_shape,
            registry_account_len,
        },
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    solana_define_syscall::define_syscall,
};

// Declared here until the published solana-define-syscall ships them.
define_syscall!(fn sol_alt_bn128_g1_msm(num_points: u64, points_addr: *const u8, scalars_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_check(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_map(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_vk_registry_init(packed_shape: u64, g2_sources_addr: *const u8, gt_sources_addr: *const u8, keyset_digest_addr: *const u8, registry_data_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_check_registered(packed_shape: u64, full_addr: *const u8, registered_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_trusted_gt_multiexp(packed_shape: u64, operands_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_lincomb(num_elems: u64, a_addr: *const u8, b_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_batch_invert(num_elems: u64, a_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_plonk_batch_reduce(shape: u64, context_addr: *const u8, inputs_addr: *const u8, public_inputs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_snarkjs_plonk_batch_reduce(shape: u64, context_addr: *const u8, inputs_addr: *const u8, public_inputs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(shape: u64, contexts_addr: *const u8, inputs_addr: *const u8, public_inputs_addr: *const u8, result_addr: *mut u8) -> u64);

pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    validate_equal_lengths(points.len(), scalars.len())?;
    let mut result = PodG1Point([0u8; crate::encoding::G1_BYTES]);
    let code = unsafe {
        sol_alt_bn128_g1_msm(
            points.len() as u64,
            points.as_ptr().cast(),
            scalars.as_ptr().cast(),
            result.0.as_mut_ptr(),
        )
    };
    check(code)?;
    Ok(result)
}

pub fn alt_bn128_pairing_check(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let mut result = PodPairingResult([0u8; 32]);
    let code = unsafe {
        sol_alt_bn128_pairing_check(
            pairs.len() as u64,
            pairs.as_ptr().cast(),
            result.0.as_mut_ptr(),
        )
    };
    check(code)?;
    Ok(result.verdict())
}

pub fn alt_bn128_pairing_map(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128BatchError> {
    let mut result = PodGtElement([0u8; crate::encoding::FQ12_BYTES]);
    let code = unsafe {
        sol_alt_bn128_pairing_map(
            pairs.len() as u64,
            pairs.as_ptr().cast(),
            result.0.as_mut_ptr(),
        )
    };
    check(code)?;
    Ok(result)
}

/// Initialize a current-program-owned registry PDA through its writable
/// account-data slice. The runtime validates the exact account index, owner,
/// PDA address, zero-filled length, keyset digest, source points, and targets.
pub fn alt_bn128_vk_registry_init(
    _version: Version,
    account_index: u16,
    g2_sources: &[crate::PodG2Point],
    gt_sources: &[PodG1G2Pair],
    keyset_digest: &[u8; 32],
    registry_data: &mut [u8],
) -> Result<(), AltBn128BatchError> {
    if g2_sources.len().saturating_add(gt_sources.len()) == 0 {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if g2_sources.len() > REGISTRY_MAX_G2_ENTRIES || gt_sources.len() > REGISTRY_MAX_GT_ENTRIES {
        return Err(AltBn128BatchError::CapExceeded);
    }
    if registry_data.len() != registry_account_len(g2_sources.len(), gt_sources.len()) {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    let shape = pack_registry_init_shape(
        g2_sources.len() as u16,
        gt_sources.len() as u16,
        account_index,
    );
    // Solana's VM rejects the Rust empty-slice sentinel address (0x1) even
    // when the ABI count is zero. Keep the count authoritative while passing
    // an in-frame, mapped fallback pointer for either optional source list.
    let g2_sources_addr = if g2_sources.is_empty() {
        registry_data.as_ptr()
    } else {
        g2_sources.as_ptr().cast()
    };
    let gt_sources_addr = if gt_sources.is_empty() {
        registry_data.as_ptr()
    } else {
        gt_sources.as_ptr().cast()
    };
    let code = unsafe {
        sol_alt_bn128_vk_registry_init(
            shape,
            g2_sources_addr,
            gt_sources_addr,
            keyset_digest.as_ptr(),
            registry_data.as_mut_ptr(),
        )
    };
    check(code)
}

/// Pair ordinary terms with authenticated registry G2 IDs.
pub fn alt_bn128_pairing_check_registered(
    _version: Version,
    account_index: u16,
    full: &[PodG1G2Pair],
    registered: &[PodG1RegisteredG2Pair],
) -> Result<bool, AltBn128BatchError> {
    let total = full
        .len()
        .checked_add(registered.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    if total == 0 {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if total > REGISTRY_MAX_REGISTERED_PAIRS || registered.len() > REGISTRY_MAX_G2_ENTRIES {
        return Err(AltBn128BatchError::CapExceeded);
    }
    let shape =
        pack_registered_pairing_shape(full.len() as u16, registered.len() as u16, account_index);
    let mut result = PodPairingResult([0u8; 32]);
    let fallback = result.0.as_ptr();
    let full_addr = if full.is_empty() {
        fallback
    } else {
        full.as_ptr().cast()
    };
    let registered_addr = if registered.is_empty() {
        fallback
    } else {
        registered.as_ptr().cast()
    };
    let code = unsafe {
        sol_alt_bn128_pairing_check_registered(
            shape,
            full_addr,
            registered_addr,
            result.0.as_mut_ptr(),
        )
    };
    check(code)?;
    Ok(result.verdict())
}

/// Resolve authenticated post-final-exponentiation targets by registry ID and
/// apply their canonical Fr exponents.
pub fn alt_bn128_trusted_gt_multiexp(
    _version: Version,
    account_index: u16,
    operands: &[PodTrustedGtExponent],
) -> Result<PodGtElement, AltBn128BatchError> {
    if operands.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if operands.len() > REGISTRY_MAX_GT_ENTRIES {
        return Err(AltBn128BatchError::CapExceeded);
    }
    let shape = pack_gt_multiexp_shape(operands.len() as u16, account_index);
    let mut result = PodGtElement([0u8; crate::encoding::FQ12_BYTES]);
    let code = unsafe {
        sol_alt_bn128_trusted_gt_multiexp(shape, operands.as_ptr().cast(), result.0.as_mut_ptr())
    };
    check(code)?;
    Ok(result)
}

pub fn alt_bn128_fr_lincomb(
    _version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    validate_equal_lengths(a.len(), b.len())?;
    let mut result = PodScalar([0u8; crate::encoding::SCALAR_BYTES]);
    let code = unsafe {
        sol_alt_bn128_fr_lincomb(
            a.len() as u64,
            a.as_ptr().cast(),
            b.as_ptr().cast(),
            result.0.as_mut_ptr(),
        )
    };
    check(code)?;
    Ok(result)
}

pub fn alt_bn128_fr_batch_invert(
    _version: Version,
    a: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let mut out = vec![PodScalar([0u8; crate::encoding::SCALAR_BYTES]); a.len()];
    let code = unsafe {
        sol_alt_bn128_fr_batch_invert(a.len() as u64, a.as_ptr().cast(), out.as_mut_ptr().cast())
    };
    check(code)?;
    Ok(out)
}

/// Non-production synthetic benchmark reducer.
///
/// The caller supplies challenges and randomizers, so this cannot enforce the
/// canonical snarkjs transcript or Frozen Batch rule. It is retained only for
/// baseline reproduction. Use [`alt_bn128_snarkjs_plonk_batch_reduce`] for the
/// recommended API.
///
/// Output layout is `PLONK_SHARED_OUTPUTS` scalars followed by
/// `PLONK_PER_PROOF_OUTPUTS` scalars per proof; see the host implementation's
/// module documentation for the signed coefficient order.
pub fn alt_bn128_plonk_batch_reduce(
    _version: Version,
    context: &PodPlonkReductionContext,
    inputs: &[PodPlonkReductionInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let output_count = plonk_reduction_output_count(inputs.len()).ok_or(if inputs.is_empty() {
        AltBn128BatchError::ZeroInput
    } else {
        AltBn128BatchError::CapExceeded
    })?;
    let expected_public_inputs = (context.num_public_inputs() as usize)
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    if public_inputs.len() != expected_public_inputs {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    let shape = plonk_reduction_shape(inputs.len(), context.num_public_inputs() as usize)
        .ok_or(AltBn128BatchError::CapExceeded)?;

    let mut out = vec![PodScalar([0u8; crate::encoding::SCALAR_BYTES]); output_count];
    let code = unsafe {
        sol_alt_bn128_plonk_batch_reduce(
            shape,
            core::ptr::from_ref(context).cast(),
            inputs.as_ptr().cast(),
            public_inputs.as_ptr().cast(),
            out.as_mut_ptr().cast(),
        )
    };
    check(code)?;
    Ok(out)
}

/// Replay the canonical snarkjs transcript and reduce a same-key PLONK batch
/// to the two MSMs' signed canonical scalar coefficients. This is the only
/// reducer recommended for verifier integration.
pub fn alt_bn128_snarkjs_plonk_batch_reduce(
    _version: Version,
    context: &PodSnarkjsPlonkReductionContext,
    inputs: &[PodSnarkjsPlonkReductionInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let output_count = plonk_reduction_output_count(inputs.len()).ok_or(if inputs.is_empty() {
        AltBn128BatchError::ZeroInput
    } else {
        AltBn128BatchError::CapExceeded
    })?;
    let expected_public_inputs = (context.num_public_inputs() as usize)
        .checked_mul(inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    if public_inputs.len() != expected_public_inputs {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    let shape = plonk_reduction_shape(inputs.len(), context.num_public_inputs() as usize)
        .ok_or(AltBn128BatchError::CapExceeded)?;

    let mut out = vec![PodScalar([0u8; crate::encoding::SCALAR_BYTES]); output_count];
    let code = unsafe {
        sol_alt_bn128_snarkjs_plonk_batch_reduce(
            shape,
            core::ptr::from_ref(context).cast(),
            inputs.as_ptr().cast(),
            public_inputs.as_ptr().cast(),
            out.as_mut_ptr().cast(),
        )
    };
    check(code)?;
    Ok(out)
}

/// Replay and atomically freeze a canonical snarkjs PLONK batch spanning
/// multiple verifier-resolved keys. The runtime derives every independent
/// outer randomizer from the complete batch; callers cannot supply
/// challenges, randomizers, indices, or partial per-key seeds.
pub fn alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
    _version: Version,
    contexts: &[PodSnarkjsPlonkMultiVkContext],
    inputs: &[PodSnarkjsPlonkMultiVkInput],
    public_inputs: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let output_count = snarkjs_plonk_multi_vk_output_count(contexts.len(), inputs.len()).ok_or(
        if contexts.is_empty() || inputs.is_empty() {
            AltBn128BatchError::ZeroInput
        } else {
            AltBn128BatchError::CapExceeded
        },
    )?;
    let shape = snarkjs_plonk_multi_vk_shape(contexts.len(), inputs.len(), public_inputs.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;

    let mut out = vec![PodScalar([0u8; crate::encoding::SCALAR_BYTES]); output_count];
    let code = unsafe {
        sol_alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
            shape,
            contexts.as_ptr().cast(),
            inputs.as_ptr().cast(),
            public_inputs.as_ptr().cast(),
            out.as_mut_ptr().cast(),
        )
    };
    check(code)?;
    Ok(out)
}

fn check(code: u64) -> Result<(), AltBn128BatchError> {
    if code == 0 {
        Ok(())
    } else {
        Err(AltBn128BatchError::SyscallFailed)
    }
}
