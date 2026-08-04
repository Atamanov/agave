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
            PodG1G2Pair, PodG1Point, PodGtElement, PodPairingResult, PodPlonkReductionContext,
            PodPlonkReductionInput, PodScalar, PodSnarkjsPlonkMultiVkContext,
            PodSnarkjsPlonkMultiVkInput, PodSnarkjsPlonkReductionContext,
            PodSnarkjsPlonkReductionInput,
        },
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    solana_define_syscall::define_syscall,
};

// Declared here until the published solana-define-syscall ships them.
define_syscall!(fn sol_alt_bn128_g1_msm(num_points: u64, points_addr: *const u8, scalars_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_check(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_map(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
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
