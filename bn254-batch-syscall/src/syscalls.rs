//! The solana-target half of the crate: the same entry points, dispatched to
//! the runtime instead of computed here.
//!
//! Validation, caps, and the error taxonomy all live behind the syscall, which
//! reports any rejection as a nonzero return code. The distinctions the native
//! path draws are not recoverable here, so every failure surfaces as
//! `SyscallFailed`.

use {
    crate::{
        Version,
        pod::{PodG1G2Pair, PodG1Point, PodPairingResult, PodScalar},
        validation::AltBn128BatchError,
    },
    solana_define_syscall::define_syscall,
};

// Declared here until the published solana-define-syscall ships them.
define_syscall!(fn sol_alt_bn128_g1_msm(num_points: u64, points_addr: *const u8, scalars_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_check(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_lincomb(num_elems: u64, a_addr: *const u8, b_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_batch_invert(num_elems: u64, a_addr: *const u8, result_addr: *mut u8) -> u64);

pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
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

pub fn alt_bn128_fr_lincomb(
    _version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
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

fn check(code: u64) -> Result<(), AltBn128BatchError> {
    if code == 0 {
        Ok(())
    } else {
        Err(AltBn128BatchError::SyscallFailed)
    }
}
