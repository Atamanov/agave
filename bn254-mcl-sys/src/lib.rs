//! Raw FFI bindings to the vendored herumi/mcl bn_c256 C API (BN_SNARK1 =
//! alt_bn128, 256-bit Fp and Fr), plus a safe typed layer in [`api`].
//!
//! All unsafe in the workspace's bn254 batch stack is confined to this crate;
//! consumers go through [`api`], which initializes the library exactly once
//! and never hands out an uninitialized or unchecked value.

#![allow(non_snake_case)]

pub mod api;

use std::os::raw::c_int;

/// mcl curve id for BN_SNARK1 (alt_bn128 / bn254).
pub const MCL_BN_SNARK1: c_int = 4;
/// MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE for the 256/256-bit build;
/// mclBn_init rejects a mismatch against the compiled library.
pub const MCLBN_COMPILED_TIME_VAR: c_int = 44;

/// Fp element: four 64-bit limbs, little-endian, Montgomery form.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MclFp {
    pub d: [u64; 4],
}

/// Fr element, same layout as [`MclFp`] in the 256/256-bit build.
pub type MclFr = MclFp;

/// Fp2 element: c0 + c1*u as two Fp values.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MclFp2 {
    pub d: [MclFp; 2],
}

/// G1 point in Jacobian coordinates; z == 0 encodes infinity, a normalized
/// point has z == 1.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MclG1 {
    pub x: MclFp,
    pub y: MclFp,
    pub z: MclFp,
}

/// G2 point in Jacobian coordinates over Fp2; z == 0 encodes infinity.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MclG2 {
    pub x: MclFp2,
    pub y: MclFp2,
    pub z: MclFp2,
}

/// GT (Fp12) element as twelve Fp values.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MclGT {
    pub d: [MclFp; 12],
}

unsafe extern "C" {
    pub fn mclBn_init(curve: c_int, compiledTimeVar: c_int) -> c_int;
    pub fn mclBn_verifyOrderG1(doVerify: c_int);
    pub fn mclBn_verifyOrderG2(doVerify: c_int);

    pub fn mclBnFp_setLittleEndian(x: *mut MclFp, buf: *const u8, bufSize: usize) -> c_int;
    pub fn mclBnFp_serialize(buf: *mut u8, maxBufSize: usize, x: *const MclFp) -> usize;
    pub fn mclBnFp_neg(y: *mut MclFp, x: *const MclFp);
    pub fn mclBnFp_isValid(x: *const MclFp) -> c_int;
    pub fn mclBnFp_isEqual(x: *const MclFp, y: *const MclFp) -> c_int;

    pub fn mclBnFr_setLittleEndian(x: *mut MclFr, buf: *const u8, bufSize: usize) -> c_int;
    pub fn mclBnFr_setLittleEndianMod(x: *mut MclFr, buf: *const u8, bufSize: usize) -> c_int;
    pub fn mclBnFr_setBigEndianMod(x: *mut MclFr, buf: *const u8, bufSize: usize) -> c_int;
    pub fn mclBnFr_serialize(buf: *mut u8, maxBufSize: usize, x: *const MclFr) -> usize;
    pub fn mclBnFr_add(z: *mut MclFr, x: *const MclFr, y: *const MclFr);
    pub fn mclBnFr_sub(z: *mut MclFr, x: *const MclFr, y: *const MclFr);
    pub fn mclBnFr_mul(z: *mut MclFr, x: *const MclFr, y: *const MclFr);
    pub fn mclBnFr_sqr(y: *mut MclFr, x: *const MclFr);
    pub fn mclBnFr_neg(y: *mut MclFr, x: *const MclFr);
    pub fn mclBnFr_inv(y: *mut MclFr, x: *const MclFr);
    pub fn mclBnFr_isZero(x: *const MclFr) -> c_int;
    pub fn mclBnFr_isValid(x: *const MclFr) -> c_int;
    pub fn mclBnFr_isEqual(x: *const MclFr, y: *const MclFr) -> c_int;

    pub fn mclBnG1_isValid(x: *const MclG1) -> c_int;
    pub fn mclBnG1_isValidOrder(x: *const MclG1) -> c_int;
    pub fn mclBnG1_isZero(x: *const MclG1) -> c_int;
    pub fn mclBnG1_isEqual(x: *const MclG1, y: *const MclG1) -> c_int;
    pub fn mclBnG1_neg(y: *mut MclG1, x: *const MclG1);
    pub fn mclBnG1_add(z: *mut MclG1, x: *const MclG1, y: *const MclG1);
    pub fn mclBnG1_dbl(y: *mut MclG1, x: *const MclG1);
    pub fn mclBnG1_mul(z: *mut MclG1, x: *const MclG1, y: *const MclFr);
    pub fn mclBnG1_mulVec(z: *mut MclG1, x: *mut MclG1, y: *const MclFr, n: usize);
    pub fn mclBnG1_normalize(y: *mut MclG1, x: *const MclG1);
    pub fn mclBnG1_hashAndMapTo(x: *mut MclG1, buf: *const u8, bufSize: usize) -> c_int;

    pub fn mclBnG2_isValid(x: *const MclG2) -> c_int;
    pub fn mclBnG2_isValidOrder(x: *const MclG2) -> c_int;
    pub fn mclBnG2_isZero(x: *const MclG2) -> c_int;
    pub fn mclBnG2_isEqual(x: *const MclG2, y: *const MclG2) -> c_int;
    pub fn mclBnG2_neg(y: *mut MclG2, x: *const MclG2);
    pub fn mclBnG2_add(z: *mut MclG2, x: *const MclG2, y: *const MclG2);
    pub fn mclBnG2_mul(z: *mut MclG2, x: *const MclG2, y: *const MclFr);
    pub fn mclBnG2_normalize(y: *mut MclG2, x: *const MclG2);
    pub fn mclBnG2_hashAndMapTo(x: *mut MclG2, buf: *const u8, bufSize: usize) -> c_int;

    pub fn mclBnGT_isOne(x: *const MclGT) -> c_int;
    pub fn mclBnGT_isEqual(x: *const MclGT, y: *const MclGT) -> c_int;
    pub fn mclBnGT_mul(z: *mut MclGT, x: *const MclGT, y: *const MclGT);

    pub fn mclBn_pairing(z: *mut MclGT, x: *const MclG1, y: *const MclG2);
    pub fn mclBn_millerLoop(z: *mut MclGT, x: *const MclG1, y: *const MclG2);
    pub fn mclBn_millerLoopVec(z: *mut MclGT, x: *const MclG1, y: *const MclG2, n: usize);
    pub fn mclBn_finalExp(y: *mut MclGT, x: *const MclGT);
}
