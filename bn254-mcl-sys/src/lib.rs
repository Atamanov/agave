//! Safe Rust access to the vendored MCL BN254 implementation.

pub mod api;

use std::os::raw::c_int;

const MCL_BN_SNARK1: c_int = 4;
const MCLBN_COMPILED_TIME_VAR: c_int = 44;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MclFp {
    d: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MclFr {
    d: [u64; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MclFp2 {
    d: [MclFp; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MclG1 {
    x: MclFp,
    y: MclFp,
    z: MclFp,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MclG2 {
    x: MclFp2,
    y: MclFp2,
    z: MclFp2,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct MclG2OnCurve(MclG2);

#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct MclG2Subgroup(MclG2);

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MclGt {
    d: [MclFp; 12],
}

const _: () = {
    assert!(size_of::<MclFp>() == 32);
    assert!(align_of::<MclFp>() == 8);
    assert!(size_of::<MclFr>() == 32);
    assert!(align_of::<MclFr>() == 8);
    assert!(size_of::<MclFp2>() == 64);
    assert!(align_of::<MclFp2>() == 8);
    assert!(size_of::<MclG1>() == 96);
    assert!(align_of::<MclG1>() == 8);
    assert!(size_of::<MclG2>() == 192);
    assert!(align_of::<MclG2>() == 8);
    assert!(size_of::<MclG2OnCurve>() == 192);
    assert!(align_of::<MclG2OnCurve>() == 8);
    assert!(size_of::<MclG2Subgroup>() == 192);
    assert!(align_of::<MclG2Subgroup>() == 8);
    assert!(size_of::<MclGt>() == 384);
    assert!(align_of::<MclGt>() == 8);
};

unsafe extern "C" {
    #[link_name = "mclBn_init"]
    pub(crate) fn mcl_bn_init(curve: c_int, compiled_time_var: c_int) -> c_int;
    #[link_name = "mclBn_verifyOrderG2"]
    pub(crate) fn mcl_bn_verify_order_g2(verify: c_int);

    #[link_name = "mclBnFp_setLittleEndian"]
    pub(crate) fn mcl_bn_fp_set_little_endian(
        value: *mut MclFp,
        input: *const u8,
        input_len: usize,
    ) -> c_int;
    #[link_name = "mclBnFp_serialize"]
    pub(crate) fn mcl_bn_fp_serialize(
        output: *mut u8,
        output_len: usize,
        value: *const MclFp,
    ) -> usize;

    #[link_name = "mclBnFr_setLittleEndian"]
    pub(crate) fn mcl_bn_fr_set_little_endian(
        value: *mut MclFr,
        input: *const u8,
        input_len: usize,
    ) -> c_int;
    #[link_name = "mclBnFr_serialize"]
    pub(crate) fn mcl_bn_fr_serialize(
        output: *mut u8,
        output_len: usize,
        value: *const MclFr,
    ) -> usize;
    #[link_name = "mclBnFr_add"]
    pub(crate) fn mcl_bn_fr_add(output: *mut MclFr, left: *const MclFr, right: *const MclFr);
    #[link_name = "mclBnFr_mul"]
    pub(crate) fn mcl_bn_fr_mul(output: *mut MclFr, left: *const MclFr, right: *const MclFr);
    #[link_name = "mclBnFr_inv"]
    pub(crate) fn mcl_bn_fr_inverse(output: *mut MclFr, value: *const MclFr);
    #[link_name = "mclBnFr_isZero"]
    pub(crate) fn mcl_bn_fr_is_zero(value: *const MclFr) -> c_int;

    #[link_name = "mclBnG1_isValid"]
    pub(crate) fn mcl_bn_g1_is_valid(value: *const MclG1) -> c_int;
    #[link_name = "mclBnG1_isZero"]
    pub(crate) fn mcl_bn_g1_is_zero(value: *const MclG1) -> c_int;
    #[link_name = "mclBnG1_mul"]
    pub(crate) fn mcl_bn_g1_mul(output: *mut MclG1, point: *const MclG1, scalar: *const MclFr);
    #[link_name = "mclBnG1_mulVec"]
    pub(crate) fn mcl_bn_g1_mul_vec(
        output: *mut MclG1,
        points: *mut MclG1,
        scalars: *const MclFr,
        count: usize,
    );
    #[link_name = "mclBnG1_normalize"]
    pub(crate) fn mcl_bn_g1_normalize(output: *mut MclG1, value: *const MclG1);

    #[link_name = "mclBnG2_isValid"]
    pub(crate) fn mcl_bn_g2_is_valid(value: *const MclG2) -> c_int;
    #[link_name = "mclBnG2_isValidOrder"]
    pub(crate) fn mcl_bn_g2_is_valid_order(value: *const MclG2) -> c_int;
    #[link_name = "mclBnG2_isZero"]
    pub(crate) fn mcl_bn_g2_is_zero(value: *const MclG2) -> c_int;
    #[link_name = "mclBnGT_setInt32"]
    pub(crate) fn mcl_bn_gt_set_i32(output: *mut MclGt, value: c_int);
    #[link_name = "mclBnGT_isOne"]
    pub(crate) fn mcl_bn_gt_is_one(value: *const MclGt) -> c_int;

    #[link_name = "mclBn_millerLoopVec"]
    pub(crate) fn mcl_bn_miller_loop_vec(
        output: *mut MclGt,
        g1_points: *const MclG1,
        g2_points: *const MclG2Subgroup,
        count: usize,
    );
    #[link_name = "mclBn_finalExp"]
    pub(crate) fn mcl_bn_final_exp(output: *mut MclGt, value: *const MclGt);
}
