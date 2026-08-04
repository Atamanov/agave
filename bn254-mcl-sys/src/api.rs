//! Checked access to the MCL C interface.

use {
    crate::{
        MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR, MclFp, MclFp2, MclFr, MclG1, MclG2, MclG2OnCurve,
        MclG2Subgroup, MclGt, mcl_bn_final_exp, mcl_bn_fp_serialize, mcl_bn_fp_set_little_endian,
        mcl_bn_fr_add, mcl_bn_fr_inverse, mcl_bn_fr_is_zero, mcl_bn_fr_mul, mcl_bn_fr_serialize,
        mcl_bn_fr_set_little_endian, mcl_bn_g1_is_valid, mcl_bn_g1_is_zero, mcl_bn_g1_mul,
        mcl_bn_g1_mul_vec, mcl_bn_g1_normalize, mcl_bn_g2_is_valid, mcl_bn_g2_is_valid_order,
        mcl_bn_g2_is_zero, mcl_bn_gt_is_one, mcl_bn_gt_set_i32, mcl_bn_init,
        mcl_bn_miller_loop_vec, mcl_bn_verify_order_g2,
    },
    std::sync::OnceLock,
};

pub const FIELD_BYTES: usize = 32;
const GT_COEFFICIENTS: usize = 12;
pub const GT_BYTES: usize = FIELD_BYTES * GT_COEFFICIENTS;

const FQ_MODULUS_BE: [u8; FIELD_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

const FR_MODULUS_BE: [u8; FIELD_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(thiserror::Error, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MclError {
    #[error("MCL initialization failed with code {0}")]
    Initialization(i32),
    #[error("MCL {function} failed with code {code}")]
    FunctionReturn { function: &'static str, code: i32 },
    #[error("MCL {function} returned size {actual}, expected {expected}")]
    OutputSize {
        function: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("MCL {function} returned invalid boolean value {value}")]
    InvalidBoolean { function: &'static str, value: i32 },
    #[error("base field input is not canonical")]
    NonCanonicalBaseField,
    #[error("scalar field input is not canonical")]
    NonCanonicalScalar,
    #[error("point is not on the curve")]
    NotOnCurve,
    #[error("G2 point is not in the scalar subgroup")]
    NotInSubgroup,
    #[error("MCL input slices have different lengths")]
    LengthMismatch,
    #[error("MCL input slice is empty")]
    EmptyInput,
    #[error("MCL precondition failed: {0}")]
    Precondition(&'static str),
}

pub fn fp_from_be(bytes: &[u8; FIELD_BYTES]) -> Result<MclFp, MclError> {
    if bytes >= &FQ_MODULUS_BE {
        return Err(MclError::NonCanonicalBaseField);
    }
    ensure_init()?;
    let mut little_endian = *bytes;
    little_endian.reverse();
    let mut value = MclFp::default();
    // SAFETY: the input and output buffers have the exact MCL Fp size.
    let code = unsafe {
        mcl_bn_fp_set_little_endian(&mut value, little_endian.as_ptr(), little_endian.len())
    };
    check_return("mclBnFp_setLittleEndian", code)?;
    Ok(value)
}

pub fn fp_to_be(value: &MclFp) -> Result<[u8; FIELD_BYTES], MclError> {
    ensure_init()?;
    let mut output = [0u8; FIELD_BYTES];
    // SAFETY: the output buffer is writable for FIELD_BYTES bytes and value is initialized.
    let actual = unsafe { mcl_bn_fp_serialize(output.as_mut_ptr(), output.len(), value) };
    check_size("mclBnFp_serialize", actual, output.len())?;
    output.reverse();
    Ok(output)
}

pub fn fr_from_be(bytes: &[u8; FIELD_BYTES]) -> Result<MclFr, MclError> {
    if bytes >= &FR_MODULUS_BE {
        return Err(MclError::NonCanonicalScalar);
    }
    ensure_init()?;
    let mut little_endian = *bytes;
    little_endian.reverse();
    let mut value = MclFr::default();
    // SAFETY: the input and output buffers have the exact MCL Fr size.
    let code = unsafe {
        mcl_bn_fr_set_little_endian(&mut value, little_endian.as_ptr(), little_endian.len())
    };
    check_return("mclBnFr_setLittleEndian", code)?;
    Ok(value)
}

pub fn fr_to_be(value: &MclFr) -> Result<[u8; FIELD_BYTES], MclError> {
    ensure_init()?;
    let mut output = [0u8; FIELD_BYTES];
    // SAFETY: the output buffer is writable for FIELD_BYTES bytes and value is initialized.
    let actual = unsafe { mcl_bn_fr_serialize(output.as_mut_ptr(), output.len(), value) };
    check_size("mclBnFr_serialize", actual, output.len())?;
    output.reverse();
    Ok(output)
}

macro_rules! fr_binary_operation {
    ($name:ident, $ffi:ident) => {
        pub fn $name(left: &MclFr, right: &MclFr) -> Result<MclFr, MclError> {
            ensure_init()?;
            let mut output = MclFr::default();
            // SAFETY: all pointers refer to initialized MCL values and output is distinct.
            unsafe { $ffi(&mut output, left, right) };
            Ok(output)
        }
    };
}

fr_binary_operation!(fr_add, mcl_bn_fr_add);
fr_binary_operation!(fr_mul, mcl_bn_fr_mul);

pub fn fr_inverse(value: &MclFr) -> Result<MclFr, MclError> {
    ensure_init()?;
    if fr_is_zero(value)? {
        return Err(MclError::Precondition("Fr inverse input is zero"));
    }
    let mut output = MclFr::default();
    // SAFETY: value is nonzero and both pointers refer to initialized MCL values.
    unsafe { mcl_bn_fr_inverse(&mut output, value) };
    Ok(output)
}

pub fn fr_is_zero(value: &MclFr) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: value refers to an initialized MCL Fr value.
    let result = unsafe { mcl_bn_fr_is_zero(value) };
    check_boolean("mclBnFr_isZero", result)
}

pub fn g1_affine(x: MclFp, y: MclFp) -> Result<MclG1, MclError> {
    let point = MclG1 { x, y, z: fp_one()? };
    if !g1_is_on_curve(&point)? {
        return Err(MclError::NotOnCurve);
    }
    Ok(point)
}

pub fn g1_infinity() -> MclG1 {
    MclG1::default()
}

pub fn g1_xy(point: &MclG1) -> Result<Option<(MclFp, MclFp)>, MclError> {
    ensure_init()?;
    if g1_is_zero(point)? {
        return Ok(None);
    }
    let mut normalized = MclG1::default();
    // SAFETY: point is initialized and normalized is a distinct writable value.
    unsafe { mcl_bn_g1_normalize(&mut normalized, point) };
    Ok(Some((normalized.x, normalized.y)))
}

pub fn g1_is_zero(point: &MclG1) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: point refers to an initialized MCL G1 value.
    let result = unsafe { mcl_bn_g1_is_zero(point) };
    check_boolean("mclBnG1_isZero", result)
}

pub fn g1_mul(point: &MclG1, scalar: &MclFr) -> Result<MclG1, MclError> {
    ensure_init()?;
    let mut output = MclG1::default();
    // SAFETY: all pointers refer to initialized values and output is distinct.
    unsafe { mcl_bn_g1_mul(&mut output, point, scalar) };
    Ok(output)
}

pub fn g1_mul_vec(points: &mut [MclG1], scalars: &[MclFr]) -> Result<MclG1, MclError> {
    ensure_init()?;
    if points.len() != scalars.len() {
        return Err(MclError::LengthMismatch);
    }
    if points.is_empty() {
        return Err(MclError::EmptyInput);
    }
    let mut output = MclG1::default();
    // SAFETY: both slices contain count initialized values. Rust enforces exclusive point access.
    unsafe {
        mcl_bn_g1_mul_vec(
            &mut output,
            points.as_mut_ptr(),
            scalars.as_ptr(),
            points.len(),
        )
    };
    Ok(output)
}

pub fn g2_affine(x0: MclFp, x1: MclFp, y0: MclFp, y1: MclFp) -> Result<MclG2OnCurve, MclError> {
    let point = MclG2 {
        x: MclFp2 { d: [x0, x1] },
        y: MclFp2 { d: [y0, y1] },
        z: MclFp2 {
            d: [fp_one()?, MclFp::default()],
        },
    };
    if !g2_is_on_curve(&point)? {
        return Err(MclError::NotOnCurve);
    }
    Ok(MclG2OnCurve(point))
}

pub fn g2_infinity() -> MclG2OnCurve {
    MclG2OnCurve(MclG2::default())
}

pub fn g2_is_zero(point: &MclG2OnCurve) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: point refers to an initialized MCL G2 value.
    let result = unsafe { mcl_bn_g2_is_zero(&point.0) };
    check_boolean("mclBnG2_isZero", result)
}

pub fn g2_into_subgroup(point: MclG2OnCurve) -> Result<MclG2Subgroup, MclError> {
    ensure_init()?;
    // SAFETY: MclG2OnCurve proves the precondition for mclBnG2_isValidOrder.
    let result = unsafe { mcl_bn_g2_is_valid_order(&point.0) };
    if !check_boolean("mclBnG2_isValidOrder", result)? {
        return Err(MclError::NotInSubgroup);
    }
    Ok(MclG2Subgroup(point.0))
}

pub fn pairing_product(
    g1_points: &[MclG1],
    g2_points: &[MclG2Subgroup],
) -> Result<MclGt, MclError> {
    ensure_init()?;
    if g1_points.len() != g2_points.len() {
        return Err(MclError::LengthMismatch);
    }
    if g1_points.is_empty() {
        return Err(MclError::EmptyInput);
    }
    let mut miller_output = zero_fp12();
    // SAFETY: both slices contain count initialized values and output is distinct.
    unsafe {
        mcl_bn_miller_loop_vec(
            &mut miller_output,
            g1_points.as_ptr(),
            g2_points.as_ptr(),
            g1_points.len(),
        )
    };
    let mut output = zero_fp12();
    // SAFETY: miller_output is initialized by MCL and output is distinct.
    unsafe { mcl_bn_final_exp(&mut output, &miller_output) };
    Ok(output)
}

pub fn gt_one() -> Result<MclGt, MclError> {
    ensure_init()?;
    let mut output = zero_fp12();
    // SAFETY: output is writable and the integer value one is valid in Fp12.
    unsafe { mcl_bn_gt_set_i32(&mut output, 1) };
    Ok(output)
}

pub fn gt_is_one(value: &MclGt) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: value refers to an initialized MCL GT value.
    let result = unsafe { mcl_bn_gt_is_one(value) };
    check_boolean("mclBnGT_isOne", result)
}

/// MCL stores Fp12 as Fp6(a, b), each Fp6 as Fp2(a, b, c), and each Fp2 as (a, b).
pub fn gt_to_be(value: &MclGt) -> Result<[u8; GT_BYTES], MclError> {
    let mut output = [0u8; GT_BYTES];
    for (slot, coefficient) in output.chunks_exact_mut(FIELD_BYTES).zip(value.d.iter()) {
        slot.copy_from_slice(&fp_to_be(coefficient)?);
    }
    Ok(output)
}

fn ensure_init() -> Result<(), MclError> {
    static INIT: OnceLock<Result<(), MclError>> = OnceLock::new();
    *INIT.get_or_init(|| {
        // SAFETY: OnceLock serializes the process-wide MCL initialization.
        let code = unsafe { mcl_bn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR) };
        if code != 0 {
            return Err(MclError::Initialization(code));
        }
        // SAFETY: initialization succeeded and this call only sets MCL validation policy.
        unsafe { mcl_bn_verify_order_g2(0) };
        Ok(())
    })
}

fn g1_is_on_curve(point: &MclG1) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: point refers to an initialized MCL G1 value.
    let result = unsafe { mcl_bn_g1_is_valid(point) };
    check_boolean("mclBnG1_isValid", result)
}

fn g2_is_on_curve(point: &MclG2) -> Result<bool, MclError> {
    ensure_init()?;
    // SAFETY: point refers to an initialized MCL G2 value.
    let result = unsafe { mcl_bn_g2_is_valid(point) };
    check_boolean("mclBnG2_isValid", result)
}

fn fp_one() -> Result<MclFp, MclError> {
    static ONE: OnceLock<Result<MclFp, MclError>> = OnceLock::new();
    *ONE.get_or_init(|| {
        let mut one = [0u8; FIELD_BYTES];
        one[FIELD_BYTES - 1] = 1;
        fp_from_be(&one)
    })
}

fn zero_fp12() -> MclGt {
    MclGt {
        d: [MclFp::default(); GT_COEFFICIENTS],
    }
}

fn check_return(function: &'static str, code: i32) -> Result<(), MclError> {
    if code == 0 {
        Ok(())
    } else {
        Err(MclError::FunctionReturn { function, code })
    }
}

fn check_size(function: &'static str, actual: usize, expected: usize) -> Result<(), MclError> {
    if actual == expected {
        Ok(())
    } else {
        Err(MclError::OutputSize {
            function,
            actual,
            expected,
        })
    }
}

fn check_boolean(function: &'static str, value: i32) -> Result<bool, MclError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MclError::InvalidBoolean { function, value }),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{Bn254, Fq, G1Affine, G2Affine},
        ark_ec::{AffineRepr, pairing::Pairing},
        ark_ff::{BigInteger, PrimeField},
    };

    fn fq_to_be(value: &Fq) -> [u8; FIELD_BYTES] {
        let mut output = [0u8; FIELD_BYTES];
        output.copy_from_slice(&value.into_bigint().to_bytes_be());
        output
    }

    fn g1_from_ark(point: &G1Affine) -> MclG1 {
        let (x, y) = point.xy().unwrap();
        g1_affine(
            fp_from_be(&fq_to_be(&x)).unwrap(),
            fp_from_be(&fq_to_be(&y)).unwrap(),
        )
        .unwrap()
    }

    fn g2_from_ark(point: &G2Affine) -> MclG2Subgroup {
        let (x, y) = point.xy().unwrap();
        g2_into_subgroup(
            g2_affine(
                fp_from_be(&fq_to_be(&x.c0)).unwrap(),
                fp_from_be(&fq_to_be(&x.c1)).unwrap(),
                fp_from_be(&fq_to_be(&y.c0)).unwrap(),
                fp_from_be(&fq_to_be(&y.c1)).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn ark_gt_to_be(value: &ark_bn254::Fq12) -> [u8; GT_BYTES] {
        let coefficients = [
            &value.c0.c0.c0,
            &value.c0.c0.c1,
            &value.c0.c1.c0,
            &value.c0.c1.c1,
            &value.c0.c2.c0,
            &value.c0.c2.c1,
            &value.c1.c0.c0,
            &value.c1.c0.c1,
            &value.c1.c1.c0,
            &value.c1.c1.c1,
            &value.c1.c2.c0,
            &value.c1.c2.c1,
        ];
        let mut output = [0u8; GT_BYTES];
        for (slot, coefficient) in output.chunks_exact_mut(FIELD_BYTES).zip(coefficients) {
            slot.copy_from_slice(&fq_to_be(coefficient));
        }
        output
    }

    #[test]
    fn field_encodings_are_canonical() {
        let mut one = [0u8; FIELD_BYTES];
        one[FIELD_BYTES - 1] = 1;
        assert_eq!(fp_to_be(&fp_from_be(&one).unwrap()).unwrap(), one);
        assert_eq!(fr_to_be(&fr_from_be(&one).unwrap()).unwrap(), one);
        assert_eq!(
            fp_from_be(&FQ_MODULUS_BE),
            Err(MclError::NonCanonicalBaseField)
        );
        assert_eq!(
            fr_from_be(&FR_MODULUS_BE),
            Err(MclError::NonCanonicalScalar)
        );
    }

    #[test]
    fn gt_identity_has_the_canonical_tower_encoding() {
        let identity = gt_one().unwrap();
        assert!(gt_is_one(&identity).unwrap());
        let encoded = gt_to_be(&identity).unwrap();
        let mut expected = [0u8; GT_BYTES];
        expected[FIELD_BYTES - 1] = 1;
        assert_eq!(encoded, expected);
    }

    #[test]
    fn pairing_gt_matches_arkworks_coefficient_order() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::generator();
        let mcl = pairing_product(&[g1_from_ark(&g1)], &[g2_from_ark(&g2)]).unwrap();
        let ark = Bn254::pairing(g1, g2).0;
        assert_eq!(gt_to_be(&mcl).unwrap(), ark_gt_to_be(&ark));
        assert!(!gt_is_one(&mcl).unwrap());
    }
}
