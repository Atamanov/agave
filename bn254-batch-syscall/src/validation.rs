use solana_bn254_mcl_sys::{MclG1, MclG2, api};

/// Stable error taxonomy for both batch syscalls. The syscall boundary
/// flattens every variant to a nonzero return code; the distinctions exist for
/// crate users and tests.
#[derive(thiserror::Error, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AltBn128BatchError {
    #[error("input length is not a whole number of elements")]
    InvalidLength,
    #[error("field element encoding is not canonical (>= modulus)")]
    NonCanonical,
    #[error("point is not on the curve")]
    NotOnCurve,
    #[error("G2 point is not in the r-order subgroup")]
    NotInSubgroup,
    #[error("input is empty")]
    ZeroInput,
    #[error("input exceeds the per-call cap")]
    CapExceeded,
    #[error("points and scalars disagree in count")]
    LengthMismatch,
}

// infinity is a valid group element at this layer; rejecting infinity in proof
// positions is the on-chain verifier's job, not the syscall's
pub(crate) fn validate_g1(point: &MclG1) -> Result<(), AltBn128BatchError> {
    if api::g1_is_zero(point) {
        return Ok(());
    }
    if !api::g1_is_on_curve(point) {
        return Err(AltBn128BatchError::NotOnCurve);
    }
    // G1 cofactor is 1: on-curve implies subgroup membership
    Ok(())
}

pub(crate) fn validate_g2(point: &MclG2) -> Result<(), AltBn128BatchError> {
    if api::g2_is_zero(point) {
        return Ok(());
    }
    if !api::g2_is_on_curve(point) {
        return Err(AltBn128BatchError::NotOnCurve);
    }
    // the twist cofactor is ~2^254, so on-curve says nothing about subgroup
    // membership; mcl's isValidOrder checks [r]P == 0 directly, the defining
    // property every endomorphism-based fast test is proven equivalent to
    if !api::g2_is_in_subgroup(point) {
        return Err(AltBn128BatchError::NotInSubgroup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::{parse_g1, parse_g2},
            test_utils::{g1_bytes, g2_bytes, non_subgroup_g2, random_g1, random_g2, rng},
        },
        ark_bn254::{Fq, G1Affine},
    };

    #[test]
    fn test_validate_g1() {
        let mut rng = rng();
        assert_eq!(validate_g1(&parse_g1(&[0u8; 64]).unwrap()), Ok(()));
        let point = random_g1(&mut rng);
        assert_eq!(validate_g1(&parse_g1(&g1_bytes(&point)).unwrap()), Ok(()));
        let off_curve = G1Affine::new_unchecked(point.x, point.y + Fq::from(1u64));
        assert_eq!(
            validate_g1(&parse_g1(&g1_bytes(&off_curve)).unwrap()),
            Err(AltBn128BatchError::NotOnCurve)
        );
    }

    #[test]
    fn test_validate_g2() {
        let mut rng = rng();
        assert_eq!(validate_g2(&parse_g2(&[0u8; 128]).unwrap()), Ok(()));
        let point = random_g2(&mut rng);
        assert_eq!(validate_g2(&parse_g2(&g2_bytes(&point)).unwrap()), Ok(()));
        let mut off_curve = point;
        off_curve.y.c0 += Fq::from(1u64);
        assert_eq!(
            validate_g2(&parse_g2(&g2_bytes(&off_curve)).unwrap()),
            Err(AltBn128BatchError::NotOnCurve)
        );
    }

    #[test]
    fn test_non_subgroup_g2_fails_only_the_subgroup_check() {
        // companion to the rejection tests: the vector must pass every earlier
        // validation stage, or those tests would exercise the wrong branch
        let point = non_subgroup_g2();
        assert!(point.is_on_curve());
        assert_eq!(
            validate_g2(&parse_g2(&g2_bytes(&point)).unwrap()),
            Err(AltBn128BatchError::NotInSubgroup)
        );
        // its negation is out of the subgroup too (used by the cancellation test)
        assert_eq!(
            validate_g2(&parse_g2(&g2_bytes(&-point)).unwrap()),
            Err(AltBn128BatchError::NotInSubgroup)
        );
    }
}
