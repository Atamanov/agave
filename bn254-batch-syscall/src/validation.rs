use {
    ark_bn254::{G1Affine, G2Affine},
    ark_ec::AffineRepr,
};

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

// exhaustive on both sides: a variant added to either taxonomy fails this
// impl instead of silently renumbering the syscall's error surface
impl From<helios_bn254::AltBn128BatchError> for AltBn128BatchError {
    fn from(error: helios_bn254::AltBn128BatchError) -> Self {
        match error {
            helios_bn254::AltBn128BatchError::InvalidLength => Self::InvalidLength,
            helios_bn254::AltBn128BatchError::NonCanonical => Self::NonCanonical,
            helios_bn254::AltBn128BatchError::NotOnCurve => Self::NotOnCurve,
            helios_bn254::AltBn128BatchError::NotInSubgroup => Self::NotInSubgroup,
            helios_bn254::AltBn128BatchError::ZeroInput => Self::ZeroInput,
            helios_bn254::AltBn128BatchError::CapExceeded => Self::CapExceeded,
            helios_bn254::AltBn128BatchError::LengthMismatch => Self::LengthMismatch,
        }
    }
}

// infinity is a valid group element at this layer; rejecting infinity in proof
// positions is the on-chain verifier's job, not the syscall's
pub(crate) fn validate_g1(point: &G1Affine) -> Result<(), AltBn128BatchError> {
    if point.is_zero() {
        return Ok(());
    }
    if !point.is_on_curve() {
        return Err(AltBn128BatchError::NotOnCurve);
    }
    // G1 cofactor is 1: on-curve implies subgroup membership
    Ok(())
}

pub(crate) fn validate_g2(point: &G2Affine) -> Result<(), AltBn128BatchError> {
    if point.is_zero() {
        return Ok(());
    }
    if !point.is_on_curve() {
        return Err(AltBn128BatchError::NotOnCurve);
    }
    // the twist cofactor is ~2^254, so on-curve says nothing about subgroup
    // membership; arkworks 0.5 implements the fast endomorphism test
    // [x+1]P + psi([x]P) + psi^2([x]P) == psi^3([2x]P)
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(AltBn128BatchError::NotInSubgroup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{non_subgroup_g2, random_g1, random_g2, rng},
        ark_bn254::Fq,
    };

    #[test]
    fn test_validate_g1() {
        let mut rng = rng();
        assert_eq!(validate_g1(&G1Affine::zero()), Ok(()));
        let point = random_g1(&mut rng);
        assert_eq!(validate_g1(&point), Ok(()));
        let off_curve = G1Affine::new_unchecked(point.x, point.y + Fq::from(1u64));
        assert_eq!(validate_g1(&off_curve), Err(AltBn128BatchError::NotOnCurve));
    }

    #[test]
    fn test_validate_g2() {
        let mut rng = rng();
        assert_eq!(validate_g2(&G2Affine::zero()), Ok(()));
        let point = random_g2(&mut rng);
        assert_eq!(validate_g2(&point), Ok(()));
        let mut off_curve = point;
        off_curve.y.c0 += Fq::from(1u64);
        assert_eq!(validate_g2(&off_curve), Err(AltBn128BatchError::NotOnCurve));
    }

    #[test]
    fn test_non_subgroup_g2_fails_only_the_subgroup_check() {
        // companion to the rejection tests: the vector must pass every earlier
        // validation stage, or those tests would exercise the wrong branch
        let point = non_subgroup_g2();
        assert!(point.is_on_curve());
        assert_eq!(validate_g2(&point), Err(AltBn128BatchError::NotInSubgroup));
        // its negation is out of the subgroup too (used by the cancellation test)
        assert_eq!(validate_g2(&-point), Err(AltBn128BatchError::NotInSubgroup));
    }
}
