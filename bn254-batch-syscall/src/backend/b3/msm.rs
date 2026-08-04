use {
    super::{map_mcl_error, wire},
    crate::{
        Version,
        encoding::MSM_MAX_POINTS,
        pod::{PodG1Point, PodScalar},
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    solana_bn254_mcl_sys::api,
};

pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    validate_equal_lengths(points.len(), scalars.len())?;
    if points.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if points.len() > MSM_MAX_POINTS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut points = points
        .iter()
        .map(wire::parse_g1)
        .collect::<Result<Vec<_>, _>>()?;
    let scalars = scalars
        .iter()
        .map(wire::parse_scalar)
        .collect::<Result<Vec<_>, _>>()?;
    let result = api::g1_mul_vec(&mut points, &scalars).map_err(map_mcl_error)?;
    wire::serialize_g1(&result)
}
