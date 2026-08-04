use {
    super::map_mcl_error,
    crate::{
        pod::{PodG1Point, PodG2Point, PodScalar},
        validation::AltBn128BatchError,
    },
    solana_bn254_mcl_sys::{MclFp, MclFr, MclG1, MclG2OnCurve, api},
};

pub(super) fn parse_scalar(scalar: &PodScalar) -> Result<MclFr, AltBn128BatchError> {
    api::fr_from_be(&scalar.0).map_err(map_mcl_error)
}

pub(super) fn parse_g1(point: &PodG1Point) -> Result<MclG1, AltBn128BatchError> {
    let (coordinates, remainder) = point.0.as_chunks::<32>();
    let [x_bytes, y_bytes] = coordinates else {
        return Err(AltBn128BatchError::BackendInvariant);
    };
    if !remainder.is_empty() {
        return Err(AltBn128BatchError::BackendInvariant);
    }

    let x = parse_base_field(x_bytes)?;
    let y = parse_base_field(y_bytes)?;
    let point = if point.0.iter().all(|byte| *byte == 0) {
        api::g1_infinity()
    } else {
        api::g1_affine(x, y).map_err(map_mcl_error)?
    };
    Ok(point)
}

/// The deferred subgroup phase preserves cross-pair error order.
pub(super) fn parse_g2_on_curve(point: &PodG2Point) -> Result<MclG2OnCurve, AltBn128BatchError> {
    let (coordinates, remainder) = point.0.as_chunks::<32>();
    let [x1_bytes, x0_bytes, y1_bytes, y0_bytes] = coordinates else {
        return Err(AltBn128BatchError::BackendInvariant);
    };
    if !remainder.is_empty() {
        return Err(AltBn128BatchError::BackendInvariant);
    }

    // Wire-order parsing keeps the public error precedence stable.
    let x1 = parse_base_field(x1_bytes)?;
    let x0 = parse_base_field(x0_bytes)?;
    let y1 = parse_base_field(y1_bytes)?;
    let y0 = parse_base_field(y0_bytes)?;
    let point = if point.0.iter().all(|byte| *byte == 0) {
        api::g2_infinity()
    } else {
        api::g2_affine(x0, x1, y0, y1).map_err(map_mcl_error)?
    };
    Ok(point)
}

pub(super) fn serialize_g1(point: &MclG1) -> Result<PodG1Point, AltBn128BatchError> {
    let mut output = [0u8; 64];
    if let Some((x, y)) = api::g1_xy(point).map_err(map_mcl_error)? {
        let (coordinates, remainder) = output.as_chunks_mut::<32>();
        let [x_bytes, y_bytes] = coordinates else {
            return Err(AltBn128BatchError::BackendInvariant);
        };
        if !remainder.is_empty() {
            return Err(AltBn128BatchError::BackendInvariant);
        }
        *x_bytes = api::fp_to_be(&x).map_err(map_mcl_error)?;
        *y_bytes = api::fp_to_be(&y).map_err(map_mcl_error)?;
    }
    Ok(PodG1Point(output))
}

fn parse_base_field(bytes: &[u8; 32]) -> Result<MclFp, AltBn128BatchError> {
    api::fp_from_be(bytes).map_err(map_mcl_error)
}
