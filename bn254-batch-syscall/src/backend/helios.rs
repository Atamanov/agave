use {
    crate::{
        Version,
        pod::{PodG1G2Pair, PodG1Point, PodG2Point, PodGtElement, PodPairingResult, PodScalar},
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    core::mem::{align_of, offset_of, size_of},
    helios_bn254::{
        InputError as HeliosInputError, PodG1G2Pair as HeliosPair, PodG1Point as HeliosG1Point,
        PodG2Point as HeliosG2Point, PodGt as HeliosGt, PodPairingResult as HeliosPairingResult,
        PodScalar as HeliosScalar, Version as HeliosVersion,
    },
};

pub fn alt_bn128_g1_msm(
    version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    validate_equal_lengths(points.len(), scalars.len())?;
    let points = bytemuck::try_cast_slice::<_, HeliosG1Point>(points)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let scalars = bytemuck::try_cast_slice::<_, HeliosScalar>(scalars)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helios_bn254::alt_bn128_g1_msm(helios_version(version), points, scalars)
        .map(|point| PodG1Point(point.0))
        .map_err(map_error)
}

pub fn alt_bn128_pairing_check(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let pairs = bytemuck::try_cast_slice::<_, HeliosPair>(pairs)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helios_bn254::alt_bn128_pairing_check(helios_version(version), pairs).map_err(map_error)
}

pub fn alt_bn128_pairing_map(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128BatchError> {
    let pairs = bytemuck::try_cast_slice::<_, HeliosPair>(pairs)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helios_bn254::alt_bn128_pairing_map(helios_version(version), pairs)
        .map(|target| PodGtElement(target.0))
        .map_err(map_error)
}

pub fn alt_bn128_fr_lincomb(
    version: Version,
    left: &[PodScalar],
    right: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    validate_equal_lengths(left.len(), right.len())?;
    let left = bytemuck::try_cast_slice::<_, HeliosScalar>(left)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let right = bytemuck::try_cast_slice::<_, HeliosScalar>(right)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helios_bn254::alt_bn128_fr_lincomb(helios_version(version), left, right)
        .map(|scalar| PodScalar(scalar.0))
        .map_err(map_error)
}

pub fn alt_bn128_fr_batch_invert(
    version: Version,
    values: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let values = bytemuck::try_cast_slice::<_, HeliosScalar>(values)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helios_bn254::alt_bn128_fr_batch_invert(helios_version(version), values)
        .map(|values| {
            values
                .into_iter()
                .map(|scalar| PodScalar(scalar.0))
                .collect()
        })
        .map_err(map_error)
}

const fn helios_version(version: Version) -> HeliosVersion {
    match version {
        Version::V0 => HeliosVersion::V0,
    }
}

const fn map_error(error: HeliosInputError) -> AltBn128BatchError {
    match error {
        HeliosInputError::InvalidLength => AltBn128BatchError::InvalidLength,
        HeliosInputError::NonCanonical => AltBn128BatchError::NonCanonical,
        HeliosInputError::NotOnCurve => AltBn128BatchError::NotOnCurve,
        HeliosInputError::NotInSubgroup => AltBn128BatchError::NotInSubgroup,
        HeliosInputError::ZeroInput => AltBn128BatchError::ZeroInput,
        HeliosInputError::CapExceeded => AltBn128BatchError::CapExceeded,
        HeliosInputError::LengthMismatch => AltBn128BatchError::LengthMismatch,
    }
}

const _: () = {
    assert!(size_of::<PodG1Point>() == size_of::<HeliosG1Point>());
    assert!(align_of::<PodG1Point>() == align_of::<HeliosG1Point>());
    assert!(size_of::<PodG2Point>() == size_of::<HeliosG2Point>());
    assert!(align_of::<PodG2Point>() == align_of::<HeliosG2Point>());
    assert!(size_of::<PodScalar>() == size_of::<HeliosScalar>());
    assert!(align_of::<PodScalar>() == align_of::<HeliosScalar>());
    assert!(size_of::<PodG1G2Pair>() == size_of::<HeliosPair>());
    assert!(align_of::<PodG1G2Pair>() == align_of::<HeliosPair>());
    assert!(offset_of!(PodG1G2Pair, g1) == offset_of!(HeliosPair, g1));
    assert!(offset_of!(PodG1G2Pair, g2) == offset_of!(HeliosPair, g2));
    assert!(size_of::<PodPairingResult>() == size_of::<HeliosPairingResult>());
    assert!(align_of::<PodPairingResult>() == align_of::<HeliosPairingResult>());
    assert!(size_of::<PodGtElement>() == size_of::<HeliosGt>());
    assert!(align_of::<PodGtElement>() == align_of::<HeliosGt>());
    assert!(crate::G1_BYTES == helios_bn254::G1_BYTES);
    assert!(crate::G2_BYTES == helios_bn254::G2_BYTES);
    assert!(crate::SCALAR_BYTES == helios_bn254::SCALAR_BYTES);
    assert!(crate::PAIR_BYTES == helios_bn254::PAIR_BYTES);
    assert!(crate::FQ12_BYTES == helios_bn254::GT_BYTES);
    assert!(crate::MSM_MAX_POINTS == helios_bn254::MSM_MAX_POINTS);
    assert!(crate::PAIRING_MAX_PAIRS == helios_bn254::PAIRING_MAX_PAIRS);
    assert!(crate::PAIRING_MAP_MAX_PAIRS == helios_bn254::PAIRING_MAP_MAX_PAIRS);
    assert!(crate::FR_MAX_ELEMS == helios_bn254::FR_MAX_ELEMS);
};
