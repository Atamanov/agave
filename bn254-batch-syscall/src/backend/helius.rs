use {
    crate::{
        Version,
        pod::{PodG1G2Pair, PodG1Point, PodG2Point, PodGtElement, PodPairingResult, PodScalar},
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    core::mem::{align_of, offset_of, size_of},
    helius_bn254::{
        FinalExponentiationProbe as HeliusFinalExponentiationProbe,
        FinalExponentiationResult as HeliusFinalExponentiationResult,
        G2SubgroupProbe as HeliusG2SubgroupProbe, InputError as HeliusInputError,
        PodG1G2Pair as HeliusPair, PodG1Point as HeliusG1Point, PodG2Point as HeliusG2Point,
        PodGt as HeliusGt, PodPairingResult as HeliusPairingResult, PodScalar as HeliusScalar,
        RegisteredG2 as HeliusRegisteredG2, RegisteredG2Pair as HeliusRegisteredG2Pair,
        TrustedGt as HeliusTrustedGt, Version as HeliusVersion,
    },
};

#[derive(Clone, Debug)]
pub struct RegisteredG2(HeliusRegisteredG2);

#[derive(Clone, Debug)]
pub struct RegisteredG2Pair {
    pub g1: PodG1Point,
    pub g2: RegisteredG2,
}

#[derive(Clone, Debug)]
pub struct TrustedGt(HeliusTrustedGt);

#[derive(Clone, Debug)]
pub struct FinalExponentiationProbe(HeliusFinalExponentiationProbe);

#[derive(Clone, Debug)]
pub struct FinalExponentiationResult(HeliusFinalExponentiationResult);

#[derive(Clone, Copy, Debug)]
pub struct G2SubgroupProbe(HeliusG2SubgroupProbe);

impl RegisteredG2 {
    pub fn to_bytes(&self) -> PodG2Point {
        PodG2Point(self.0.to_bytes().0)
    }

    pub fn prepared_bytes(&self) -> Vec<u8> {
        self.0.prepared_bytes()
    }
}

pub fn alt_bn128_g1_msm(
    version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    validate_equal_lengths(points.len(), scalars.len())?;
    let points = bytemuck::try_cast_slice::<_, HeliusG1Point>(points)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let scalars = bytemuck::try_cast_slice::<_, HeliusScalar>(scalars)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::alt_bn128_g1_msm(helius_version(version), points, scalars)
        .map(|point| PodG1Point(point.0))
        .map_err(map_error)
}

pub fn alt_bn128_pairing_check(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let pairs = bytemuck::try_cast_slice::<_, HeliusPair>(pairs)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::alt_bn128_pairing_check(helius_version(version), pairs).map_err(map_error)
}

pub fn alt_bn128_pairing_map(
    version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128BatchError> {
    let pairs = bytemuck::try_cast_slice::<_, HeliusPair>(pairs)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::alt_bn128_pairing_map(helius_version(version), pairs)
        .map(|target| PodGtElement(target.0))
        .map_err(map_error)
}

pub fn alt_bn128_fr_lincomb(
    version: Version,
    left: &[PodScalar],
    right: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    validate_equal_lengths(left.len(), right.len())?;
    let left = bytemuck::try_cast_slice::<_, HeliusScalar>(left)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let right = bytemuck::try_cast_slice::<_, HeliusScalar>(right)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::alt_bn128_fr_lincomb(helius_version(version), left, right)
        .map(|scalar| PodScalar(scalar.0))
        .map_err(map_error)
}

pub fn alt_bn128_fr_batch_invert(
    version: Version,
    values: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    let values = bytemuck::try_cast_slice::<_, HeliusScalar>(values)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::alt_bn128_fr_batch_invert(helius_version(version), values)
        .map(|values| {
            values
                .into_iter()
                .map(|scalar| PodScalar(scalar.0))
                .collect()
        })
        .map_err(map_error)
}

pub fn validate_registered_g2(source: &PodG2Point) -> Result<RegisteredG2, AltBn128BatchError> {
    HeliusRegisteredG2::validate_for_registry(&HeliusG2Point(source.0))
        .map(RegisteredG2)
        .map_err(map_error)
}

/// Recreate a registered G2 only after the runtime authenticated its account.
///
/// # Safety
///
/// See [`helius_bn254::RegisteredG2::from_authenticated_registry_bytes`].
pub unsafe fn registered_g2_from_authenticated_bytes(
    source: &PodG2Point,
    prepared: &[u8],
) -> Result<RegisteredG2, AltBn128BatchError> {
    // SAFETY: forwarded unchanged to the caller-visible authentication contract.
    unsafe {
        HeliusRegisteredG2::from_authenticated_registry_bytes(&HeliusG2Point(source.0), prepared)
    }
    .map(RegisteredG2)
    .map_err(map_error)
}

pub fn pairing_check_registered(
    full: &[PodG1G2Pair],
    registered: &[RegisteredG2Pair],
) -> Result<bool, AltBn128BatchError> {
    let full = bytemuck::try_cast_slice::<_, HeliusPair>(full)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    let registered: Vec<_> = registered
        .iter()
        .map(|pair| HeliusRegisteredG2Pair {
            g1: HeliusG1Point(pair.g1.0),
            g2: pair.g2.0.clone(),
        })
        .collect();
    helius_bn254::pairing_product_registered(full, &registered).map_err(map_error)
}

pub fn trusted_gt_from_pair(pair: &PodG1G2Pair) -> Result<TrustedGt, AltBn128BatchError> {
    HeliusTrustedGt::from_pair(&HeliusPair {
        g1: HeliusG1Point(pair.g1.0),
        g2: HeliusG2Point(pair.g2.0),
    })
    .map(TrustedGt)
    .map_err(map_error)
}

/// Recreate a trusted GT only after the runtime authenticated its account.
///
/// # Safety
///
/// See [`helius_bn254::TrustedGt::from_authenticated_registry_bytes`].
pub unsafe fn trusted_gt_from_authenticated_bytes(
    source: &PodGtElement,
) -> Result<TrustedGt, AltBn128BatchError> {
    // SAFETY: forwarded unchanged to the caller-visible authentication contract.
    unsafe { HeliusTrustedGt::from_authenticated_registry_bytes(&HeliusGt(source.0)) }
        .map(TrustedGt)
        .map_err(map_error)
}

pub fn trusted_gt_to_bytes(target: &TrustedGt) -> PodGtElement {
    PodGtElement(target.0.to_bytes().0)
}

pub fn trusted_gt_multiexp(
    targets: &[TrustedGt],
    exponents: &[PodScalar],
) -> Result<PodGtElement, AltBn128BatchError> {
    let targets: Vec<_> = targets.iter().map(|target| target.0.clone()).collect();
    let exponents: Vec<_> = exponents
        .iter()
        .map(|exponent| HeliusScalar(exponent.0))
        .collect();
    helius_bn254::trusted_gt_multiexp(&targets, &exponents)
        .map(|target| PodGtElement(target.0))
        .map_err(map_error)
}

pub fn prepare_g2_subgroup_probe(
    source: &PodG2Point,
) -> Result<G2SubgroupProbe, AltBn128BatchError> {
    helius_bn254::prepare_g2_subgroup_probe(&HeliusG2Point(source.0))
        .map(G2SubgroupProbe)
        .map_err(map_error)
}

pub fn run_g2_subgroup_probe(probe: &G2SubgroupProbe) -> Result<bool, AltBn128BatchError> {
    Ok(helius_bn254::run_g2_subgroup_probe(&probe.0))
}

pub fn prepare_final_exponentiation_probe(
    pairs: &[PodG1G2Pair],
) -> Result<FinalExponentiationProbe, AltBn128BatchError> {
    let pairs = bytemuck::try_cast_slice::<_, HeliusPair>(pairs)
        .map_err(|_| AltBn128BatchError::BackendInvariant)?;
    helius_bn254::prepare_final_exponentiation_probe(pairs)
        .map(FinalExponentiationProbe)
        .map_err(map_error)
}

pub fn run_final_exponentiation_probe(
    probe: &FinalExponentiationProbe,
) -> Result<FinalExponentiationResult, AltBn128BatchError> {
    Ok(FinalExponentiationResult(
        helius_bn254::run_final_exponentiation_probe(&probe.0),
    ))
}

pub fn encode_final_exponentiation_result(
    result: &FinalExponentiationResult,
) -> Result<PodGtElement, AltBn128BatchError> {
    Ok(PodGtElement(
        helius_bn254::encode_final_exponentiation_result(&result.0).0,
    ))
}

const fn helius_version(version: Version) -> HeliusVersion {
    match version {
        Version::V0 => HeliusVersion::V0,
    }
}

const fn map_error(error: HeliusInputError) -> AltBn128BatchError {
    match error {
        HeliusInputError::InvalidLength => AltBn128BatchError::InvalidLength,
        HeliusInputError::NonCanonical => AltBn128BatchError::NonCanonical,
        HeliusInputError::NotOnCurve => AltBn128BatchError::NotOnCurve,
        HeliusInputError::NotInSubgroup => AltBn128BatchError::NotInSubgroup,
        HeliusInputError::ZeroInput => AltBn128BatchError::ZeroInput,
        HeliusInputError::CapExceeded => AltBn128BatchError::CapExceeded,
        HeliusInputError::LengthMismatch => AltBn128BatchError::LengthMismatch,
    }
}

const _: () = {
    assert!(size_of::<PodG1Point>() == size_of::<HeliusG1Point>());
    assert!(align_of::<PodG1Point>() == align_of::<HeliusG1Point>());
    assert!(size_of::<PodG2Point>() == size_of::<HeliusG2Point>());
    assert!(align_of::<PodG2Point>() == align_of::<HeliusG2Point>());
    assert!(size_of::<PodScalar>() == size_of::<HeliusScalar>());
    assert!(align_of::<PodScalar>() == align_of::<HeliusScalar>());
    assert!(size_of::<PodG1G2Pair>() == size_of::<HeliusPair>());
    assert!(align_of::<PodG1G2Pair>() == align_of::<HeliusPair>());
    assert!(offset_of!(PodG1G2Pair, g1) == offset_of!(HeliusPair, g1));
    assert!(offset_of!(PodG1G2Pair, g2) == offset_of!(HeliusPair, g2));
    assert!(size_of::<PodPairingResult>() == size_of::<HeliusPairingResult>());
    assert!(align_of::<PodPairingResult>() == align_of::<HeliusPairingResult>());
    assert!(size_of::<PodGtElement>() == size_of::<HeliusGt>());
    assert!(align_of::<PodGtElement>() == align_of::<HeliusGt>());
    assert!(crate::G1_BYTES == helius_bn254::G1_BYTES);
    assert!(crate::G2_BYTES == helius_bn254::G2_BYTES);
    assert!(crate::SCALAR_BYTES == helius_bn254::SCALAR_BYTES);
    assert!(crate::PAIR_BYTES == helius_bn254::PAIR_BYTES);
    assert!(crate::FQ12_BYTES == helius_bn254::GT_BYTES);
    assert!(crate::MSM_MAX_POINTS == helius_bn254::MSM_MAX_POINTS);
    assert!(crate::PAIRING_MAX_PAIRS == helius_bn254::PAIRING_MAX_PAIRS);
    assert!(crate::PAIRING_MAP_MAX_PAIRS == helius_bn254::PAIRING_MAP_MAX_PAIRS);
    assert!(crate::FR_MAX_ELEMS == helius_bn254::FR_MAX_ELEMS);
};
