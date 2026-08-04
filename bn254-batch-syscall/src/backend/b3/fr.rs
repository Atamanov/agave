use {
    super::{map_mcl_error, wire::parse_scalar},
    crate::{
        Version,
        encoding::FR_MAX_ELEMS,
        pod::PodScalar,
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    solana_bn254_mcl_sys::{MclFr, api},
};

pub fn alt_bn128_fr_lincomb(
    _version: Version,
    left: &[PodScalar],
    right: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    validate_equal_lengths(left.len(), right.len())?;
    if left.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if left.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut accumulator = MclFr::default();
    for (left, right) in left.iter().zip(right) {
        let left = parse_scalar(left)?;
        let right = parse_scalar(right)?;
        let product = api::fr_mul(&left, &right).map_err(map_mcl_error)?;
        accumulator = api::fr_add(&accumulator, &product).map_err(map_mcl_error)?;
    }
    Ok(PodScalar(
        api::fr_to_be(&accumulator).map_err(map_mcl_error)?,
    ))
}

pub fn alt_bn128_fr_batch_invert(
    _version: Version,
    input: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    if input.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if input.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut values = Vec::with_capacity(input.len());
    for scalar in input {
        let value = parse_scalar(scalar)?;
        if api::fr_is_zero(&value).map_err(map_mcl_error)? {
            return Err(AltBn128BatchError::ZeroInput);
        }
        values.push(value);
    }
    batch_invert(&mut values)?;
    values
        .iter()
        .map(|value| api::fr_to_be(value).map(PodScalar).map_err(map_mcl_error))
        .collect()
}

fn batch_invert(values: &mut [MclFr]) -> Result<(), AltBn128BatchError> {
    let count = values.len();
    let (first, rest) = values
        .split_first_mut()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let mut product = *first;
    let mut prefixes = Vec::with_capacity(count);
    prefixes.push(product);
    for value in rest.iter() {
        product = api::fr_mul(&product, value).map_err(map_mcl_error)?;
        prefixes.push(product);
    }

    let mut inverse = api::fr_inverse(
        prefixes
            .last()
            .ok_or(AltBn128BatchError::BackendInvariant)?,
    )
    .map_err(map_mcl_error)?;
    let (_, prefixes_before_last) = prefixes
        .split_last()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    for (value, prefix) in rest.iter_mut().rev().zip(prefixes_before_last.iter().rev()) {
        let original = *value;
        *value = api::fr_mul(&inverse, prefix).map_err(map_mcl_error)?;
        inverse = api::fr_mul(&inverse, &original).map_err(map_mcl_error)?;
    }
    *first = inverse;
    Ok(())
}
