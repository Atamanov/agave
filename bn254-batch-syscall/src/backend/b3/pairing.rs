use {
    super::{map_mcl_error, wire},
    crate::{
        Version,
        encoding::{PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS},
        pod::{PodG1G2Pair, PodGtElement},
        validation::AltBn128BatchError,
    },
    solana_bn254_mcl_sys::{MclG1, MclG2OnCurve, MclG2Subgroup, MclGt, api},
};

pub fn alt_bn128_pairing_map(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGtElement, AltBn128BatchError> {
    let product = multi_pairing_gt(pairs, PAIRING_MAP_MAX_PAIRS)?;
    Ok(PodGtElement(
        api::gt_to_be(&product).map_err(map_mcl_error)?,
    ))
}

pub fn alt_bn128_pairing_check(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    let product = multi_pairing_gt(pairs, PAIRING_MAX_PAIRS)?;
    api::gt_is_one(&product).map_err(map_mcl_error)
}

fn multi_pairing_gt(
    pairs: &[PodG1G2Pair],
    maximum_pairs: usize,
) -> Result<MclGt, AltBn128BatchError> {
    if pairs.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if pairs.len() > maximum_pairs {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut live_g1 = Vec::<MclG1>::with_capacity(pairs.len());
    let mut live_g2 = Vec::<MclG2Subgroup>::with_capacity(pairs.len());
    let mut subgroup_candidates = Vec::<(MclG2OnCurve, bool)>::with_capacity(pairs.len());
    let mut deferred_error = None;
    for pair in pairs {
        match parse_pair_on_curve(pair) {
            Ok((g1, g2)) => {
                let g2_is_zero = api::g2_is_zero(&g2).map_err(map_mcl_error)?;
                if !g2_is_zero {
                    let is_live = !api::g1_is_zero(&g1).map_err(map_mcl_error)?;
                    subgroup_candidates.push((g2, is_live));
                    if is_live {
                        live_g1.push(g1);
                    }
                }
            }
            Err(error) => {
                deferred_error = Some(error);
                break;
            }
        }
    }

    for (point, is_live) in subgroup_candidates {
        let point = api::g2_into_subgroup(point).map_err(map_mcl_error)?;
        if is_live {
            live_g2.push(point);
        }
    }
    if let Some(error) = deferred_error {
        return Err(error);
    }
    if live_g1.is_empty() {
        return api::gt_one().map_err(map_mcl_error);
    }
    api::pairing_product(&live_g1, &live_g2).map_err(map_mcl_error)
}

fn parse_pair_on_curve(pair: &PodG1G2Pair) -> Result<(MclG1, MclG2OnCurve), AltBn128BatchError> {
    let g1 = wire::parse_g1(&pair.g1)?;
    let g2 = wire::parse_g2_on_curve(&pair.g2)?;
    Ok((g1, g2))
}
