use {
    crate::{
        AltBn128BatchError, PAIRING_MAX_PAIRS, PodG1G2Pair, PodG2Point, PodGtElement,
        encoding::parse_g2,
    },
    ark_bn254::{Bn254, Fq12},
    ark_ec::{
        AffineRepr,
        pairing::{MillerLoopOutput, Pairing},
    },
    ark_ff::One,
};

#[derive(Clone, Debug)]
pub struct FinalExponentiationProbe {
    miller: MillerLoopOutput<Bn254>,
}

#[derive(Clone, Debug)]
pub struct FinalExponentiationResult {
    value: Fq12,
}

#[derive(Clone, Copy, Debug)]
pub struct G2SubgroupProbe {
    point: ark_bn254::G2Affine,
}

pub fn prepare_g2_subgroup_probe(
    source: &PodG2Point,
) -> Result<G2SubgroupProbe, AltBn128BatchError> {
    let point = parse_g2(&source.0)?;
    if !point.is_zero() && !point.is_on_curve() {
        return Err(AltBn128BatchError::NotOnCurve);
    }
    Ok(G2SubgroupProbe { point })
}

pub fn run_g2_subgroup_probe(probe: &G2SubgroupProbe) -> Result<bool, AltBn128BatchError> {
    Ok(probe.point.is_zero() || probe.point.is_in_correct_subgroup_assuming_on_curve())
}

pub fn prepare_final_exponentiation_probe(
    pairs: &[PodG1G2Pair],
) -> Result<FinalExponentiationProbe, AltBn128BatchError> {
    if pairs.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if pairs.len() > PAIRING_MAX_PAIRS {
        return Err(AltBn128BatchError::CapExceeded);
    }
    let mut g1 = Vec::with_capacity(pairs.len());
    let mut g2 = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let p = pair.g1.to_affine()?;
        let q = pair.g2.to_affine()?;
        if !p.is_zero() && !q.is_zero() {
            g1.push(p);
            g2.push(q);
        }
    }
    let miller = if g1.is_empty() {
        MillerLoopOutput(Fq12::one())
    } else {
        Bn254::multi_miller_loop(g1, g2)
    };
    Ok(FinalExponentiationProbe { miller })
}

pub fn run_final_exponentiation_probe(
    probe: &FinalExponentiationProbe,
) -> Result<FinalExponentiationResult, AltBn128BatchError> {
    Bn254::final_exponentiation(probe.miller)
        .map(|target| FinalExponentiationResult { value: target.0 })
        .ok_or(AltBn128BatchError::BackendInvariant)
}

pub fn encode_final_exponentiation_result(
    result: &FinalExponentiationResult,
) -> Result<PodGtElement, AltBn128BatchError> {
    Ok(PodGtElement::from(&result.value))
}
