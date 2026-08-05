#[cfg(any(
    all(
        feature = "backend-b2-arkworks-optimized",
        not(feature = "backend-b1-arkworks")
    ),
    test
))]
pub(crate) mod b2;
#[cfg(all(
    feature = "backend-b3-mcl",
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized")
))]
pub(crate) mod b3;
#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) mod helius;

#[cfg(any(
    feature = "backend-b1-arkworks",
    not(any(
        feature = "backend-b2-arkworks-optimized",
        feature = "backend-b3-mcl",
        feature = "backend-b4-helius",
        feature = "backend-b5-helius-ifma"
    ))
))]
mod probes_b1;

#[cfg(any(
    feature = "backend-b1-arkworks",
    not(any(
        feature = "backend-b2-arkworks-optimized",
        feature = "backend-b3-mcl",
        feature = "backend-b4-helius",
        feature = "backend-b5-helius-ifma"
    ))
))]
pub use crate::{
    fr::{alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb},
    msm::alt_bn128_g1_msm,
    pairing::{alt_bn128_pairing_check, alt_bn128_pairing_map},
};

#[cfg(any(
    feature = "backend-b1-arkworks",
    not(any(
        feature = "backend-b2-arkworks-optimized",
        feature = "backend-b3-mcl",
        feature = "backend-b4-helius",
        feature = "backend-b5-helius-ifma"
    ))
))]
pub use probes_b1::{
    FinalExponentiationProbe, FinalExponentiationResult, G2SubgroupProbe,
    encode_final_exponentiation_result, prepare_final_exponentiation_probe,
    prepare_g2_subgroup_probe, run_final_exponentiation_probe, run_g2_subgroup_probe,
};

#[cfg(all(
    feature = "backend-b2-arkworks-optimized",
    not(feature = "backend-b1-arkworks")
))]
pub use b2::{
    FinalExponentiationProbe, FinalExponentiationResult, G2SubgroupProbe,
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map, encode_final_exponentiation_result, prepare_final_exponentiation_probe,
    prepare_g2_subgroup_probe, run_final_exponentiation_probe, run_g2_subgroup_probe,
};

#[cfg(all(
    feature = "backend-b3-mcl",
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized")
))]
pub use b3::{
    FinalExponentiationProbe, FinalExponentiationResult, G2SubgroupProbe,
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map, encode_final_exponentiation_result, prepare_final_exponentiation_probe,
    prepare_g2_subgroup_probe, run_final_exponentiation_probe, run_g2_subgroup_probe,
};

#[cfg(all(
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub use helius::{
    FinalExponentiationProbe, FinalExponentiationResult, G2SubgroupProbe, PreparedG2,
    RegisteredG2, RegisteredG2Pair, TrustedGt, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb,
    alt_bn128_g1_msm, alt_bn128_pairing_check, alt_bn128_pairing_map,
    encode_final_exponentiation_result, g2_prepare, pairing_check_prepared,
    pairing_check_prepared_vs_target, pairing_check_registered, pairing_map_prepared,
    prepare_final_exponentiation_probe, prepare_g2_subgroup_probe, prepared_g2_from_wire,
    registered_g2_from_authenticated_bytes, run_final_exponentiation_probe, run_g2_subgroup_probe,
    trusted_gt_from_authenticated_bytes, trusted_gt_from_pair, trusted_gt_multiexp,
    trusted_gt_to_bytes, validate_registered_g2,
};

#[cfg(test)]
mod conformance;
