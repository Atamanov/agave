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
    any(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub(crate) mod helios;

#[cfg(any(
    feature = "backend-b1-arkworks",
    not(any(
        feature = "backend-b2-arkworks-optimized",
        feature = "backend-b3-mcl",
        feature = "backend-b4-helios",
        feature = "backend-b5-helios-ifma"
    ))
))]
pub use crate::{
    fr::{alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb},
    msm::alt_bn128_g1_msm,
    pairing::{alt_bn128_pairing_check, alt_bn128_pairing_map},
};

#[cfg(all(
    feature = "backend-b2-arkworks-optimized",
    not(feature = "backend-b1-arkworks")
))]
pub use b2::{
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map,
};

#[cfg(all(
    feature = "backend-b3-mcl",
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized")
))]
pub use b3::{
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map,
};

#[cfg(all(
    any(feature = "backend-b4-helios", feature = "backend-b5-helios-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]
pub use helios::{
    alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
    alt_bn128_pairing_map,
};

#[cfg(test)]
mod conformance;
