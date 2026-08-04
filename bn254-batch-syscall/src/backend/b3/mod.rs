mod fr;
mod msm;
mod pairing;
mod wire;

use {crate::validation::AltBn128BatchError, solana_bn254_mcl_sys::api::MclError};
pub use {
    fr::{alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb},
    msm::alt_bn128_g1_msm,
    pairing::{alt_bn128_pairing_check, alt_bn128_pairing_map},
};

fn map_mcl_error(error: MclError) -> AltBn128BatchError {
    match error {
        MclError::NonCanonicalBaseField | MclError::NonCanonicalScalar => {
            AltBn128BatchError::NonCanonical
        }
        MclError::NotOnCurve => AltBn128BatchError::NotOnCurve,
        MclError::NotInSubgroup => AltBn128BatchError::NotInSubgroup,
        MclError::Initialization(_)
        | MclError::FunctionReturn { .. }
        | MclError::OutputSize { .. }
        | MclError::InvalidBoolean { .. }
        | MclError::LengthMismatch
        | MclError::EmptyInput
        | MclError::Precondition(_) => AltBn128BatchError::BackendInvariant,
    }
}
