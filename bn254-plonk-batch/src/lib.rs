#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Reference batched KZG PLONK verifier over the alt_bn128 batch syscalls.
//!
//! Reference for on-chain programs: the inner and outer transcript derivations
//! in [`transcript`], the per-proof reduction in [`reduce`], the batch folding
//! in [`verify`], and the verifying-key validation in [`vk`] together define
//! the batch layer. A batch of n proofs under one verifying
//! key reduces to per-proof inner transcripts, outer randomizers over the
//! frozen batch, field-side scalar work, one G1 MSM for P = sum rho_i P_i,
//! one G1 MSM for Q = sum rho_i Q_i, and a single boolean pairing check over
//! exactly [(P, [tau]_2), (-Q, [1]_2)]. Negations fold into MSM scalars, so
//! no point is ever negated; no G2 arithmetic, no prepared points, and no GT
//! values appear anywhere.

pub use crate::{
    proof::{Evaluations, Proof},
    transcript::{RandomizerMode, derive_randomizers, derive_seed},
    verify::{FoldGroup, MAX_PROOFS, fold_msms, plonk_batch_verify, validate_batch_shape},
    vk::{ValidatedVerifyingKey, VerifyingKey},
};
use solana_bn254_batch_syscall::AltBn128BatchError;

pub(crate) mod proof;
pub(crate) mod reduce;
pub(crate) mod scalar;
pub(crate) mod transcript;
pub(crate) mod verify;
pub(crate) mod vk;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_support;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V0,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum PlonkBatchError {
    #[error("batch is empty")]
    EmptyBatch,
    #[error("batch exceeds the Q-side MSM point budget")]
    TooManyProofs,
    #[error("randomizer count does not match the proof count")]
    RandomizerCountMismatch,
    #[error("public input count does not match the verifying key")]
    InputCountMismatch,
    #[error("infinity point in a proof position")]
    InfinityInProofPosition,
    #[error("evaluation or public input is not a canonical field element")]
    NonCanonicalScalar,
    #[error("zeta landed in the evaluation domain")]
    ZetaInEvaluationDomain,
    #[error("invalid verifying key: {0}")]
    InvalidVerifyingKey(&'static str),
    #[error("syscall: {0}")]
    Syscall(#[from] AltBn128BatchError),
}
