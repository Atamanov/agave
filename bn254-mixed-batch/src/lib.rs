#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Reference mixed Groth16 + PLONK batch verifier over the alt_bn128 batch
//! syscalls.
//!
//! One joint Fiat-Shamir transcript covers both sections, one randomizer
//! stream spans every verification equation, and one boolean pairing check
//! decides the whole batch: the Groth16 pair fold concatenated with a
//! constant two-pair tail per PLONK SRS. PLONK groups that share an SRS
//! merge into one tail whatever their keys, so heterogeneous circuits cost
//! no extra pairing terms.

pub use crate::{
    transcript::RandomizerMode,
    verify::{MixedBatch, PlonkGroup, mixed_batch_verify},
};
use solana_bn254_batch_syscall::AltBn128BatchError;

pub(crate) mod transcript;
pub(crate) mod verify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V0,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum MixedBatchError {
    #[error("batch is empty on both sides")]
    EmptyBatch,
    #[error("batch exceeds the pairing-check pair cap")]
    TooManyPairs,
    #[error("groth16 section: {0}")]
    Groth16(#[from] solana_bn254_groth16_batch::Groth16BatchError),
    #[error("plonk section: {0}")]
    Plonk(#[from] solana_bn254_plonk_batch::PlonkBatchError),
    #[error("syscall: {0}")]
    Syscall(#[from] AltBn128BatchError),
}
