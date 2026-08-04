/// PLONK verifier for BN254 curve operations.
///
/// On Solana: uses pinocchio alt_bn128 syscalls.
/// Off-chain: uses arkworks fallback.
///
/// All G1 points are 64 bytes big-endian (x || y).
/// All G2 points are 128 bytes big-endian (x1 || x0 || y1 || y0).
/// All scalars are 32 bytes big-endian.
use crate::fr::Fr;
use crate::g1::G1;
use crate::g2::G2;

/// Verification key (G1 points + G2 generator + scalar parameters).
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VerificationKey {
    pub n_public: u32,
    pub power: u32,
    pub k1: Fr,
    pub k2: Fr,
    pub w: Fr,
    pub qm: G1,
    pub ql: G1,
    pub qr: G1,
    pub qo: G1,
    pub qc: G1,
    pub s1: G1,
    pub s2: G1,
    pub s3: G1,
    pub x_2: G2,
}

/// Proof (G1 commitments + scalar evaluations).
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof {
    pub a: G1,
    pub b: G1,
    pub c: G1,
    pub z: G1,
    pub t1: G1,
    pub t2: G1,
    pub t3: G1,
    pub wxi: G1,
    pub wxiw: G1,
    pub eval_a: Fr,
    pub eval_b: Fr,
    pub eval_c: Fr,
    pub eval_s1: Fr,
    pub eval_s2: Fr,
    pub eval_zw: Fr,
}

