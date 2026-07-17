#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

//! Reference batched Groth16 verifier over the alt_bn128 batch syscalls.
//!
//! Reference for on-chain programs: the transcript derivation in
//! [`transcript`], the verification-equation folding in [`verify`], and the
//! verifying-key validation in [`vk`] together define the batch layer.
//! Every fold is a G1 MSM and the verdict is one boolean pairing check; no
//! G2 arithmetic, no prepared points, and no GT values appear anywhere.

pub use crate::{
    transcript::RandomizerMode,
    verify::{Proof, ProofCommitment, groth16_batch_verify},
    vk::{PedersenKey, ValidatedVerifyingKey, VerifyingKey},
};
use solana_bn254_batch_syscall::AltBn128BatchError;

pub(crate) mod transcript;
pub(crate) mod verify;
pub(crate) mod vk;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V0,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum Groth16BatchError {
    #[error("batch is empty")]
    EmptyBatch,
    #[error("proof names a verifying-key index outside the batch's key list")]
    UnknownVerifyingKey,
    #[error("more verifying keys than the u16 index and transcript count can frame")]
    TooManyVerifyingKeys,
    #[error("public input count does not match the named verifying key")]
    InputCountMismatch,
    #[error("proof and verifying key disagree on the BSB22 commitment rail")]
    CommitmentMismatch,
    #[error("infinity point in a proof position")]
    InfinityInProofPosition,
    #[error("public input is not a canonical field element")]
    NonCanonicalInput,
    #[error("invalid verifying key: {0}")]
    InvalidVerifyingKey(&'static str),
    #[error("syscall: {0}")]
    Syscall(#[from] AltBn128BatchError),
}

#[cfg(test)]
pub(crate) mod test_utils {
    use {
        crate::{
            verify::{Proof, ProofCommitment},
            vk::{PedersenKey, ValidatedVerifyingKey, VerifyingKey},
        },
        ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero},
        ark_std::rand::{SeedableRng, rngs::StdRng},
        solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar},
    };

    pub fn rng() -> StdRng {
        StdRng::seed_from_u64(0x6702716)
    }

    pub fn g1_bytes(point: &G1Affine) -> PodG1Point {
        let mut out = [0u8; 64];
        if let Some((x, y)) = point.xy() {
            out[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
            out[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
        }
        PodG1Point(out)
    }

    pub fn g2_bytes(point: &G2Affine) -> PodG2Point {
        let mut out = [0u8; 128];
        if let Some((x, y)) = point.xy() {
            out[0..32].copy_from_slice(&x.c1.into_bigint().to_bytes_be());
            out[32..64].copy_from_slice(&x.c0.into_bigint().to_bytes_be());
            out[64..96].copy_from_slice(&y.c1.into_bigint().to_bytes_be());
            out[96..128].copy_from_slice(&y.c0.into_bigint().to_bytes_be());
        }
        PodG2Point(out)
    }

    pub fn fr_bytes(scalar: &Fr) -> PodScalar {
        let mut out = [0u8; 32];
        out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
        PodScalar(out)
    }

    pub fn g1(scalar: Fr) -> G1Affine {
        (G1Projective::generator() * scalar).into_affine()
    }

    pub fn g2(scalar: Fr) -> G2Affine {
        (G2Projective::generator() * scalar).into_affine()
    }

    pub fn non_subgroup_g2() -> G2Affine {
        for k in 0u64.. {
            let x = Fq2::new(Fq::from(k), Fq::zero());
            if let Some(point) = G2Affine::get_point_from_x_unchecked(x, true) {
                assert!(point.is_on_curve());
                if !point.is_in_correct_subgroup_assuming_on_curve() {
                    return point;
                }
            }
        }
        unreachable!("BN254 twist has non-subgroup points with small x");
    }

    /// Trapdoor scalars behind a synthetic verifying key: with them, valid
    /// proofs are solvable directly from the verification equation, so no
    /// circuit compiler is needed to build fixtures.
    pub struct TrapdoorKey {
        pub alpha: Fr,
        pub beta: Fr,
        pub gamma: Fr,
        pub delta: Fr,
        pub ic: Vec<Fr>,
        pub sigma: Option<Fr>,
    }

    pub fn make_vk(
        rng: &mut StdRng,
        num_inputs: usize,
        committed: bool,
    ) -> (TrapdoorKey, ValidatedVerifyingKey) {
        let key = TrapdoorKey {
            alpha: Fr::rand(rng),
            beta: Fr::rand(rng),
            gamma: Fr::rand(rng),
            delta: Fr::rand(rng),
            ic: (0..=num_inputs).map(|_| Fr::rand(rng)).collect(),
            sigma: committed.then(|| Fr::rand(rng)),
        };
        let vk = VerifyingKey {
            alpha_g1: g1_bytes(&g1(key.alpha)),
            beta_g2: g2_bytes(&g2(key.beta)),
            gamma_g2: g2_bytes(&g2(key.gamma)),
            delta_g2: g2_bytes(&g2(key.delta)),
            ic: key.ic.iter().map(|s| g1_bytes(&g1(*s))).collect(),
            pedersen: key.sigma.map(|sigma| PedersenKey {
                g2: g2_bytes(&G2Affine::generator()),
                sigma_g2: g2_bytes(&g2(sigma)),
            }),
        };
        (key, vk.validate().expect("synthetic key must validate"))
    }

    /// Solve the verification equation for C: with L = [l]G1 (commitment
    /// included on the committed rail), e(A,B) = e(alpha,beta) e(L,gamma)
    /// e(C,delta) holds iff c = (ab - alpha beta - l gamma) / delta.
    pub fn make_proof(rng: &mut StdRng, key: &TrapdoorKey, vk_index: u16, inputs: &[Fr]) -> Proof {
        assert_eq!(inputs.len() + 1, key.ic.len());
        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        let mut l = key.ic[0];
        for (x, ic) in inputs.iter().zip(key.ic.iter().skip(1)) {
            l += *x * ic;
        }
        let commitment = key.sigma.map(|sigma| {
            let t = Fr::rand(rng);
            l += t;
            (
                t,
                ProofCommitment {
                    com: g1_bytes(&g1(t)),
                    pok: g1_bytes(&g1(t * sigma.inverse().unwrap())),
                },
            )
        });
        let c = (a * b - key.alpha * key.beta - l * key.gamma) * key.delta.inverse().unwrap();
        Proof {
            vk_index,
            a: g1_bytes(&g1(a)),
            b: g2_bytes(&g2(b)),
            c: g1_bytes(&g1(c)),
            commitment: commitment.map(|(_, c)| c),
            public_inputs: inputs.iter().map(fr_bytes).collect(),
        }
    }
}
