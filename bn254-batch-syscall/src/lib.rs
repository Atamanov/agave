#![cfg(feature = "agave-unstable-api")]
#![allow(clippy::arithmetic_side_effects)]

pub use crate::{
    encoding::{
        FR_MAX_ELEMS, G1_BYTES, G2_BYTES, MSM_MAX_POINTS, PAIR_BYTES, PAIRING_MAX_PAIRS,
        SCALAR_BYTES,
    },
    fr::{alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb},
    msm::alt_bn128_g1_msm,
    pairing::alt_bn128_pairing_check,
    pod::{PodG1G2Pair, PodG1Point, PodG2Point, PodPairingResult, PodScalar},
    validation::AltBn128BatchError,
};

pub(crate) mod arith;
pub(crate) mod encoding;
pub(crate) mod fr;
pub(crate) mod msm;
pub(crate) mod pairing;
pub(crate) mod pod;
pub(crate) mod validation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V0,
}

#[cfg(test)]
pub(crate) mod test_utils {
    use {
        crate::encoding::{G1_BYTES, G2_BYTES, PAIR_BYTES, SCALAR_BYTES, fq_to_be},
        ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        ark_std::rand::{SeedableRng, rngs::StdRng},
    };

    // fixed seed for reproducibility, mirroring the bench fixtures
    pub fn rng() -> StdRng {
        StdRng::seed_from_u64(0xa17b428)
    }

    pub fn random_g1(rng: &mut StdRng) -> G1Affine {
        (G1Projective::generator() * Fr::rand(rng)).into_affine()
    }

    pub fn random_g2(rng: &mut StdRng) -> G2Affine {
        (G2Projective::generator() * Fr::rand(rng)).into_affine()
    }

    pub fn g1_bytes(point: &G1Affine) -> [u8; G1_BYTES] {
        crate::encoding::serialize_g1(point)
    }

    pub fn g2_bytes(point: &G2Affine) -> [u8; G2_BYTES] {
        let mut out = [0u8; G2_BYTES];
        if let Some((x, y)) = point.xy() {
            fq_to_be(&x.c1, &mut out[0..32]);
            fq_to_be(&x.c0, &mut out[32..64]);
            fq_to_be(&y.c1, &mut out[64..96]);
            fq_to_be(&y.c0, &mut out[96..128]);
        }
        out
    }

    pub fn fr_bytes(scalar: &Fr) -> [u8; SCALAR_BYTES] {
        let mut out = [0u8; SCALAR_BYTES];
        out.copy_from_slice(&scalar.into_bigint().to_bytes_be());
        out
    }

    pub fn pair_bytes(g1: &G1Affine, g2: &G2Affine) -> [u8; PAIR_BYTES] {
        let mut out = [0u8; PAIR_BYTES];
        out[..G1_BYTES].copy_from_slice(&g1_bytes(g1));
        out[G1_BYTES..].copy_from_slice(&g2_bytes(g2));
        out
    }

    pub fn fq_modulus_be() -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Fq::MODULUS.to_bytes_be());
        out
    }

    pub fn fr_modulus_be() -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Fr::MODULUS.to_bytes_be());
        out
    }

    pub fn be_add_one(bytes: &mut [u8; 32]) {
        for byte in bytes.iter_mut().rev() {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                break;
            }
        }
    }

    /// Deterministic G2 point on the twist curve but outside the r-order
    /// subgroup: the twist cofactor is ~2^254, so nearly every curve point
    /// qualifies; the asserts fail loud if the found point is not the
    /// negative test it claims to be.
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

    /// n real pairs over a shared G2 whose pairing product is the identity:
    /// (s_1 P, Q) ... (s_{n-1} P, Q), (-(s_1 + ... + s_{n-1}) P, Q).
    pub fn telescoping_pairs(rng: &mut StdRng, n: usize) -> Vec<u8> {
        assert!(n >= 2, "telescoping construction needs at least two pairs");
        let p = G1Projective::generator();
        let q = (G2Projective::generator() * Fr::rand(rng)).into_affine();
        let mut sum = Fr::zero();
        let mut out = Vec::with_capacity(n * PAIR_BYTES);
        for _ in 0..n - 1 {
            let s = Fr::rand(rng);
            sum += s;
            out.extend_from_slice(&pair_bytes(&(p * s).into_affine(), &q));
        }
        out.extend_from_slice(&pair_bytes(&(p * (-sum)).into_affine(), &q));
        out
    }

    pub fn decode_hex(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2));
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
