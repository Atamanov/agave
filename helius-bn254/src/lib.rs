//! Variable-time BN254 arithmetic for proof verification.
//!
//! The [`batch`] facade implements the Agave byte ABI. It validates canonical
//! fields, curve membership, G2 subgroup membership, limits, and error order.
//! The typed field and curve APIs require already validated public values.
//!
//! # Security
//!
//! Execution time and memory access depend on input values. Use this crate only
//! with public verifier data. Do not use it with secret keys, scalars, or
//! witnesses. The crate has differential and conformance tests, but it has no
//! external security audit.
//!
//! # Build selection
//!
//! Backend selection occurs at build time. `force-portable` selects portable
//! Rust. `deny-ifma` prevents AVX-512 IFMA selection. `force-ifma` requires the
//! IFMA target features. The default build uses `no_std` with `alloc`.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(all(feature = "deny-ifma", feature = "force-ifma"))]
compile_error!("deny-ifma and force-ifma cannot be enabled together");
#[cfg(all(feature = "force-portable", feature = "force-ifma"))]
compile_error!("force-portable and force-ifma cannot be enabled together");

extern crate alloc;

pub mod batch;
/// 8-wide multi-pairing tower, driving the batch pairing check on IFMA targets.
#[cfg(helius_avx512_ifma)]
mod batch8;

mod const_tower;
pub mod consts;
pub mod fp;
pub mod fp12;
pub mod fp2;
mod fp2_fast;
pub mod fp6;
pub mod fr;
pub mod g1;
mod g1_fast;
pub mod g2;
mod g2_fast;
mod limb;
mod msm;
pub mod pairing;
#[cfg(all(test, feature = "std"))]
mod sos_micro;
#[cfg(test)]
mod sos_tests;
mod wnaf;

#[cfg(test)]
mod arkworks_bn254_0_5_tests;

pub use batch::{
    AVX512_IFMA_COMPILED, AltBn128BatchError, FR_MAX_ELEMS, FinalExponentiationProbe,
    FinalExponentiationResult, G1_BYTES, G1Bytes, G2_BYTES, G2Bytes, G2SubgroupProbe, GT_BYTES,
    GtBytes, InputError, MSM_MAX_POINTS, PAIR_BYTES, PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS,
    PREPARED_G2_BYTES, PairBytes, PodG1G2Pair, PodG1Point, PodG2Point, PodGt, PodPairingResult,
    PodScalar, RegisteredG2, RegisteredG2Pair, SCALAR_BYTES, ScalarBytes, TRUSTED_GT_MAX_TARGETS,
    TrustedGt, Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm,
    alt_bn128_pairing_check, alt_bn128_pairing_map, encode_final_exponentiation_result,
    fr_batch_invert, fr_lincomb, g1_msm, pairing_map, pairing_product_is_one,
    pairing_product_registered, prepare_final_exponentiation_probe, prepare_g2_subgroup_probe,
    probe_g2_subgroup, run_final_exponentiation_probe, run_g2_subgroup_probe, selects_ifma_batch8,
    trusted_gt_multiexp,
};
// Compile README examples as doctests without duplicating them in crate docs.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme_doctests {}

pub use fp::Fp;
pub use fp2::Fp2;
pub use fp6::Fp6;
pub use fp12::Fp12;
pub use fr::Fr;
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
pub use pairing::{Gt, multi_pairing, pairing};

#[cfg(test)]
mod mcl_vectors {
    use super::*;
    use core::ops::{Mul, Neg};

    /// Golden pairing from herumi/mcl `test/bn_test.cpp` `BN_SNARK1` entry.
    #[test]
    fn mcl_bn_snark1_pairing_vector() {
        let p = G1Affine {
            x: Fp::from_u64(1),
            y: Fp::from_u64(2),
            infinity: false,
        };
        assert!(p.is_on_curve());

        let q = G2Affine::test_generator();
        assert!(q.is_on_curve());

        let e = pairing(&p, &q);

        let expected = Fp12::from_mcl_dec_coeffs(&[
            "15163392945550945552839911839294582974434771053565812675833291179413834896953",
            "20389211011850518572149982239826345669421868561029856883955740401696801984953",
            "17766795911013516700216709333389761327222334145011922123798810516425387779347",
            "6064163297423711021549973931984064750876944939004405231004441199168710504090",
            "296093106139306574860102680862436174771023602986903675151017278048818344347",
            "1573596951222456889652521728261836933382094474023551133585236991207205981715",
            "3511871642997169996730611220058787939468653751355351269812083879279936651479",
            "17848534184080172844395614793152774197360421729995967636680357250333093768504",
            "3273860031361637906105800996652640969711942192883181518057117446820546419132",
            "7212721189663231589365009629980400132745687533815732336503876102977912682966",
            "18569236611881855981733896549089319395087993987737891870319625215675547032585",
            "10088832670068482545658647976676953228519838542958787800193793260459700064172",
        ])
        .expect("parse expected GT");

        assert_eq!(
            e, expected,
            "pairing must match mcl BN_SNARK1 golden vector"
        );
    }

    #[test]
    fn bilinearity_smoke() {
        let p = G1Affine::generator();
        let q = G2Affine::test_generator();
        let a = Fr::from_u64(7);
        let e1 = pairing(&p, &q).pow_u64(7);
        let pa = G1Projective::from(p).mul(a).to_affine();
        let e2 = pairing(&pa, &q);
        assert_eq!(e1, e2);

        let qa = G2Projective::from(q).mul(a).to_affine();
        let e3 = pairing(&p, &qa);
        assert_eq!(e1, e3);
    }

    #[test]
    fn identity_pairing() {
        let p = G1Affine::generator();
        let q = G2Affine::test_generator();
        assert_eq!(pairing(&G1Affine::identity(), &q), Fp12::ONE);
        assert_eq!(pairing(&p, &G2Affine::identity()), Fp12::ONE);
    }

    #[test]
    fn g1_order() {
        // [r] P = O
        let p = G1Projective::generator();
        // [r-1]P = -P
        let rm1 = Fr::from_raw([
            0x43e1f593f0000000, // r-1 low
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]);
        let q = p.mul(rm1).to_affine();
        assert_eq!(q.neg(), G1Affine::generator());
    }
}
