//! Variable-time BN254 (`alt_bn128` / mcl `BN_SNARK1`) arithmetic for proof
//! verification.
//!
//! Curve parameters match Solana's `alt_bn128` syscalls, arkworks
//! `ark-bn254`, and herumi/mcl `CurveParam BN_SNARK1`. The production entry
//! point is the [`batch`] byte facade: Agave-shaped G1 MSM, boolean
//! pairing-product check, Fr linear combination, and Fr batch inversion over
//! canonical big-endian bytes, with consensus-stable validation order
//! and error taxonomy. The typed tower underneath ([`Fp`], [`Fr`], [`Fp12`],
//! [`G1Affine`], [`G2Affine`], [`pairing()`]) is exported for tests, benches,
//! and embedders that already hold validated points.
//!
//! # Security model
//!
//! Every algorithm here is **variable-time by design**: running time, branch
//! pattern, and memory access depend on input values. That is the right trade
//! for the sole intended workload: verifying proofs over public inputs,
//! where every byte is already public.
//!
//! **Strictly for verification.** Never use this crate for signatures, key
//! material, witness processing, or any secret-dependent computation; its
//! timing will leak the secret.
//!
//! Curve types are plain structs with public fields, so safe code can build
//! off-curve or off-subgroup points. The [`batch`] facade is the checked
//! boundary: it validates canonicity, curve membership, and (for G2) subgroup
//! membership before any arithmetic.
//!
//! # Audit status
//!
//! **Not yet audited.** An audit is planned; until it lands, use at your own
//! risk. Current evidence is differential testing against arkworks 0.5 and
//! mcl golden vectors plus Agave fixture conformance. Useful, but not a
//! substitute for an audit.
//!
//! # Performance
//!
//! Quick-mode Criterion medians, single thread, same host and flags per row.
//! The Apple M4 rows and the Zen 4 phase splits were measured 2026-07-18; the
//! Zen 4 full-pairing row was remeasured 2026-07-24 on-box (EPYC 9354, the
//! default AMD build with the sosd6 leaf), where helios now edges mcl.
//! Diagnostic only: the strict three-run CI-gated protocol (repository
//! `PERFORMANCE.md`) is still pending. Single-pairing phase split, in us:
//!
//! | Host | Phase | helios | mcl | arkworks 0.5 |
//! |---|---|---:|---:|---:|
//! | Apple M4 | full pairing | 219.6 | 252.1 | 287.6 |
//! | Apple M4 | Miller loop | 106.3 | 109.2 | 131.6 |
//! | Apple M4 | final exponentiation | 112.9 | 139.0 | 151.1 |
//! | x86 Zen 4 | full pairing | 409.5 | 414.1 | 428.8 |
//! | x86 Zen 4 | Miller loop | 174.2 | 143.8 | 205.8 |
//! | x86 Zen 4 | final exponentiation | 190.6 | 177.2 | 222.6 |
//!
//! On the 31-row end-to-end Agave workload scoreboard (byte facade, versus
//! both mcl and arkworks 0.5): Apple M4 26/31 strict wins, the five open rows
//! within measurement noise (ratios 1.003-1.018); x86 Zen 4 27/31 at the
//! 2026-07-18 snapshot, its widest open row the single pairing (1.146), which
//! has since flipped to a win on the sosd6-default AMD build (409-410 vs mcl
//! 414.1, on-box EPYC 9354, 2026-07-24); the other open rows sit from 1.022.
//! Fr lincomb runs up to 4.4x faster than mcl and 12x faster than arkworks;
//! the G2 subgroup check 2.7x faster than mcl; Fr batch inversion 1.4-1.7x
//! versus mcl. Full tables live in the repository under
//! `docs/handout/CAMPAIGN-RESULTS.md`.
//!
//! # Platform tiers
//!
//! | Tier | Active when | Scope |
//! |---|---|---|
//! | Portable Rust | any target; always under `force-portable` | everything |
//! | AArch64 Apple leaf | `aarch64-apple-*` targets | one 68-instruction Montgomery-multiply leaf |
//! | x86-64 ADX | x86-64 Linux with `bmi2`+`adx` target features | the full generated tower: 10 schedule-DSL kernels (mont mul/sqr, sos, sosd2, sosd6, fp6 mul, fp12 034/sqr/mul, cyc sqr; asm rendered at build time, interpreter-verified) |
//! | AVX-512 IFMA | `avx512f`+`avx512ifma` target features | radix-52 8-way batched Montgomery multiply in the MSM bucket phase, plus the 8-wide multi-pairing batch check |
//!
//! Tier selection is a compile-time property of the target; there is no
//! runtime dispatch and no silent fallback. `HELIOS_AVX512_IFMA=1` forces the
//! IFMA tier (the build fails if the target cannot honour it) and `=0` denies
//! it.
//!
//! # Features and portability
//!
//! - Default build is `no_std + alloc`; `std` is opt-in and pulls only the
//!   test/timing harness (run the test suite with `--features std`).
//! - `force-portable`: compile the portable Rust field kernel even where an
//!   assembly tier exists; an explicit benchmark/test tier, never a fallback.
//! - MSRV 1.97.1, edition 2024, matching the target Agave toolchain.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![allow(clippy::many_single_char_names)]
// The preserved low-level API predates the typed batch facade and exposes
// inherent `add`/`mul`/`neg` spellings. Keep it source-compatible while new
// public work targets the Agave-named facade rather than extending this API.
#![allow(clippy::should_implement_trait)]

extern crate alloc;

pub mod batch;
/// 8-wide multi-pairing tower, driving the batch pairing check on IFMA targets.
#[cfg(helios_avx512_ifma)]
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
    AltBn128BatchError, FR_MAX_ELEMS, G1_BYTES, G1Bytes, G2_BYTES, G2Bytes, GT_BYTES, GtBytes,
    InputError, MSM_MAX_POINTS, PAIR_BYTES, PAIRING_MAX_PAIRS, PairBytes, PodG1G2Pair, PodG1Point,
    PodG2Point, PodGt, PodPairingResult, PodScalar, SCALAR_BYTES, ScalarBytes,
    TRUSTED_GT_MAX_TARGETS, TrustedGt, Version, alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb,
    alt_bn128_g1_msm, alt_bn128_pairing_check, alt_bn128_pairing_map, fr_batch_invert, fr_lincomb,
    g1_msm, pairing_map, pairing_product_is_one, trusted_gt_multiexp,
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
