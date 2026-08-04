// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Provenance-preserving adaptations of the default native test suite from:
//
// - ark-bn254 0.5.0
//   crates.io: d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc
//   VCS: df907e8c1601a898c2903ed7ab7bbbb10607f36b
//   sources: src/fields/tests.rs, src/curves/tests.rs, src/curves/g2.rs
// - ark-ec 0.5.0
//   crates.io: 43d68f2d516162846c1238e755a7c4d131b892b70cc70c471a8e3ca3ed818fce
//   VCS: 7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c
// - ark-ff 0.5.0
//   crates.io: a177aba0ed1e0fbb62aa9f6d0502e9b46dad8c2eab04c14258a1212d2557ea70
//   VCS: 7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c
// - ark-algebra-test-templates 0.5.0
//   crates.io: fd4c6293624cb11978fe9940af61faa16e85431fa9993ed2e11ea422099a564c
//   VCS: 7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c
//   sources: src/fields.rs, src/groups.rs, src/msm.rs, src/pairing.rs, src/glv.rs
//
// Adaptation policy:
//
// 1. Preserve upstream module/test names and iteration metadata; classify every
//    semantic difference as `Adapted` with a specific waiver.
// 2. Exercise a Helios operation on every adapted property. Ark-only assertions
//    may guard pinned provenance/configuration, including an inert generated
//    body, but never count as Helios coverage. Arkworks supplies inputs and
//    expected values, not Ark-vs-Ark coverage.
// 3. Use a fixed StdRng seed instead of ark_std::test_rng so failures are
//    reproducible without adding another direct dependency.
// 4. Keep every one of the 103 default-native upstream cases in the manifest,
//    including unsupported or deliberately deferred cases.

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use alloc::vec::Vec;
use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, Fr as ArkFr,
    G1Affine as ArkG1Affine, G1Projective as ArkG1Projective, G2Affine as ArkG2Affine,
    G2Projective as ArkG2Projective,
};
use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup,
    pairing::{MillerLoopOutput, Pairing as ArkPairing},
    scalar_mul::glv::GLVConfig,
};
use ark_ff::{AdditiveGroup, Field as ArkField, PrimeField, UniformRand, Zero};
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::{
    Fp, Fp2, Fp6, Fp12, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
    batch::{ScalarBytes, fr_lincomb},
    pairing::{final_exponentiation, multi_pairing},
};

const FIELD_ITERATIONS: usize = 1_000;
const GROUP_ITERATIONS: usize = 500;
const PAIRING_ITERATIONS: usize = 100;

/// Immutable identity for the source file that defines an upstream test.
///
/// The crate checksum pins the published archive; the file checksum makes a
/// moved or edited test body visible without unpacking that archive by hand.
#[derive(Clone, Copy, Debug)]
struct SourcePin {
    package: &'static str,
    version: &'static str,
    crate_sha256: &'static str,
    vcs_revision: &'static str,
    path: &'static str,
    file_sha256: &'static str,
}

const ARK_TEMPLATE_FIELDS: SourcePin = SourcePin {
    package: "ark-algebra-test-templates",
    version: "0.5.0",
    crate_sha256: "fd4c6293624cb11978fe9940af61faa16e85431fa9993ed2e11ea422099a564c",
    vcs_revision: "7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c",
    path: "src/fields.rs",
    file_sha256: "0c75c532796f80c00aaac57c59c98611561994d1de13432b32019689b495b7f7",
};

const ARK_TEMPLATE_GROUPS: SourcePin = SourcePin {
    package: "ark-algebra-test-templates",
    version: "0.5.0",
    crate_sha256: "fd4c6293624cb11978fe9940af61faa16e85431fa9993ed2e11ea422099a564c",
    vcs_revision: "7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c",
    path: "src/groups.rs",
    file_sha256: "e76f6873509144d9008abbd4f4566d3292253da839a1b37138f5c2c85395d699",
};

const ARK_TEMPLATE_PAIRING: SourcePin = SourcePin {
    package: "ark-algebra-test-templates",
    version: "0.5.0",
    crate_sha256: "fd4c6293624cb11978fe9940af61faa16e85431fa9993ed2e11ea422099a564c",
    vcs_revision: "7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c",
    path: "src/pairing.rs",
    file_sha256: "8fb04ff635c4b644e30dbf7e84d7d8fd2d4ea0bd31cb5bf2bc580aaee0dbedbe",
};

const ARK_TEMPLATE_GLV: SourcePin = SourcePin {
    package: "ark-algebra-test-templates",
    version: "0.5.0",
    crate_sha256: "fd4c6293624cb11978fe9940af61faa16e85431fa9993ed2e11ea422099a564c",
    vcs_revision: "7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c",
    path: "src/glv.rs",
    file_sha256: "a645ebbf65f71cd1a3da441bfb8a0a4a915fccd63dd322caca6ce1b21cf981c8",
};

const ARK_BN254_FIELD_TESTS: SourcePin = SourcePin {
    package: "ark-bn254",
    version: "0.5.0",
    crate_sha256: "d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc",
    vcs_revision: "df907e8c1601a898c2903ed7ab7bbbb10607f36b",
    path: "src/fields/tests.rs",
    file_sha256: "a98a0572736cab83e28dbf3d024995cb1a9d63da90271502eae2a167582e571c",
};

const ARK_BN254_CURVE_TESTS: SourcePin = SourcePin {
    package: "ark-bn254",
    version: "0.5.0",
    crate_sha256: "d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc",
    vcs_revision: "df907e8c1601a898c2903ed7ab7bbbb10607f36b",
    path: "src/curves/tests.rs",
    file_sha256: "251bd52592a825db6488624ffab1ecc4f64a6fb06e49a8cf944fa26ff9b6e1c8",
};

const ARK_BN254_G2: SourcePin = SourcePin {
    package: "ark-bn254",
    version: "0.5.0",
    crate_sha256: "d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc",
    vcs_revision: "df907e8c1601a898c2903ed7ab7bbbb10607f36b",
    path: "src/curves/g2.rs",
    file_sha256: "199e048b5cf199be9b053e41879e2e2cd61e04eaffe54852f4fbf27aff85eb9b",
};

#[derive(Clone, Copy, Debug)]
enum UpstreamExecution {
    Once,
    Iterations(usize),
    /// The generated test exists, but its configuration guard is false.
    Inert {
        configured_iterations: usize,
        condition: &'static str,
    },
}

/// A compile-time link from a manifest row to its executable test symbol.
#[derive(Clone, Copy, Debug)]
struct ExecutableMigration {
    id: &'static str,
    test_symbol: &'static str,
    test_fn: fn(),
    body_source: SourcePin,
    instantiated_at: Option<SourcePin>,
    upstream_test: &'static str,
    execution: UpstreamExecution,
}

#[derive(Clone, Copy, Debug)]
struct AdaptedMigration {
    executable: ExecutableMigration,
    waiver: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum MigrationStatus {
    Adapted(&'static AdaptedMigration),
    Covered(&'static str),
    PendingApi(&'static str),
    Inapplicable(&'static str),
}

/// Declare the test and its evidence row together. Deleting the declaration
/// breaks the manifest at compile time; the integrity test also requires its
/// generated Rust name to match the pinned upstream test name.
macro_rules! ark_adapted_case {
    (
        record $record:ident {
            id: $id:expr,
            body_source: $body_source:expr,
            instantiated_at: $instantiated_at:expr,
            upstream_test: $upstream_test:literal,
            execution: $execution:expr,
            waiver: $waiver:literal $(,)?
        }
        fn $name:ident() $body:block
    ) => {
        #[test]
        fn $name() $body

        pub(in crate::arkworks_bn254_0_5_tests) const $record: AdaptedMigration =
            AdaptedMigration {
                executable: ExecutableMigration {
                    id: $id,
                    test_symbol: concat!(module_path!(), "::", stringify!($name)),
                    test_fn: $name,
                    body_source: $body_source,
                    instantiated_at: $instantiated_at,
                    upstream_test: $upstream_test,
                    execution: $execution,
                },
                waiver: $waiver,
            };
    };
}

trait HeliosField:
    Copy
    + Debug
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    fn is_zero(self) -> bool;
    fn double(self) -> Self;
    fn square(self) -> Self;
    fn invert(self) -> Option<Self>;
}

macro_rules! impl_helios_field {
    ($field:ty) => {
        impl HeliosField for $field {
            const ZERO: Self = <$field>::ZERO;
            const ONE: Self = <$field>::ONE;

            fn is_zero(self) -> bool {
                <$field>::is_zero(&self)
            }

            fn double(self) -> Self {
                <$field>::double(self)
            }

            fn square(self) -> Self {
                <$field>::square(self)
            }

            fn invert(self) -> Option<Self> {
                <$field>::invert(self)
            }
        }
    };
}

impl_helios_field!(Fp);
impl_helios_field!(Fr);
impl_helios_field!(Fp2);
impl_helios_field!(Fp6);
impl_helios_field!(Fp12);

trait ArkBridge: ArkField + UniformRand + Copy {
    type Helios: HeliosField;

    fn to_helios(self) -> Self::Helios;
}

fn fq_to_fp(value: ArkFq) -> Fp {
    Fp::from_raw(value.into_bigint().0)
}

fn fr_to_fr(value: ArkFr) -> Fr {
    Fr::from_raw(value.into_bigint().0)
}

fn fq2_to_fp2(value: ArkFq2) -> Fp2 {
    Fp2::new(fq_to_fp(value.c0), fq_to_fp(value.c1))
}

fn fq6_to_fp6(value: ArkFq6) -> Fp6 {
    Fp6::new(
        fq2_to_fp2(value.c0),
        fq2_to_fp2(value.c1),
        fq2_to_fp2(value.c2),
    )
}

fn fq12_to_fp12(value: ArkFq12) -> Fp12 {
    Fp12::new(fq6_to_fp6(value.c0), fq6_to_fp6(value.c1))
}

macro_rules! impl_ark_bridge {
    ($ark:ty, $helios:ty, $convert:ident) => {
        impl ArkBridge for $ark {
            type Helios = $helios;

            fn to_helios(self) -> Self::Helios {
                $convert(self)
            }
        }
    };
}

impl_ark_bridge!(ArkFq, Fp, fq_to_fp);
impl_ark_bridge!(ArkFr, Fr, fr_to_fr);
impl_ark_bridge!(ArkFq2, Fp2, fq2_to_fp2);
impl_ark_bridge!(ArkFq6, Fp6, fq6_to_fp6);
impl_ark_bridge!(ArkFq12, Fp12, fq12_to_fp12);

/// Test-side analogue of Ark's variable-width `Field::pow`.
///
/// Helios deliberately gives each production field only the exponentiation
/// surface its hot paths need. Keeping this generic adapter in the oracle
/// module preserves the template's ten-limb exponent claims without growing
/// the production API merely to improve a migration count.
fn field_pow_limbs<F: HeliosField>(value: F, limbs: &[u64]) -> F {
    let mut acc = F::ONE;
    for &limb in limbs.iter().rev() {
        for bit in (0..64).rev() {
            acc = acc.square();
            if (limb >> bit) & 1 == 1 {
                acc = acc * value;
            }
        }
    }
    acc
}

/// Prime fields are degree-one extensions, so their base-field embedding is
/// the identity and `mul_by_base_prime_field` is ordinary multiplication.
fn mul_by_prime_base_field<F: HeliosField>(value: F, base: F) -> F {
    value * base
}

fn run_prime_mul_by_base_field_elem<A: ArkBridge>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    for sample in 0..FIELD_ITERATIONS {
        let a = A::rand(&mut rng);
        let b = A::rand(&mut rng);
        let ha = a.to_helios();
        let embedded_b = b.to_helios();

        let computed = mul_by_prime_base_field(ha, embedded_b);
        let naive = ha * embedded_b;
        assert_eq!(computed, naive, "sample {sample}");
        assert_eq!(computed, (a * b).to_helios(), "Ark oracle sample {sample}");
    }
}

/// Exercise the degree-one Frobenius law through the operation Helios does
/// expose: exponentiation by the scalar-field characteristic.
fn run_fr_frobenius() {
    let mut rng = StdRng::seed_from_u64(0x4652_4652_4f42_0001);
    let identity_exponent = [1, 0, 0, 0];

    for sample in 0..FIELD_ITERATIONS {
        let a = ArkFr::rand(&mut rng);
        let h = fr_to_fr(a);

        let mapped_at_zero = h.pow_raw(&identity_exponent);
        assert_eq!(mapped_at_zero, h, "sample {sample}, power 0");

        let mapped_at_one = h.pow_raw(&crate::consts::R);
        assert_eq!(mapped_at_one, h, "sample {sample}, power 1");
        assert_eq!(
            mapped_at_one,
            fr_to_fr(a.pow(crate::consts::R)),
            "Ark oracle sample {sample}, power 1"
        );

        // Preserve the template's final characteristic-power update. Its
        // result is not asserted upstream; checking it here catches drift.
        assert_eq!(
            mapped_at_one.pow_raw(&crate::consts::R),
            h,
            "sample {sample}, power 2"
        );
    }
}

trait HeliosSqrtField: HeliosField {
    fn sqrt(self) -> Option<Self>;
}

macro_rules! impl_helios_sqrt_field {
    ($field:ty) => {
        impl HeliosSqrtField for $field {
            fn sqrt(self) -> Option<Self> {
                <$field>::sqrt(self)
            }
        }
    };
}

impl_helios_sqrt_field!(Fp);
impl_helios_sqrt_field!(Fp2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SquareClass {
    Zero,
    QuadraticResidue,
    QuadraticNonResidue,
}

/// Euler/Legendre classification via the existing square-root surface. This
/// is test-only: it does not add a low-value production API merely for parity.
fn square_class<F: HeliosSqrtField>(value: F) -> SquareClass {
    if value.is_zero() {
        SquareClass::Zero
    } else if value.sqrt().is_some() {
        SquareClass::QuadraticResidue
    } else {
        SquareClass::QuadraticNonResidue
    }
}

fn assert_upstream_sqrt_test_is_inert<A: ArkField>() {
    assert!(
        A::SQRT_PRECOMP.is_none(),
        "upstream sqrt body would become active; migrate its full assertions"
    );
}

// UPSTREAM: ark-algebra-test-templates 0.5.0/src/fields.rs::__test_field::test_mul_properties
// ADAPTATION: retain 1,000 samples; compare each Helios result to the converted Ark result.
fn run_mul_properties<A: ArkBridge>(seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let zero = A::ZERO.to_helios();
    let one = A::ONE.to_helios();
    assert_eq!(zero, A::Helios::ZERO);
    assert!(zero.is_zero());
    assert_eq!(one, A::Helios::ONE);
    assert_eq!(one.invert(), Some(one));

    for sample in 0..FIELD_ITERATIONS {
        let a = A::rand(&mut rng);
        let b = A::rand(&mut rng);
        let c = A::rand(&mut rng);
        let ha = a.to_helios();
        let hb = b.to_helios();
        let hc = c.to_helios();

        let associated_left = (ha * hb) * hc;
        let associated_right = ha * (hb * hc);
        assert_eq!(associated_left, associated_right, "sample {sample}");
        assert_eq!(
            associated_left,
            ((a * b) * c).to_helios(),
            "sample {sample}"
        );

        assert_eq!(ha * hb, hb * ha, "sample {sample}");
        assert_eq!(ha * hb, (a * b).to_helios(), "sample {sample}");

        assert_eq!(one * ha, ha, "sample {sample}, a identity");
        assert_eq!(one * hb, hb, "sample {sample}, b identity");
        assert_eq!(one * hc, hc, "sample {sample}, c identity");
        assert_eq!(zero * ha, zero, "sample {sample}, a zero");
        assert_eq!(zero * hb, zero, "sample {sample}, b zero");
        assert_eq!(zero * hc, zero, "sample {sample}, c zero");

        for (label, value, ark_value) in [("a", ha, a), ("b", hb, b), ("c", hc, c)] {
            let inverse = value.invert().expect("fixed random sample is nonzero");
            assert_eq!(value * inverse, one, "sample {sample}, {label} inverse");
            assert_eq!(
                inverse,
                ark_value
                    .inverse()
                    .expect("fixed random sample is nonzero")
                    .to_helios(),
                "sample {sample}, {label} Ark inverse"
            );
        }

        let t0 = (ha * hb) * hc;
        let t1 = (ha * hc) * hb;
        let t2 = (hb * hc) * ha;
        assert_eq!(t0, t1, "sample {sample}, permutation 0");
        assert_eq!(t1, t2, "sample {sample}, permutation 1");

        assert_eq!(ha * ha, ha.square(), "sample {sample}, a square");
        assert_eq!(hb * hb, hb.square(), "sample {sample}, b square");
        assert_eq!(hc * hc, hc.square(), "sample {sample}, c square");
        assert_eq!(ha.square(), a.square().to_helios(), "sample {sample}");

        assert_eq!(ha * (hb + hc), ha * hb + ha * hc, "sample {sample}");
        assert_eq!(hb * (ha + hc), hb * ha + hb * hc, "sample {sample}");
        assert_eq!(hc * (ha + hb), hc * ha + hc * hb, "sample {sample}");

        assert_eq!(
            (ha + hb).square(),
            ha.square() + hb.square() + ha * hb.double(),
            "sample {sample}, square distributivity a/b"
        );
        assert_eq!(
            (hb + hc).square(),
            hc.square() + hb.square() + hc * hb.double(),
            "sample {sample}, square distributivity b/c"
        );
        assert_eq!(
            (hc + ha).square(),
            ha.square() + hc.square() + ha * hc.double(),
            "sample {sample}, square distributivity c/a"
        );
    }
}

const ADDITIVE_POOL_SIZE: usize = 1 << 12;

fn next_pool_index(state: &mut u64) -> usize {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as usize & (ADDITIVE_POOL_SIZE - 1)
}

fn additive_pool<A: ArkBridge>(seed: u64) -> Vec<(A, A::Helios)> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..ADDITIVE_POOL_SIZE)
        .map(|_| {
            let ark = A::rand(&mut rng);
            (ark, ark.to_helios())
        })
        .collect()
}

// UPSTREAM: ark-algebra-test-templates 0.5.0/src/fields.rs::test_add_properties.
// ADAPTATION: preserve its exact ITERATIONS^2 = 1,000,000 cases while
// recombining a deterministic random corpus, avoiding millions of redundant
// extension-field input conversions in debug CI.
fn run_add_properties<A: ArkBridge>(seed: u64) {
    let pool = additive_pool::<A>(seed);
    let zero = A::Helios::ZERO;
    assert_eq!(-zero, zero);
    assert!(zero.is_zero());
    let mut state = seed ^ 0xa409_3822_299f_31d0;

    for sample in 0..(FIELD_ITERATIONS * FIELD_ITERATIONS) {
        let (a, ha) = pool[next_pool_index(&mut state)];
        let (b, hb) = pool[next_pool_index(&mut state)];
        let (c, hc) = pool[next_pool_index(&mut state)];

        let left = (ha + hb) + hc;
        let right = ha + (hb + hc);
        assert_eq!(left, right, "associativity sample {sample}");
        assert_eq!(left, ((a + b) + c).to_helios(), "sample {sample}");
        assert_eq!(ha + hb, hb + ha, "commutativity sample {sample}");
        assert_eq!(ha + hb, (a + b).to_helios(), "Ark sample {sample}");

        assert_eq!(zero + ha, ha, "sample {sample}, a identity");
        assert_eq!(zero + hb, hb, "sample {sample}, b identity");
        assert_eq!(zero + hc, hc, "sample {sample}, c identity");
        assert_eq!((-ha) + ha, zero, "sample {sample}, a negation");
        assert_eq!((-hb) + hb, zero, "sample {sample}, b negation");
        assert_eq!((-hc) + hc, zero, "sample {sample}, c negation");
        assert_eq!(-zero, zero, "sample {sample}, zero negation");

        let t0 = (ha + hb) + hc;
        let t1 = (ha + hc) + hb;
        let t2 = (hb + hc) + ha;
        assert_eq!(t0, t1, "permutation sample {sample}");
        assert_eq!(t1, t2, "permutation sample {sample}");

        assert_eq!(ha.double(), ha + ha, "sample {sample}, a double");
        assert_eq!(hb.double(), hb + hb, "sample {sample}, b double");
        assert_eq!(hc.double(), hc + hc, "sample {sample}, c double");
        assert_eq!(ha.double(), a.double().to_helios(), "Ark sample {sample}");
    }
}

// UPSTREAM: ark-algebra-test-templates 0.5.0/src/fields.rs::test_sub_properties.
fn run_sub_properties<A: ArkBridge>(seed: u64) {
    let pool = additive_pool::<A>(seed);
    let zero = A::Helios::ZERO;
    let mut state = seed ^ 0x082e_fa98_ec4e_6c89;

    for sample in 0..(FIELD_ITERATIONS * FIELD_ITERATIONS) {
        let (a, ha) = pool[next_pool_index(&mut state)];
        let (b, hb) = pool[next_pool_index(&mut state)];

        assert!(((ha - hb) + (hb - ha)).is_zero(), "sample {sample}");
        assert_eq!(ha - hb, (a - b).to_helios(), "Ark sample {sample}");
        assert_eq!(zero - ha, -ha, "sample {sample}, a left identity");
        assert_eq!(zero - hb, -hb, "sample {sample}, b left identity");
        assert_eq!(ha - zero, ha, "sample {sample}, a right identity");
        assert_eq!(hb - zero, hb, "sample {sample}, b right identity");
    }
}

fn random_limbs<const N: usize>(rng: &mut impl RngCore) -> [u64; N] {
    core::array::from_fn(|_| rng.next_u64())
}

// UPSTREAM: ark-algebra-test-templates 0.5.0/src/fields.rs::test_pow.
// ADAPTATION: Fp/Fr expose a fixed four-limb exponent. The algebraic claims
// are unchanged, with Ark evaluating the same exponent as the oracle.
fn run_prime_pow<A: ArkBridge>(
    seed: u64,
    modulus: [u64; 4],
    helios_pow: fn(A::Helios, &[u64; 4]) -> A::Helios,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    for sample in 0..(FIELD_ITERATIONS / 10) {
        for exponent in 0..20u64 {
            let a = A::rand(&mut rng);
            let ha = a.to_helios();
            let limbs = [exponent, 0, 0, 0];
            let computed = helios_pow(ha, &limbs);
            let mut repeated = A::Helios::ONE;
            for _ in 0..exponent {
                repeated = repeated * ha;
            }
            assert_eq!(computed, repeated, "sample {sample}, exponent {exponent}");
            assert_eq!(computed, a.pow(limbs).to_helios(), "sample {sample}");
        }

        let a = A::rand(&mut rng);
        let ha = a.to_helios();
        assert_eq!(helios_pow(ha, &modulus), a.to_helios(), "sample {sample}");

        let e1 = random_limbs::<10>(&mut rng);
        let e2 = random_limbs::<10>(&mut rng);
        let e3 = random_limbs::<10>(&mut rng);
        let h_e1 = field_pow_limbs(ha, &e1);
        let h_e2 = field_pow_limbs(ha, &e2);
        assert_eq!(h_e1, a.pow(e1).to_helios(), "sample {sample}, e1");
        assert_eq!(h_e2, a.pow(e2).to_helios(), "sample {sample}, e2");
        assert_eq!(
            field_pow_limbs(h_e1, &e2),
            field_pow_limbs(h_e2, &e1),
            "commutativity sample {sample}"
        );
        assert_eq!(
            field_pow_limbs(h_e1 * h_e2, &e3),
            field_pow_limbs(h_e1, &e3) * field_pow_limbs(h_e2, &e3),
            "distributivity sample {sample}"
        );
    }
}

fn limbs_to_bits_le(limbs: &[u64]) -> Vec<bool> {
    limbs
        .iter()
        .flat_map(|limb| (0..64).map(move |bit| (limb >> bit) & 1 == 1))
        .collect()
}

fn fp12_pow_limbs(value: Fp12, limbs: &[u64]) -> Fp12 {
    value.pow_bits(&limbs_to_bits_le(limbs))
}

mod fields {
    use super::*;

    pub(in crate::arkworks_bn254_0_5_tests) mod fr {
        use super::*;

        ark_adapted_case! {
            record TEST_FROBENIUS {
                id: "fields.fr.test_frobenius",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_frobenius",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Fr is a degree-one extension but exposes no Frobenius method. Map frobenius_map(0) to exponent one and frobenius_map(1) to a^r, collapsing the unavailable in-place/value variants; retain all 1,000 iterations, use the suite's fixed RNG, and add an Ark oracle plus a check of the upstream body's otherwise-unasserted final power."
            }
            fn test_frobenius() {
                run_fr_frobenius();
            }
        }

        fn assert_lincomb_matches_ark(a: &[ArkFr], b: &[ArkFr], context: &str) {
            let encoded_a: Vec<_> = a
                .iter()
                .copied()
                .map(fr_to_fr)
                .map(ScalarBytes::from_fr)
                .collect();
            let encoded_b: Vec<_> = b
                .iter()
                .copied()
                .map(fr_to_fr)
                .map(ScalarBytes::from_fr)
                .collect();
            let computed = fr_lincomb(&encoded_a, &encoded_b)
                .expect("nonempty in-cap lincomb")
                .to_fr()
                .expect("Helios emits a canonical scalar");
            let helios_naive = a.iter().zip(b).fold(Fr::ZERO, |sum, (&left, &right)| {
                sum + fr_to_fr(left) * fr_to_fr(right)
            });
            let ark_naive = a
                .iter()
                .zip(b)
                .fold(ArkFr::ZERO, |sum, (&left, &right)| sum + left * right);
            assert_eq!(computed, helios_naive, "{context}");
            assert_eq!(helios_naive, fr_to_fr(ark_naive), "Ark oracle: {context}");
        }

        ark_adapted_case! {
            record TEST_ADD_PROPERTIES {
                id: "fields.fr.test_add_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_add_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and recombine a deterministic 4,096-value Ark corpus instead of drawing three fresh values in each case; collapse Ark's duplicate zero()/ZERO predicates and reference-operand overloads to Helios ZERO/value operations. Preserve exactly 1,000^2 cases and all additive laws on Helios, with Ark conversion oracles."
            }
            fn test_add_properties() {
                run_add_properties::<ArkFr>(0x4652_4144_4400_0002);
            }
        }

        ark_adapted_case! {
            record TEST_SUB_PROPERTIES {
                id: "fields.fr.test_sub_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sub_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map Ark's zero() constructor to Helios ZERO, and recombine a deterministic 4,096-value Ark corpus instead of drawing two fresh values in each case. Preserve exactly 1,000^2 cases and all subtraction laws on Helios, with an Ark conversion oracle."
            }
            fn test_sub_properties() {
                run_sub_properties::<ArkFr>(0x4652_5355_4200_0002);
            }
        }

        ark_adapted_case! {
            record TEST_MUL_PROPERTIES {
                id: "fields.fr.test_mul_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map in-place/reference spellings to Helios values, replace duplicate one()/ONE/is_one predicates with equality/inversion checks on Helios ONE, and unwrap Option inverses for the same fixed nonzero samples. Preserve all 1,000 iterations and every multiplication, inverse, square, and distributivity law on Helios, adding Ark oracles."
            }
            fn test_mul_properties() {
                run_mul_properties::<ArkFr>(0x4652_4d55_4c00_0001);
            }
        }

        ark_adapted_case! {
            record TEST_MUL_BY_BASE_FIELD_ELEM {
                id: "fields.fr.test_mul_by_base_field_elem",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_by_base_field_elem",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "For prime Fr, BasePrimeField=Fr and extension_degree=1. Helios has no generic embedding/mul_by_base_prime_field facade, so map both to identity embedding and ordinary Fr multiplication; retain all 1,000 iterations, use the suite's fixed RNG, and add an Ark product oracle."
            }
            fn test_mul_by_base_field_elem() {
                run_prime_mul_by_base_field_elem::<ArkFr>(0x4652_4241_5345_0001);
            }
        }

        ark_adapted_case! {
            record TEST_POW {
                id: "fields.fr.test_pow",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_pow",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS / 10),
                waiver: "Replace ark_std::test_rng with a fixed StdRng. Use Fr::pow_raw for the 20 small exponents and characteristic check, and a test-only Helios square-and-multiply adapter for the template's full ten-limb random exponents because production Fr intentionally accepts four limbs. Preserve 100 outer iterations and add Ark result oracles."
            }
            fn test_pow() {
                run_prime_pow::<ArkFr>(0x4652_504f_5700_0002, crate::consts::R, Fr::pow_raw);
            }
        }

        ark_adapted_case! {
            record TEST_SUM_OF_PRODUCTS_TESTS {
                id: "fields.fr.test_sum_of_products_tests",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sum_of_products_tests",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and map generic const arrays to Helios' fallible ScalarBytes slice facade. Preserve all 1,000 outer iterations, lengths 1 through 10, and both random and maximal-value datasets; compare the Helios kernel with a Helios naive sum and Ark oracle."
            }
            fn test_sum_of_products_tests() {
                let mut rng = StdRng::seed_from_u64(0x4652_534f_5000_0002);
                let two_inv = ArkFr::from(2u64).inverse().expect("two is invertible");
                let max = -ArkFr::ONE * two_inv - ArkFr::ONE;
                for iteration in 0..FIELD_ITERATIONS {
                    for length in 1..=10 {
                        let a: Vec<_> = (0..length).map(|_| ArkFr::rand(&mut rng)).collect();
                        let b: Vec<_> = (0..length).map(|_| ArkFr::rand(&mut rng)).collect();
                        assert_lincomb_matches_ark(
                            &a,
                            &b,
                            &format!("iteration {iteration}, n={length}"),
                        );
                        assert_lincomb_matches_ark(
                            &vec![max; length],
                            &vec![max; length],
                            &format!("max iteration {iteration}, n={length}"),
                        );
                    }
                }
            }
        }

        ark_adapted_case! {
            record TEST_SUM_OF_PRODUCTS_EDGE_CASE {
                id: "fields.fr.test_sum_of_products_edge_case",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sum_of_products_edge_case",
                execution: UpstreamExecution::Once,
                waiver: "Specialize the template's generic modulus-bit derivation to the equivalent four-limb BN254 Fr boundary and map const arrays to Helios' fallible ScalarBytes slice facade. Preserve each length 1 through 10 and compare the Helios kernel with a Helios naive sum and Ark oracle."
            }
            fn test_sum_of_products_edge_case() {
                let a_max = ArkFr::from_bigint(ark_ff::BigInt::new([
                    u64::MAX,
                    u64::MAX,
                    u64::MAX,
                    u64::MAX >> 3,
                ]))
                .expect("upstream edge operand is canonical");
                let b_max = -ArkFr::ONE;
                for length in 1..=10 {
                    assert_lincomb_matches_ark(
                        &vec![a_max; length],
                        &vec![b_max; length],
                        &format!("edge n={length}"),
                    );
                }
            }
        }

        ark_adapted_case! {
            record TEST_MONTGOMERY_CONFIG {
                id: "fields.fr.test_montgomery_config",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_montgomery_config",
                execution: UpstreamExecution::Once,
                waiver: "Replace the template's num-bigint recomputation with Helios constructor-domain identities, the defining wrapping p*INV=-1 equation, and equality to pinned Ark Fr R/R2/INV constants. This proves the same three Montgomery constants without adding bigint code to Helios."
            }
            fn test_montgomery_config() {
                use crate::consts::{FR_MONT_ONE, FR_MONT_R2, R, R_INV};

                assert_eq!(Fr::ONE.0, FR_MONT_ONE);
                assert_eq!(Fr::from_raw([1, 0, 0, 0]).0, FR_MONT_ONE);
                assert_eq!(Fr::from_raw(FR_MONT_ONE).0, FR_MONT_R2);
                assert_eq!(R[0].wrapping_mul(R_INV), u64::MAX);
                assert_eq!(FR_MONT_ONE, ArkFr::R.0);
                assert_eq!(FR_MONT_R2, ArkFr::R2.0);
                assert_eq!(R_INV, ArkFr::INV);
                assert_eq!(fr_to_fr(ArkFr::ONE), Fr::ONE);
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod fq {
        use super::*;

        ark_adapted_case! {
            record TEST_ADD_PROPERTIES {
                id: "fields.fq.test_add_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_add_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and recombine a deterministic 4,096-value Ark corpus instead of drawing three fresh values in each case; collapse Ark's duplicate zero()/ZERO predicates and reference-operand overloads to Helios ZERO/value operations. Preserve exactly 1,000^2 cases and all additive laws on Helios, with Ark conversion oracles."
            }
            fn test_add_properties() {
                run_add_properties::<ArkFq>(0x4651_4144_4400_0002);
            }
        }

        ark_adapted_case! {
            record TEST_SUB_PROPERTIES {
                id: "fields.fq.test_sub_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sub_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map Ark's zero() constructor to Helios ZERO, and recombine a deterministic 4,096-value Ark corpus instead of drawing two fresh values in each case. Preserve exactly 1,000^2 cases and all subtraction laws on Helios, with an Ark conversion oracle."
            }
            fn test_sub_properties() {
                run_sub_properties::<ArkFq>(0x4651_5355_4200_0002);
            }
        }

        ark_adapted_case! {
            record TEST_FROBENIUS {
                id: "fields.fq.test_frobenius",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_frobenius",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and collapse Ark's power-indexed in-place/value Frobenius variants to Fp's value-only degree-one map; use the test-only Helios square-and-multiply adapter for the characteristic power. Preserve power zero, power one, and all 1,000 iterations with Ark oracles; turn the upstream body's otherwise-unasserted final recurrence update into a Helios wraparound assertion."
            }
            fn test_frobenius() {
                let mut rng = StdRng::seed_from_u64(0x4651_4652_4f42_0001);
                for sample in 0..FIELD_ITERATIONS {
                    let a = ArkFq::rand(&mut rng);
                    let h = fq_to_fp(a);
                    assert_eq!(field_pow_limbs(h, &[1]), h, "sample {sample}, power 0");
                    let mapped = h.frobenius_map();
                    assert_eq!(mapped, field_pow_limbs(h, &crate::consts::P));
                    assert_eq!(mapped, a.frobenius_map(1).to_helios());
                    assert_eq!(mapped.frobenius_map(), mapped, "final sample {sample}");
                }
            }
        }

        ark_adapted_case! {
            record TEST_MUL_PROPERTIES {
                id: "fields.fq.test_mul_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map in-place/reference spellings to Helios values, replace duplicate one()/ONE/is_one predicates with equality/inversion checks on Helios ONE, and unwrap Option inverses for the same fixed nonzero samples. Preserve all 1,000 iterations and every multiplication, inverse, square, and distributivity law on Helios, adding Ark oracles."
            }
            fn test_mul_properties() {
                run_mul_properties::<ArkFq>(0x4651_4d55_4c00_0001);
            }
        }

        ark_adapted_case! {
            record TEST_MUL_BY_BASE_FIELD_ELEM {
                id: "fields.fq.test_mul_by_base_field_elem",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_by_base_field_elem",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "For prime Fq, BasePrimeField=Fq and extension_degree=1. Helios has no generic embedding/mul_by_base_prime_field facade, so map both to identity embedding and ordinary Fp multiplication; retain all 1,000 iterations, use the suite's fixed RNG, and add an Ark product oracle."
            }
            fn test_mul_by_base_field_elem() {
                run_prime_mul_by_base_field_elem::<ArkFq>(0x4651_4241_5345_0001);
            }
        }

        ark_adapted_case! {
            record TEST_POW {
                id: "fields.fq.test_pow",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_pow",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS / 10),
                waiver: "Replace ark_std::test_rng with a fixed StdRng. Use Fp::pow_raw for the 20 small exponents and characteristic check, and a test-only Helios square-and-multiply adapter for the template's full ten-limb random exponents because production Fp intentionally accepts four limbs. Preserve 100 outer iterations and add Ark result oracles."
            }
            fn test_pow() {
                run_prime_pow::<ArkFq>(0x4651_504f_5700_0002, crate::consts::P, Fp::pow_raw);
            }
        }

        ark_adapted_case! {
            record TEST_SQRT {
                id: "fields.fq.test_sqrt",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sqrt",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Pin the upstream SQRT_PRECOMP active branch, replace ark_std::test_rng with a fixed StdRng, map mutable square/sqrt operations to Helios values, and translate the final Legendre-residue assertion to successful Helios sqrt because Fp has no Legendre API. Preserve zero handling, two fresh random draws per iteration, and all 1,000 iterations; add Ark sqrt-existence/result oracles."
            }
            fn test_sqrt() {
                let mut rng = StdRng::seed_from_u64(0x4651_5351_5254_0001);
                assert!(ArkFq::SQRT_PRECOMP.is_some(), "upstream sqrt body is inert");
                assert_eq!(Fp::ZERO.sqrt(), Some(Fp::ZERO));
                for sample in 0..FIELD_ITERATIONS {
                    let a = ArkFq::rand(&mut rng);
                    let h = fq_to_fp(a);
                    let square = h.square();
                    let root = square.sqrt().expect("a square must have a square root");
                    assert!(root == h || root == -h, "sample {sample}");
                    assert_eq!(root.square(), a.square().to_helios(), "sample {sample}");

                    let ark_root = a.sqrt();
                    let helios_root = h.sqrt();
                    assert_eq!(helios_root.is_some(), ark_root.is_some(), "sample {sample}");
                    if let Some(root) = helios_root {
                        assert_eq!(root.square(), h, "sample {sample}");
                    }

                    let residue = fq_to_fp(ArkFq::rand(&mut rng)).square();
                    assert!(residue.sqrt().is_some(), "residue sample {sample}");
                }
            }
        }

        ark_adapted_case! {
            record TEST_MONTGOMERY_CONFIG {
                id: "fields.fq.test_montgomery_config",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_montgomery_config",
                execution: UpstreamExecution::Once,
                waiver: "Replace the template's num-bigint recomputation with Helios constructor-domain identities, the defining wrapping p*INV=-1 equation, and equality to pinned Ark Fq R/R2/INV constants. This proves the same three Montgomery constants without adding bigint code to Helios."
            }
            fn test_montgomery_config() {
                use crate::consts::{MONT_ONE, MONT_R2, P, P_INV};

                assert_eq!(Fp::ONE.0, MONT_ONE);
                assert_eq!(Fp::from_raw([1, 0, 0, 0]).0, MONT_ONE);
                assert_eq!(Fp::from_raw(MONT_ONE).0, MONT_R2);
                assert_eq!(P[0].wrapping_mul(P_INV), u64::MAX);
                assert_eq!(MONT_ONE, ArkFq::R.0);
                assert_eq!(MONT_R2, ArkFq::R2.0);
                assert_eq!(P_INV, ArkFq::INV);
                assert_eq!(fq_to_fp(ArkFq::ONE), Fp::ONE);
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod fq2 {
        use super::*;

        ark_adapted_case! {
            record TEST_ADD_PROPERTIES {
                id: "fields.fq2.test_add_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_add_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and recombine a deterministic 4,096-value Ark corpus instead of drawing three fresh values in each case; collapse Ark's duplicate zero()/ZERO predicates and reference-operand overloads to Helios ZERO/value operations. Preserve exactly 1,000^2 cases and all additive laws on Helios, with Ark conversion oracles."
            }
            fn test_add_properties() {
                run_add_properties::<ArkFq2>(0x4651_3241_4444_0002);
            }
        }

        ark_adapted_case! {
            record TEST_SUB_PROPERTIES {
                id: "fields.fq2.test_sub_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sub_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map Ark's zero() constructor to Helios ZERO, and recombine a deterministic 4,096-value Ark corpus instead of drawing two fresh values in each case. Preserve exactly 1,000^2 cases and all subtraction laws on Helios, with an Ark conversion oracle."
            }
            fn test_sub_properties() {
                run_sub_properties::<ArkFq2>(0x4651_3253_5542_0002);
            }
        }

        ark_adapted_case! {
            record TEST_FROBENIUS {
                id: "fields.fq2.test_frobenius",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_frobenius",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and collapse Ark's power-indexed in-place/value Frobenius variants to Fp2's composable value-only p-map; use the test-only Helios square-and-multiply adapter because Fp2 has no public pow. Preserve powers zero through two and all 1,000 iterations with Ark oracles; turn the upstream body's otherwise-unasserted final recurrence update into a Helios wraparound assertion."
            }
            fn test_frobenius() {
                let mut rng = StdRng::seed_from_u64(0x4651_3246_524f_0001);
                for sample in 0..FIELD_ITERATIONS {
                    let a = ArkFq2::rand(&mut rng);
                    let h = fq2_to_fp2(a);
                    assert_eq!(field_pow_limbs(h, &[1]), h, "sample {sample}, power 0");

                    let characteristic_1 = field_pow_limbs(h, &crate::consts::P);
                    let mapped_1 = h.frobenius_map();
                    assert_eq!(mapped_1, characteristic_1, "sample {sample}, power 1");
                    assert_eq!(mapped_1, a.frobenius_map(1).to_helios());

                    let characteristic_2 = field_pow_limbs(characteristic_1, &crate::consts::P);
                    let mapped_2 = mapped_1.frobenius_map();
                    assert_eq!(mapped_2, characteristic_2, "sample {sample}, power 2");
                    assert_eq!(mapped_2, a.frobenius_map(2).to_helios());
                    assert_eq!(
                        mapped_2.frobenius_map(),
                        mapped_1,
                        "final sample {sample}"
                    );
                }
            }
        }

        ark_adapted_case! {
            record TEST_MUL_PROPERTIES {
                id: "fields.fq2.test_mul_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map in-place/reference spellings to Helios values, replace duplicate one()/ONE/is_one predicates with equality/inversion checks on Helios ONE, and unwrap Option inverses for the same fixed nonzero samples. Preserve all 1,000 iterations and every multiplication, inverse, square, and distributivity law on Helios, adding Ark oracles."
            }
            fn test_mul_properties() {
                run_mul_properties::<ArkFq2>(0x4651_324d_554c_0001);
            }
        }

        ark_adapted_case! {
            record TEST_SQRT {
                id: "fields.fq2.test_sqrt",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sqrt",
                execution: UpstreamExecution::Inert {
                    configured_iterations: FIELD_ITERATIONS,
                    condition: "<ark_bn254::Fq2 as ark_ff::Field>::SQRT_PRECOMP.is_some() == false",
                },
                waiver: "The generated upstream body executes zero assertions and zero of its configured 1,000 iterations because Fq2::SQRT_PRECOMP=None, even though Ark and Helios expose direct sqrt methods. Replace the silent false branch with a provenance guard; retain the preexisting Helios-vs-Ark sqrt properties as a separately named local test that does not count as upstream execution."
            }
            fn test_sqrt() {
                assert_upstream_sqrt_test_is_inert::<ArkFq2>();
            }
        }

        #[test]
        fn helios_sqrt_matches_ark() {
            let mut rng = StdRng::seed_from_u64(0x4651_3253_5152_0001);
            assert_eq!(Fp2::ZERO.sqrt(), Some(Fp2::ZERO));
            for sample in 0..FIELD_ITERATIONS {
                let a = ArkFq2::rand(&mut rng);
                let h = fq2_to_fp2(a);
                let square = h.square();
                let root = square.sqrt().expect("a square must have a square root");
                assert!(root == h || root == -h, "sample {sample}");
                assert_eq!(root.square(), a.square().to_helios(), "sample {sample}");

                let ark_root = a.sqrt();
                let helios_root = h.sqrt();
                assert_eq!(helios_root.is_some(), ark_root.is_some(), "sample {sample}");
                if let Some(root) = helios_root {
                    assert_eq!(root.square(), h, "sample {sample}");
                }

                let residue = fq2_to_fp2(ArkFq2::rand(&mut rng)).square();
                assert!(residue.sqrt().is_some(), "residue sample {sample}");
            }
        }

        ark_adapted_case! {
            record TEST_MUL_BY_BASE_FIELD_ELEM {
                id: "fields.fq2.test_mul_by_base_field_elem",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_by_base_field_elem",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, spell upstream vec![rand; 2] as ArkFq2::new(c, c) so the single draw-and-clone behavior remains explicit, and map generic embedding/mul_by_base_prime_field to Fp2::from/Fp2::mul_by_fp value operations. Preserve two base-field draws and every assertion in all 1,000 iterations; add dense Helios and Ark product oracles."
            }
            fn test_mul_by_base_field_elem() {
                let mut rng = StdRng::seed_from_u64(0x4651_3242_4153_0001);
                for sample in 0..FIELD_ITERATIONS {
                    // Upstream `vec![rand(rng); 2]` evaluates `rand` once and
                    // clones it; do not "simplify" this to `ArkFq2::rand`.
                    let c = ArkFq::rand(&mut rng);
                    let a = ArkFq2::new(c, c);
                    let b = ArkFq::rand(&mut rng);
                    let ha = fq2_to_fp2(a);
                    let hb = fq_to_fp(b);
                    let computed = ha.mul_by_fp(hb);
                    let naive = ha * Fp2::from(hb);
                    let oracle = a * ArkFq2::new(b, ArkFq::ZERO);
                    assert_eq!(computed, naive, "sample {sample}");
                    assert_eq!(computed, fq2_to_fp2(oracle), "sample {sample}");
                }
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod fq6 {
        use super::*;

        ark_adapted_case! {
            record TEST_ADD_PROPERTIES {
                id: "fields.fq6.test_add_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_add_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and recombine a deterministic 4,096-value Ark corpus instead of drawing three fresh values in each case; collapse Ark's duplicate zero()/ZERO predicates and reference-operand overloads to Helios ZERO/value operations. Preserve exactly 1,000^2 cases and all additive laws on Helios, with Ark conversion oracles."
            }
            fn test_add_properties() {
                run_add_properties::<ArkFq6>(0x4651_3641_4444_0002);
            }
        }

        ark_adapted_case! {
            record TEST_SUB_PROPERTIES {
                id: "fields.fq6.test_sub_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sub_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map Ark's zero() constructor to Helios ZERO, and recombine a deterministic 4,096-value Ark corpus instead of drawing two fresh values in each case. Preserve exactly 1,000^2 cases and all subtraction laws on Helios, with an Ark conversion oracle."
            }
            fn test_sub_properties() {
                run_sub_properties::<ArkFq6>(0x4651_3653_5542_0002);
            }
        }

        ark_adapted_case! {
            record TEST_MUL_PROPERTIES {
                id: "fields.fq6.test_mul_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map in-place/reference spellings to Helios values, replace duplicate one()/ONE/is_one predicates with equality/inversion checks on Helios ONE, and unwrap Option inverses for the same fixed nonzero samples. Preserve all 1,000 iterations and every multiplication, inverse, square, and distributivity law on Helios, adding Ark oracles."
            }
            fn test_mul_properties() {
                run_mul_properties::<ArkFq6>(0x4651_364d_554c_0001);
            }
        }

        ark_adapted_case! {
            record TEST_SQRT {
                id: "fields.fq6.test_sqrt",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sqrt",
                execution: UpstreamExecution::Inert {
                    configured_iterations: FIELD_ITERATIONS,
                    condition: "<ark_bn254::Fq6 as ark_ff::Field>::SQRT_PRECOMP.is_some() == false",
                },
                waiver: "The generated upstream body executes zero assertions and zero of its configured 1,000 iterations because Fq6::SQRT_PRECOMP=None. Helios intentionally has no Fp6 sqrt API; replace the silent false branch with a provenance guard that fails if Ark activates it."
            }
            fn test_sqrt() {
                assert_upstream_sqrt_test_is_inert::<ArkFq6>();
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod fq12 {
        use super::*;

        ark_adapted_case! {
            record TEST_ADD_PROPERTIES {
                id: "fields.fq12.test_add_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_add_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and recombine a deterministic 4,096-value Ark corpus instead of drawing three fresh values in each case; collapse Ark's duplicate zero()/ZERO predicates and reference-operand overloads to Helios ZERO/value operations. Preserve exactly 1,000^2 cases and all additive laws on Helios, with Ark conversion oracles."
            }
            fn test_add_properties() {
                run_add_properties::<ArkFq12>(0x4631_3241_4444_0002);
            }
        }

        ark_adapted_case! {
            record TEST_SUB_PROPERTIES {
                id: "fields.fq12.test_sub_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sub_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS * FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map Ark's zero() constructor to Helios ZERO, and recombine a deterministic 4,096-value Ark corpus instead of drawing two fresh values in each case. Preserve exactly 1,000^2 cases and all subtraction laws on Helios, with an Ark conversion oracle."
            }
            fn test_sub_properties() {
                run_sub_properties::<ArkFq12>(0x4631_3253_5542_0002);
            }
        }

        ark_adapted_case! {
            record TEST_FROBENIUS {
                id: "fields.fq12.test_frobenius",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_frobenius",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng; collapse Ark's power-indexed in-place/value methods and characteristic exponentiation recurrence to composition of Helios' value-only p-map. Preserve powers zero through twelve and all 1,000 iterations with an Ark oracle at every power, pin the specialized p^2/p^3 maps, and turn the otherwise-unasserted final update into a Helios wraparound assertion."
            }
            fn test_frobenius() {
                let mut rng = StdRng::seed_from_u64(0x4631_3246_524f_0001);
                for sample in 0..FIELD_ITERATIONS {
                    let a = ArkFq12::rand(&mut rng);
                    let h = fq12_to_fp12(a);
                    let mut h_power = field_pow_limbs(h, &[1]);
                    assert_eq!(
                        h_power,
                        a.frobenius_map(0).to_helios(),
                        "sample {sample}, power 0"
                    );
                    for power in 1..=12 {
                        h_power = h_power.frobenius_map();
                        assert_eq!(
                            h_power,
                            a.frobenius_map(power).to_helios(),
                            "sample {sample}, power {power}"
                        );
                    }
                    assert_eq!(
                        h_power.frobenius_map(),
                        h.frobenius_map(),
                        "final sample {sample}"
                    );

                    assert_eq!(h.frobenius_map_squared(), a.frobenius_map(2).to_helios());
                    assert_eq!(h.frobenius_map_cubed(), a.frobenius_map(3).to_helios());
                }
            }
        }

        ark_adapted_case! {
            record TEST_MUL_PROPERTIES {
                id: "fields.fq12.test_mul_properties",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_mul_properties",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, map in-place/reference spellings to Helios values, replace duplicate one()/ONE/is_one predicates with equality/inversion checks on Helios ONE, and unwrap Option inverses for the same fixed nonzero samples. Preserve all 1,000 iterations and every multiplication, inverse, square, and distributivity law on Helios, adding Ark oracles."
            }
            fn test_mul_properties() {
                run_mul_properties::<ArkFq12>(0x4631_324d_554c_0001);
            }
        }

        ark_adapted_case! {
            record TEST_SQRT {
                id: "fields.fq12.test_sqrt",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_sqrt",
                execution: UpstreamExecution::Inert {
                    configured_iterations: FIELD_ITERATIONS,
                    condition: "<ark_bn254::Fq12 as ark_ff::Field>::SQRT_PRECOMP.is_some() == false",
                },
                waiver: "The generated upstream body executes zero assertions and zero of its configured 1,000 iterations because Fq12::SQRT_PRECOMP=None. Helios intentionally has no Fp12 sqrt API; replace the silent false branch with a provenance guard that fails if Ark activates it."
            }
            fn test_sqrt() {
                assert_upstream_sqrt_test_is_inert::<ArkFq12>();
            }
        }

        ark_adapted_case! {
            record TEST_POW {
                id: "fields.fq12.test_pow",
                body_source: ARK_TEMPLATE_FIELDS,
                instantiated_at: Some(ARK_BN254_FIELD_TESTS),
                upstream_test: "__test_field!::test_pow",
                execution: UpstreamExecution::Iterations(FIELD_ITERATIONS / 10),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and map Ark's little-endian limb exponent API to Fp12::pow_bits through an explicit limb-to-bit adapter. Preserve 100 outer iterations, 20 small exponents, twelve characteristic powers, and all three ten-limb random exponents; add Ark result oracles throughout."
            }
            fn test_pow() {
                let mut rng = StdRng::seed_from_u64(0x4631_3250_4f57_0002);
                for sample in 0..(FIELD_ITERATIONS / 10) {
                    for exponent in 0..20u64 {
                        let a = ArkFq12::rand(&mut rng);
                        let h = fq12_to_fp12(a);
                        let limbs = [exponent];
                        let computed = fp12_pow_limbs(h, &limbs);
                        let mut repeated = Fp12::ONE;
                        for _ in 0..exponent {
                            repeated *= h;
                        }
                        assert_eq!(computed, repeated, "sample {sample}, exponent {exponent}");
                        assert_eq!(computed, fq12_to_fp12(a.pow(limbs)), "sample {sample}");
                    }

                    let a = ArkFq12::rand(&mut rng);
                    let h = fq12_to_fp12(a);
                    let mut characteristic_power = h;
                    let mut ark_characteristic_power = a;
                    for power in 1..=12 {
                        characteristic_power =
                            fp12_pow_limbs(characteristic_power, &crate::consts::P);
                        ark_characteristic_power = ark_characteristic_power.pow(crate::consts::P);
                        assert_eq!(
                            characteristic_power,
                            fq12_to_fp12(ark_characteristic_power),
                            "sample {sample}, characteristic power {power}"
                        );
                    }
                    assert_eq!(characteristic_power, h, "sample {sample}");

                    let e1 = random_limbs::<10>(&mut rng);
                    let e2 = random_limbs::<10>(&mut rng);
                    let e3 = random_limbs::<10>(&mut rng);
                    let h_e1 = fp12_pow_limbs(h, &e1);
                    let h_e2 = fp12_pow_limbs(h, &e2);
                    assert_eq!(h_e1, fq12_to_fp12(a.pow(e1)), "sample {sample}, e1");
                    assert_eq!(h_e2, fq12_to_fp12(a.pow(e2)), "sample {sample}, e2");
                    assert_eq!(
                        fp12_pow_limbs(h_e1, &e2),
                        fp12_pow_limbs(h_e2, &e1),
                        "commutativity sample {sample}"
                    );
                    assert_eq!(
                        fp12_pow_limbs(h_e1 * h_e2, &e3),
                        fp12_pow_limbs(h_e1, &e3) * fp12_pow_limbs(h_e2, &e3),
                        "distributivity sample {sample}"
                    );
                }
            }
        }
    }

    ark_adapted_case! {
        record TEST_FQ2_BASICS {
            id: "fields.direct.test_fq2_basics",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq2_basics",
            execution: UpstreamExecution::Once,
            waiver: "Map Ark's zero()/one() constructors and coefficient field to Helios Fp2::ZERO/ONE/new. Preserve all five upstream assertions on Helios and add two Ark-to-Helios conversion guards."
        }
        fn test_fq2_basics() {
            assert_eq!(Fp2::new(Fp::ZERO, Fp::ZERO), Fp2::ZERO);
            assert_eq!(Fp2::new(Fp::ONE, Fp::ZERO), Fp2::ONE);
            assert!(Fp2::ZERO.is_zero());
            assert!(!Fp2::ONE.is_zero());
            assert!(!Fp2::new(Fp::ZERO, Fp::ONE).is_zero());
            assert_eq!(fq2_to_fp2(ArkFq2::ZERO), Fp2::ZERO);
            assert_eq!(fq2_to_fp2(ArkFq2::ONE), Fp2::ONE);
        }
    }

    ark_adapted_case! {
        record TEST_FQ_NUM_BITS {
            id: "fields.direct.test_fq_num_bits",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq_num_bits",
            execution: UpstreamExecution::Once,
            waiver: "Helios exposes the modulus limbs rather than a PrimeField::MODULUS_BIT_SIZE associated constant. Compute the bit length from Helios' pinned modulus, preserve the upstream value 254, and add Ark's constant as a provenance-only equality guard; that Ark-only operand does not count as coverage."
        }
        fn test_fq_num_bits() {
            let modulus_bits = 64 * crate::consts::P.len()
                - crate::consts::P
                    .iter()
                    .rev()
                    .find(|&&limb| limb != 0)
                    .expect("BN254 modulus is nonzero")
                    .leading_zeros() as usize;
            assert_eq!(modulus_bits, 254);
            // PROVENANCE GUARD: the Ark operand does not count as Helios coverage.
            assert_eq!(modulus_bits, ArkFq::MODULUS_BIT_SIZE as usize);
        }
    }

    ark_adapted_case! {
        record TEST_FQ_LEGENDRE {
            id: "fields.direct.test_fq_legendre",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq_legendre",
            execution: UpstreamExecution::Once,
            waiver: "Fp exposes sqrt rather than LegendreSymbol. Preserve the upstream values and four classifications, deriving the character from zero/sqrt so every assertion executes Helios code."
        }
        fn test_fq_legendre() {
            use SquareClass::{QuadraticNonResidue, QuadraticResidue, Zero};

            assert_eq!(QuadraticResidue, square_class(Fp::ONE));
            assert_eq!(Zero, square_class(Fp::ZERO));
            assert_eq!(QuadraticResidue, square_class(Fp::from_u64(4)));
            assert_eq!(QuadraticNonResidue, square_class(Fp::from_u64(5)));
        }
    }

    ark_adapted_case! {
        record TEST_FQ2_LEGENDRE {
            id: "fields.direct.test_fq2_legendre",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq2_legendre",
            execution: UpstreamExecution::Once,
            waiver: "Fp2 exposes sqrt rather than LegendreSymbol. Preserve the upstream zero/-1/(9+u)*-1 values and three classifications; map Fq6Config's in-place nonresidue helper to the equivalent Fp2::mul_by_nonresidue value operation."
        }
        fn test_fq2_legendre() {
            use SquareClass::{QuadraticNonResidue, QuadraticResidue, Zero};

            assert_eq!(Zero, square_class(Fp2::ZERO));
            // u^2 = -1.
            let mut minus_one = -Fp2::ONE;
            assert_eq!(QuadraticResidue, square_class(minus_one));
            minus_one = minus_one.mul_by_nonresidue();
            assert_eq!(QuadraticNonResidue, square_class(minus_one));
        }
    }

    ark_adapted_case! {
        record TEST_FQ6_MUL_BY_1 {
            id: "fields.direct.test_fq6_mul_by_1",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq6_mul_by_1",
            execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
            waiver: "Replace ark_std::test_rng with a fixed StdRng and Ark's in-place sparse/dense operations with Helios value-returning operations. Preserve all 1,000 samples and the exact (0,c1,0) placement; add Ark's sparse result as an oracle after the Helios sparse-versus-dense assertion."
        }
        fn test_fq6_mul_by_1() {
            let mut rng = StdRng::seed_from_u64(0x4651_364d_554c_0001);
            for sample in 0..FIELD_ITERATIONS {
                let c1 = ArkFq2::rand(&mut rng);
                let a = ArkFq6::rand(&mut rng);
                let ha = fq6_to_fp6(a);
                let hc1 = fq2_to_fp2(c1);

                let computed = ha.mul_by_1(hc1);
                let naive = ha * Fp6::new(Fp2::ZERO, hc1, Fp2::ZERO);
                let mut oracle = a;
                oracle.mul_by_1(&c1);
                assert_eq!(computed, naive, "sample {sample}");
                assert_eq!(computed, fq6_to_fp6(oracle), "sample {sample}");
            }
        }
    }

    ark_adapted_case! {
        record TEST_FQ6_MUL_BY_01 {
            id: "fields.direct.test_fq6_mul_by_01",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq6_mul_by_01",
            execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
            waiver: "Replace ark_std::test_rng with a fixed StdRng and Ark's in-place sparse/dense operations with Helios value-returning operations. Preserve all 1,000 samples and the exact (c0,c1,0) placement; add Ark's sparse result as an oracle after the Helios sparse-versus-dense assertion."
        }
        fn test_fq6_mul_by_01() {
            let mut rng = StdRng::seed_from_u64(0x4651_364d_3031_0001);
            for sample in 0..FIELD_ITERATIONS {
                let c0 = ArkFq2::rand(&mut rng);
                let c1 = ArkFq2::rand(&mut rng);
                let a = ArkFq6::rand(&mut rng);
                let ha = fq6_to_fp6(a);
                let hc0 = fq2_to_fp2(c0);
                let hc1 = fq2_to_fp2(c1);

                let computed = ha.mul_by_01(hc0, hc1);
                let naive = ha * Fp6::new(hc0, hc1, Fp2::ZERO);
                let mut oracle = a;
                oracle.mul_by_01(&c0, &c1);
                assert_eq!(computed, naive, "sample {sample}");
                assert_eq!(computed, fq6_to_fp6(oracle), "sample {sample}");
            }
        }
    }

    ark_adapted_case! {
        record TEST_FQ12_MUL_BY_034 {
            id: "fields.direct.test_fq12_mul_by_034",
            body_source: ARK_BN254_FIELD_TESTS,
            instantiated_at: None,
            upstream_test: "test_fq12_mul_by_034",
            execution: UpstreamExecution::Iterations(FIELD_ITERATIONS),
            waiver: "Replace ark_std::test_rng with a fixed StdRng and Ark's in-place sparse/dense operations with Helios value-returning operations. Preserve all 1,000 samples and D-twist coefficient placement ((c0,0,0),(c3,c4,0)); add Ark's sparse result as an oracle after the Helios sparse-versus-dense assertion."
        }
        fn test_fq12_mul_by_034() {
            let mut rng = StdRng::seed_from_u64(0x4631_324d_3033_3401);
            for sample in 0..FIELD_ITERATIONS {
                let c0 = ArkFq2::rand(&mut rng);
                let c3 = ArkFq2::rand(&mut rng);
                let c4 = ArkFq2::rand(&mut rng);
                let a = ArkFq12::rand(&mut rng);
                let ha = fq12_to_fp12(a);
                let hc0 = fq2_to_fp2(c0);
                let hc3 = fq2_to_fp2(c3);
                let hc4 = fq2_to_fp2(c4);

                let computed = ha.mul_by_034(hc0, hc3, hc4);
                let naive = ha
                    * Fp12::new(
                        Fp6::new(hc0, Fp2::ZERO, Fp2::ZERO),
                        Fp6::new(hc3, hc4, Fp2::ZERO),
                    );
                let mut oracle = a;
                oracle.mul_by_034(&c0, &c3, &c4);
                assert_eq!(computed, naive, "sample {sample}");
                assert_eq!(computed, fq12_to_fp12(oracle), "sample {sample}");
            }
        }
    }
}

fn g1_affine_to_helios(point: ArkG1Affine) -> G1Affine {
    if point.is_zero() {
        G1Affine::identity()
    } else {
        G1Affine {
            x: fq_to_fp(point.x),
            y: fq_to_fp(point.y),
            infinity: false,
        }
    }
}

fn g2_affine_to_helios(point: ArkG2Affine) -> G2Affine {
    if point.is_zero() {
        G2Affine::identity()
    } else {
        G2Affine {
            x: fq2_to_fp2(point.x),
            y: fq2_to_fp2(point.y),
            infinity: false,
        }
    }
}

trait HeliosCurveGroup: Copy {
    fn group_identity() -> Self;
    fn group_double(self) -> Self;
    fn group_add(self, other: Self) -> Self;
}

macro_rules! impl_helios_curve_group {
    ($group:ty) => {
        impl HeliosCurveGroup for $group {
            fn group_identity() -> Self {
                <$group>::identity()
            }

            fn group_double(self) -> Self {
                <$group>::double(self)
            }

            fn group_add(self, other: Self) -> Self {
                core::ops::Add::add(self, other)
            }
        }
    };
}

impl_helios_curve_group!(G1Projective);
impl_helios_curve_group!(G2Projective);

/// Independent test-side double-and-add for template claims that Ark expresses
/// through configurable wNAF or batch-preprocessing facades.
fn mul_group_words<G: HeliosCurveGroup>(base: G, words: [u64; 4]) -> G {
    let mut acc = G::group_identity();
    for word in words.iter().rev() {
        for bit in (0..64).rev() {
            acc = acc.group_double();
            if (word >> bit) & 1 == 1 {
                acc = acc.group_add(base);
            }
        }
    }
    acc
}

macro_rules! port_group_tests {
    (
        $module:ident,
        $ark_projective:ty,
        $helios_projective:ty,
        $convert:ident,
        $seed:expr
        $(, { $($extra:item)* })?
    ) => {
        pub(in crate::arkworks_bn254_0_5_tests) mod $module {
            use super::*;

            ark_adapted_case! {
                record TEST_ADD_PROPERTIES {
                    id: concat!("curves.", stringify!($module), ".test_add_properties"),
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_add_properties",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS),
                    waiver: "Replace ark_std::test_rng with a fixed StdRng, Ark operator/reference overloads with Helios inherent value methods, and raw projective equality with affine equality because equivalent Jacobian points need not share coordinates. Preserve all 500 iterations and every associativity, commutativity, identity, negation, permutation, and doubling assertion on Helios; add Ark affine oracles."
                }
                fn test_add_properties() {
                    #[inline(never)]
                    fn assert_associativity(
                        a: $ark_projective,
                        b: $ark_projective,
                        c: $ark_projective,
                        sample: usize,
                    ) {
                        let ha = $convert(a.into_affine()).to_curve();
                        let hb = $convert(b.into_affine()).to_curve();
                        let hc = $convert(c.into_affine()).to_curve();
                        let left = ha.add(hb).add(hc).to_affine();
                        let right = ha.add(hb.add(hc)).to_affine();
                        assert_eq!(left, right, "associativity sample {sample}");
                        assert_eq!(left, $convert(((a + b) + c).into_affine()));
                    }

                    #[inline(never)]
                    fn assert_commutativity(
                        a: $ark_projective,
                        b: $ark_projective,
                    ) {
                        let ha = $convert(a.into_affine()).to_curve();
                        let hb = $convert(b.into_affine()).to_curve();
                        assert_eq!(ha.add(hb).to_affine(), hb.add(ha).to_affine());
                        assert_eq!(ha.add(hb).to_affine(), $convert((a + b).into_affine()));
                    }

                    #[inline(never)]
                    fn assert_identities_and_negation(
                        a: $ark_projective,
                        b: $ark_projective,
                        c: $ark_projective,
                        sample: usize,
                    ) {
                        let zero = <$helios_projective>::identity();
                        let points = [
                            ("a", $convert(a.into_affine()).to_curve()),
                            ("b", $convert(b.into_affine()).to_curve()),
                            ("c", $convert(c.into_affine()).to_curve()),
                        ];
                        for (label, point) in points {
                            assert_eq!(zero.add(point).to_affine(), point.to_affine(), "{label} left identity sample {sample}");
                            assert_eq!(point.add(zero).to_affine(), point.to_affine(), "{label} right identity sample {sample}");
                            assert!(point.neg().add(point).is_identity(), "{label} negation sample {sample}");
                        }
                        assert!(zero.neg().is_identity(), "zero negation sample {sample}");
                    }

                    #[inline(never)]
                    fn assert_permutations(
                        a: $ark_projective,
                        b: $ark_projective,
                        c: $ark_projective,
                        sample: usize,
                    ) {
                        let ha = $convert(a.into_affine()).to_curve();
                        let hb = $convert(b.into_affine()).to_curve();
                        let hc = $convert(c.into_affine()).to_curve();
                        let t0 = ha.add(hb).add(hc).to_affine();
                        let t1 = ha.add(hc).add(hb).to_affine();
                        let t2 = hb.add(hc).add(ha).to_affine();
                        assert_eq!(t0, t1, "permutation 0 sample {sample}");
                        assert_eq!(t1, t2, "permutation 1 sample {sample}");
                    }

                    #[inline(never)]
                    fn assert_doubling(
                        a: $ark_projective,
                        b: $ark_projective,
                        c: $ark_projective,
                        sample: usize,
                    ) {
                        let zero = <$helios_projective>::identity();
                        for (point, ark) in [
                            ($convert(a.into_affine()).to_curve(), a),
                            ($convert(b.into_affine()).to_curve(), b),
                            ($convert(c.into_affine()).to_curve(), c),
                        ] {
                            assert_eq!(point.double().to_affine(), point.add(point).to_affine());
                            assert_eq!(point.double().to_affine(), $convert(ark.double().into_affine()));
                        }
                        assert!(zero.double().is_identity(), "zero double sample {sample}");
                        assert!(zero.neg().double().is_identity(), "negative-zero double sample {sample}");
                    }

                    let mut rng = StdRng::seed_from_u64($seed ^ 0x4144_4400_0000_0002);
                    for sample in 0..GROUP_ITERATIONS {
                        let a = <$ark_projective>::rand(&mut rng);
                        let b = <$ark_projective>::rand(&mut rng);
                        let c = <$ark_projective>::rand(&mut rng);
                        assert_associativity(a, b, c, sample);
                        assert_commutativity(a, b);
                        assert_identities_and_negation(a, b, c, sample);
                        assert_permutations(a, b, c, sample);
                        assert_doubling(a, b, c, sample);
                    }
                }
            }

            ark_adapted_case! {
                record TEST_SUB_PROPERTIES {
                    id: concat!("curves.", stringify!($module), ".test_sub_properties"),
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_sub_properties",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS),
                    waiver: "Replace ark_std::test_rng with a fixed StdRng and subtraction with Helios addition of negation. Preserve all 500 anti-commutativity and two-sided identity assertions. Map Ark's affine-minus-projective overload to Helios' mixed-add kernel with the affine left operand added to the negated projective right operand; compare all results in affine form and add Ark oracles."
                }
                fn test_sub_properties() {
                    let mut rng = StdRng::seed_from_u64($seed ^ 0x5355_4200_0000_0002);
                    let zero = <$helios_projective>::identity();
                    for sample in 0..GROUP_ITERATIONS {
                        let a = <$ark_projective>::rand(&mut rng);
                        let b = <$ark_projective>::rand(&mut rng);
                        let ha_affine = $convert(a.into_affine());
                        let ha = ha_affine.to_curve();
                        let hb = $convert(b.into_affine()).to_curve();
                        let a_minus_b = ha.add(hb.neg());
                        let b_minus_a = hb.add(ha.neg());

                        assert!(a_minus_b.add(b_minus_a).is_identity(), "sample {sample}");
                        assert_eq!(a_minus_b.to_affine(), $convert((a - b).into_affine()));
                        assert_eq!(b_minus_a.to_affine(), $convert((b - a).into_affine()));

                        assert_eq!(zero.add(ha.neg()).to_affine(), ha.neg().to_affine());
                        assert_eq!(zero.add(hb.neg()).to_affine(), hb.neg().to_affine());
                        assert_eq!(ha.add(zero).to_affine(), ha.to_affine());
                        assert_eq!(hb.add(zero).to_affine(), hb.to_affine());

                        let affine_minus_projective = hb.neg().add_mixed(ha_affine);
                        assert_eq!(affine_minus_projective.to_affine(), a_minus_b.to_affine());
                    }
                }
            }

            ark_adapted_case! {
                record TEST_MUL_PROPERTIES {
                    id: concat!("curves.", stringify!($module), ".test_mul_properties"),
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_mul_properties",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS),
                    waiver: "Replace ark_std::test_rng with a fixed StdRng, map ScalarField::is_one to equality with Helios' canonical one constructor, and make the template's probabilistic nonzero-inverse premise explicit by resampling zero. Preserve all 500 associativity, identity, inverse, and distributivity laws on Helios. Exercise Helios' typed wNAF evaluator at widths 2 through 5 against a test-side double-and-add oracle. Helios has no runtime-mismatched-table state or BatchMulPreprocessing facade: const generics reject a width/table mismatch at compile time, and the 100-scalar batch claim maps to public Helios multiplication versus independent Helios double-and-add. Add Ark affine oracles."
                }
                fn test_mul_properties() {
                    let mut rng = StdRng::seed_from_u64($seed ^ 0x4d55_4c00_0000_0002);
                    assert_eq!(Fr::ONE.invert(), Some(Fr::ONE));
                    assert_eq!(Fr::ONE, Fr::from_u64(1));
                    for sample in 0..GROUP_ITERATIONS {
                        let a = <$ark_projective>::rand(&mut rng);
                        let b = loop {
                            let candidate = ArkFr::rand(&mut rng);
                            if !candidate.is_zero() {
                                break candidate;
                            }
                        };
                        let c = ArkFr::rand(&mut rng);
                        let ha = $convert(a.into_affine()).to_curve();
                        let hb = fr_to_fr(b);
                        let hc = fr_to_fr(c);

                        let associated_left = ha.mul(hb).mul(hc).to_affine();
                        let associated_right = ha.mul(fr_to_fr(b * c)).to_affine();
                        assert_eq!(associated_left, associated_right, "sample {sample}");
                        assert_eq!(associated_left, $convert(((a * b) * c).into_affine()));

                        assert_eq!(ha.mul(Fr::ONE).to_affine(), ha.to_affine());
                        assert!(ha.mul(Fr::ZERO).is_identity(), "sample {sample}");
                        let inverse = b.inverse().expect("resampled nonzero scalar");
                        assert_eq!(
                            ha.mul(fr_to_fr(inverse)).mul(hb).to_affine(),
                            ha.to_affine(),
                            "inverse sample {sample}"
                        );
                        assert_eq!(
                            ha.mul(fr_to_fr(b + c)).to_affine(),
                            ha.mul(hb).add(ha.mul(hc)).to_affine(),
                            "distributivity sample {sample}"
                        );

                        let expected = mul_group_words::<$helios_projective>(ha, b.into_bigint().0).to_affine();
                        assert_eq!(ha.mul(hb).to_affine(), expected);
                        assert_eq!(
                            crate::wnaf::mul_group::<$helios_projective, 2, 1, 257>(ha, hb).to_affine(),
                            expected
                        );
                        assert_eq!(
                            crate::wnaf::mul_group::<$helios_projective, 3, 2, 257>(ha, hb).to_affine(),
                            expected
                        );
                        assert_eq!(
                            crate::wnaf::mul_group::<$helios_projective, 4, 4, 257>(ha, hb).to_affine(),
                            expected
                        );
                        assert_eq!(
                            crate::wnaf::mul_group::<$helios_projective, 5, 8, 257>(ha, hb).to_affine(),
                            expected
                        );
                        assert_eq!(expected, $convert((a * b).into_affine()));

                        let scalars: Vec<_> = (0..100).map(|_| ArkFr::rand(&mut rng)).collect();
                        let batch: Vec<_> = scalars
                            .iter()
                            .map(|scalar| ha.mul(fr_to_fr(*scalar)).to_affine())
                            .collect();
                        let naive: Vec<_> = scalars
                            .iter()
                            .map(|scalar| {
                                mul_group_words::<$helios_projective>(
                                    ha,
                                    scalar.into_bigint().0,
                                )
                                .to_affine()
                            })
                            .collect();
                        assert_eq!(batch, naive, "batch sample {sample}");
                    }
                }
            }

            ark_adapted_case! {
                record TEST_AFFINE_CONVERSION {
                    id: concat!("curves.", stringify!($module), ".test_affine_conversion"),
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_affine_conversion",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS + 10 * GROUP_ITERATIONS),
                    waiver: "Replace ark_std::test_rng and Uniform index sampling with fixed StdRng draws. Preserve the 500 projective-affine-projective cases plus ten 500-point doubled corpora, each with five identities and five normalized points. Helios exposes no public normalize_batch facade, so map that body to per-point Helios normalization and compare every output with Ark; this proves affine conversion, not a nonexistent batch API."
                }
                fn test_affine_conversion() {
                    let mut rng = StdRng::seed_from_u64($seed ^ 0x4146_4649_4e45_0002);
                    for sample in 0..GROUP_ITERATIONS {
                        let a = <$ark_projective>::rand(&mut rng);
                        let expected = $convert(a.into_affine());
                        let projective = expected.to_curve();
                        let affine = projective.to_affine();
                        assert_eq!(affine, expected, "sample {sample}");
                        assert_eq!(affine.to_curve().to_affine(), affine, "sample {sample}");
                    }

                    for batch in 0..10 {
                        let mut values: Vec<_> = (0..GROUP_ITERATIONS)
                            .map(|_| {
                                let point = <$ark_projective>::rand(&mut rng);
                                let projective = $convert(point.into_affine()).to_curve().double();
                                let expected = $convert(point.double().into_affine());
                                (projective, expected)
                            })
                            .collect();

                        for _ in 0..5 {
                            let index = rng.next_u64() as usize % GROUP_ITERATIONS;
                            values[index] = (
                                <$helios_projective>::identity(),
                                <$helios_projective>::identity().to_affine(),
                            );
                        }
                        for _ in 0..5 {
                            let index = rng.next_u64() as usize % GROUP_ITERATIONS;
                            values[index].0 = values[index].0.to_affine().to_curve();
                        }

                        let actual: Vec<_> = values.iter().map(|(point, _)| point.to_affine()).collect();
                        let expected: Vec<_> = values.iter().map(|(_, point)| *point).collect();
                        assert_eq!(actual, expected, "normalization batch {batch}");
                    }
                }
            }

            ark_adapted_case! {
                record TEST_MIXED_ADDITION {
                    id: concat!("curves.", stringify!($module), ".test_mixed_addition"),
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_mixed_addition",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS),
                    waiver: "Replace ark_std::test_rng with a fixed StdRng and Ark's affine/projective operator overloads with Helios add_mixed and explicit affine-to-projective conversion. Preserve all 500 on-curve guards and both operand orders, comparing the mixed kernel with dense Helios addition and Ark affine results."
                }
                fn test_mixed_addition() {
                    let mut rng = StdRng::seed_from_u64($seed ^ 0x4d49_5845_4400_0002);
                    for sample in 0..GROUP_ITERATIONS {
                        let a = <$ark_projective>::rand(&mut rng).into_affine();
                        let b = <$ark_projective>::rand(&mut rng);
                        let ha = $convert(a);
                        let hb_affine = $convert(b.into_affine());
                        let hb = hb_affine.to_curve();
                        assert!(ha.is_on_curve(), "affine sample {sample}");
                        assert!(hb_affine.is_on_curve(), "projective sample {sample}");

                        let b_plus_a = hb.add_mixed(ha);
                        let b_plus_a_dense = hb.add(ha.to_curve());
                        let a_plus_b = ha.to_curve().add(hb);
                        let expected = $convert((b + a.into_group()).into_affine());
                        assert_eq!(b_plus_a.to_affine(), b_plus_a_dense.to_affine());
                        assert_eq!(b_plus_a.to_affine(), expected);
                        assert_eq!(a_plus_b.to_affine(), expected);
                    }
                }
            }

            $($($extra)*)?
        }
    };
}

mod curves {
    use super::*;

    port_group_tests!(
        g1,
        ArkG1Projective,
        G1Projective,
        g1_affine_to_helios,
        0x4731_0000_0000_0000,
        {
            ark_adapted_case! {
                record TEST_COFACTOR_OPS {
                    id: "curves.g1.test_cofactor_ops",
                    body_source: ARK_TEMPLATE_GROUPS,
                    instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                    upstream_test: "__test_group!::test_cofactor_ops",
                    execution: UpstreamExecution::Iterations(GROUP_ITERATIONS),
                waiver: "BN254 G1 has COFACTOR=COFACTOR_INV=1, while Helios intentionally exposes neither generic cofactor method. Preserve all 500 samples and six upstream laws by substituting identity conversion/Fr::ONE multiplication, use the suite's fixed RNG, compare clear-cofactor with Ark, and check the resulting Helios point is on-curve. Two Ark-only assertions pin the cofactor-one premise and do not count as Helios coverage."
                }
                fn test_cofactor_ops() {
                    // PROVENANCE GUARDS: Ark pins the cofactor-one adaptation
                    // premise; neither assertion counts as Helios coverage.
                    assert_eq!(
                        <ark_bn254::g1::Config as ark_ec::CurveConfig>::COFACTOR,
                        &[1]
                    );
                    assert_eq!(
                        <ark_bn254::g1::Config as ark_ec::CurveConfig>::COFACTOR_INV,
                        ArkFr::ONE
                    );

                    let mut rng = StdRng::seed_from_u64(0x4731_434f_4641_0001);
                    for sample in 0..GROUP_ITERATIONS {
                        let ark_a = ArkG1Affine::rand(&mut rng);
                        let a = g1_affine_to_helios(ark_a);

                        let mul_by_cofactor_to_group = a.to_curve().mul(Fr::ONE);
                        let mul_bigint_cofactor = a.to_curve();
                        assert_eq!(
                            mul_by_cofactor_to_group.to_affine(),
                            mul_bigint_cofactor.to_affine(),
                            "sample {sample}"
                        );

                        let mul_by_cofactor = mul_by_cofactor_to_group.to_affine();
                        assert_eq!(
                            mul_by_cofactor,
                            mul_bigint_cofactor.to_affine(),
                            "sample {sample}"
                        );

                        let mul_by_cofactor_inv = |point: G1Affine| {
                            point.to_curve().mul(Fr::ONE).to_affine()
                        };
                        assert_eq!(
                            mul_by_cofactor_inv(mul_by_cofactor),
                            a,
                            "sample {sample}"
                        );
                        assert_eq!(
                            mul_by_cofactor_inv(a)
                                .to_curve()
                                .mul(Fr::ONE)
                                .to_affine(),
                            a,
                            "sample {sample}"
                        );
                        assert_eq!(
                            mul_by_cofactor_inv(a),
                            a.to_curve().mul(Fr::ONE).to_affine(),
                            "sample {sample}"
                        );

                        let cleared = a;
                        assert!(cleared.is_on_curve(), "sample {sample}");
                        assert_eq!(
                            cleared,
                            g1_affine_to_helios(ark_a.clear_cofactor()),
                            "Ark clear-cofactor sample {sample}"
                        );
                    }
                }
            }
        }
    );
    port_group_tests!(
        g2,
        ArkG2Projective,
        G2Projective,
        g2_affine_to_helios,
        0x4732_0000_0000_0000
    );

    pub(in crate::arkworks_bn254_0_5_tests) mod pairing {
        use super::*;

        ark_adapted_case! {
            record TEST_BILINEARITY {
                id: "curves.pairing.test_bilinearity",
                body_source: ARK_TEMPLATE_PAIRING,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_pairing!::test_bilinearity",
                execution: UpstreamExecution::Iterations(PAIRING_ITERATIONS),
                waiver: "Replace per-iteration ark_std::test_rng with one fixed StdRng and resample identity points/zero scalars so the upstream nonidentity assertions cannot fail probabilistically. Map PairingOutput's additive notation to Helios Fp12 multiplication/exponentiation and its zero to Fp12::ONE. Preserve all 100 bilinearity, nonidentity, and three group-order assertions on Helios; add an Ark pairing oracle."
            }
            fn test_bilinearity() {
                let mut rng = StdRng::seed_from_u64(0x5041_4952_4249_0002);
                let order_bits = limbs_to_bits_le(&crate::consts::R);
                for sample in 0..PAIRING_ITERATIONS {
                    let a = loop {
                        let candidate = ArkG1Projective::rand(&mut rng);
                        if !candidate.is_zero() {
                            break candidate;
                        }
                    };
                    let b = loop {
                        let candidate = ArkG2Projective::rand(&mut rng);
                        if !candidate.is_zero() {
                            break candidate;
                        }
                    };
                    let scalar = loop {
                        let candidate = ArkFr::rand(&mut rng);
                        if !candidate.is_zero() {
                            break candidate;
                        }
                    };
                    let ha = g1_affine_to_helios(a.into_affine());
                    let hb = g2_affine_to_helios(b.into_affine());
                    let hs = fr_to_fr(scalar);
                    let sa = ha.to_curve().mul(hs).to_affine();
                    let sb = hb.to_curve().mul(hs).to_affine();

                    let ans1 = crate::pairing(&sa, &hb);
                    let ans2 = crate::pairing(&ha, &sb);
                    let ans3 = crate::pairing(&ha, &hb).pow_bits(&hs.to_bits_le());
                    assert_eq!(ans1, ans2, "sample {sample}");
                    assert_eq!(ans2, ans3, "sample {sample}");
                    assert_eq!(
                        ans1,
                        fq12_to_fp12(Bn254::pairing(a * scalar, b).0),
                        "Ark oracle sample {sample}"
                    );
                    assert!(!ans1.is_one(), "ans1 sample {sample}");
                    assert!(!ans2.is_one(), "ans2 sample {sample}");
                    assert!(!ans3.is_one(), "ans3 sample {sample}");
                    assert_eq!(ans1.pow_bits(&order_bits), Fp12::ONE, "ans1 sample {sample}");
                    assert_eq!(ans2.pow_bits(&order_bits), Fp12::ONE, "ans2 sample {sample}");
                    assert_eq!(ans3.pow_bits(&order_bits), Fp12::ONE, "ans3 sample {sample}");
                }
            }
        }

        ark_adapted_case! {
            record TEST_MULTI_PAIRING {
                id: "curves.pairing.test_multi_pairing",
                body_source: ARK_TEMPLATE_PAIRING,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_pairing!::test_multi_pairing",
                execution: UpstreamExecution::Iterations(PAIRING_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng, PairingOutput addition with the equivalent Fp12 multiplication, and Ark's parallel point slices with Helios' pair slice. Preserve both random pairings and all 100 equality assertions on Helios; add Ark multi_pairing as an oracle."
            }
            fn test_multi_pairing() {
                let mut rng = StdRng::seed_from_u64(0x5041_4952_4d55_0002);
                for sample in 0..PAIRING_ITERATIONS {
                    let a = ArkG1Projective::rand(&mut rng).into_affine();
                    let b = ArkG2Projective::rand(&mut rng).into_affine();
                    let c = ArkG1Projective::rand(&mut rng).into_affine();
                    let d = ArkG2Projective::rand(&mut rng).into_affine();
                    let ha = g1_affine_to_helios(a);
                    let hb = g2_affine_to_helios(b);
                    let hc = g1_affine_to_helios(c);
                    let hd = g2_affine_to_helios(d);

                    let computed = multi_pairing(&[(&ha, &hb), (&hc, &hd)]);
                    let individual = crate::pairing(&ha, &hb) * crate::pairing(&hc, &hd);
                    let oracle = fq12_to_fp12(Bn254::multi_pairing([a, c], [b, d]).0);
                    assert_eq!(computed, individual, "sample {sample}");
                    assert_eq!(computed, oracle, "Ark oracle sample {sample}");
                }
            }
        }

        ark_adapted_case! {
            record TEST_FINAL_EXP {
                id: "curves.pairing.test_final_exp",
                body_source: ARK_TEMPLATE_PAIRING,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_pairing!::test_final_exp",
                execution: UpstreamExecution::Iterations(PAIRING_ITERATIONS),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and resample zero to make the upstream unwrap's implicit invertibility premise deterministic. Map cyclotomic_exp(r).is_one() to Helios Fp12::pow_bits(r)==ONE. Preserve all 100 final exponentiations and subgroup assertions on Helios; add Ark final_exponentiation as an oracle."
            }
            fn test_final_exp() {
                let mut rng = StdRng::seed_from_u64(0x5041_4952_4645_0002);
                let order_bits = limbs_to_bits_le(&crate::consts::R);
                for sample in 0..PAIRING_ITERATIONS {
                    let input = loop {
                        let candidate = ArkFq12::rand(&mut rng);
                        if !candidate.is_zero() {
                            break candidate;
                        }
                    };
                    let computed = final_exponentiation(&fq12_to_fp12(input));
                    let oracle = Bn254::final_exponentiation(MillerLoopOutput(input))
                        .expect("nonzero target-field input")
                        .0;
                    assert_eq!(computed, fq12_to_fp12(oracle), "sample {sample}");
                    assert_eq!(computed.pow_bits(&order_bits), Fp12::ONE, "sample {sample}");
                }
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod g1_glv {
        use super::*;

        ark_adapted_case! {
            record TEST_SCALAR_DECOMPOSITION {
                id: "curves.g1_glv.test_scalar_decomposition",
                body_source: ARK_TEMPLATE_GLV,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_scalar_decomposition",
                execution: UpstreamExecution::Iterations(100),
                waiver: "Replace ark_std::test_rng with a fixed StdRng. Helios deliberately keeps signed GLV components private, so inspect them through an exact-cfg(test) audit helper that is absent from release codegen. Preserve all 100 direct <2^127 component bounds and signed k1+lambda*k2 congruences using Helios Fr arithmetic, then execute one-point GLV MSM against independent Helios wNAF and an Ark result oracle. This does not expose the component signs as production API."
            }
            fn test_scalar_decomposition() {
                let mut rng = StdRng::seed_from_u64(0x4731_474c_5653_0002);
                let generator = G1Affine::generator();
                let ark_generator = ArkG1Projective::generator();
                for sample in 0..100 {
                    let scalar = ArkFr::rand(&mut rng);
                    let limbs = scalar.into_bigint().0;
                    let ((k1_negative, k1_magnitude), (k2_negative, k2_magnitude)) =
                        crate::msm::audit_decompose_scalar(limbs);
                    assert!(k1_magnitude < (1u128 << 127), "k1 sample {sample}");
                    assert!(k2_magnitude < (1u128 << 127), "k2 sample {sample}");

                    let signed = |negative: bool, magnitude: u128| {
                        let value = Fr::from_raw([
                            magnitude as u64,
                            (magnitude >> 64) as u64,
                            0,
                            0,
                        ]);
                        if negative { -value } else { value }
                    };
                    let k1 = signed(k1_negative, k1_magnitude);
                    let k2 = signed(k2_negative, k2_magnitude);
                    let lambda = fr_to_fr(<ark_bn254::g1::Config as GLVConfig>::LAMBDA);
                    assert_eq!(k1 + lambda * k2, fr_to_fr(scalar), "sample {sample}");

                    let glv = crate::msm::msm_variable_time(&[generator], &[limbs]);
                    let wnaf = generator.to_curve().mul(fr_to_fr(scalar));
                    let oracle = g1_affine_to_helios((ark_generator * scalar).into_affine());
                    assert_eq!(glv.to_affine(), wnaf.to_affine(), "sample {sample}");
                    assert_eq!(glv.to_affine(), oracle, "sample {sample}");
                }
            }
        }

        ark_adapted_case! {
            record TEST_ENDOMORPHISM_EIGENVALUE {
                id: "curves.g1_glv.test_endomorphism_eigenvalue",
                body_source: ARK_TEMPLATE_GLV,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_endomorphism_eigenvalue",
                execution: UpstreamExecution::Once,
                waiver: "Helios keeps its beta*x endomorphism private. Feed the checksum-pinned Ark lambda into Helios' one-point GLV MSM, whose lambda decomposition selects the endomorphism component, and compare the Helios result with lambda times the Ark generator. The Ark lambda is a configuration input and does not count as coverage; the assertion itself executes Helios."
            }
            fn test_endomorphism_eigenvalue() {
                // PROVENANCE INPUT: this Ark constant does not count as Helios coverage.
                let lambda = <ark_bn254::g1::Config as GLVConfig>::LAMBDA;
                let limbs = lambda.into_bigint().0;
                let computed = crate::msm::msm_variable_time(&[G1Affine::generator()], &[limbs]);
                let oracle = g1_affine_to_helios((ArkG1Projective::generator() * lambda).into_affine());
                assert_eq!(computed.to_affine(), oracle);
            }
        }

        ark_adapted_case! {
            record TEST_GLV_MUL {
                id: "curves.g1_glv.test_glv_mul",
                body_source: ARK_TEMPLATE_GLV,
                instantiated_at: Some(ARK_BN254_CURVE_TESTS),
                upstream_test: "test_glv_mul",
                execution: UpstreamExecution::Iterations(200),
                waiver: "Replace ark_std::test_rng with a fixed StdRng and Ark's separate generic projective/affine GLV helpers with Helios' one-point GLV MSM projective and affine-result facades. Preserve 100 projective plus 100 affine checks (the same 100 scalars), compare both Helios paths with test-side double-and-add over Helios group operations, and add Ark scalar multiplication as an oracle."
            }
            fn test_glv_mul() {
                let mut rng = StdRng::seed_from_u64(0x4731_474c_564d_0002);
                let generator = G1Affine::generator();
                let ark_generator = ArkG1Projective::generator();
                for sample in 0..100 {
                    let scalar = ArkFr::rand(&mut rng);
                    let limbs = scalar.into_bigint().0;
                    let projective = crate::msm::msm_variable_time(&[generator], &[limbs]);
                    let affine = crate::msm::msm_variable_time_affine(&[generator], &[limbs]);
                    let independent =
                        mul_group_words::<G1Projective>(generator.to_curve(), limbs).to_affine();
                    let expected = g1_affine_to_helios((ark_generator * scalar).into_affine());
                    assert_eq!(projective.to_affine(), independent, "sample {sample}");
                    assert_eq!(affine, independent, "sample {sample}");
                    assert_eq!(independent, expected, "Ark sample {sample}");
                }
            }
        }
    }

    pub(in crate::arkworks_bn254_0_5_tests) mod g2_subgroup {
        use super::*;

        fn sample_unchecked(rng: &mut StdRng) -> ArkG2Affine {
            loop {
                let x = ArkFq2::rand(rng);
                let greatest = rng.next_u32() & 1 == 1;
                if let Some(point) = ArkG2Affine::get_point_from_x_unchecked(x, greatest) {
                    return point;
                }
            }
        }

        ark_adapted_case! {
            record TEST_IS_IN_SUBGROUP_ASSUMING_ON_CURVE {
                id: "curves.g2_subgroup.test_is_in_subgroup_assuming_on_curve",
                body_source: ARK_BN254_G2,
                instantiated_at: None,
                upstream_test: "test_is_in_subgroup_assuming_on_curve",
                execution: UpstreamExecution::Iterations(100),
                waiver: "Upstream sample_unchecked creates a fresh deterministic test_rng on every call and therefore repeats one sample 100 times; retain 100 iterations but intentionally use one fixed shared StdRng to cover 100 distinct reproducible samples. Map direct Fq coefficient draws to equivalent Ark Fq2 draws and naive Ark scalar multiplication to Helios multiplication by the scalar-modulus limbs. Compare Helios' optimized subgroup check with both Helios [r]P and Ark. Helios has no G2 clear-cofactor API: Ark supplies that checksum-pinned fixture only, then two Helios subgroup assertions validate it; this does not count as clear-cofactor coverage."
            }
            fn test_is_in_subgroup_assuming_on_curve() {
                let mut rng = StdRng::seed_from_u64(0x4732_5355_4247_0002);
                for sample in 0..100 {
                    let ark_point = sample_unchecked(&mut rng);
                    let point = g2_affine_to_helios(ark_point);
                    assert!(point.is_on_curve(), "sample {sample}");

                    let optimized = point.is_in_correct_subgroup_assuming_on_curve();
                    let naive = point.to_curve().mul_words(&crate::consts::R).is_identity();
                    assert_eq!(optimized, naive, "sample {sample}");
                    assert_eq!(
                        optimized,
                        ark_point.is_in_correct_subgroup_assuming_on_curve()
                    );

                    // FIXTURE ONLY: Ark clears the point; Helios validates the result.
                    let cleared = g2_affine_to_helios(ark_point.clear_cofactor());
                    assert!(cleared.is_in_correct_subgroup_assuming_on_curve());
                    assert!(
                        cleared
                            .to_curve()
                            .mul_words(&crate::consts::R)
                            .is_identity()
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct UpstreamCase {
    id: &'static str,
    source: &'static str,
    status: MigrationStatus,
}

const FIELD_GENERATED: &str = concat!(
    "ark-bn254-0.5.0/src/fields/tests.rs -> ",
    "ark-algebra-test-templates-0.5.0/src/fields.rs"
);
const FIELD_DIRECT: &str = "ark-bn254-0.5.0/src/fields/tests.rs";
const GROUP_GENERATED: &str = concat!(
    "ark-bn254-0.5.0/src/curves/tests.rs -> ",
    "ark-algebra-test-templates-0.5.0/src/{groups,msm}.rs"
);
const PAIRING_GENERATED: &str = concat!(
    "ark-bn254-0.5.0/src/curves/tests.rs -> ",
    "ark-algebra-test-templates-0.5.0/src/pairing.rs"
);
const GLV_GENERATED: &str = concat!(
    "ark-bn254-0.5.0/src/curves/tests.rs -> ",
    "ark-algebra-test-templates-0.5.0/src/{groups,glv}.rs"
);
const G2_DIRECT: &str = "ark-bn254-0.5.0/src/curves/g2.rs";

use MigrationStatus::{Adapted, Covered, Inapplicable, PendingApi};

macro_rules! case {
    ($id:literal, $source:ident, Adapted($migration:path)) => {
        UpstreamCase {
            id: $id,
            source: $source,
            status: Adapted(&$migration),
        }
    };
    ($id:literal, $source:ident, $status:expr) => {
        UpstreamCase {
            id: $id,
            source: $source,
            status: $status,
        }
    };
}

// This literal inventory is intentionally verbose: review must be able to map
// an upstream macro expansion to exactly one decision without running codegen.
static UPSTREAM_CASES: [UpstreamCase; 103] = [
    // fields.fr: 9 common field tests + 4 Montgomery-prime-field tests.
    case!(
        "fields.fr.test_frobenius",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_FROBENIUS)
    ),
    case!(
        "fields.fr.test_serialization",
        FIELD_GENERATED,
        Inapplicable("Ark compress/validate/flags IO is not Helios fixed-array BE/LE encoding")
    ),
    case!(
        "fields.fr.test_add_properties",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_ADD_PROPERTIES)
    ),
    case!(
        "fields.fr.test_sub_properties",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_SUB_PROPERTIES)
    ),
    case!(
        "fields.fr.test_mul_properties",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_MUL_PROPERTIES)
    ),
    case!(
        "fields.fr.test_pow",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_POW)
    ),
    case!(
        "fields.fr.test_sum_of_products_tests",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_SUM_OF_PRODUCTS_TESTS)
    ),
    case!(
        "fields.fr.test_sqrt",
        FIELD_GENERATED,
        PendingApi("Fr exposes no sqrt or Legendre API")
    ),
    case!(
        "fields.fr.test_mul_by_base_field_elem",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_MUL_BY_BASE_FIELD_ELEM)
    ),
    case!(
        "fields.fr.test_fft",
        FIELD_GENERATED,
        PendingApi("no FFT or root-of-unity API")
    ),
    case!(
        "fields.fr.test_sum_of_products_edge_case",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_SUM_OF_PRODUCTS_EDGE_CASE)
    ),
    case!(
        "fields.fr.test_constants",
        FIELD_GENERATED,
        PendingApi(
            "upstream case targets FftField/sqrt configuration constants absent from Helios"
        )
    ),
    case!(
        "fields.fr.test_montgomery_config",
        FIELD_GENERATED,
        Adapted(fields::fr::TEST_MONTGOMERY_CONFIG)
    ),
    // fields.fq.
    case!(
        "fields.fq.test_frobenius",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_FROBENIUS)
    ),
    case!(
        "fields.fq.test_serialization",
        FIELD_GENERATED,
        Inapplicable("Ark canonical serialization modes differ from Agave fixed BE encoding")
    ),
    case!(
        "fields.fq.test_add_properties",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_ADD_PROPERTIES)
    ),
    case!(
        "fields.fq.test_sub_properties",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_SUB_PROPERTIES)
    ),
    case!(
        "fields.fq.test_mul_properties",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_MUL_PROPERTIES)
    ),
    case!(
        "fields.fq.test_pow",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_POW)
    ),
    case!(
        "fields.fq.test_sum_of_products_tests",
        FIELD_GENERATED,
        PendingApi("Fp exposes no sum_of_products API")
    ),
    case!(
        "fields.fq.test_sqrt",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_SQRT)
    ),
    case!(
        "fields.fq.test_mul_by_base_field_elem",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_MUL_BY_BASE_FIELD_ELEM)
    ),
    case!(
        "fields.fq.test_fft",
        FIELD_GENERATED,
        PendingApi("no FFT or root-of-unity API")
    ),
    case!(
        "fields.fq.test_sum_of_products_edge_case",
        FIELD_GENERATED,
        PendingApi("Fp exposes no sum_of_products API")
    ),
    case!(
        "fields.fq.test_constants",
        FIELD_GENERATED,
        PendingApi(
            "upstream case targets FftField/sqrt configuration constants absent from Helios"
        )
    ),
    case!(
        "fields.fq.test_montgomery_config",
        FIELD_GENERATED,
        Adapted(fields::fq::TEST_MONTGOMERY_CONFIG)
    ),
    // fields.fq2.
    case!(
        "fields.fq2.test_frobenius",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_FROBENIUS)
    ),
    case!(
        "fields.fq2.test_serialization",
        FIELD_GENERATED,
        Inapplicable("no canonical extension-field serialization API")
    ),
    case!(
        "fields.fq2.test_add_properties",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_ADD_PROPERTIES)
    ),
    case!(
        "fields.fq2.test_sub_properties",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_SUB_PROPERTIES)
    ),
    case!(
        "fields.fq2.test_mul_properties",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_MUL_PROPERTIES)
    ),
    case!(
        "fields.fq2.test_pow",
        FIELD_GENERATED,
        PendingApi("Fp2 exposes no exponentiation API")
    ),
    case!(
        "fields.fq2.test_sum_of_products_tests",
        FIELD_GENERATED,
        PendingApi("Fp2 exposes no sum_of_products API")
    ),
    case!(
        "fields.fq2.test_sqrt",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_SQRT)
    ),
    case!(
        "fields.fq2.test_mul_by_base_field_elem",
        FIELD_GENERATED,
        Adapted(fields::fq2::TEST_MUL_BY_BASE_FIELD_ELEM)
    ),
    // fields.fq6.
    case!(
        "fields.fq6.test_frobenius",
        FIELD_GENERATED,
        PendingApi("Fp6 exposes no Frobenius API")
    ),
    case!(
        "fields.fq6.test_serialization",
        FIELD_GENERATED,
        Inapplicable("no canonical extension-field serialization API")
    ),
    case!(
        "fields.fq6.test_add_properties",
        FIELD_GENERATED,
        Adapted(fields::fq6::TEST_ADD_PROPERTIES)
    ),
    case!(
        "fields.fq6.test_sub_properties",
        FIELD_GENERATED,
        Adapted(fields::fq6::TEST_SUB_PROPERTIES)
    ),
    case!(
        "fields.fq6.test_mul_properties",
        FIELD_GENERATED,
        Adapted(fields::fq6::TEST_MUL_PROPERTIES)
    ),
    case!(
        "fields.fq6.test_pow",
        FIELD_GENERATED,
        PendingApi("Fp6 exposes no exponentiation API")
    ),
    case!(
        "fields.fq6.test_sum_of_products_tests",
        FIELD_GENERATED,
        PendingApi("Fp6 exposes no sum_of_products API")
    ),
    case!(
        "fields.fq6.test_sqrt",
        FIELD_GENERATED,
        Adapted(fields::fq6::TEST_SQRT)
    ),
    case!(
        "fields.fq6.test_mul_by_base_field_elem",
        FIELD_GENERATED,
        PendingApi("Fp6 exposes no generic base-prime-field multiply API")
    ),
    // fields.fq12.
    case!(
        "fields.fq12.test_frobenius",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_FROBENIUS)
    ),
    case!(
        "fields.fq12.test_serialization",
        FIELD_GENERATED,
        Inapplicable("no canonical extension-field serialization API")
    ),
    case!(
        "fields.fq12.test_add_properties",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_ADD_PROPERTIES)
    ),
    case!(
        "fields.fq12.test_sub_properties",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_SUB_PROPERTIES)
    ),
    case!(
        "fields.fq12.test_mul_properties",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_MUL_PROPERTIES)
    ),
    case!(
        "fields.fq12.test_pow",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_POW)
    ),
    case!(
        "fields.fq12.test_sum_of_products_tests",
        FIELD_GENERATED,
        PendingApi("Fp12 exposes no sum_of_products API")
    ),
    case!(
        "fields.fq12.test_sqrt",
        FIELD_GENERATED,
        Adapted(fields::fq12::TEST_SQRT)
    ),
    case!(
        "fields.fq12.test_mul_by_base_field_elem",
        FIELD_GENERATED,
        PendingApi("Fp12 exposes no generic base-prime-field multiply API")
    ),
    // Direct field tests in ark-bn254 itself.
    case!(
        "fields.direct.test_fq_repr_from",
        FIELD_DIRECT,
        Inapplicable("tests Ark BigInteger256 construction, not Helios curve arithmetic")
    ),
    case!(
        "fields.direct.test_fq_repr_is_odd",
        FIELD_DIRECT,
        Inapplicable("tests an Ark BigInteger256 helper")
    ),
    case!(
        "fields.direct.test_fq_repr_is_zero",
        FIELD_DIRECT,
        Inapplicable("tests an Ark BigInteger256 helper")
    ),
    case!(
        "fields.direct.test_fq_repr_num_bits",
        FIELD_DIRECT,
        Inapplicable("tests Ark BigInteger256 shift and bit-count semantics")
    ),
    case!(
        "fields.direct.test_fq_num_bits",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ_NUM_BITS)
    ),
    case!(
        "fields.direct.test_fq_root_of_unity",
        FIELD_DIRECT,
        PendingApi("no FftField generator or root-of-unity API")
    ),
    case!(
        "fields.direct.test_fq_ordering",
        FIELD_DIRECT,
        PendingApi("Fp intentionally has no Ord contract")
    ),
    case!(
        "fields.direct.test_fq_legendre",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ_LEGENDRE)
    ),
    case!(
        "fields.direct.test_fq2_ordering",
        FIELD_DIRECT,
        PendingApi("Fp2 intentionally has no Ord contract")
    ),
    case!(
        "fields.direct.test_fq2_basics",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ2_BASICS)
    ),
    case!(
        "fields.direct.test_fq2_legendre",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ2_LEGENDRE)
    ),
    case!(
        "fields.direct.test_fq6_mul_by_1",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ6_MUL_BY_1)
    ),
    case!(
        "fields.direct.test_fq6_mul_by_01",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ6_MUL_BY_01)
    ),
    case!(
        "fields.direct.test_fq12_mul_by_014",
        FIELD_DIRECT,
        Inapplicable("M-twist sparse helper is absent; Helios uses D-twist mul_by_034")
    ),
    case!(
        "fields.direct.test_fq12_mul_by_034",
        FIELD_DIRECT,
        Adapted(fields::TEST_FQ12_MUL_BY_034)
    ),
    // G1 generated group, MSM, curve, and short-Weierstrass cases.
    case!(
        "curves.g1.test_add_properties",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_ADD_PROPERTIES)
    ),
    case!(
        "curves.g1.test_sub_properties",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_SUB_PROPERTIES)
    ),
    case!(
        "curves.g1.test_mul_properties",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_MUL_PROPERTIES)
    ),
    case!(
        "curves.g1.test_serialization",
        GROUP_GENERATED,
        Inapplicable("Ark curve flags format differs from fixed alt_bn128 encoding")
    ),
    case!(
        "curves.g1.test_var_base_msm",
        GROUP_GENERATED,
        Covered(
            "src/msm.rs::tests::msm_matches_independent_scalar_multiplication + tests/ark_differential.rs::g1_msm_matches_arkworks_across_window_boundaries"
        )
    ),
    case!(
        "curves.g1.test_chunked_pippenger",
        GROUP_GENERATED,
        Inapplicable("no streaming ChunkedPippenger algorithm class")
    ),
    case!(
        "curves.g1.test_hashmap_pippenger",
        GROUP_GENERATED,
        Inapplicable("no HashMapPippenger algorithm class")
    ),
    case!(
        "curves.g1.test_affine_conversion",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_AFFINE_CONVERSION)
    ),
    case!(
        "curves.g1.test_cofactor_ops",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_COFACTOR_OPS)
    ),
    case!(
        "curves.g1.test_mixed_addition",
        GROUP_GENERATED,
        Adapted(curves::g1::TEST_MIXED_ADDITION)
    ),
    case!(
        "curves.g1.test_sw_properties",
        GROUP_GENERATED,
        PendingApi(
            "partial generator/order coverage lacks randomized config-helper claims; flags are unsupported"
        )
    ),
    // G2 generated cases.
    case!(
        "curves.g2.test_add_properties",
        GROUP_GENERATED,
        Adapted(curves::g2::TEST_ADD_PROPERTIES)
    ),
    case!(
        "curves.g2.test_sub_properties",
        GROUP_GENERATED,
        Adapted(curves::g2::TEST_SUB_PROPERTIES)
    ),
    case!(
        "curves.g2.test_mul_properties",
        GROUP_GENERATED,
        Adapted(curves::g2::TEST_MUL_PROPERTIES)
    ),
    case!(
        "curves.g2.test_serialization",
        GROUP_GENERATED,
        Inapplicable("Ark curve flags format differs from fixed Agave encoding")
    ),
    case!(
        "curves.g2.test_var_base_msm",
        GROUP_GENERATED,
        PendingApi("Helios exposes no G2 MSM")
    ),
    case!(
        "curves.g2.test_chunked_pippenger",
        GROUP_GENERATED,
        Inapplicable("no G2 MSM or streaming Pippenger class")
    ),
    case!(
        "curves.g2.test_hashmap_pippenger",
        GROUP_GENERATED,
        Inapplicable("no G2 MSM or HashMapPippenger class")
    ),
    case!(
        "curves.g2.test_affine_conversion",
        GROUP_GENERATED,
        Adapted(curves::g2::TEST_AFFINE_CONVERSION)
    ),
    case!(
        "curves.g2.test_cofactor_ops",
        GROUP_GENERATED,
        PendingApi("no cofactor-clear/multiply/inverse API")
    ),
    case!(
        "curves.g2.test_mixed_addition",
        GROUP_GENERATED,
        Adapted(curves::g2::TEST_MIXED_ADDITION)
    ),
    case!(
        "curves.g2.test_sw_properties",
        GROUP_GENERATED,
        PendingApi(
            "partial fixed generator/subgroup coverage lacks randomized config claims; flags unsupported"
        )
    ),
    // Pairing-output MSM cases.
    case!(
        "curves.pairing_output.test_var_base_msm",
        GROUP_GENERATED,
        PendingApi("no GT/PairingOutput MSM surface")
    ),
    case!(
        "curves.pairing_output.test_chunked_pippenger",
        GROUP_GENERATED,
        Inapplicable("no GT streaming Pippenger surface")
    ),
    case!(
        "curves.pairing_output.test_hashmap_pippenger",
        GROUP_GENERATED,
        Inapplicable("no GT HashMapPippenger surface")
    ),
    // Pairing properties.
    case!(
        "curves.pairing.test_bilinearity",
        PAIRING_GENERATED,
        Adapted(curves::pairing::TEST_BILINEARITY)
    ),
    case!(
        "curves.pairing.test_multi_pairing",
        PAIRING_GENERATED,
        Adapted(curves::pairing::TEST_MULTI_PAIRING)
    ),
    case!(
        "curves.pairing.test_final_exp",
        PAIRING_GENERATED,
        Adapted(curves::pairing::TEST_FINAL_EXP)
    ),
    // G1 and G2 GLV cases.
    case!(
        "curves.g1_glv.test_scalar_decomposition",
        GLV_GENERATED,
        Adapted(curves::g1_glv::TEST_SCALAR_DECOMPOSITION)
    ),
    case!(
        "curves.g1_glv.test_endomorphism_eigenvalue",
        GLV_GENERATED,
        Adapted(curves::g1_glv::TEST_ENDOMORPHISM_EIGENVALUE)
    ),
    case!(
        "curves.g1_glv.test_glv_mul",
        GLV_GENERATED,
        Adapted(curves::g1_glv::TEST_GLV_MUL)
    ),
    case!(
        "curves.g2_glv.test_scalar_decomposition",
        GLV_GENERATED,
        PendingApi("Helios has no G2 GLV implementation or configuration")
    ),
    case!(
        "curves.g2_glv.test_endomorphism_eigenvalue",
        GLV_GENERATED,
        PendingApi("Helios has no G2 GLV implementation or configuration")
    ),
    case!(
        "curves.g2_glv.test_glv_mul",
        GLV_GENERATED,
        PendingApi("G2 scalar multiplication uses WNAF rather than GLV")
    ),
    // Inline optimized subgroup test.
    case!(
        "curves.g2_subgroup.test_is_in_subgroup_assuming_on_curve",
        G2_DIRECT,
        Adapted(curves::g2_subgroup::TEST_IS_IN_SUBGROUP_ASSUMING_ON_CURVE)
    ),
];

#[test]
fn upstream_manifest_is_complete_and_unique() {
    fn assert_hex(value: &str, len: usize, context: &str) {
        assert_eq!(value.len(), len, "{context} has the wrong length");
        assert!(
            value.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{context} is not hexadecimal"
        );
    }

    fn validate_source_pin(source: SourcePin, case_id: &str) {
        assert!(
            !source.package.is_empty(),
            "{case_id} has no source package"
        );
        assert!(
            !source.version.is_empty(),
            "{case_id} has no source version"
        );
        assert!(!source.path.is_empty(), "{case_id} has no source path");
        assert_hex(source.crate_sha256, 64, "crate SHA-256");
        assert_hex(source.file_sha256, 64, "file SHA-256");
        assert_hex(source.vcs_revision, 40, "VCS revision");
    }

    fn validate_executable(case: &UpstreamCase, executable: ExecutableMigration) {
        assert_eq!(executable.id, case.id, "manifest/executable ID drift");
        assert!(
            !executable.test_symbol.is_empty(),
            "{} has no linked test symbol",
            case.id
        );
        // Merely binding this value is the compile-time link: a stale or
        // renamed function cannot leave a string-only green manifest behind.
        let _linked_test: fn() = executable.test_fn;
        assert!(
            !executable.upstream_test.is_empty(),
            "{} has no upstream test identity",
            case.id
        );
        assert_eq!(
            executable.test_symbol.rsplit("::").next(),
            executable.upstream_test.rsplit("::").next(),
            "{} renamed its executable without matching upstream identity",
            case.id
        );
        validate_source_pin(executable.body_source, case.id);
        if let Some(driver) = executable.instantiated_at {
            validate_source_pin(driver, case.id);
        }
        match executable.execution {
            UpstreamExecution::Once => {}
            UpstreamExecution::Iterations(iterations) => {
                assert!(iterations > 0, "{} has zero iterations", case.id);
            }
            UpstreamExecution::Inert {
                configured_iterations,
                condition,
            } => {
                assert!(
                    configured_iterations > 0,
                    "{} lost its configured iteration metadata",
                    case.id
                );
                assert!(
                    !condition.is_empty(),
                    "{} has no inert-branch condition",
                    case.id
                );
            }
        }
    }

    fn executable(status: MigrationStatus) -> Option<ExecutableMigration> {
        match status {
            Adapted(migration) => Some(migration.executable),
            Covered(_) | PendingApi(_) | Inapplicable(_) => None,
        }
    }

    assert_eq!(UPSTREAM_CASES.len(), 103);
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| case.id.starts_with("fields."))
            .count(),
        68
    );
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| case.id.starts_with("curves."))
            .count(),
        35
    );

    for (index, case) in UPSTREAM_CASES.iter().enumerate() {
        assert!(!case.id.is_empty(), "case {index} has an empty ID");
        assert!(!case.source.is_empty(), "{} has no source", case.id);
        assert!(
            !UPSTREAM_CASES[..index]
                .iter()
                .any(|previous| previous.id == case.id),
            "duplicate upstream case ID: {}",
            case.id
        );
        match case.status {
            Adapted(migration) => {
                validate_executable(case, migration.executable);
                assert!(
                    !migration.waiver.is_empty(),
                    "{} has an empty waiver",
                    case.id
                );
            }
            Covered(path) => assert!(!path.is_empty(), "{} has an empty coverage path", case.id),
            PendingApi(issue) => {
                assert!(
                    !issue.is_empty(),
                    "{} has an empty pending-API issue",
                    case.id
                )
            }
            Inapplicable(reason) => assert!(
                !reason.is_empty(),
                "{} has an empty inapplicable reason",
                case.id
            ),
        }

        if let Some(current) = executable(case.status) {
            assert!(
                !UPSTREAM_CASES[..index].iter().any(|previous| {
                    executable(previous.status)
                        .is_some_and(|candidate| candidate.test_symbol == current.test_symbol)
                }),
                "duplicate executable test symbol: {}",
                current.test_symbol
            );
        }
    }

    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| case.source == FIELD_GENERATED)
            .filter(|case| matches!(case.status, Adapted(_)))
            .count(),
        33,
        "generated-field proof ledger drifted"
    );
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| case.source == FIELD_GENERATED)
            .filter(|case| {
                matches!(
                    case.status,
                    Adapted(migration)
                        if matches!(
                            migration.executable.execution,
                            UpstreamExecution::Inert { .. }
                        )
                )
            })
            .count(),
        3,
        "Fq2/Fq6/Fq12 sqrt branches must remain visibly inert"
    );
    for (source, expected, label) in [
        (FIELD_DIRECT, 7, "direct-field"),
        (GROUP_GENERATED, 11, "generated-group"),
        (PAIRING_GENERATED, 3, "pairing"),
        (GLV_GENERATED, 3, "G1 GLV"),
        (G2_DIRECT, 1, "direct G2"),
    ] {
        assert_eq!(
            UPSTREAM_CASES
                .iter()
                .filter(|case| case.source == source)
                .filter(|case| matches!(case.status, Adapted(_)))
                .count(),
            expected,
            "{label} proof ledger drifted"
        );
    }
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| matches!(case.status, Adapted(_)))
            .count(),
        58,
        "update the adapted count deliberately when migrating another case"
    );
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| matches!(case.status, Covered(_)))
            .count(),
        1
    );
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| matches!(case.status, PendingApi(_)))
            .count(),
        26
    );
    assert_eq!(
        UPSTREAM_CASES
            .iter()
            .filter(|case| matches!(case.status, Inapplicable(_)))
            .count(),
        18
    );
}
