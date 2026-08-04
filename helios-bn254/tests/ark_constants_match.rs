//! Pins every compile-time-derived Helios constant to its arkworks 0.5
//! counterpart, either by direct value comparison or by an observable
//! identity through the public API.
//!
//! Direct comparisons (public on both sides): moduli, Montgomery R/R2/INV,
//! BN seed, ATE loop digits, curve coefficients, GLV lattice data, psi
//! coefficients (TWIST_MUL_BY_Q_X/Y).
//!
//! Observational comparisons (Helios side private): Fp12 gamma tables via
//! frobenius_map on random elements, twist b' via the G2 curve equation,
//! GLV beta/lambda action via the endomorphism eigenvalue identity.
//!
//! Helios constants that are pub(crate) only (BETA_MONT, GLV basis,
//! GAMMA1/GAMMA2, TWIST_B, FROB_TWIST_X/Y, PSI_X/Y) are const-asserted
//! in-crate to equal closed-form functions of BN_X and P; here the same
//! closed forms are recomputed through public field types and compared to
//! the ark constants, which pins the private values transitively.

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq2Config as ArkFq2Config, Fq6 as ArkFq6,
    Fq6Config as ArkFq6Config, Fq12 as ArkFq12, FqConfig as ArkFqConfig, Fr as ArkFr,
    FrConfig as ArkFrConfig, G1Affine as ArkG1Affine, G1Projective as ArkG1Projective,
    G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ec::scalar_mul::glv::GLVConfig;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, bn::BnConfig, pairing::Pairing};
use ark_ff::{
    BigInt, BigInteger, Field, Fp2Config, Fp6Config, MontConfig, One, PrimeField, UniformRand, Zero,
};
use helios_bn254::{Fp, Fp2, Fp6, Fp12, Fr, G1Affine, G1Projective, G2Affine, consts, pairing};
use rand::{SeedableRng, rngs::StdRng};
use std::ops::{Mul, Neg};

const SEED: u64 = 0xc057_a75e_ed11;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

// Canonical-limb bridge: ark into_bigint() yields the canonical (non
// Montgomery) little-endian limbs, exactly what Helios from_raw consumes.

fn fp_from_ark(v: ArkFq) -> Fp {
    Fp::from_raw(v.into_bigint().0)
}

fn fp2_from_ark(v: ArkFq2) -> Fp2 {
    Fp2::new(fp_from_ark(v.c0), fp_from_ark(v.c1))
}

fn fp6_from_ark(v: ArkFq6) -> Fp6 {
    Fp6::new(fp2_from_ark(v.c0), fp2_from_ark(v.c1), fp2_from_ark(v.c2))
}

fn fp12_from_ark(v: ArkFq12) -> Fp12 {
    Fp12::new(fp6_from_ark(v.c0), fp6_from_ark(v.c1))
}

fn fr_from_ark(v: ArkFr) -> Fr {
    Fr::from_raw(v.into_bigint().0)
}

fn ark_fr_nonzero(rng: &mut StdRng) -> ArkFr {
    loop {
        let value = ArkFr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

fn ark_g1(rng: &mut StdRng) -> ArkG1Affine {
    (ArkG1Projective::generator() * ark_fr_nonzero(rng)).into_affine()
}

fn ark_g2(rng: &mut StdRng) -> ArkG2Affine {
    (ArkG2Projective::generator() * ark_fr_nonzero(rng)).into_affine()
}

fn g1_from_ark(p: ArkG1Affine) -> G1Affine {
    let (x, y) = p.xy().expect("finite point");
    G1Affine {
        x: fp_from_ark(x),
        y: fp_from_ark(y),
        infinity: false,
    }
}

fn g2_from_ark(p: ArkG2Affine) -> G2Affine {
    let (x, y) = p.xy().expect("finite point");
    G2Affine {
        x: fp2_from_ark(x),
        y: fp2_from_ark(y),
        infinity: false,
    }
}

/// Exact x / d over four little-endian limbs; asserts divisibility.
fn div_exact(x: [u64; 4], d: u64) -> [u64; 4] {
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for i in (0..4).rev() {
        let cur = (rem << 64) | u128::from(x[i]);
        q[i] = (cur / u128::from(d)) as u64;
        rem = cur % u128::from(d);
    }
    assert_eq!(rem, 0);
    q
}

/// MSB-first square-and-multiply through the public Fp2 type.
fn fp2_pow(base: Fp2, e: &[u64; 4]) -> Fp2 {
    let mut acc = Fp2::ONE;
    for limb in e.iter().rev() {
        for bit in (0..64).rev() {
            acc = acc.square();
            if (limb >> bit) & 1 == 1 {
                acc *= base;
            }
        }
    }
    acc
}

/// Two-limb value of an ark BigInt known to fit u128.
fn bigint_u128(v: BigInt<4>) -> u128 {
    assert_eq!(v.0[2] | v.0[3], 0, "value exceeds 128 bits");
    (u128::from(v.0[1]) << 64) | u128::from(v.0[0])
}

/// xi = 9 + u built from the public seed constant XI_A.
fn xi() -> Fp2 {
    Fp2::new(Fp::from_u64(consts::XI_A), Fp::ONE)
}

#[test]
fn moduli_match_ark() {
    assert_eq!(consts::P, ArkFq::MODULUS.0, "base field modulus p");
    assert_eq!(consts::R, ArkFr::MODULUS.0, "scalar field modulus r");
}

/// Direct Montgomery-domain comparison: ark's MontConfig exposes
/// R = 2^256 mod m, R2 = 2^512 mod m, and INV = -m^{-1} mod 2^64, the exact
/// counterparts of MONT_ONE / MONT_R2 / P_INV (and the FR_ / R_INV trio).
/// R3 = 2^768 mod m has no ark constant; ark computes it as 2^768 in the
/// field, which pins MONT_R3 / FR_MONT_R3 numerically.
#[test]
fn montgomery_domain_constants_match_ark() {
    assert_eq!(consts::MONT_ONE, <ArkFqConfig as MontConfig<4>>::R.0);
    assert_eq!(consts::MONT_R2, <ArkFqConfig as MontConfig<4>>::R2.0);
    assert_eq!(consts::P_INV, <ArkFqConfig as MontConfig<4>>::INV);
    assert_eq!(consts::FR_MONT_ONE, <ArkFrConfig as MontConfig<4>>::R.0);
    assert_eq!(consts::FR_MONT_R2, <ArkFrConfig as MontConfig<4>>::R2.0);
    assert_eq!(consts::R_INV, <ArkFrConfig as MontConfig<4>>::INV);

    let r3_p = ArkFq::from(2u64).pow([768u64]);
    assert_eq!(consts::MONT_R3, r3_p.into_bigint().0, "2^768 mod p");
    let r3_r = ArkFr::from(2u64).pow([768u64]);
    assert_eq!(consts::FR_MONT_R3, r3_r.into_bigint().0, "2^768 mod r");

    // MONT_ONE is the Montgomery form of 1 as seen by the public Fp type.
    assert_eq!(Fp::from_raw_canonical(consts::MONT_ONE), Fp::ONE);
    assert_eq!(Fp::ONE.to_raw(), [1, 0, 0, 0]);
    assert_eq!(Fr::from_u64(1), Fr::ONE);
    assert_eq!(Fr::ONE.to_raw(), [1, 0, 0, 0]);
}

/// Behavioral pin of MONT_R2 / FR_MONT_R2 and the CIOS reduction constants:
/// from_raw enters the Montgomery domain via R2, to_raw leaves it, and a
/// product exercises P_INV / R_INV. 1000 seeded cases per field.
#[test]
fn montgomery_conversions_match_ark_on_random_values() {
    let mut rng = rng();
    for case in 0..1000 {
        let k: u64 = rand::Rng::r#gen(&mut rng);
        assert_eq!(
            Fp::from_u64(k).to_raw(),
            ArkFq::from(k).into_bigint().0,
            "fp from_u64 case {case}"
        );
        assert_eq!(
            Fr::from_u64(k).to_raw(),
            ArkFr::from(k).into_bigint().0,
            "fr from_u64 case {case}"
        );

        let (a, b) = (ArkFq::rand(&mut rng), ArkFq::rand(&mut rng));
        let limbs = a.into_bigint().0;
        assert_eq!(Fp::from_raw(limbs).to_raw(), limbs, "fp round-trip {case}");
        assert_eq!(
            (fp_from_ark(a) * fp_from_ark(b)).to_raw(),
            (a * b).into_bigint().0,
            "fp product case {case}"
        );

        let (a, b) = (ArkFr::rand(&mut rng), ArkFr::rand(&mut rng));
        let limbs = a.into_bigint().0;
        assert_eq!(Fr::from_raw(limbs).to_raw(), limbs, "fr round-trip {case}");
        assert_eq!(
            (fr_from_ark(a) * fr_from_ark(b)).to_raw(),
            (a * b).into_bigint().0,
            "fr product case {case}"
        );
    }
}

#[test]
fn bn_seed_matches_ark() {
    assert_eq!(<ark_bn254::Config as BnConfig>::X, &[consts::BN_X]);
    const { assert!(!<ark_bn254::Config as BnConfig>::X_IS_NEGATIVE) };
}

/// Digit-for-digit: both tables are LSB-first signed digits of 6x + 2 with
/// the same sign convention (+1 means add, -1 means subtract), verified by
/// reconstructing sum(d_i * 2^i) = 6 * BN_X + 2 from each side.
#[test]
fn ate_loop_count_matches_ark() {
    let ark = <ark_bn254::Config as BnConfig>::ATE_LOOP_COUNT;
    assert_eq!(consts::ATE_LOOP_COUNT.as_slice(), ark);

    let value = |digits: &[i8]| {
        digits
            .iter()
            .enumerate()
            .map(|(bit, &d)| i128::from(d) << bit)
            .sum::<i128>()
    };
    let expected = 6 * i128::from(consts::BN_X) + 2;
    assert_eq!(value(&consts::ATE_LOOP_COUNT), expected);
    assert_eq!(value(ark), expected);
}

/// Structural pin of the tower relations u^2 = -1, v^3 = xi, w^2 = v:
/// multiplication agrees with ark at every level on 200 seeded pairs.
#[test]
fn tower_multiplication_matches_ark() {
    let mut rng = rng();
    for case in 0..200 {
        let (a, b) = (ArkFq2::rand(&mut rng), ArkFq2::rand(&mut rng));
        assert_eq!(
            fp2_from_ark(a) * fp2_from_ark(b),
            fp2_from_ark(a * b),
            "fp2 case {case}"
        );

        let (a, b) = (ArkFq6::rand(&mut rng), ArkFq6::rand(&mut rng));
        assert_eq!(
            fp6_from_ark(a) * fp6_from_ark(b),
            fp6_from_ark(a * b),
            "fp6 case {case}"
        );

        let (a, b) = (ArkFq12::rand(&mut rng), ArkFq12::rand(&mut rng));
        assert_eq!(
            fp12_from_ark(a) * fp12_from_ark(b),
            fp12_from_ark(a * b),
            "fp12 case {case}"
        );
    }
}

/// Observational pin of the private GAMMA1 / GAMMA2 frobenius tables: Helios
/// frobenius_map (p, p^2, p^3) equals ark frobenius_map(1 / 2 / 3) on 200
/// seeded elements. Fp6 exposes no standalone frobenius; its coefficients
/// are the same gamma entries and are covered through Fp12.
#[test]
fn frobenius_matches_ark() {
    let mut rng = rng();
    for case in 0..200 {
        let a = ArkFq2::rand(&mut rng);
        let h = fp2_from_ark(a);
        assert_eq!(
            h.frobenius_map(),
            fp2_from_ark(a.frobenius_map(1)),
            "fp2 p case {case}"
        );
        assert_eq!(
            h.frobenius_map().frobenius_map(),
            fp2_from_ark(a.frobenius_map(2)),
            "fp2 p^2 case {case}"
        );

        let a = ArkFq12::rand(&mut rng);
        let h = fp12_from_ark(a);
        assert_eq!(
            h.frobenius_map(),
            fp12_from_ark(a.frobenius_map(1)),
            "fp12 p case {case}"
        );
        assert_eq!(
            h.frobenius_map_squared(),
            fp12_from_ark(a.frobenius_map(2)),
            "fp12 p^2 case {case}"
        );
        assert_eq!(
            h.frobenius_map_cubed(),
            fp12_from_ark(a.frobenius_map(3)),
            "fp12 p^3 case {case}"
        );
    }
}

/// Non-residues: ark Fq2 NONRESIDUE = -1 (u^2 = -1) and Fq6 NONRESIDUE =
/// 9 + u, matching XI_A. mul_by_nonresidue agrees on 200 seeded elements at
/// both levels (Fp6 nonresidue = multiplication by v in the Fq12 tower).
#[test]
fn nonresidue_constants_match_ark() {
    assert_eq!(<ArkFq2Config as Fp2Config>::NONRESIDUE, -ArkFq::one());
    let ark_xi = <ArkFq6Config as Fp6Config>::NONRESIDUE;
    assert_eq!(ark_xi, ArkFq2::new(ArkFq::from(consts::XI_A), ArkFq::one()));
    assert_eq!(fp2_from_ark(ark_xi), xi());

    let ark_v = ArkFq6::new(ArkFq2::zero(), ArkFq2::one(), ArkFq2::zero());
    let mut rng = rng();
    for case in 0..200 {
        let a = ArkFq2::rand(&mut rng);
        assert_eq!(
            fp2_from_ark(a).mul_by_nonresidue(),
            fp2_from_ark(a * ark_xi),
            "fp2 case {case}"
        );

        let a = ArkFq6::rand(&mut rng);
        assert_eq!(
            fp6_from_ark(a).mul_by_nonresidue(),
            fp6_from_ark(a * ark_v),
            "fp6 case {case}"
        );
    }
}

/// G1: b = 3, a = 0, generator (1, 2). G2 twist b' = 3/xi: Helios keeps
/// TWIST_B private, so recover it through the public curve equation
/// b' = y^2 - x^3 at ark points and compare with ark g2 COEFF_B; the
/// on-curve predicate must also agree on accepted and corrupted points.
#[test]
fn curve_coefficients_match_ark() {
    assert_eq!(ark_bn254::g1::Config::COEFF_A, ArkFq::zero());
    assert_eq!(ark_bn254::g1::Config::COEFF_B, ArkFq::from(consts::G1_B));
    let helios_g1 = G1Affine::generator();
    let ark_g1_gen = g1_from_ark(ArkG1Affine::generator());
    assert_eq!(helios_g1.x, ark_g1_gen.x);
    assert_eq!(helios_g1.y, ark_g1_gen.y);

    assert_eq!(ark_bn254::g2::Config::COEFF_A, ArkFq2::zero());
    let twist_b = fp2_from_ark(ark_bn254::g2::Config::COEFF_B);
    // b' * xi = 3 pins the choice b' = 3/xi rather than 3*xi (M-twist).
    assert_eq!(twist_b * xi(), Fp2::new(Fp::from_u64(3), Fp::ZERO));

    let mut rng = rng();
    for case in 0..20 {
        let q = g2_from_ark(ark_g2(&mut rng));
        assert_eq!(
            q.y.square() - q.x.square() * q.x,
            twist_b,
            "b' from curve equation, case {case}"
        );
        assert!(q.is_on_curve(), "case {case}");

        // Corrupt y: both implementations must reject the same point.
        let bad = G2Affine {
            x: q.x,
            y: q.y + Fp2::ONE,
            infinity: false,
        };
        assert!(!bad.is_on_curve(), "case {case}");
        let ark_bad = ArkG2Affine::new_unchecked(
            ArkFq2::new(
                ArkFq::from_le_bytes_mod_order(&q.x.c0.to_bytes_le()),
                ArkFq::from_le_bytes_mod_order(&q.x.c1.to_bytes_le()),
            ),
            ArkFq2::new(
                ArkFq::from_le_bytes_mod_order(&bad.y.c0.to_bytes_le()),
                ArkFq::from_le_bytes_mod_order(&bad.y.c1.to_bytes_le()),
            ),
        );
        assert!(!ark_bad.is_on_curve(), "case {case}");
    }
}

/// GLV data. Helios keeps BETA_MONT, the lattice basis, and the scalar
/// decomposition private, but const-asserts them in msm.rs to equal closed
/// forms in BN_X. The same closed forms are recomputed here through public
/// field types and compared with ark's GLVConfig:
///   beta   = -(18x^3 + 18x^2 + 9x + 2) mod p  == ENDO_COEFFS[0]
///   lambda = -(36x^3 + 18x^2 + 6x + 2) mod r  == LAMBDA
///   basis  = [[6x^2 + 2x, -(2x + 1)], [2x + 1, 6x^2 + 4x + 1]]
///            == SCALAR_DECOMP_COEFFS rows (sign flag true = negative).
/// The eigenvalue identity (beta * x, y) = [lambda](x, y) is then executed
/// on Helios types with the ark constants, tying the values to behavior.
#[test]
fn glv_constants_match_ark() {
    let x = Fp::from_u64(consts::BN_X);
    let beta = (((Fp::from_u64(18) * x + Fp::from_u64(18)) * x + Fp::from_u64(9)) * x
        + Fp::from_u64(2))
    .neg();
    let ark_endo = <ark_bn254::g1::Config as GLVConfig>::ENDO_COEFFS[0];
    assert_eq!(beta, fp_from_ark(ark_endo));

    let x = Fr::from_u64(consts::BN_X);
    let lambda = (((Fr::from_u64(36) * x + Fr::from_u64(18)) * x + Fr::from_u64(6)) * x
        + Fr::from_u64(2))
    .neg();
    let ark_lambda = <ark_bn254::g1::Config as GLVConfig>::LAMBDA;
    assert_eq!(lambda, fr_from_ark(ark_lambda));

    let x = u128::from(consts::BN_X);
    let decomp = <ark_bn254::g1::Config as GLVConfig>::SCALAR_DECOMP_COEFFS;
    let signs: Vec<bool> = decomp.iter().map(|(neg, _)| *neg).collect();
    // Ark stores (is_negative, magnitude); only the off-diagonal -(2x+1) of
    // row one is negative.
    assert_eq!(signs, [false, true, false, false]);
    assert_eq!(bigint_u128(decomp[0].1), 6 * x * x + 2 * x);
    assert_eq!(bigint_u128(decomp[1].1), 2 * x + 1);
    assert_eq!(bigint_u128(decomp[2].1), 2 * x + 1);
    assert_eq!(bigint_u128(decomp[3].1), 6 * x * x + 4 * x + 1);

    let mut rng = rng();
    for case in 0..20 {
        let p = g1_from_ark(ark_g1(&mut rng));
        let endo = G1Affine {
            x: p.x * beta,
            y: p.y,
            infinity: false,
        };
        assert!(endo.is_on_curve(), "case {case}");
        let expected = G1Projective::from(p).mul(lambda).to_affine();
        assert_eq!(endo.x, expected.x, "case {case}");
        assert_eq!(endo.y, expected.y, "case {case}");
    }
}

/// psi coefficients: ark TWIST_MUL_BY_Q_X / _Y are xi^((p-1)/3) and
/// xi^((p-1)/2), the same values Helios pins privately as FROB_TWIST_X/Y in
/// the Miller loop and PSI_X/Y in the G2 subgroup check (both const-asserted
/// in-crate against GAMMA1[1] and GAMMA1[2]). Recomputed here from public
/// XI_A and P alone. PSI2_X = PSI_X * conj(PSI_X) has no ark constant; the
/// norm identity is asserted on the derived value instead.
#[test]
fn psi_constants_match_ark() {
    let p_minus_1 = {
        let mut limbs = consts::P;
        limbs[0] -= 1; // p is odd, no borrow
        limbs
    };
    let gamma_1_2 = fp2_pow(xi(), &div_exact(p_minus_1, 3));
    let gamma_1_3 = fp2_pow(xi(), &div_exact(p_minus_1, 2));
    assert_eq!(
        gamma_1_2,
        fp2_from_ark(<ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_X)
    );
    assert_eq!(
        gamma_1_3,
        fp2_from_ark(<ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_Y)
    );

    // psi^2 x-scale: gamma_{1,2} * conj(gamma_{1,2}) is a real primitive
    // cube root of unity (the same value g2.rs stores as PSI2_X).
    let psi2_x = gamma_1_2 * gamma_1_2.conjugate();
    assert_eq!(psi2_x.c1, Fp::ZERO);
    let w = psi2_x.c0;
    assert_ne!(w, Fp::ONE);
    assert_eq!(w * w * w, Fp::ONE);
}

/// Big-endian canonical bytes of all 12 Fq coefficients, fixed traversal
/// order, for cross-implementation byte comparison.
fn fp12_bytes(f: &Fp12) -> Vec<u8> {
    [f.c0, f.c1]
        .iter()
        .flat_map(|c6| [c6.c0, c6.c1, c6.c2])
        .flat_map(|c2| [c2.c0, c2.c1])
        .flat_map(|c| c.to_bytes_be())
        .collect()
}

fn ark_fq12_bytes(f: &ArkFq12) -> Vec<u8> {
    [f.c0, f.c1]
        .iter()
        .flat_map(|c6| [c6.c0, c6.c1, c6.c2])
        .flat_map(|c2| [c2.c0, c2.c1])
        .flat_map(|c| {
            let bytes = c.into_bigint().to_bytes_be();
            assert_eq!(bytes.len(), 32);
            bytes
        })
        .collect::<Vec<u8>>()
}

/// End-to-end constants sanity: the full pairing equals ark on 50 seeded
/// random pairs, byte-compared through canonical encodings. This
/// transitively pins every Miller-loop and final-exponentiation constant
/// (ATE digits, line coefficients, gamma tables, hard-part seed powers).
/// ark_differential.rs only checks the boolean product-is-one facade; the
/// GT value comparison here is the constants-focused addition.
#[test]
fn pairing_matches_ark_on_random_pairs() {
    let mut rng = rng();
    for case in 0..50 {
        let p = ark_g1(&mut rng);
        let q = ark_g2(&mut rng);
        let helios = pairing(&g1_from_ark(p), &g2_from_ark(q));
        let ark = Bn254::pairing(p, q).0;
        assert_eq!(fp12_bytes(&helios), ark_fq12_bytes(&ark), "case {case}");
    }

    // Generator pairing, plus identity behavior on both sides.
    let g1 = ArkG1Affine::generator();
    let g2 = ArkG2Affine::generator();
    let helios = pairing(&g1_from_ark(g1), &g2_from_ark(g2));
    assert_eq!(
        fp12_bytes(&helios),
        ark_fq12_bytes(&Bn254::pairing(g1, g2).0)
    );
    assert_eq!(pairing(&G1Affine::identity(), &g2_from_ark(g2)), Fp12::ONE);
    assert!(Bn254::pairing(ArkG1Affine::zero(), g2).0.is_one());
}
