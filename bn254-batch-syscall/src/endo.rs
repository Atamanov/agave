//! G2 twist endomorphism psi and the x-psi subgroup membership check.
//!
//! psi is the untwist-Frobenius-twist endomorphism on E'(Fq2), rebuilt from
//! public field ops: (x, y) -> (x^p * (u+9)^((p-1)/3), y^p * (u+9)^((p-1)/2)).
//! The coefficient constants mirror arkworks' private `p_power_endomorphism`
//! (ark-bn254 0.5.0 src/curves/g2.rs) and a provenance test re-derives them
//! from the public nonresidue, alongside psi's defining eigenvalue psi(P) =
//! [p]P on the subgroup.
//!
//! Membership uses Scott's BN-curve endomorphism test (equivalence to
//! [r]-torsion membership via the endomorphism identity): with Q = [x]P
//! walked by a w = 4 wNAF ladder (63
//! doubles, ~13 digit adds), accept iff (Q + P) + psi(Q) + psi^2(Q) ==
//! psi^3([2]Q). The identity is evaluated with actual psi applications, valid
//! on the whole twist curve; scalars are never folded through the psi
//! eigenvalue, which only exists inside the subgroup being tested. Agreement
//! with `is_in_correct_subgroup_assuming_on_curve` across subgroup, on-curve
//! non-subgroup, and pure cofactor-order points is unit-checked.
//!
//! The batch variant amortizes the ladder-table normalization: one shared
//! inversion for the whole call instead of one per point (measured -7.5% of
//! the subgroup phase at n = 53; the K-interleaved-accumulator challenger
//! lost its sweep and is not ported).

use {
    ark_bn254::{Fq2, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{AdditiveGroup, Field, MontFp},
};

// PSI_X = (u+9)^((p-1)/3), arkworks' TWIST_MUL_BY_Q_X (copied verbatim from
// ark-bn254 0.5.0, never invented locally; pinned by the provenance tests)
const P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
    MontFp!("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
    MontFp!("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
);

// PSI_Y = (u+9)^((p-1)/2), arkworks' TWIST_MUL_BY_Q_Y
const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    MontFp!("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
    MontFp!("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
);

/// BN parameter x (ark_bn254 Config::X): p = 36x^4 + 36x^3 + 24x^2 + 6x + 1
/// and p - r = 6x^2.
const X: u64 = 4965661367192848881;

/// Digit-array capacity for the wNAF of X (63 bits plus window slack).
const WNAF_MAX: usize = 65;

/// wNAF digits (w = 4, digits zero or odd in [-7, 7]) of X, least
/// significant first, plus the index of the top (always positive) nonzero
/// digit. Integer preprocessing of a fixed public constant; reconstruction,
/// digit oddness and the digit bound are unit-checked.
const fn x_wnaf() -> ([i8; WNAF_MAX], usize) {
    let mut k = X as u128;
    let mut digits = [0i8; WNAF_MAX];
    let mut i = 0;
    let mut top = 0;
    while k > 0 {
        if k & 1 == 1 {
            let m = (k & 15) as i8;
            let d = if m > 8 { m - 16 } else { m };
            if d >= 0 {
                k -= d as u128;
            } else {
                k += (-d) as u128;
            }
            digits[i] = d;
            top = i;
        }
        k >>= 1;
        i += 1;
    }
    (digits, top)
}

const WNAF: ([i8; WNAF_MAX], usize) = x_wnaf();

/// psi(P) on E'(Fq2): copy of the private ark-bn254 0.5.0
/// `p_power_endomorphism` body over public field ops.
pub(crate) fn p_power_endomorphism(p: &G2Affine) -> G2Affine {
    let mut res = *p;
    res.x.frobenius_map_in_place(1);
    res.y.frobenius_map_in_place(1);
    res.x *= P_POWER_ENDOMORPHISM_COEFF_0;
    res.y *= P_POWER_ENDOMORPHISM_COEFF_1;
    res
}

/// Odd multiples {3, 5, 7}P via one double + adds, left projective so the
/// caller picks the normalization granularity. No intermediate can be
/// infinity for a non-infinity P: on the r-order subgroup because r is
/// prime, and outside it because jP = 0 for odd j <= 7 would force P into
/// the small-torsion subgroup, which meets the twist only at infinity.
fn odd_multiples(point: &G2Affine) -> [G2Projective; 3] {
    let two_p = point.into_group().double();
    let p3 = two_p + *point;
    let p5 = p3 + two_p;
    let p7 = p5 + two_p;
    [p3, p5, p7]
}

/// Q = [x]P by the shared wNAF digits of X; odd digit d maps to
/// table[d / 2], the top digit seeds the accumulator, every add is mixed
/// (affine table) and negation is free.
fn x_ladder(table: &[G2Affine; 4]) -> G2Projective {
    let (digits, top) = WNAF;
    let mut acc = table[(digits[top] / 2) as usize].into_group();
    for i in (0..top).rev() {
        acc.double_in_place();
        let d = digits[i];
        if d > 0 {
            acc += table[(d / 2) as usize];
        } else if d < 0 {
            acc -= table[(-d / 2) as usize];
        }
    }
    acc
}

/// Scott's identity over Q = [x]P: accept iff
/// (Q + P) + psi(Q) + psi^2(Q) == psi^3([2]Q). One shared inversion
/// normalizes Q and [2]Q so the affine psi applies iteratively to both
/// sides; the lhs lands as three mixed adds onto the ladder accumulator.
fn psi_identity_holds(point: &G2Affine, mut acc: G2Projective) -> bool {
    let normalized = G2Projective::normalize_batch(&[acc, acc.double()]);
    let psi_q = p_power_endomorphism(&normalized[0]);
    let psi2_q = p_power_endomorphism(&psi_q);
    let rhs = p_power_endomorphism(&p_power_endomorphism(&p_power_endomorphism(&normalized[1])));
    acc += *point;
    acc += psi_q;
    acc += psi2_q;
    acc == rhs
}

/// Single-point x-psi membership check; the reference the batch variant and
/// the provenance tests pin themselves to (production callers go through
/// the batch form). Callers exclude infinity.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn is_in_subgroup_x_psi(point: &G2Affine) -> bool {
    let normalized = G2Projective::normalize_batch(&odd_multiples(point));
    let table = [*point, normalized[0], normalized[1], normalized[2]];
    psi_identity_holds(point, x_ladder(&table))
}

/// Per-point membership bits with the {3, 5, 7}P tables of ALL points
/// sharing one `normalize_batch` inversion; walks and psi
/// identities then run in input order, op for op the single-point check, so
/// batch inversion being exact re-associated field math makes every bit
/// identical (pointwise agreement is unit-checked). Callers exclude
/// infinity entries.
pub(crate) fn is_in_subgroup_x_psi_batch(points: &[G2Affine]) -> Vec<bool> {
    let mut odd = Vec::with_capacity(3 * points.len());
    for point in points {
        odd.extend_from_slice(&odd_multiples(point));
    }
    let odd = G2Projective::normalize_batch(&odd);
    points
        .iter()
        .enumerate()
        .map(|(i, point)| {
            let table = [*point, odd[3 * i], odd[3 * i + 1], odd[3 * i + 2]];
            psi_identity_holds(point, x_ladder(&table))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{non_subgroup_g2, random_g2, rng},
        ark_bn254::{Config, Fq, Fq6Config, Fr},
        ark_ec::bn::BnConfig,
        ark_ff::{BigInt, BigInteger, PrimeField, UniformRand},
        ark_std::rand::{Rng, rngs::StdRng},
    };

    /// (p - 1) / d as little-endian limbs, by top-down long division; the
    /// oracle for re-deriving the psi coefficient exponents.
    fn fq_modulus_minus_one_div(d: u64) -> [u64; 4] {
        let mut n = Fq::MODULUS;
        assert!(!n.sub_with_borrow(&BigInt::one()));
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | n.0[i] as u128;
            out[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        assert_eq!(rem, 0, "p - 1 must divide by {d}");
        out
    }

    #[test]
    fn test_psi_coefficients_match_derivation() {
        // the Fq6 nonresidue IS u+9; both psi coefficients are its public
        // powers, so the copied constants cannot drift from the library
        let nonresidue: Fq2 = <Fq6Config as ark_ff::fields::fp6_3over2::Fp6Config>::NONRESIDUE;
        assert_eq!(
            nonresidue.pow(fq_modulus_minus_one_div(3)),
            P_POWER_ENDOMORPHISM_COEFF_0
        );
        assert_eq!(
            nonresidue.pow(fq_modulus_minus_one_div(2)),
            P_POWER_ENDOMORPHISM_COEFF_1
        );
    }

    #[test]
    fn test_psi_is_frobenius_eigenvalue_p_on_subgroup() {
        // the defining property: on the r-order subgroup psi acts as the
        // q-power Frobenius, i.e. multiplication by p
        let mut rng = rng();
        for _ in 0..16 {
            let p = random_g2(&mut rng);
            assert_eq!(
                p_power_endomorphism(&p),
                p.mul_bigint(Fq::MODULUS).into_affine()
            );
        }
        // and psi is a homomorphism on the whole twist, subgroup or not
        let t = non_subgroup_g2();
        let u = (t + t).into_affine();
        assert_eq!(
            p_power_endomorphism(&(t + u).into_affine()),
            (p_power_endomorphism(&t) + p_power_endomorphism(&u)).into_affine()
        );
        assert_eq!(p_power_endomorphism(&-t), -p_power_endomorphism(&t));
    }

    #[test]
    fn test_x_and_ladder_congruence_match_library() {
        assert_eq!(Config::X, &[X], "BN seed drifted from the library");
        const { assert!(!Config::X_IS_NEGATIVE) };
        // p - r == 6x^2 exactly, as integers
        let six_x_sq = 6u128 * X as u128 * X as u128;
        let mut p = Fr::MODULUS;
        let carry = p.add_with_carry(&BigInt::new([
            six_x_sq as u64,
            (six_x_sq >> 64) as u64,
            0,
            0,
        ]));
        assert!(!carry);
        assert_eq!(p, Fq::MODULUS, "p - r != 6x^2");
        // psi acts on the subgroup as multiplication by l = 6x^2 mod r, and
        // the short vector behind Scott's identity must vanish:
        // (x+1) + x*l + x*l^2 - 2*x*l^3 == 0 mod r
        let x = Fr::from(X);
        let l = Fr::from(6u64) * x * x;
        let lhs = (x + Fr::from(1u64)) + x * l + x * l * l;
        let rhs = Fr::from(2u64) * x * l * l * l;
        assert_eq!(lhs, rhs, "(x+1) + x*l + x*l^2 - 2*x*l^3 != 0 mod r");
    }

    #[test]
    fn test_wnaf_digits_reconstruct_x() {
        let (digits, top) = WNAF;
        assert!(digits[top] > 0, "top wNAF digit must be positive");
        let mut acc: i128 = 0;
        let mut i = WNAF_MAX;
        while i > 0 {
            i -= 1;
            if i > top {
                assert_eq!(digits[i], 0, "digits above top must be zero");
            }
            acc = 2 * acc + digits[i] as i128;
        }
        assert_eq!(acc, X as i128, "wNAF digits must reconstruct X");
        for d in digits {
            assert!(
                d == 0 || (d % 2 != 0 && d.abs() <= 7),
                "digits must be zero or odd in [-7, 7]"
            );
        }
    }

    /// On-curve points sampled from random x WITHOUT cofactor clearing: the
    /// twist cofactor is ~2^254, so these are almost surely non-subgroup.
    fn sample_on_curve(rng: &mut StdRng) -> G2Affine {
        loop {
            let x = Fq2::new(Fq::rand(rng), Fq::rand(rng));
            if let Some(p) = G2Affine::get_point_from_x_unchecked(x, rng.r#gen()) {
                return p;
            }
        }
    }

    #[test]
    fn test_subgroup_check_matches_library_across_eigenspaces() {
        let mut rng = rng();
        let mut rejected = 0;
        let mut cofactor_order = 0;
        for _ in 0..48 {
            let p = sample_on_curve(&mut rng);
            assert!(p.is_on_curve());
            // raw on-curve point, almost surely outside the subgroup
            let library = p.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(is_in_subgroup_x_psi(&p), library);
            rejected += usize::from(!library);
            // cofactor-cleared point, inside the subgroup
            let cleared = p.clear_cofactor();
            assert!(is_in_subgroup_x_psi(&cleared));
            // [r]*P kills the subgroup component leaving a pure
            // cofactor-order point, the eigenspace where an unsound
            // short-vector test would differ
            let rp = p.mul_bigint(Fr::MODULUS).into_affine();
            if !rp.is_zero() {
                assert!(!is_in_subgroup_x_psi(&rp));
                assert!(!rp.is_in_correct_subgroup_assuming_on_curve());
                cofactor_order += 1;
            }
        }
        assert!(rejected > 0, "sampling never left the subgroup");
        assert!(cofactor_order > 0, "no pure cofactor-order point exercised");
        // the deterministic reject vectors the validation tests rely on
        let t = non_subgroup_g2();
        assert!(!is_in_subgroup_x_psi(&t));
        assert!(!is_in_subgroup_x_psi(&-t));
        assert!(is_in_subgroup_x_psi(&random_g2(&mut rng)));
    }

    #[test]
    fn test_batch_matches_single_pointwise() {
        let mut rng = rng();
        // pool mixing subgroup, non-subgroup, and cofactor-order points
        let mut pool = Vec::new();
        while pool.len() < 24 {
            let p = sample_on_curve(&mut rng);
            pool.push(p.clear_cofactor());
            pool.push(p);
            let rp = p.mul_bigint(Fr::MODULUS).into_affine();
            if !rp.is_zero() {
                pool.push(rp);
            }
        }
        assert!(is_in_subgroup_x_psi_batch(&[]).is_empty());
        for round in 0..8 {
            for len in [1usize, 2, 3, 7, 8, 9, 53] {
                let points: Vec<G2Affine> = (0..len)
                    .map(|i| pool[(round * 13 + i * 7) % pool.len()])
                    .collect();
                let expected: Vec<bool> = points.iter().map(is_in_subgroup_x_psi).collect();
                assert_eq!(
                    is_in_subgroup_x_psi_batch(&points),
                    expected,
                    "len = {len}, round = {round}"
                );
            }
        }
    }
}
