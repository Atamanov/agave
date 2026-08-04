//! G2 x-psi subgroup checks for the BN254 twist.
//!
//! The batch path shares one normalization across all wNAF tables. The
//! identity is valid on the full twist, including points outside the subgroup.

use {
    crate::validation::AltBn128BatchError,
    ark_bn254::{Fq2, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{AdditiveGroup, Field, MontFp},
    core::ops::{Add, MulAssign, Sub},
};

// These arkworks BN254 constants implement the untwist-Frobenius-twist map.
const P_POWER_ENDOMORPHISM_COEFF_0: Fq2 = Fq2::new(
    MontFp!("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
    MontFp!("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
);
const P_POWER_ENDOMORPHISM_COEFF_1: Fq2 = Fq2::new(
    MontFp!("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
    MontFp!("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
);

/// The positive BN254 parameter from `ark_bn254::Config::X`.
#[cfg(test)]
const X: u64 = 4_965_661_367_192_848_881;

/// Width-four wNAF digits for [`X`], in least-significant-first order.
const X_WNAF: [i8; 65] = [
    1, 0, 0, 0, -1, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 7, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1,
    0, 0, 0, -3, 0, 0, 0, -5, 0, 0, 0, 5, 0, 0, 0, 0, 3, 0, 0, 0, -3, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0,
    1, 0, 0,
];
const X_WNAF_TOP: usize = 62;

/// Return one subgroup-membership result per non-infinity input point.
pub(crate) fn is_in_subgroup_x_psi_batch(
    points: &[G2Affine],
) -> Result<Vec<bool>, AltBn128BatchError> {
    let capacity = 3usize
        .checked_mul(points.len())
        .ok_or(AltBn128BatchError::CapExceeded)?;
    let mut odd = Vec::with_capacity(capacity);
    for point in points {
        odd.extend_from_slice(&odd_multiples(point));
    }
    let odd = G2Projective::normalize_batch(&odd);
    let mut multiples = odd.chunks_exact(3);
    let mut results = Vec::with_capacity(points.len());
    for (point, odd_multiples) in points.iter().zip(&mut multiples) {
        let [p3, p5, p7] = odd_multiples else {
            return Err(AltBn128BatchError::BackendInvariant);
        };
        let table = [*point, *p3, *p5, *p7];
        results.push(psi_identity_holds(point, x_ladder(&table)?)?);
    }
    if !multiples.remainder().is_empty() || results.len() != points.len() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    Ok(results)
}

/// Apply the BN254 twist Frobenius endomorphism.
fn p_power_endomorphism(point: &G2Affine) -> G2Affine {
    let mut result = *point;
    result.x.frobenius_map_in_place(1);
    result.y.frobenius_map_in_place(1);
    result.x.mul_assign(P_POWER_ENDOMORPHISM_COEFF_0);
    result.y.mul_assign(P_POWER_ENDOMORPHISM_COEFF_1);
    result
}

/// Build the nontrivial odd multiples for a width-four wNAF table.
fn odd_multiples(point: &G2Affine) -> [G2Projective; 3] {
    let two_p = point.into_group().double();
    let p3 = two_p.add(*point);
    let p5 = p3.add(two_p);
    let p7 = p5.add(two_p);
    [p3, p5, p7]
}

/// Compute `[x]P` from one normalized odd-multiple table.
fn x_ladder(table: &[G2Affine; 4]) -> Result<G2Projective, AltBn128BatchError> {
    let top_digit = X_WNAF
        .get(X_WNAF_TOP)
        .copied()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let top_index = usize::from(top_digit.unsigned_abs() / 2);
    let mut accumulator = table
        .get(top_index)
        .ok_or(AltBn128BatchError::BackendInvariant)?
        .into_group();

    for digit in X_WNAF.iter().take(X_WNAF_TOP).rev().copied() {
        accumulator.double_in_place();
        if digit == 0 {
            continue;
        }
        let index = usize::from(digit.unsigned_abs() / 2);
        let point = table
            .get(index)
            .ok_or(AltBn128BatchError::BackendInvariant)?;
        accumulator = if digit > 0 {
            accumulator.add(point)
        } else {
            accumulator.sub(point)
        };
    }
    Ok(accumulator)
}

/// Check Scott's identity for `Q = [x]P`.
fn psi_identity_holds(point: &G2Affine, mut q: G2Projective) -> Result<bool, AltBn128BatchError> {
    let normalized = G2Projective::normalize_batch(&[q, q.double()]);
    let [q_affine, two_q_affine] = normalized.as_slice() else {
        return Err(AltBn128BatchError::BackendInvariant);
    };
    let psi_q = p_power_endomorphism(q_affine);
    let psi2_q = p_power_endomorphism(&psi_q);
    let rhs = p_power_endomorphism(&p_power_endomorphism(&p_power_endomorphism(two_q_affine)));
    q = q.add(*point).add(psi_q).add(psi2_q);
    Ok(q == rhs)
}

#[cfg(test)]
fn is_in_subgroup_x_psi(point: &G2Affine) -> Result<bool, AltBn128BatchError> {
    let normalized = G2Projective::normalize_batch(&odd_multiples(point));
    let [p3, p5, p7] = normalized.as_slice() else {
        return Err(AltBn128BatchError::BackendInvariant);
    };
    let table = [*point, *p3, *p5, *p7];
    psi_identity_holds(point, x_ladder(&table)?)
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
        core::ops::{Add, Mul, Neg},
    };

    fn fq_modulus_minus_one_div(divisor: u64) -> [u64; 4] {
        let mut numerator = Fq::MODULUS;
        assert!(!numerator.sub_with_borrow(&BigInt::one()));
        let mut output = [0u64; 4];
        let mut remainder = 0u128;
        for (limb, quotient) in numerator.0.iter().rev().zip(output.iter_mut().rev()) {
            let current = (remainder << 64) | u128::from(*limb);
            *quotient = u64::try_from(current.checked_div(u128::from(divisor)).unwrap()).unwrap();
            remainder = current.checked_rem(u128::from(divisor)).unwrap();
        }
        assert_eq!(remainder, 0, "p - 1 must divide by {divisor}");
        output
    }

    #[test]
    fn psi_coefficients_match_arkworks_derivation() {
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
    fn psi_matches_frobenius_on_the_subgroup() {
        let mut rng = rng();
        for _ in 0..16 {
            let point = random_g2(&mut rng);
            assert_eq!(
                p_power_endomorphism(&point),
                point.mul_bigint(Fq::MODULUS).into_affine()
            );
        }
        let point = non_subgroup_g2();
        let doubled = point.add(point).into_affine();
        assert_eq!(
            p_power_endomorphism(&point.add(doubled).into_affine()),
            p_power_endomorphism(&point)
                .add(p_power_endomorphism(&doubled))
                .into_affine()
        );
        assert_eq!(
            p_power_endomorphism(&point.neg()),
            p_power_endomorphism(&point).neg()
        );
    }

    #[test]
    fn x_and_short_vector_match_arkworks() {
        assert_eq!(Config::X, &[X]);
        const { assert!(!Config::X_IS_NEGATIVE) };

        let six_x_squared = 6u128
            .checked_mul(u128::from(X))
            .and_then(|value| value.checked_mul(u128::from(X)))
            .unwrap();
        let mut modulus = Fr::MODULUS;
        assert!(!modulus.add_with_carry(&BigInt::new([
            six_x_squared as u64,
            (six_x_squared >> 64) as u64,
            0,
            0,
        ])));
        assert_eq!(modulus, Fq::MODULUS);

        let x = Fr::from(X);
        let lambda = Fr::from(6u64).mul(x).mul(x);
        let lhs = x
            .add(Fr::from(1u64))
            .add(x.mul(lambda))
            .add(x.mul(lambda).mul(lambda));
        let rhs = Fr::from(2u64).mul(x).mul(lambda).mul(lambda).mul(lambda);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn wnaf_digits_reconstruct_x() {
        assert!(X_WNAF.get(X_WNAF_TOP).copied().unwrap() > 0);
        let mut reconstructed = 0i128;
        for (index, digit) in X_WNAF.iter().enumerate().rev() {
            if index > X_WNAF_TOP {
                assert_eq!(*digit, 0);
            }
            reconstructed = reconstructed
                .checked_mul(2)
                .and_then(|value| value.checked_add(i128::from(*digit)))
                .unwrap();
        }
        assert_eq!(reconstructed, i128::from(X));
        assert!(
            X_WNAF
                .iter()
                .all(|digit| *digit == 0 || (digit % 2 != 0 && digit.abs() <= 7))
        );
    }

    fn sample_on_curve(rng: &mut StdRng) -> G2Affine {
        loop {
            let x = Fq2::new(Fq::rand(rng), Fq::rand(rng));
            if let Some(point) = G2Affine::get_point_from_x_unchecked(x, rng.r#gen()) {
                return point;
            }
        }
    }

    #[test]
    fn subgroup_check_matches_arkworks_across_eigenspaces() {
        let mut rng = rng();
        let mut rejected = 0usize;
        let mut cofactor_order = 0usize;
        for _ in 0..48 {
            let point = sample_on_curve(&mut rng);
            let library = point.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(is_in_subgroup_x_psi(&point).unwrap(), library);
            rejected = rejected.checked_add(usize::from(!library)).unwrap();

            let cleared = point.clear_cofactor();
            assert!(is_in_subgroup_x_psi(&cleared).unwrap());
            let torsion = point.mul_bigint(Fr::MODULUS).into_affine();
            if !torsion.is_zero() {
                assert!(!is_in_subgroup_x_psi(&torsion).unwrap());
                assert!(!torsion.is_in_correct_subgroup_assuming_on_curve());
                cofactor_order = cofactor_order.checked_add(1).unwrap();
            }
        }
        assert!(rejected > 0);
        assert!(cofactor_order > 0);
        let reject = non_subgroup_g2();
        assert!(!is_in_subgroup_x_psi(&reject).unwrap());
        assert!(!is_in_subgroup_x_psi(&reject.neg()).unwrap());
        assert!(is_in_subgroup_x_psi(&random_g2(&mut rng)).unwrap());
    }

    #[test]
    fn batch_results_match_single_checks() {
        let mut rng = rng();
        let mut pool = Vec::new();
        while pool.len() < 24 {
            let point = sample_on_curve(&mut rng);
            pool.push(point.clear_cofactor());
            pool.push(point);
            let torsion = point.mul_bigint(Fr::MODULUS).into_affine();
            if !torsion.is_zero() {
                pool.push(torsion);
            }
        }
        assert_eq!(is_in_subgroup_x_psi_batch(&[]).unwrap(), Vec::new());
        for round in 0usize..8 {
            for len in [1usize, 2, 3, 7, 8, 9, 53] {
                let offset = round.checked_mul(13).unwrap();
                let points: Vec<_> = pool
                    .iter()
                    .cycle()
                    .skip(offset)
                    .step_by(7)
                    .take(len)
                    .copied()
                    .collect();
                let expected: Vec<_> = points
                    .iter()
                    .map(|point| is_in_subgroup_x_psi(point).unwrap())
                    .collect();
                assert_eq!(is_in_subgroup_x_psi_batch(&points).unwrap(), expected);
            }
        }
    }
}
