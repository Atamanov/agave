//! Allocation-free GLV scalar decomposition for BN254 G1.
//!
//! The split satisfies `k = k1 + lambda * k2 mod r` with both magnitudes
//! below `2^128`. Provenance tests derive the constants from arkworks.

use {
    super::u256::{add_u128_into, geq_u256, mul_hi_256, mul_u128, sub_u256},
    ark_bn254::Fr,
    ark_ff::PrimeField,
};

// Lattice constants for ark_bn254 g1::Config, read from its GLVConfig impl:
// SCALAR_DECOMP_COEFFS = [(-A1), (+G), (-G), (-A2)] with determinant
// A1*A2 + G^2 == r (asserted against Fr::MODULUS by the tests below).
const A1: u128 = 147946756881789319000765030803803410728;
const A2: u128 = 147946756881789319010696353538189108491;
const G: u64 = 9931322734385697763;
// Barrett constants M1 = floor(A2 * 2^256 / r), M2 = floor(G * 2^256 / r),
// little-endian u64 limbs; derived and asserted by the tests below.
const M1: [u64; 3] = [6023842690951505253, 5534624963584316114, 2];
const M2: [u64; 3] = [15644699364383830999, 2, 0];

/// GLV split k = k1 + LAMBDA*k2 mod r with |k1|, |k2| < 2^128, same
/// ((sign, half), (sign, half)) semantics as the library's
/// `GLVConfig::scalar_decomposition` (sign true = positive; k1 is
/// non-negative by construction).
#[inline]
pub(crate) fn scalar_decomposition(k: &Fr) -> Option<((bool, Fr), (bool, Fr))> {
    let s = k.into_bigint().0;
    let c1 = mul_hi_256(&s, &M1)?;
    let c2 = u64::try_from(mul_hi_256(&s, &M2)?).ok()?;
    // k1 = k - (c1*A1 + c2*G): non-negative and < 2^128, so the high limbs
    // of the subtraction vanish
    let mut b1 = mul_u128(c1, A1)?;
    add_u128_into(&mut b1, u128::from(c2).checked_mul(u128::from(G))?)?;
    let k1l = sub_u256(&s, &b1)?;
    let [k1_lo, k1_hi, k1_top_lo, k1_top_hi] = k1l;
    if k1_top_lo != 0 || k1_top_hi != 0 {
        return None;
    }
    let k1 = u128::from(k1_lo) | (u128::from(k1_hi) << 64);
    // k2 = c1*G - c2*A2, signed with |k2| < 2^128
    let t1 = mul_u128(c1, u128::from(G))?;
    let t2 = mul_u128(A2, u128::from(c2))?;
    let sgn2 = geq_u256(&t1, &t2);
    let k2l = if sgn2 {
        sub_u256(&t1, &t2)?
    } else {
        sub_u256(&t2, &t1)?
    };
    let [k2_lo, k2_hi, k2_top_lo, k2_top_hi] = k2l;
    if k2_top_lo != 0 || k2_top_hi != 0 {
        return None;
    }
    let k2 = u128::from(k2_lo) | (u128::from(k2_hi) << 64);
    Some(((true, Fr::from(k1)), (sgn2, Fr::from(k2))))
}

/// Return the integer form only when the decomposition bound holds.
#[inline]
pub(crate) fn half_to_u128(k: &Fr) -> Option<u128> {
    let limbs = k.into_bigint().0;
    let [lo, hi, top_lo, top_hi] = limbs;
    (top_lo == 0 && top_hi == 0).then_some(u128::from(lo) | (u128::from(hi) << 64))
}

/// Digit-array capacity for [`wnaf_u128`]: the top digit index for k < 2^128
/// stays at most 128, plus the trailing window positions.
pub(crate) const HALF_WNAF_MAX: usize = 130;

/// wNAF digits (w = 4, digits zero or odd in [-7, 7]) of a runtime
/// half-scalar, least significant first, plus the index of the top nonzero
/// digit (0 for k == 0; callers drop zero half-scalars first). The
/// intermediate value can touch 2^128 exactly (k up to 2^128 - 1 plus a
/// digit correction of at most 7), so the overflow bit is carried explicitly
/// and re-entered on the next shift. Reconstruction and the digit bound are
/// unit-checked.
#[inline]
pub(crate) fn wnaf_u128(mut k: u128) -> Option<([i8; HALF_WNAF_MAX], usize)> {
    let mut digits = [0i8; HALF_WNAF_MAX];
    let mut i = 0;
    let mut top = 0;
    let mut hi = false;
    while k > 0 || hi {
        if k & 1 == 1 {
            let m = (k & 15) as i8;
            let d = if m > 8 { m.checked_sub(16)? } else { m };
            if d >= 0 {
                k = k.checked_sub(d as u128)?;
            } else {
                let magnitude = d.checked_neg()? as u128;
                let (next, overflow) = k.overflowing_add(magnitude);
                k = next;
                hi |= overflow;
            }
            *digits.get_mut(i)? = d;
            top = i;
        }
        k >>= 1;
        if hi {
            k |= 1 << 127;
            hi = false;
        }
        i = i.checked_add(1)?;
    }
    Some((digits, top))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::g1::Config as G1Config,
        ark_ec::scalar_mul::glv::GLVConfig,
        ark_ff::{BigInt, UniformRand, Zero},
    };

    /// floor((x << 256) / r) by restoring long division, bit by bit; the
    /// slow-but-obvious oracle for the hardcoded Barrett constants.
    fn barrett(x: u128) -> [u64; 3] {
        let r = Fr::MODULUS.0;
        let mut rem = [0u64; 4];
        let mut q = [0u64; 3];
        for i in (0usize..384).rev() {
            // rem = (rem << 1) | bit_i(x << 256); rem stays < r < 2^254
            let mut carry = i
                .checked_sub(256)
                .map_or(0, |shift| ((x >> shift) & 1) as u64);
            for limb in rem.iter_mut() {
                let t = (*limb >> 63, (*limb << 1) | carry);
                *limb = t.1;
                carry = t.0;
            }
            if geq_u256(&rem, &r) {
                rem = sub_u256(&rem, &r).unwrap();
                let limb = q.get_mut(i.checked_div(64).unwrap()).unwrap();
                *limb |= 1u64 << i.checked_rem(64).unwrap();
            }
        }
        q
    }

    #[test]
    fn test_lattice_constants_match_library() {
        let big = |v: u128| BigInt::new([v as u64, (v >> 64) as u64, 0, 0]);
        let [(s11, n11), (s12, n12), (s21, n21), (s22, n22)] = G1Config::SCALAR_DECOMP_COEFFS;
        assert_eq!((s11, n11), (false, big(A1)));
        assert_eq!((s12, n12), (true, big(G as u128)));
        assert_eq!((s21, n21), (false, big(G as u128)));
        assert_eq!((s22, n22), (false, big(A2)));
        // determinant A1*A2 + G^2 == r
        let mut det = mul_u128(A1, A2).unwrap();
        add_u128_into(&mut det, u128::from(G).checked_mul(u128::from(G)).unwrap()).unwrap();
        assert_eq!(det, Fr::MODULUS.0);
    }

    #[test]
    fn test_barrett_constants_match_derivation() {
        assert_eq!(M1, barrett(A2), "M1 must be floor(A2 * 2^256 / r)");
        assert_eq!(M2, barrett(G as u128), "M2 must be floor(G * 2^256 / r)");
    }

    #[test]
    fn test_decomposition_recomposes_over_seeded_scalars() {
        let mut rng = crate::test_utils::rng();
        let mut cases = vec![
            Fr::zero(),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::from(1u128 << 64),
            Fr::from(BigInt::new([0, 0, 1, 0])), // 2^128
        ];
        for _ in 0..512 {
            cases.push(Fr::rand(&mut rng));
        }
        for k in cases {
            let ((sgn1, k1), (sgn2, k2)) = scalar_decomposition(&k).unwrap();
            let t1 = if sgn1 { k1 } else { -k1 };
            let t2 = if sgn2 { k2 } else { -k2 };
            assert_eq!(t1 + G1Config::LAMBDA * t2, k, "k1 + lambda*k2 != k");
            // both halves must actually be half-width (top two limbs clear)
            // and round-trip through the integer view the walk consumes
            for half in [k1, k2] {
                let [_, _, top_lo, top_hi] = half.into_bigint().0;
                assert_eq!((top_lo, top_hi), (0, 0), "half exceeds 128 bits");
                assert_eq!(Fr::from(half_to_u128(&half).unwrap()), half);
            }
        }
    }

    #[test]
    fn test_half_to_u128_rejects_wide_value() {
        let wide = Fr::from(BigInt::new([0, 0, 1, 0]));
        assert_eq!(half_to_u128(&wide), None);
    }

    #[test]
    fn test_wnaf_u128_reconstructs_over_edges_and_seeded() {
        use ark_std::rand::Rng;
        let mut rng = crate::test_utils::rng();
        let mut cases = vec![
            1u128,
            7,
            8,
            9,
            15,
            16,
            u64::MAX as u128,
            1 << 127,
            (1 << 127) + 1,
            u128::MAX,
            u128::MAX.checked_sub(6).unwrap(),
            u128::MAX.checked_sub(7).unwrap(),
        ];
        for _ in 0..512 {
            cases.push(rng.r#gen());
        }
        for k in cases {
            let (digits, top) = wnaf_u128(k).unwrap();
            assert!(
                digits.get(top).copied().unwrap() > 0,
                "top digit must be positive for k > 0"
            );
            // reconstruct MSB-first, wrapping mod 2^128: sum d_i * 2^i wraps
            // identically for value and accumulator since k < 2^128
            let mut acc: u128 = 0;
            for (index, digit) in digits.iter().enumerate().rev() {
                if index > top {
                    assert_eq!(*digit, 0, "digits above top must be zero");
                }
                acc = acc.wrapping_mul(2).wrapping_add(*digit as u128);
            }
            assert_eq!(acc, k, "wNAF digits must reconstruct k");
            for d in digits {
                assert!(
                    d == 0 || (d % 2 != 0 && d.abs() <= 7),
                    "digits must be zero or odd in [-7, 7]"
                );
            }
        }
    }
}
