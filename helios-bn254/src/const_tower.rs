//! Compile-time derivation of tower/pairing constants from first principles.
//!
//! Every precomputed literal in `fp12` and `pairing::miller` (Frobenius gamma
//! tables, twist coefficient, seed recodings) is pinned by a const assertion
//! to a value derived here at compile time from `P`, `xi = 9 + u`, and the BN
//! seed `x` alone. A wrong or stale literal cannot compile. Integer-only
//! const evaluation: Montgomery arithmetic mod p, Fp2 arithmetic over
//! u^2 = -1, square-and-multiply exponentiation, signed recodings.
//!
//! Generic limb kernels come from `consts::derive` (CIOS `mont_mul4`, `eq4`).
//! The Fp2 / mod-p layer on top is local to this module.

use crate::consts::derive::mont_mul4;
use crate::consts::{MONT_ONE, MONT_R2, P, P_INV, XI_A};

/// Fp2 element as canonical Montgomery limb pairs `(c0, c1)`.
pub(crate) type F2c = ([u64; 4], [u64; 4]);

const fn geq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

const fn sub4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (d, br) = crate::limb::sbb(a[i], b[i], borrow);
        out[i] = d;
        borrow = br;
        i += 1;
    }
    out
}

/// `a + b mod p` for canonical inputs. The raw sum < 2p < 2^255 cannot carry.
const fn add_p(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut s = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (v, c) = crate::limb::adc(a[i], b[i], carry);
        s[i] = v;
        carry = c;
        i += 1;
    }
    if geq(&s, &P) { sub4(&s, &P) } else { s }
}

/// `a - b mod p`. `sub4` wraps mod 2^256 and a wrapping add of p corrects the
/// borrow case: a - b + p < p < 2^256, so the discarded carry is exact.
const fn sub_p(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let d = sub4(&a, &b);
    if geq(&a, &b) {
        return d;
    }
    let mut s = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (v, c) = crate::limb::adc(d[i], P[i], carry);
        s[i] = v;
        carry = c;
        i += 1;
    }
    s
}

const fn neg_p(a: [u64; 4]) -> [u64; 4] {
    if a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0 {
        a
    } else {
        sub4(&P, &a)
    }
}

/// Montgomery product a*b*R^-1 mod p: the shared const CIOS kernel
/// specialized to the base field.
pub(crate) const fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    mont_mul4(*a, *b, P, P_INV)
}

/// Small integer into Montgomery form: v*R mod p = v * R^2 * R^-1.
const fn mont_from_u64(v: u64) -> [u64; 4] {
    mont_mul(&[v, 0, 0, 0], &MONT_R2)
}

/// base^e mod p in Montgomery form, MSB-first square-and-multiply.
const fn fp_pow(base: [u64; 4], e: &[u64; 4]) -> [u64; 4] {
    let mut acc = MONT_ONE;
    let mut i = 4;
    while i > 0 {
        i -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            acc = mont_mul(&acc, &acc);
            if (e[i] >> bit) & 1 == 1 {
                acc = mont_mul(&acc, &base);
            }
        }
    }
    acc
}

/// Schoolbook Fp2 product over u^2 = -1:
/// (a0 + a1*u)(b0 + b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u.
pub(crate) const fn fp2_mul(a: F2c, b: F2c) -> F2c {
    (
        sub_p(mont_mul(&a.0, &b.0), mont_mul(&a.1, &b.1)),
        add_p(mont_mul(&a.0, &b.1), mont_mul(&a.1, &b.0)),
    )
}

const fn fp2_pow(base: F2c, e: &[u64; 4]) -> F2c {
    let mut acc = (MONT_ONE, [0u64; 4]);
    let mut i = 4;
    while i > 0 {
        i -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            acc = fp2_mul(acc, acc);
            if (e[i] >> bit) & 1 == 1 {
                acc = fp2_mul(acc, base);
            }
        }
    }
    acc
}

/// p - k for small k. No borrow past limb 0: P[0] > k.
const fn p_minus(k: u64) -> [u64; 4] {
    assert!(P[0] > k);
    [P[0] - k, P[1], P[2], P[3]]
}

/// Exact x / 6 by long division MSB -> LSB. Asserts divisibility.
const fn div6_exact(x: [u64; 4]) -> [u64; 4] {
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    let mut i = 4;
    while i > 0 {
        i -= 1;
        let cur = (rem << 64) | x[i] as u128;
        q[i] = (cur / 6) as u64;
        rem = cur % 6;
    }
    assert!(rem == 0);
    q
}

/// Tower non-residue xi = 9 + u in Montgomery form.
pub(crate) const XI: F2c = (mont_from_u64(XI_A), MONT_ONE);

/// (p - 1)/6. Exact: p = 36x^4 + 36x^3 + 24x^2 + 6x + 1 == 1 (mod 6).
const P_MINUS_1_DIV_6: [u64; 4] = div6_exact(p_minus(1));

/// Frobenius scale factors gamma_{1,j} = xi^(j(p-1)/6), j = 1..=5:
/// with w^6 = xi and c in Fp2, (c*w^j)^p = conj(c)*gamma_{1,j}*w^j.
pub(crate) const GAMMA1: [F2c; 5] = {
    let g1 = fp2_pow(XI, &P_MINUS_1_DIV_6);
    let g2 = fp2_mul(g1, g1);
    let g3 = fp2_mul(g2, g1);
    let g4 = fp2_mul(g2, g2);
    let g5 = fp2_mul(g4, g1);
    [g1, g2, g3, g4, g5]
};

/// gamma_{2,j} = xi^(j(p^2-1)/6) = gamma_{1,j}^(p+1)
/// = gamma_{1,j}*conj(gamma_{1,j}) since Frobenius on Fp2 is conjugation.
/// Hence real: a^2 + b^2 for gamma_{1,j} = a + b*u.
pub(crate) const GAMMA2: [[u64; 4]; 5] = {
    let mut out = [[0u64; 4]; 5];
    let mut j = 0;
    while j < 5 {
        let (a, b) = GAMMA1[j];
        out[j] = add_p(mont_mul(&a, &a), mont_mul(&b, &b));
        j += 1;
    }
    out
};

/// D-twist coefficient b' = 3/xi. 1/xi = conj(xi)/|xi|^2 and |xi|^2 = 82,
/// so b' = (27 - 3u)/82 with 1/82 by Fermat (82^(p-2)).
pub(crate) const TWIST_B: F2c = {
    let inv82 = fp_pow(mont_from_u64(82), &p_minus(2));
    (
        mont_mul(&mont_from_u64(27), &inv82),
        neg_p(mont_mul(&mont_from_u64(3), &inv82)),
    )
};

/// Non-adjacent form of x, LSB first, 63 digits (x < 2^63): at each odd step
/// the digit is +-1 == x (mod 4), forcing the next bit to zero.
pub(crate) const fn naf63(x: u64) -> [i8; 63] {
    let mut out = [0i8; 63];
    let mut x = x as u128;
    let mut i = 0;
    while x != 0 {
        assert!(i < 63);
        if x & 1 == 1 {
            if x & 3 == 1 {
                out[i] = 1;
                x -= 1;
            } else {
                out[i] = -1;
                x += 1;
            }
        }
        x >>= 1;
        i += 1;
    }
    out
}

/// Signed width-4 window (w-NAF) recoding of x, LSB first, 63 digits: at each
/// odd step take d == x (mod 16) mapped into (-8, 8) (odd, |d| <= 7) and
/// subtract, forcing >= 3 zero digits after each nonzero one.
pub(crate) const fn wnaf4_63(x: u64) -> [i8; 63] {
    let mut out = [0i8; 63];
    let mut x = x as i128;
    let mut i = 0;
    while x != 0 {
        assert!(i < 63);
        if x & 1 == 1 {
            let mut d = (x & 15) as i8;
            if d > 8 {
                d -= 16;
            }
            out[i] = d;
            x -= d as i128;
        }
        x >>= 1;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::BN_X;
    use crate::fp::Fp;
    use crate::fp2::Fp2;

    fn fp2(v: F2c) -> Fp2 {
        Fp2::new(Fp::from_raw_canonical(v.0), Fp::from_raw_canonical(v.1))
    }

    fn xi() -> Fp2 {
        Fp2::new(Fp::from_u64(9), Fp::ONE)
    }

    /// Runtime square-and-multiply, independent of the const-eval path.
    fn fp2_pow_rt(base: Fp2, e: &[u64; 4]) -> Fp2 {
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

    /// Recompute (p - 1)/6 at runtime, check gamma_{1,j} = xi^(j(p-1)/6).
    #[test]
    fn gamma1_regenerates_from_xi() {
        let mut e = [0u64; 4];
        let mut rem: u128 = 0;
        let x = p_minus(1);
        for i in (0..4).rev() {
            let cur = (rem << 64) | x[i] as u128;
            e[i] = (cur / 6) as u64;
            rem = cur % 6;
        }
        assert_eq!(rem, 0, "p != 1 mod 6");
        let g = fp2_pow_rt(xi(), &e);
        let mut acc = Fp2::ONE;
        for (j, &gj) in GAMMA1.iter().enumerate() {
            acc *= g;
            assert_eq!(fp2(gj), acc, "gamma1[{}]", j + 1);
        }
    }

    /// Defining relation without exponent arithmetic:
    /// gamma_{1,1}^6 = xi^(p-1), so gamma_{1,1}^6 * xi = xi^p = conj(xi).
    #[test]
    fn gamma1_sixth_power_is_frobenius_of_xi() {
        let g = fp2(GAMMA1[0]);
        let g6 = g.square() * g.square() * g.square();
        assert_eq!(g6 * xi(), xi().conjugate());
    }

    /// gamma_{2,j} = gamma_{1,j} * conj(gamma_{1,j}), real.
    #[test]
    fn gamma2_is_norm_of_gamma1() {
        for (j, (&g1, &g2)) in GAMMA1.iter().zip(GAMMA2.iter()).enumerate() {
            let g1 = fp2(g1);
            let want = g1 * g1.conjugate();
            assert_eq!(want.c1, Fp::ZERO);
            assert_eq!(Fp::from_raw_canonical(g2), want.c0, "gamma2[{}]", j + 1);
        }
    }

    /// b' * xi = 3.
    #[test]
    fn twist_b_times_xi_is_three() {
        assert_eq!(fp2(TWIST_B) * xi(), Fp2::from(3u64));
    }

    /// Both recodings reconstruct the seed and satisfy their digit invariants.
    #[test]
    fn seed_recodings_reconstruct_bn_x() {
        let naf = naf63(BN_X);
        let w4 = wnaf4_63(BN_X);
        let value = |d: &[i8; 63]| {
            d.iter()
                .enumerate()
                .map(|(i, &v)| i128::from(v) << i)
                .sum::<i128>()
        };
        assert_eq!(value(&naf), i128::from(BN_X));
        assert_eq!(value(&w4), i128::from(BN_X));
        for i in 0..63 {
            assert!(naf[i].abs() <= 1);
            assert!(naf[i] == 0 || i + 1 >= 63 || naf[i + 1] == 0);
            assert!(w4[i] == 0 || (w4[i] % 2 != 0 && w4[i].abs() <= 7));
            if w4[i] != 0 {
                for k in 1..=3 {
                    assert!(i + k >= 63 || w4[i + k] == 0);
                }
            }
        }
    }

    /// Const CIOS agrees with the production Fp backend.
    #[test]
    fn const_mont_mul_matches_fp_backend() {
        let a = Fp::from_u64(0x1234_5678_9abc_def0).pow_u64(3);
        let b = Fp::from_u64(0xfedc_ba98_7654_3210).pow_u64(5);
        assert_eq!(Fp::from_raw_canonical(mont_mul(&a.0, &b.0)), a * b);
    }
}
