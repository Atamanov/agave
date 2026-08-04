//! Curve and field constants for BN254 / BN_SNARK1 (Solana alt_bn128).
//!
//! Matches herumi/mcl `CurveParam BN_SNARK1` and arkworks `ark-bn254`.
//!
//! Everything here is derived at compile time from the seed [`BN_X`] by the
//! integer-only `const fn`s in [`derive`]; a const assert pins each derived
//! value to its canonical literal, so any drift fails the build.

/// BN seed `x = 4965661367192848881`: the root constant of the curve.
/// BN254 is the Barreto-Naehrig family instantiated at this seed, with
/// `p(x) = 36x^4+36x^3+24x^2+6x+1`, `r(x) = 36x^4+36x^3+18x^2+6x+1`, and trace of
/// Frobenius `t(x) = 6x^2+1` (so `r = p + 1 - t`).
pub const BN_X: u64 = 4965661367192848881;
const _: () = assert!(BN_X == 0x44e992b44a6909f1);

/// Base field prime `p = p(BN_X)` (little-endian limbs).
pub const P: [u64; 4] = derive::bn_poly(BN_X, [1, 6, 24, 36, 36]);
const _: () = assert!(derive::eq4(
    P,
    [
        0x3c208c16d87cfd47,
        0x97816a916871ca8d,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]
));

/// Scalar field prime `r = r(BN_X)` (little-endian limbs).
pub const R: [u64; 4] = derive::bn_poly(BN_X, [1, 6, 18, 36, 36]);
const _: () = assert!(derive::eq4(
    R,
    [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ]
));

// Family invariant `r = p + 1 - t`, i.e. `p - r = t - 1 = 6x^2`.
const _: () = {
    let t_minus_1 = derive::six_x_squared(BN_X);
    assert!(derive::eq4(
        derive::add4(R, [t_minus_1[0], t_minus_1[1], 0, 0]),
        P
    ));
};

/// Montgomery `-p^{-1} mod 2^64` for CIOS.
pub const P_INV: u64 = derive::neg_inv64(P[0]);
const _: () = assert!(P_INV == 0x87d20782e4866389);
const _: () = assert!(P[0].wrapping_mul(P_INV) == u64::MAX);

/// `floor(2^310 / p)`: quotient-estimate constant of the fp6 kernel's in-asm
/// xi scaling (`q = floor(E*mu/2^58)` with `E = floor(value/2^252)` reduces
/// any value below 10p to below 1.33p).
pub const P_MU_310: u64 = derive::div_pow2(310, P);
const _: () = assert!(P_MU_310 == 0x015291d18988e812);

/// Montgomery `-r^{-1} mod 2^64`.
pub const R_INV: u64 = derive::neg_inv64(R[0]);
const _: () = assert!(R_INV == 0xc2e1f593efffffff);
const _: () = assert!(R[0].wrapping_mul(R_INV) == u64::MAX);

/// `2^256 mod p` = Montgomery representation of 1.
pub const MONT_ONE: [u64; 4] = derive::pow2_mod(256, P);
const _: () = assert!(derive::eq4(
    MONT_ONE,
    [
        0xd35d438dc58f0d9d,
        0x0a78eb28f5c70b3d,
        0x666ea36f7879462c,
        0x0e0a77c19a07df2f,
    ]
));

/// `2^512 mod p`. Multiply a raw integer by this to enter Montgomery form.
pub const MONT_R2: [u64; 4] = derive::pow2_mod(512, P);
const _: () = assert!(derive::eq4(
    MONT_R2,
    [
        0xf32cfc5b538afa89,
        0xb5e71911d44501fb,
        0x47ab1eff0a417ff6,
        0x06d89f71cab8351f,
    ]
));

/// `2^768 mod p`.
pub const MONT_R3: [u64; 4] = derive::pow2_mod(768, P);
const _: () = assert!(derive::eq4(
    MONT_R3,
    [
        0xb1cd6dafda1530df,
        0x62f210e6a7283db6,
        0xef7f0b0c0ada0afb,
        0x20fd6e902d592544,
    ]
));

/// `2^256 mod r` = Montgomery representation of 1 in `Fr`.
pub const FR_MONT_ONE: [u64; 4] = derive::pow2_mod(256, R);
const _: () = assert!(derive::eq4(
    FR_MONT_ONE,
    [
        0xac96341c4ffffffb,
        0x36fc76959f60cd29,
        0x666ea36f7879462e,
        0x0e0a77c19a07df2f,
    ]
));

/// `2^512 mod r`. Multiply a raw integer by this to enter Montgomery form.
pub const FR_MONT_R2: [u64; 4] = derive::pow2_mod(512, R);
const _: () = assert!(derive::eq4(
    FR_MONT_R2,
    [
        0x1bb8e645ae216da7,
        0x53fe3ab1e35c59e3,
        0x8c49833d53bb8085,
        0x0216d0b17f4e44a5,
    ]
));

/// `2^768 mod r`.
pub const FR_MONT_R3: [u64; 4] = derive::pow2_mod(768, R);
const _: () = assert!(derive::eq4(
    FR_MONT_R3,
    [
        0x5e94d8e1b4bf0040,
        0x2a489cbe1cfbb6b8,
        0x893cc664a19fcfed,
        0x0cf8594b7fcc657c,
    ]
));

/// Halve mod odd `m < 2^254`: `(x + m*(x & 1)) >> 1`; the sum fits 256 bits.
pub(crate) const fn half_mod(x: [u64; 4], m: [u64; 4]) -> [u64; 4] {
    let mut y = x;
    if y[0] & 1 == 1 {
        let mut carry = 0u64;
        let mut i = 0;
        while i < 4 {
            let (sum, c) = crate::limb::adc(y[i], m[i], carry);
            y[i] = sum;
            carry = c;
            i += 1;
        }
    }
    [
        (y[0] >> 1) | (y[1] << 63),
        (y[1] >> 1) | (y[2] << 63),
        (y[2] >> 1) | (y[3] << 63),
        y[3] >> 1,
    ]
}

/// Double mod `m < 2^254` for canonical `x < m`.
pub(crate) const fn double_mod(x: [u64; 4], m: [u64; 4]) -> [u64; 4] {
    let mut y = [
        x[0] << 1,
        (x[1] << 1) | (x[0] >> 63),
        (x[2] << 1) | (x[1] >> 63),
        (x[3] << 1) | (x[2] >> 63),
    ];
    let mut borrow = 0u64;
    let mut d = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let (diff, br) = crate::limb::sbb(y[i], m[i], borrow);
        d[i] = diff;
        borrow = br;
        i += 1;
    }
    if borrow == 0 {
        y = d;
    }
    y
}

/// `table[i] = half_mod^i(first)`: descending powers of two mod `m`.
const fn kaliski_table(first: [u64; 4], m: [u64; 4]) -> [[u64; 4]; crate::limb::KALISKI_TBL_LEN] {
    let mut table = [[0u64; 4]; crate::limb::KALISKI_TBL_LEN];
    table[0] = first;
    let mut i = 1;
    while i < crate::limb::KALISKI_TBL_LEN {
        table[i] = half_mod(table[i - 1], m);
        i += 1;
    }
    table
}

/// Kaliski correction table for canonical-domain `Fr` inversion:
/// entry `i` is `2^{256-k} mod r` for `k = KALISKI_K_MIN + i`, so one
/// Montgomery multiply turns the almost-inverse `a^{-1}*2^k` into `a^{-1}`.
pub(crate) const FR_KALISKI_TBL: [[u64; 4]; crate::limb::KALISKI_TBL_LEN] =
    kaliski_table(derive::pow2_mod(256 - crate::limb::KALISKI_K_MIN, R), R);

/// Kaliski correction table for Montgomery-domain `Fp` inversion:
/// entry `i` is `2^{768-k} mod p` (the composed constant `C = 2^512`), so
/// `(aR)^{-1}*2^k` becomes `a^{-1}*R` in a single Montgomery multiply.
pub(crate) const FP_KALISKI_TBL: [[u64; 4]; crate::limb::KALISKI_TBL_LEN] =
    kaliski_table(double_mod(double_mod(double_mod(MONT_R2, P), P), P), P);

/// Curve equation `y^2 = x^3 + B` with `B = 3`.
pub const G1_B: u64 = 3;

/// Twist non-residue parameter `xi = 9 + u` real part.
pub const XI_A: u64 = 9;

/// ATE loop signed digits of `6x+2` (LSB first): the canonical NAF (66
/// digits, ending `-1, 0, 1`) with that top run folded to `1, 1` via
/// `-2^63 + 2^65 = 2^63 + 2^64`. Same 22 nonzero digits, one fewer Miller
/// doubling. This is the exact addition chain used by `ark-bn254` 0.5.0.
pub const ATE_LOOP_COUNT: [i8; 65] = derive::ate_loop_count(BN_X);
const _: () = assert!(derive::eq_i8(
    &ATE_LOOP_COUNT,
    &[
        0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0,
        0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, -1, 0,
        -1, 0, 0, 0, 1, 0, 1, 1,
    ]
));

/// Compile-time derivations of every constant in this crate from the BN seed.
/// Integer-only (u64/u128 school-book), platform-stable, and exercised by the
/// const asserts next to each constant. Misuse panics the build.
pub(crate) mod derive {
    use crate::limb::{adc, sbb};

    pub(crate) const fn eq4(a: [u64; 4], b: [u64; 4]) -> bool {
        a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
    }

    pub(crate) const fn eq_i8<const L: usize>(a: &[i8; L], b: &[i8; L]) -> bool {
        let mut i = 0;
        while i < L {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `a + b`, asserting no carry out of four limbs.
    pub(crate) const fn add4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (s0, c0) = adc(a[0], b[0], 0);
        let (s1, c1) = adc(a[1], b[1], c0);
        let (s2, c2) = adc(a[2], b[2], c1);
        let (s3, c3) = adc(a[3], b[3], c2);
        assert!(c3 == 0);
        [s0, s1, s2, s3]
    }

    /// `a - b`, asserting `a >= b`.
    const fn sub4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let (d0, b0) = sbb(a[0], b[0], 0);
        let (d1, b1) = sbb(a[1], b[1], b0);
        let (d2, b2) = sbb(a[2], b[2], b1);
        let (d3, b3) = sbb(a[3], b[3], b2);
        assert!(b3 == 0);
        [d0, d1, d2, d3]
    }

    const fn gte4(a: [u64; 4], b: [u64; 4]) -> bool {
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

    /// School-book `a*b`, asserting the product fits four limbs.
    pub(crate) const fn mul4_lo(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut t = [0u64; 8];
        let mut i = 0;
        while i < 4 {
            let mut carry = 0u64;
            let mut j = 0;
            while j < 4 {
                let acc = (a[i] as u128) * (b[j] as u128) + t[i + j] as u128 + carry as u128;
                t[i + j] = acc as u64;
                carry = (acc >> 64) as u64;
                j += 1;
            }
            t[i + 4] = carry;
            i += 1;
        }
        assert!(t[4] == 0 && t[5] == 0 && t[6] == 0 && t[7] == 0);
        [t[0], t[1], t[2], t[3]]
    }

    /// `c4*x^4 + c3*x^3 + c2*x^2 + c1*x + c0` over four limbs (coefficients
    /// lowest-first), asserting every intermediate fits 256 bits.
    pub(crate) const fn bn_poly(x: u64, c: [u64; 5]) -> [u64; 4] {
        let x1 = [x, 0, 0, 0];
        let x2 = mul4_lo(x1, x1);
        let x3 = mul4_lo(x2, x1);
        let x4 = mul4_lo(x2, x2);
        let mut acc = [c[0], 0, 0, 0];
        acc = add4(acc, mul4_lo(x1, [c[1], 0, 0, 0]));
        acc = add4(acc, mul4_lo(x2, [c[2], 0, 0, 0]));
        acc = add4(acc, mul4_lo(x3, [c[3], 0, 0, 0]));
        add4(acc, mul4_lo(x4, [c[4], 0, 0, 0]))
    }

    /// `c2*x^2 + c1*x + c0` in u128 (coefficients lowest-first); the checked
    /// ops panic the build on overflow.
    pub(crate) const fn poly2_u128(x: u64, c: [u64; 3]) -> u128 {
        let x = x as u128;
        let Some(sq) = (c[2] as u128).checked_mul(x * x) else {
            panic!("poly2_u128 overflow");
        };
        let Some(mid) = sq.checked_add((c[1] as u128) * x) else {
            panic!("poly2_u128 overflow");
        };
        let Some(out) = mid.checked_add(c[0] as u128) else {
            panic!("poly2_u128 overflow");
        };
        out
    }

    pub(crate) const fn u128_limbs(v: u128) -> [u64; 2] {
        [v as u64, (v >> 64) as u64]
    }

    /// `-m0^{-1} mod 2^64` for odd `m0` by Newton iteration: odd `m0` is its own
    /// inverse mod 8, and each step `inv <- inv*(2 - m0*inv)` doubles the
    /// valid bit count (3 -> 6 -> 12 -> 24 -> 48 -> 96 >= 64), so 5 steps suffice.
    pub(crate) const fn neg_inv64(m0: u64) -> u64 {
        assert!(m0 & 1 == 1);
        let mut inv = m0;
        let mut i = 0;
        while i < 5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
            i += 1;
        }
        inv.wrapping_neg()
    }

    /// `2^n mod m` by `n` modular doublings from 1 (`m` odd, `< 2^254`).
    pub(crate) const fn pow2_mod(n: u32, m: [u64; 4]) -> [u64; 4] {
        let mut acc = [1u64, 0, 0, 0];
        let mut i = 0;
        while i < n {
            acc = super::double_mod(acc, m);
            i += 1;
        }
        acc
    }

    /// CIOS Montgomery product `a*b*2^{-256} mod m`, canonical output.
    /// Const twin of `limb::mont_mul_limbs` (kept `fn` for codegen there).
    pub(crate) const fn mont_mul4(a: [u64; 4], b: [u64; 4], m: [u64; 4], neg_inv: u64) -> [u64; 4] {
        assert!(m[0].wrapping_mul(neg_inv) == u64::MAX);
        let mut t = [0u64; 5];
        let mut i = 0;
        while i < 4 {
            let mut carry = 0u64;
            let mut j = 0;
            while j < 4 {
                let acc = (a[j] as u128) * (b[i] as u128) + t[j] as u128 + carry as u128;
                t[j] = acc as u64;
                carry = (acc >> 64) as u64;
                j += 1;
            }
            t[4] = t[4].wrapping_add(carry);

            let k = t[0].wrapping_mul(neg_inv);
            let acc = (k as u128) * (m[0] as u128) + t[0] as u128;
            let mut carry = (acc >> 64) as u64;
            let mut j = 1;
            while j < 4 {
                let acc = (k as u128) * (m[j] as u128) + t[j] as u128 + carry as u128;
                t[j - 1] = acc as u64;
                carry = (acc >> 64) as u64;
                j += 1;
            }
            let (lo, hi) = adc(t[4], 0, carry);
            t[3] = lo;
            t[4] = hi;
            i += 1;
        }
        let mut out = [t[0], t[1], t[2], t[3]];
        if t[4] != 0 || gte4(out, m) {
            out = sub4(out, m);
        }
        out
    }

    /// `floor(2^e / d)` by binary restoring division; the quotient must fit
    /// one limb (asserted) and `d` must occupy the top limb so the remainder
    /// stays in four limbs.
    pub(crate) const fn div_pow2(e: u32, d: [u64; 4]) -> u64 {
        assert!(d[3] != 0);
        // r = 1: the dividend's single set bit has been consumed.
        let mut r = [1u64, 0, 0, 0];
        let mut q: u64 = 0;
        let mut i = 0;
        while i < e {
            r = add4(r, r);
            assert!(q >> 63 == 0);
            q <<= 1;
            if gte4(r, d) {
                r = sub4(r, d);
                q |= 1;
            }
            i += 1;
        }
        q
    }

    /// `a >> k` over four limbs, `1 <= k < 64`.
    pub(crate) const fn shr4(a: [u64; 4], k: u32) -> [u64; 4] {
        assert!(k >= 1 && k < 64);
        [
            (a[0] >> k) | (a[1] << (64 - k)),
            (a[1] >> k) | (a[2] << (64 - k)),
            (a[2] >> k) | (a[3] << (64 - k)),
            a[3] >> k,
        ]
    }

    pub(crate) const fn add4_small(a: [u64; 4], v: u64) -> [u64; 4] {
        add4(a, [v, 0, 0, 0])
    }

    /// Canonical NAF digits of `n` (LSB first), zero-padded to `L`; asserts
    /// the representation fits. Each nonzero digit `d = 2 - (n mod 4)` makes
    /// `n - d` divisible by 4, so no two nonzeros are adjacent.
    const fn naf<const L: usize>(mut n: u128) -> [i8; L] {
        let mut out = [0i8; L];
        let mut i = 0;
        while n != 0 {
            assert!(i < L);
            if n & 1 == 1 {
                if n & 3 == 1 {
                    out[i] = 1;
                    n -= 1;
                } else {
                    out[i] = -1;
                    n += 1;
                }
            }
            n >>= 1;
            i += 1;
        }
        out
    }

    /// ATE loop digits of `6x+2` (LSB first): canonical NAF with the top run
    /// `(-1, 0, 1)` at digits 63..=65 folded to `(1, 1)` at 63..=64
    /// (`-2^63 + 2^65 = 2^63 + 2^64`), matching ark-bn254's 65-digit table.
    pub(crate) const fn ate_loop_count(x: u64) -> [i8; 65] {
        let canonical: [i8; 66] = naf(6 * (x as u128) + 2);
        assert!(canonical[63] == -1 && canonical[64] == 0 && canonical[65] == 1);
        let mut out = [0i8; 65];
        let mut i = 0;
        while i < 63 {
            out[i] = canonical[i];
            i += 1;
        }
        out[63] = 1;
        out[64] = 1;
        out
    }

    /// MSB-first canonical NAF of the 63-bit BN seed with the leading 1
    /// dropped (the caller folds it into the accumulator).
    pub(crate) const fn bn_x_naf_msb(x: u64) -> [i8; 62] {
        let digits: [i8; 63] = naf(x as u128);
        assert!(digits[62] == 1);
        let mut out = [0i8; 62];
        let mut i = 0;
        while i < 62 {
            out[i] = digits[61 - i];
            i += 1;
        }
        out
    }

    /// `6x^2` (fits two limbs for a 63-bit seed): `t - 1`, the eigenvalue of
    /// the G2 Frobenius endomorphism `psi` on the r-torsion.
    pub(crate) const fn six_x_squared(x: u64) -> [u64; 2] {
        u128_limbs(poly2_u128(x, [0, 0, 6]))
    }

    /// Montgomery form of the GLV base-field cube root of unity
    /// `beta = p - (18x^3+18x^2+9x+2)`: the identity
    /// `(18x^3+18x^2+9x+2)^2 - (18x^3+18x^2+9x+2) + 1 = p(x)*(9x^2+9x+3)` holds
    /// over Z[x], so `beta^2 + beta + 1 = 0 (mod p)` by construction. Of the
    /// two primitive roots this is the one whose eigenvalue on G1 is
    /// `lambda = -(36x^3+18x^2+6x+2) mod r` (the GLV basis pins it; see msm.rs).
    pub(crate) const fn glv_beta_mont() -> [u64; 4] {
        let c = bn_poly(super::BN_X, [2, 9, 18, 18, 0]);
        mont_mul4(sub4(super::P, c), super::MONT_R2, super::P, super::P_INV)
    }

    /// Determinant `b00*b11 + b01^2` of the GLV basis `[[b00, -b01], [b01, b11]]`.
    pub(crate) const fn glv_det(b00: [u64; 2], b01: u64, b11: [u64; 2]) -> [u64; 4] {
        let prod = mul4_lo([b00[0], b00[1], 0, 0], [b11[0], b11[1], 0, 0]);
        let sq = (b01 as u128) * (b01 as u128);
        add4(prod, [sq as u64, (sq >> 64) as u64, 0, 0])
    }

    /// `floor(c*2^256 / m)` for two-limb `c` and 254-bit odd `m` by restoring
    /// binary long division over the 384-bit numerator; asserts the quotient
    /// fits three limbs. The remainder invariant `rem < m < 2^254` keeps the
    /// shifted value inside four limbs.
    pub(crate) const fn floor_mul_2_256_div(c: [u64; 2], m: [u64; 4]) -> [u64; 3] {
        let mut rem = [0u64; 4];
        let mut q = [0u64; 6];
        let mut i: i32 = 383;
        while i >= 0 {
            rem = [
                rem[0] << 1,
                (rem[1] << 1) | (rem[0] >> 63),
                (rem[2] << 1) | (rem[1] >> 63),
                (rem[3] << 1) | (rem[2] >> 63),
            ];
            if i >= 256 {
                let bit_index = (i - 256) as u32;
                rem[0] |= (c[(bit_index / 64) as usize] >> (bit_index % 64)) & 1;
            }
            if gte4(rem, m) {
                rem = sub4(rem, m);
                q[(i / 64) as usize] |= 1u64 << (i % 64);
            }
            i -= 1;
        }
        assert!(q[3] == 0 && q[4] == 0 && q[5] == 0);
        [q[0], q[1], q[2]]
    }
}

#[cfg(test)]
mod kaliski_table_tests {
    use super::{FP_KALISKI_TBL, FR_KALISKI_TBL, MONT_R2, P, P_INV, R, R_INV, double_mod};
    use crate::limb::{KALISKI_K_MIN, KALISKI_TBL_LEN, mont_mul_limbs};

    /// Regenerates both tables from first principles: entry `i` (for
    /// `k = KALISKI_K_MIN + i`) times `2^k` must be `2^256` (Fr, canonical
    /// correction) resp. `2^768` (Fp, Montgomery correction), i.e. one
    /// Montgomery multiply must yield 1 resp. `2^512`.
    #[test]
    fn kaliski_tables_regenerate() {
        assert_eq!(FR_KALISKI_TBL[0], [8, 0, 0, 0]);
        let mut pow2_r = [1u64, 0, 0, 0];
        let mut pow2_p = [1u64, 0, 0, 0];
        for _ in 0..KALISKI_K_MIN {
            pow2_r = double_mod(pow2_r, R);
            pow2_p = double_mod(pow2_p, P);
        }
        for i in 0..KALISKI_TBL_LEN {
            assert_eq!(
                mont_mul_limbs(&FR_KALISKI_TBL[i], &pow2_r, &R, R_INV),
                [1, 0, 0, 0],
                "fr entry {i}"
            );
            assert_eq!(
                mont_mul_limbs(&FP_KALISKI_TBL[i], &pow2_p, &P, P_INV),
                MONT_R2,
                "fp entry {i}"
            );
            pow2_r = double_mod(pow2_r, R);
            pow2_p = double_mod(pow2_p, P);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ATE_LOOP_COUNT, BN_X};

    #[test]
    fn ate_loop_count_matches_ark_bn254_0_5_0() {
        // Source: ark-bn254 0.5.0, src/curves/mod.rs, Config::ATE_LOOP_COUNT.
        // Crate checksum: d69eab57e8d2663efa5c63135b2af4f396d66424f88954c21104125ab6b3e6bc.
        let expected = [
            0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, -1, 0,
            0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0, -1, 0, 0,
            0, -1, 0, -1, 0, 0, 0, 1, 0, 1, 1,
        ];

        assert_eq!(ATE_LOOP_COUNT, expected);
        assert_eq!(ATE_LOOP_COUNT.len(), 65);
        assert_eq!(
            ATE_LOOP_COUNT.iter().filter(|&&digit| digit != 0).count(),
            22
        );

        let value = ATE_LOOP_COUNT
            .iter()
            .enumerate()
            .map(|(bit, &digit)| i128::from(digit) * (1_i128 << bit))
            .sum::<i128>();
        assert_eq!(value, 29_793_968_203_157_093_288_i128);
        assert_eq!(value, 6 * i128::from(BN_X) + 2);
    }
}
