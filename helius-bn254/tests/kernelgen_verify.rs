//! Host-independent verification of the build-time generated kernels
//! (ADR 0001, build-time amendment).
//!
//! This test includes the SAME `build/` modules the build script compiles,
//! so there is one source of truth and no checked-in `.s` to drift. The
//! interpreters execute the exact operation sequences the emitters print,
//! with bit-accurate carry-flag semantics, and compare them against an
//! independent u128 CIOS reference and the production portable oracle. Any
//! wrong product, mis-chained carry, violated flags claim, clobbered
//! callee-saved register, or unbalanced stack fails here on every
//! architecture -- no target hardware required. Rendering is additionally
//! gated on determinism: generating twice must produce identical text.

#[path = "../build/mod.rs"]
pub mod kernelgen;

use kernelgen::{
    BN254_MU, BN254_P, BN254_P_INV, interpret_cyc_sqr, interpret_fp6_mul, interpret_fp12_034,
    interpret_fp12_mul, interpret_fp12_sqr, interpret_mont4_a64, interpret_mont4_mul,
    interpret_mont4_sqr, interpret_sos, interpret_sosd2_small, interpret_sosd6,
};

/// Independent CIOS Montgomery multiplication oracle (word-by-word, u128).
fn reference_mont_mul(a: [u64; 4], b: [u64; 4], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut t = [0u64; 6];
    for &bi in &b {
        let mut carry = 0u128;
        for j in 0..4 {
            let sum = t[j] as u128 + a[j] as u128 * bi as u128 + carry;
            t[j] = sum as u64;
            carry = sum >> 64;
        }
        let sum = t[4] as u128 + carry;
        t[4] = sum as u64;
        t[5] = (sum >> 64) as u64;

        let m = t[0].wrapping_mul(p_inv);
        let mut carry = (t[0] as u128 + m as u128 * p[0] as u128) >> 64;
        for j in 1..4 {
            let sum = t[j] as u128 + m as u128 * p[j] as u128 + carry;
            t[j - 1] = sum as u64;
            carry = sum >> 64;
        }
        let sum = t[4] as u128 + carry;
        t[3] = sum as u64;
        t[4] = t[5] + (sum >> 64) as u64;
        t[5] = 0;
    }

    let mut reduced = [0u64; 4];
    let mut borrow = 0i128;
    for j in 0..4 {
        let difference = t[j] as i128 - p[j] as i128 + borrow;
        reduced[j] = difference as u64;
        borrow = difference >> 64;
    }
    if t[4] != 0 || borrow == 0 {
        reduced
    } else {
        [t[0], t[1], t[2], t[3]]
    }
}

/// Independent sum-of-products Montgomery oracle (Longa Alg. 2 shape,
/// u128 words, six-limb accumulator): `(sum_i a_i*b_i) * R^{-1} mod p`.
fn reference_sos(pairs: &[([u64; 4], [u64; 4])], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut t = [0u64; 6];
    for j in 0..4 {
        for (a, b) in pairs {
            let mut carry = 0u128;
            for k in 0..4 {
                let sum = t[k] as u128 + a[j] as u128 * b[k] as u128 + carry;
                t[k] = sum as u64;
                carry = sum >> 64;
            }
            let sum = t[4] as u128 + carry;
            t[4] = sum as u64;
            t[5] += (sum >> 64) as u64;
        }
        let m = t[0].wrapping_mul(p_inv);
        let mut carry = 0u128;
        for k in 0..4 {
            let sum = t[k] as u128 + m as u128 * p[k] as u128 + carry;
            t[k] = sum as u64;
            carry = sum >> 64;
        }
        let sum = t[4] as u128 + carry;
        t[4] = sum as u64;
        t[5] += (sum >> 64) as u64;
        assert_eq!(t[0], 0, "Montgomery factor cancels the low limb");
        for k in 0..5 {
            t[k] = t[k + 1];
        }
        t[5] = 0;
    }
    assert_eq!(t[4], 0, "final value < 3p < 2^256 fits four limbs");
    let mut out = [t[0], t[1], t[2], t[3]];
    for _ in 0..2 {
        if gte(&out, &p) {
            let mut borrow = 0u64;
            for k in 0..4 {
                let (mid, b1) = out[k].overflowing_sub(p[k]);
                let (low, b2) = mid.overflowing_sub(borrow);
                out[k] = low;
                borrow = (b1 | b2) as u64;
            }
        }
    }
    out
}

/// Both lanes of the dual-lane sosd2 oracle, through the single-lane SoS
/// oracle: `lane0 = (x0*y0 + x1*(p - y1))/R`, `lane1 = (x0*y1 + x1*y0)/R`.
fn reference_sosd2(
    x0: [u64; 4],
    x1: [u64; 4],
    y0: [u64; 4],
    y1: [u64; 4],
    p: [u64; 4],
    p_inv: u64,
) -> ([u64; 4], [u64; 4]) {
    let mut ny1 = [0u64; 4];
    let mut borrow = false;
    for k in 0..4 {
        let (mid, b1) = p[k].overflowing_sub(y1[k]);
        let (low, b2) = mid.overflowing_sub(borrow as u64);
        ny1[k] = low;
        borrow = b1 | b2;
    }
    assert!(!borrow, "y1 must be at most p");
    (
        reference_sos(&[(x0, y0), (x1, ny1)], p, p_inv),
        reference_sos(&[(x0, y1), (x1, y0)], p, p_inv),
    )
}

/// Both lanes of the dual-lane sosd6 oracle, through the single-lane SoS
/// oracle: `lane0 = sum x_i0*y_i0 + x_i1*(p - y_i1)`, `lane1 = sum
/// x_i0*y_i1 + x_i1*y_i0`, each over R^-1 mod p. Operand order as
/// [`interpret_sosd6`].
fn reference_sosd6(
    xs: &[[u64; 4]; 6],
    ys: &[[u64; 4]; 6],
    p: [u64; 4],
    p_inv: u64,
) -> ([u64; 4], [u64; 4]) {
    let mut lane0 = Vec::new();
    let mut lane1 = Vec::new();
    for i in 0..3 {
        let (x0, x1) = (xs[2 * i], xs[2 * i + 1]);
        let (y0, y1) = (ys[2 * i], ys[2 * i + 1]);
        lane0.push((x0, y0));
        lane0.push((x1, negp(y1, p)));
        lane1.push((x0, y1));
        lane1.push((x1, y0));
    }
    (
        reference_sos(&lane0, p, p_inv),
        reference_sos(&lane1, p, p_inv),
    )
}

/// `p - x` for `x <= p`.
fn negp(x: [u64; 4], p: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for k in 0..4 {
        let (mid, b1) = p[k].overflowing_sub(x[k]);
        let (low, b2) = mid.overflowing_sub(borrow as u64);
        out[k] = low;
        borrow = b1 | b2;
    }
    assert!(!borrow, "operand must be at most p");
    out
}

/// Independent xi = 9 + u scaling oracle over Fp2 = (re, im), canonical
/// output: `xi*w = (9*w.re - w.im, 9*w.im + w.re)`, the subtraction entering
/// as `+ (p - w.im)` so the five-limb value stays in `[0, 10p)`.
fn reference_xi(w0: [u64; 4], w1: [u64; 4], p: [u64; 4]) -> ([u64; 4], [u64; 4]) {
    fn mul9_add(a: [u64; 4], c: [u64; 4]) -> [u64; 5] {
        let mut out = [0u64; 5];
        let mut carry: u128 = 0;
        for k in 0..4 {
            let v = 9u128 * a[k] as u128 + c[k] as u128 + carry;
            out[k] = v as u64;
            carry = v >> 64;
        }
        out[4] = carry as u64;
        out
    }
    fn reduce5(mut v: [u64; 5], p: [u64; 4]) -> [u64; 4] {
        loop {
            if v[4] == 0 && !gte(&[v[0], v[1], v[2], v[3]], &p) {
                return [v[0], v[1], v[2], v[3]];
            }
            let mut borrow = 0i128;
            for k in 0..4 {
                let d = v[k] as i128 - p[k] as i128 + borrow;
                v[k] = d as u64;
                borrow = d >> 64;
            }
            v[4] = (v[4] as i128 + borrow) as u64;
        }
    }
    let ny1 = negp(w1, p);
    (reduce5(mul9_add(w0, ny1), p), reduce5(mul9_add(w1, w0), p))
}

/// Six canonical Fp values in repr(C) Fp6 order.
type Fp6Limbs = [[u64; 4]; 6];

/// Independent whole-Fp6 multiply oracle composed from [`reference_sos`]:
/// x1 = xi*b1, x2 = xi*b2, then each component is a dual-lane T = 6 sum of
/// three Fp2 products (c0 = a0*b0 + a1*x2 + a2*x1, c1 = a0*b1 + a1*b0 +
/// a2*x2, c2 = a0*b2 + a1*b1 + a2*b0). Operand order is repr(C) Fp6:
/// c0.re, c0.im, c1.re, c1.im, c2.re, c2.im.
fn reference_fp6_mul(a: &Fp6Limbs, b: &Fp6Limbs, p: [u64; 4], p_inv: u64) -> Fp6Limbs {
    let (x1re, x1im) = reference_xi(b[2], b[3], p);
    let (x2re, x2im) = reference_xi(b[4], b[5], p);
    // y operand sequences per output component, as (re, im) Fp2 pairs.
    let y: [[([u64; 4], [u64; 4]); 3]; 3] = [
        [(b[0], b[1]), (x2re, x2im), (x1re, x1im)],
        [(b[2], b[3]), (b[0], b[1]), (x2re, x2im)],
        [(b[4], b[5]), (b[2], b[3]), (b[0], b[1])],
    ];
    let mut out = [[0u64; 4]; 6];
    for component in 0..3 {
        let mut real_pairs = Vec::new();
        let mut imag_pairs = Vec::new();
        for i in 0..3 {
            let (a_re, a_im) = (a[2 * i], a[2 * i + 1]);
            let (y_re, y_im) = y[component][i];
            real_pairs.push((a_re, y_re));
            real_pairs.push((a_im, negp(y_im, p)));
            imag_pairs.push((a_re, y_im));
            imag_pairs.push((a_im, y_re));
        }
        out[2 * component] = reference_sos(&real_pairs, p, p_inv);
        out[2 * component + 1] = reference_sos(&imag_pairs, p, p_inv);
    }
    out
}

/// One canonical Fp2 as (re, im) limb pairs.
type Fp2Limbs = [[u64; 4]; 2];

/// `2x mod p` for canonical `x` (the kernel's in-frame doubling: one adding
/// chain, one conditional subtraction).
fn double_mod(x: [u64; 4], p: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = false;
    for k in 0..4 {
        let (mid, c1) = x[k].overflowing_add(x[k]);
        let (sum, c2) = mid.overflowing_add(carry as u64);
        out[k] = sum;
        carry = c1 | c2;
    }
    assert!(!carry, "2x < 2p < 2^256 for canonical x");
    if gte(&out, &p) {
        let mut borrow = false;
        for k in 0..4 {
            let (mid, b1) = out[k].overflowing_sub(p[k]);
            let (low, b2) = mid.overflowing_sub(borrow as u64);
            out[k] = low;
            borrow = b1 | b2;
        }
        assert!(!borrow);
    }
    out
}

/// The sos row lists of `Fp12::fp4_square_sos`: with `x = xi*r1` and
/// `d = 2*r0`, `t0 = r0*r0 + x*r1` (T = 4 per lane) and `t1 = d*r1`
/// (T = 2 per lane), the same negp folding as the fp6 oracle. Output order:
/// t0.re, t0.im, t1.re, t1.im.
fn reference_fp4_sqr(r0: &Fp2Limbs, r1: &Fp2Limbs, p: [u64; 4], p_inv: u64) -> [[u64; 4]; 4] {
    let (x_re, x_im) = reference_xi(r1[0], r1[1], p);
    let d = [double_mod(r0[0], p), double_mod(r0[1], p)];
    [
        reference_sos(
            &[
                (r0[0], r0[0]),
                (r0[1], negp(r0[1], p)),
                (x_re, r1[0]),
                (x_im, negp(r1[1], p)),
            ],
            p,
            p_inv,
        ),
        reference_sos(
            &[(r0[0], r0[1]), (r0[1], r0[0]), (x_re, r1[1]), (x_im, r1[0])],
            p,
            p_inv,
        ),
        reference_sos(&[(d[0], r1[0]), (d[1], negp(r1[1], p))], p, p_inv),
        reference_sos(&[(d[0], r1[1]), (d[1], r1[0])], p, p_inv),
    ]
}

/// Twelve canonical Fp values in repr(C) Fp12 order.
type Fp12Limbs = [[u64; 4]; 12];

/// The sosd6 row lists of `Fp12::mul_by_034_assign`: with `f = a + b*w`
/// (`a = f[0..6]`, `b = f[6..12]`), `c = (c0, c3, c4)` as (re, im) pairs,
/// x3 = xi*c3, x4 = xi*c4, each output Fp2 is a dual-lane T = 6 sum of
/// three Fp2 products (the same negp folding as the fp6 oracle).
fn reference_fp12_034(f: &Fp12Limbs, c: &[[u64; 4]; 6], p: [u64; 4], p_inv: u64) -> Fp12Limbs {
    let (x3re, x3im) = reference_xi(c[2], c[3], p);
    let (x4re, x4im) = reference_xi(c[4], c[5], p);
    let fp2 = |i: usize| (f[2 * i], f[2 * i + 1]);
    let (a0, a1, a2) = (fp2(0), fp2(1), fp2(2));
    let (b0, b1, b2) = (fp2(3), fp2(4), fp2(5));
    let c0 = (c[0], c[1]);
    let c3 = (c[2], c[3]);
    let c4 = (c[4], c[5]);
    let x3 = (x3re, x3im);
    let x4 = (x4re, x4im);
    // (x, y) product lists per output component, repr(C) order.
    let rows = [
        [(a0, c0), (b1, x4), (b2, x3)],
        [(a1, c0), (b0, c3), (b2, x4)],
        [(a2, c0), (b0, c4), (b1, c3)],
        [(a0, c3), (a2, x4), (b0, c0)],
        [(a0, c4), (a1, c3), (b1, c0)],
        [(a1, c4), (a2, c3), (b2, c0)],
    ];
    let mut out = [[0u64; 4]; 12];
    for (component, products) in rows.iter().enumerate() {
        let mut real_pairs = Vec::new();
        let mut imag_pairs = Vec::new();
        for ((x_re, x_im), (y_re, y_im)) in products {
            real_pairs.push((*x_re, *y_re));
            real_pairs.push((*x_im, negp(*y_im, p)));
            imag_pairs.push((*x_re, *y_im));
            imag_pairs.push((*x_im, *y_re));
        }
        out[2 * component] = reference_sos(&real_pairs, p, p_inv);
        out[2 * component + 1] = reference_sos(&imag_pairs, p, p_inv);
    }
    out
}

/// `a - b mod p` for canonical operands (add p back on borrow).
fn sub_mod(a: [u64; 4], b: [u64; 4], p: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for k in 0..4 {
        let (mid, b1) = a[k].overflowing_sub(b[k]);
        let (low, b2) = mid.overflowing_sub(borrow as u64);
        out[k] = low;
        borrow = b1 | b2;
    }
    if borrow {
        let mut carry = false;
        for k in 0..4 {
            let (mid, c1) = out[k].overflowing_add(p[k]);
            let (sum, c2) = mid.overflowing_add(carry as u64);
            out[k] = sum;
            carry = c1 | c2;
        }
    }
    out
}

/// `a + b mod p` for canonical operands.
fn add_mod(a: [u64; 4], b: [u64; 4], p: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut carry = false;
    for k in 0..4 {
        let (mid, c1) = a[k].overflowing_add(b[k]);
        let (sum, c2) = mid.overflowing_add(carry as u64);
        out[k] = sum;
        carry = c1 | c2;
    }
    assert!(!carry, "canonical sum < 2p < 2^256");
    if gte(&out, &p) {
        let mut borrow = false;
        for k in 0..4 {
            let (mid, b1) = out[k].overflowing_sub(p[k]);
            let (low, b2) = mid.overflowing_sub(borrow as u64);
            out[k] = low;
            borrow = b1 | b2;
        }
        assert!(!borrow);
    }
    out
}

/// The sosd8/sosd6 row lists of the production `Fp12::square_in_place`
/// (composed reference): res0 = a^2 + v*b^2 over three T = 8 dual-lane sums,
/// res1 = (2a)*b over three T = 6, the same negp folding as the other
/// composed oracles.
/// One Fp2 value as an (re, im) tuple of limb arrays.
type Fp2Val = ([u64; 4], [u64; 4]);

fn reference_fp12_sqr_composed(f: &Fp12Limbs, p: [u64; 4], p_inv: u64) -> Fp12Limbs {
    let fp2 = |i: usize| (f[2 * i], f[2 * i + 1]);
    let (a0, a1, a2) = (fp2(0), fp2(1), fp2(2));
    let (b0, b1, b2) = (fp2(3), fp2(4), fp2(5));
    let dbl = |w: ([u64; 4], [u64; 4])| (double_mod(w.0, p), double_mod(w.1, p));
    let xi = |w: ([u64; 4], [u64; 4])| reference_xi(w.0, w.1, p);
    let da0 = dbl(a0);
    let da1 = dbl(a1);
    let da2 = dbl(a2);
    let g = dbl(b0);
    let x = xi(da1);
    let e = xi(a2);
    let y = xi(b1);
    let h = xi(b2);
    let z = xi(g);
    let ff = dbl(y);
    let rows: [Vec<(Fp2Val, Fp2Val)>; 6] = [
        vec![(a0, a0), (x, a2), (y, b1), (z, b2)],
        vec![(da0, a1), (e, a2), (b0, b0), (ff, b2)],
        vec![(a1, a1), (da0, a2), (g, b1), (h, b2)],
        vec![(da0, b0), (da1, h), (da2, y)],
        vec![(da0, b1), (da1, b0), (da2, h)],
        vec![(da0, b2), (da1, b1), (da2, b0)],
    ];
    let mut out = [[0u64; 4]; 12];
    for (component, products) in rows.iter().enumerate() {
        let mut real_pairs = Vec::new();
        let mut imag_pairs = Vec::new();
        for ((x_re, x_im), (y_re, y_im)) in products {
            real_pairs.push((*x_re, *y_re));
            real_pairs.push((*x_im, negp(*y_im, p)));
            imag_pairs.push((*x_re, *y_im));
            imag_pairs.push((*x_im, *y_re));
        }
        out[2 * component] = reference_sos(&real_pairs, p, p_inv);
        out[2 * component + 1] = reference_sos(&imag_pairs, p, p_inv);
    }
    out
}

/// The lazy double-width reference for the fp12_sqr schedule: mirrors the
/// kernel's DAG stage for stage over 512-bit values and asserts every
/// documented intermediate bound (the mcl isLtQuad argument made explicit).
mod lazy {
    use super::{Fp12Limbs, add_mod, double_mod, gte, reference_xi, sub_mod};

    /// 512-bit little-endian value.
    pub type U512 = [u64; 8];

    fn high4(x: U512) -> [u64; 4] {
        [x[4], x[5], x[6], x[7]]
    }

    fn lt(a: U512, b: U512) -> bool {
        for k in (0..8).rev() {
            if a[k] != b[k] {
                return a[k] < b[k];
            }
        }
        false
    }

    /// p * 2^256: the double-width guard modulus.
    fn pk(p: [u64; 4]) -> U512 {
        [0, 0, 0, 0, p[0], p[1], p[2], p[3]]
    }

    fn add512(a: U512, b: U512) -> (U512, bool) {
        let mut out = [0u64; 8];
        let mut carry = false;
        for k in 0..8 {
            let (mid, c1) = a[k].overflowing_add(b[k]);
            let (sum, c2) = mid.overflowing_add(carry as u64);
            out[k] = sum;
            carry = c1 | c2;
        }
        (out, carry)
    }

    fn sub512(a: U512, b: U512) -> (U512, bool) {
        let mut out = [0u64; 8];
        let mut borrow = false;
        for k in 0..8 {
            let (mid, b1) = a[k].overflowing_sub(b[k]);
            let (low, b2) = mid.overflowing_sub(borrow as u64);
            out[k] = low;
            borrow = b1 | b2;
        }
        (out, borrow)
    }

    /// Raw 4x4 -> 512-bit product (never overflows by construction).
    fn mul_wide(a: [u64; 4], b: [u64; 4]) -> U512 {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 {
                let v = out[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
                out[i + j] = v as u64;
                carry = v >> 64;
            }
            out[i + 4] = carry as u64;
        }
        out
    }

    /// Exact subtraction: the schedule's provably nonnegative rows. Asserts
    /// the mask never fires.
    fn sub_exact(a: U512, b: U512) -> U512 {
        let (out, borrow) = sub512(a, b);
        assert!(!borrow, "exact double-width subtraction borrowed");
        out
    }

    /// Guarded subtraction mod p*2^256: p joins the high limbs on borrow.
    /// Asserts the guarded result lands below p*2^256.
    fn gsub(a: U512, b: U512, p: [u64; 4]) -> U512 {
        let (out, borrow) = sub512(a, b);
        if !borrow {
            return out;
        }
        assert!(lt(b, pk(p)), "borrowing subtrahend must be below p*2^256");
        let (fixed, carry) = add512(out, pk(p));
        assert!(carry, "the fix-up cancels the borrow");
        assert!(lt(fixed, pk(p)), "guarded difference below p*2^256");
        fixed
    }

    /// Guarded addition mod p*2^256: p leaves the high limbs when they
    /// reach p. Asserts no 2^512 overflow and the guarded bound.
    fn gadd(a: U512, b: U512, p: [u64; 4]) -> U512 {
        let (sum, carry) = add512(a, b);
        assert!(!carry, "double-width addition stays below 2^512");
        let high = high4(sum);
        if !gte(&high, &p) {
            return sum;
        }
        let (fixed, borrow) = sub512(sum, pk(p));
        assert!(!borrow);
        assert!(lt(fixed, pk(p)), "guarded sum below p*2^256");
        fixed
    }

    /// The nine-fold xi step: 9x + y mod p*2^256 with a canonical high half.
    /// Mirrors the kernel exactly: exact low half with its carry limb, high
    /// half 9*xH + yH + carry < 10p reduced by the mu quotient estimate.
    fn nine(x: U512, y: U512, p: [u64; 4], mu: u64) -> U512 {
        assert!(
            !gte(&high4(x), &p) && !gte(&high4(y), &p),
            "nine-fold operands below p*2^256 (high halves below p)",
        );
        // Low half: l = 9*xL + yL over five limbs.
        let mut l = [0u64; 5];
        let mut carry: u128 = 0;
        for k in 0..4 {
            let v = 9u128 * x[k] as u128 + y[k] as u128 + carry;
            l[k] = v as u64;
            carry = v >> 64;
        }
        l[4] = carry as u64;
        assert!(l[4] <= 10, "low-half carry limb at most 10");
        // High half: v = 9*xH + yH + l4 over five limbs, < 10p.
        let mut v = [0u64; 5];
        let mut carry: u128 = l[4] as u128;
        for k in 0..4 {
            let t = 9u128 * x[4 + k] as u128 + y[4 + k] as u128 + carry;
            v[k] = t as u64;
            carry = t >> 64;
        }
        v[4] = carry as u64;
        // value < 10p check: 10p over five limbs.
        let mut ten_p = [0u64; 5];
        let mut carry: u128 = 0;
        for k in 0..4 {
            let t = 10u128 * p[k] as u128 + carry;
            ten_p[k] = t as u64;
            carry = t >> 64;
        }
        ten_p[4] = carry as u64;
        let lt5 = |a: [u64; 5], b: [u64; 5]| {
            for k in (0..5).rev() {
                if a[k] != b[k] {
                    return a[k] < b[k];
                }
            }
            false
        };
        assert!(lt5(v, ten_p), "high half value below 10p");
        // mu quotient estimate, exactly the kernel's shape.
        let e = (v[4] << 4) | (v[3] >> 60);
        assert!(e < 32, "E fits five bits");
        let q = ((e as u128 * mu as u128) >> 58) as u64;
        assert!(q <= 10, "estimated quotient at most 10");
        let mut qp = [0u64; 5];
        let mut carry: u128 = 0;
        for k in 0..4 {
            let t = q as u128 * p[k] as u128 + carry;
            qp[k] = t as u64;
            carry = t >> 64;
        }
        qp[4] = carry as u64;
        let mut h = [0u64; 5];
        let mut borrow = false;
        for k in 0..5 {
            let (mid, b1) = v[k].overflowing_sub(qp[k]);
            let (low, b2) = mid.overflowing_sub(borrow as u64);
            h[k] = low;
            borrow = b1 | b2;
        }
        assert!(!borrow, "the quotient estimate never overshoots");
        assert!(h[4] == 0, "value - q*p fits four limbs (< 1.33p)");
        let mut high = [h[0], h[1], h[2], h[3]];
        if gte(&high, &p) {
            let mut borrow = false;
            for k in 0..4 {
                let (mid, b1) = high[k].overflowing_sub(p[k]);
                let (low, b2) = mid.overflowing_sub(borrow as u64);
                high[k] = low;
                borrow = b1 | b2;
            }
            assert!(!borrow);
        }
        assert!(!gte(&high, &p), "nine-fold high half canonical");
        [l[0], l[1], l[2], l[3], high[0], high[1], high[2], high[3]]
    }

    /// Montgomery reduction of T < p*2^256: four cancel rounds, result < 2p,
    /// one conditional subtraction, canonical.
    fn mont_red(t_in: U512, p: [u64; 4], p_inv: u64) -> [u64; 4] {
        assert!(lt(t_in, pk(p)), "reduction precondition T < p*2^256");
        let mut t = t_in;
        for round in 0..4 {
            let m = t[round].wrapping_mul(p_inv);
            let mut carry: u128 = 0;
            for k in 0..4 {
                let v = t[round + k] as u128 + m as u128 * p[k] as u128 + carry;
                t[round + k] = v as u64;
                carry = v >> 64;
            }
            assert_eq!(t[round], 0, "the Montgomery factor cancels the low word");
            for word in t.iter_mut().skip(round + 4) {
                let v = *word as u128 + carry;
                *word = v as u64;
                carry = v >> 64;
            }
            assert_eq!(carry, 0, "T + m*p*2^(64r) < 2p*2^256 never leaves T7");
        }
        let mut out = [t[4], t[5], t[6], t[7]];
        // out < 2p: at most one subtraction reaches canonical.
        if gte(&out, &p) {
            let mut borrow = false;
            for k in 0..4 {
                let (mid, b1) = out[k].overflowing_sub(p[k]);
                let (low, b2) = mid.overflowing_sub(borrow as u64);
                out[k] = low;
                borrow = b1 | b2;
            }
            assert!(!borrow);
        }
        assert!(
            !gte(&out, &p),
            "reduced coefficient canonical (< 2p before csub)"
        );
        out
    }

    /// Four-limb staged sum (no reduction); asserts it fits 256 bits.
    fn add4(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        let mut carry = false;
        for k in 0..4 {
            let (mid, c1) = a[k].overflowing_add(b[k]);
            let (sum, c2) = mid.overflowing_add(carry as u64);
            out[k] = sum;
            carry = c1 | c2;
        }
        assert!(!carry, "staged sum fits four limbs (s < 4p < 2^256)");
        out
    }

    /// One lazy Fp6Dbl mulPre: Karatsuba at both levels, the six coefficient
    /// lanes returned as 512-bit values below p*2^256 with canonical high
    /// halves (no reduction). Operands canonical. Lane order: (a, b, c) as
    /// (re, im) pairs.
    fn fp6dbl_mulpre(
        x: &[[u64; 4]; 6],
        y: &[[u64; 4]; 6],
        p: [u64; 4],
        mu: u64,
    ) -> [(U512, U512); 3] {
        for value in x.iter().chain(y.iter()) {
            assert!(!gte(value, &p), "product operands canonical");
        }
        // Stage sides: blocks c0, c1, c2, c1+c2, c0+c1, c0+c2 as
        // (re, im, re+im).
        let stage = |src: &[[u64; 4]; 6]| -> Vec<([u64; 4], [u64; 4], [u64; 4])> {
            let single = |i: usize| (src[2 * i], src[2 * i + 1], add4(src[2 * i], src[2 * i + 1]));
            let mut blocks = vec![single(0), single(1), single(2)];
            for (i, j) in [(1, 2), (0, 1), (0, 2)] {
                let (ar, ai, as_) = blocks[i];
                let (br, bi, bs) = blocks[j];
                blocks.push((add4(ar, br), add4(ai, bi), add4(as_, bs)));
            }
            blocks
        };
        let bx = stage(x);
        let by = stage(y);
        // Products and Karatsuba assembly per block pair.
        let mut prod: Vec<(U512, U512)> = Vec::new(); // (d0 = a-lane, d1 = b-lane)
        for k in 0..6 {
            let d1 = mul_wide(bx[k].2, by[k].2);
            let d0 = mul_wide(bx[k].0, by[k].0);
            let d2 = mul_wide(bx[k].1, by[k].1);
            let d1 = sub_exact(sub_exact(d1, d0), d2); // ad + bc
            let d0 = gsub(d0, d2, p); // ac - bd mod p*2^256
            prod.push((d0, d1));
        }
        let (ad, be, cf) = (prod[0], prod[1], prod[2]);
        let (mut za, mut zb, mut zc) = (prod[3], prod[4], prod[5]);
        // Cross terms: a-lanes guarded, b-lanes exact.
        za.0 = gsub(za.0, be.0, p);
        za.1 = sub_exact(za.1, be.1);
        za.0 = gsub(za.0, cf.0, p);
        za.1 = sub_exact(za.1, cf.1);
        zb.0 = gsub(zb.0, ad.0, p);
        zb.1 = sub_exact(zb.1, ad.1);
        zb.0 = gsub(zb.0, be.0, p);
        zb.1 = sub_exact(zb.1, be.1);
        zc.0 = gsub(zc.0, ad.0, p);
        zc.1 = sub_exact(zc.1, ad.1);
        zc.0 = gsub(zc.0, cf.0, p);
        zc.1 = sub_exact(zc.1, cf.1);
        // Negations feeding the nine-fold walk.
        let nb0 = gsub([0; 8], za.1, p);
        let nb1 = gsub([0; 8], cf.1, p);
        // xi on ZA and CF, then the final additions.
        let s1 = nine(za.0, nb0, p, mu);
        let s2 = nine(za.1, za.0, p, mu);
        let s3 = nine(cf.0, nb1, p, mu);
        let s4 = nine(cf.1, cf.0, p, mu);
        let out_a = (gadd(s1, ad.0, p), gadd(s2, ad.1, p));
        let out_b = (gadd(zb.0, s3, p), gadd(zb.1, s4, p));
        let out_c = (gadd(zc.0, be.0, p), gadd(zc.1, be.1, p));
        [out_a, out_b, out_c]
    }

    /// One lazy Fp6 product: [`fp6dbl_mulpre`] plus one reduction per output
    /// coefficient.
    fn fp6dbl_mul(
        x: &[[u64; 4]; 6],
        y: &[[u64; 4]; 6],
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
    ) -> [[u64; 4]; 6] {
        let lanes = fp6dbl_mulpre(x, y, p, mu);
        core::array::from_fn(|i| {
            let (re, im) = lanes[i / 2];
            mont_red(if i % 2 == 0 { re } else { im }, p, p_inv)
        })
    }

    /// The whole lazy Fp12 square, the kernel's stage order.
    pub fn reference_fp12_sqr(f: &Fp12Limbs, p: [u64; 4], p_inv: u64, mu: u64) -> Fp12Limbs {
        let a: [[u64; 4]; 6] = core::array::from_fn(|i| f[i]);
        let b: [[u64; 4]; 6] = core::array::from_fn(|i| f[6 + i]);
        // Iteration 0 prologue: t0 = a + b, t1 = b*v + a.
        let (xr, xi_) = reference_xi(b[4], b[5], p);
        let t0: [[u64; 4]; 6] = core::array::from_fn(|i| add_mod(a[i], b[i], p));
        let t1: [[u64; 4]; 6] = [
            add_mod(xr, a[0], p),
            add_mod(xi_, a[1], p),
            add_mod(b[0], a[2], p),
            add_mod(b[1], a[3], p),
            add_mod(b[2], a[4], p),
            add_mod(b[3], a[5], p),
        ];
        let v = fp6dbl_mul(&a, &b, p, p_inv, mu);
        // Iteration 1 prologue: W = V*v + V, y.b = 2V.
        let (wr, wi) = reference_xi(v[4], v[5], p);
        let w: [[u64; 4]; 6] = [
            add_mod(wr, v[0], p),
            add_mod(wi, v[1], p),
            add_mod(v[0], v[2], p),
            add_mod(v[1], v[3], p),
            add_mod(v[2], v[4], p),
            add_mod(v[3], v[5], p),
        ];
        let yb: [[u64; 4]; 6] = core::array::from_fn(|i| double_mod(v[i], p));
        let u = fp6dbl_mul(&t0, &t1, p, p_inv, mu);
        let ya: [[u64; 4]; 6] = core::array::from_fn(|i| sub_mod(u[i], w[i], p));
        core::array::from_fn(|i| if i < 6 { ya[i] } else { yb[i - 6] })
    }

    /// The whole lazy Fp12 product, the fp12_mul kernel's stage order:
    /// three Fp6Dbl mulPre (AC, BD, CR), z.a = mod(mulVadd(BD, AC)) on
    /// doubles, z.b = mod(CR - AC - BD) with every lane guarded (the parked
    /// lanes are congruences mod p*2^256, not exact values).
    pub fn reference_fp12_mul(
        a: &Fp12Limbs,
        b: &Fp12Limbs,
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
    ) -> Fp12Limbs {
        let a0: [[u64; 4]; 6] = core::array::from_fn(|i| a[i]);
        let a1: [[u64; 4]; 6] = core::array::from_fn(|i| a[6 + i]);
        let b0: [[u64; 4]; 6] = core::array::from_fn(|i| b[i]);
        let b1: [[u64; 4]; 6] = core::array::from_fn(|i| b[6 + i]);
        let t1: [[u64; 4]; 6] = core::array::from_fn(|i| add_mod(a0[i], a1[i], p));
        let t2: [[u64; 4]; 6] = core::array::from_fn(|i| add_mod(b0[i], b1[i], p));
        let ac = fp6dbl_mulpre(&a0, &b0, p, mu);
        let bd = fp6dbl_mulpre(&a1, &b1, p, mu);
        let cr = fp6dbl_mulpre(&t1, &t2, p, mu);
        // z.a = mulVadd(BD, AC) = (xi*BD.c + AC.a, BD.a + AC.b, BD.b + AC.c).
        let nbc = gsub([0; 8], bd[2].1, p);
        let s1 = nine(bd[2].0, nbc, p, mu);
        let s2 = nine(bd[2].1, bd[2].0, p, mu);
        let za = [
            (gadd(s1, ac[0].0, p), gadd(s2, ac[0].1, p)),
            (gadd(bd[0].0, ac[1].0, p), gadd(bd[0].1, ac[1].1, p)),
            (gadd(bd[1].0, ac[2].0, p), gadd(bd[1].1, ac[2].1, p)),
        ];
        // z.b = CR - AC - BD, all six lanes guarded.
        let zb: [(U512, U512); 3] = core::array::from_fn(|k| {
            (
                gsub(gsub(cr[k].0, ac[k].0, p), bd[k].0, p),
                gsub(gsub(cr[k].1, ac[k].1, p), bd[k].1, p),
            )
        });
        core::array::from_fn(|i| {
            let (re, im) = if i < 6 { za[i / 2] } else { zb[(i - 6) / 2] };
            mont_red(if i % 2 == 0 { re } else { im }, p, p_inv)
        })
    }

    /// One lazy Fp2Dbl square, the cyc_sqr kernel's staged shape (mcl
    /// Fp2Dbl::sqrPre, complex method): all four operand rows canonical
    /// (a - b, a + b, 2b, a mod p), lanes ((a-b)(a+b), 2b*a) < p^2.
    fn fp2dbl_sqrpre(x: &[[u64; 4]; 2], p: [u64; 4]) -> (U512, U512) {
        for value in x {
            assert!(!gte(value, &p), "square operand canonical");
        }
        let d = sub_mod(x[0], x[1], p);
        let s = add_mod(x[0], x[1], p);
        let w = double_mod(x[1], p);
        let out = (mul_wide(d, s), mul_wide(w, x[0]));
        let pk2 = pk(p);
        assert!(
            lt(out.0, pk2) && lt(out.1, pk2),
            "sqrPre lanes below p*2^256 (canonical rows give < p^2)",
        );
        out
    }

    /// The whole lazy cyclotomic square, the cyc_sqr kernel's stage order:
    /// three lazy Fp4 squares (T2 = xi*T1 + T0 completed inside the nine
    /// step via folded y operands, U = TS - T0 - T1 guarded, xi*t5 folded
    /// double-width), then the single-width z-combines with the
    /// subtractions as adds of negp images.
    pub fn reference_cyc_sqr(f: &Fp12Limbs, p: [u64; 4], p_inv: u64, mu: u64) -> Fp12Limbs {
        let fp2 = |i: usize| [f[2 * i], f[2 * i + 1]];
        let (r0, r4, r3) = (fp2(0), fp2(1), fp2(2));
        let (r2, r1, r5) = (fp2(3), fp2(4), fp2(5));
        let zero = [0u64; 4];
        let mut t = [[zero; 2]; 6]; // t0, t1, t2, t3, t4, xi*t5
        for (k, (x0, x1)) in [(r0, r1), (r2, r3), (r4, r5)].into_iter().enumerate() {
            let s = [add_mod(x0[0], x1[0], p), add_mod(x0[1], x1[1], p)];
            let t0d = fp2dbl_sqrpre(&x0, p);
            let t1d = fp2dbl_sqrpre(&x1, p);
            let tsd = fp2dbl_sqrpre(&s, p);
            let ya = gsub(t0d.0, t1d.1, p);
            let nbb = gsub([0; 8], t0d.1, p);
            let yb = gsub(t1d.0, nbb, p);
            let t2a = nine(t1d.0, ya, p, mu);
            let t2b = nine(t1d.1, yb, p, mu);
            let ua = gsub(gsub(tsd.0, t0d.0, p), t1d.0, p);
            let ub = gsub(gsub(tsd.1, t0d.1, p), t1d.1, p);
            t[2 * k] = [mont_red(t2a, p, p_inv), mont_red(t2b, p, p_inv)];
            t[2 * k + 1] = if k < 2 {
                [mont_red(ua, p, p_inv), mont_red(ub, p, p_inv)]
            } else {
                // xi*t5 folded onto the double-width U_2.
                let nb = gsub([0; 8], ub, p);
                [
                    mont_red(nine(ua, nb, p, mu), p, p_inv),
                    mont_red(nine(ub, ua, p, mu), p, p_inv),
                ]
            };
        }
        let combine = |tv: [[u64; 4]; 2], rv: [[u64; 4]; 2], sub: bool| -> [[u64; 4]; 2] {
            core::array::from_fn(|h| {
                let opener = if sub {
                    // The kernel's shape: t - r as t + (p - r) mod p.
                    add_mod(tv[h], sub_mod([0; 4], rv[h], p), p)
                } else {
                    add_mod(tv[h], rv[h], p)
                };
                add_mod(double_mod(opener, p), tv[h], p)
            })
        };
        let z0 = combine(t[0], r0, true);
        let z1 = combine(t[1], r1, false);
        let z2 = combine(t[5], r2, false);
        let z3 = combine(t[4], r3, true);
        let z4 = combine(t[2], r4, true);
        let z5 = combine(t[3], r5, false);
        [
            z0[0], z0[1], z4[0], z4[1], z3[0], z3[1], z2[0], z2[1], z1[0], z1[1], z5[0], z5[1],
        ]
    }
}

fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for j in (0..4).rev() {
        if a[j] != b[j] {
            return a[j] > b[j];
        }
    }
    true
}

fn next_raw(state: &mut u64) -> [u64; 4] {
    core::array::from_fn(|_| {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    })
}

fn next_residue(state: &mut u64) -> [u64; 4] {
    loop {
        let value = next_raw(state);
        if !gte(&value, &BN254_P) {
            return value;
        }
    }
}

/// Operands that maximize/minimize carries through both chains.
fn edge_corpus() -> Vec<[u64; 4]> {
    let p = BN254_P;
    let p_minus = |k: u64| {
        let mut value = p;
        value[0] -= k; // p[0] is odd and > 2, safe for k <= 2
        value
    };
    vec![
        [0, 0, 0, 0],
        [1, 0, 0, 0],
        [2, 0, 0, 0],
        p_minus(1),
        p_minus(2),
        // Densest sub-p values: all-ones low limbs under the top limb of p.
        [u64::MAX, u64::MAX, u64::MAX, p[3] - 1],
        [u64::MAX, 0, u64::MAX, 0],
        [0, u64::MAX, 0, p[3] - 1],
        // Montgomery R mod p and R^2 mod p (hot in production conversions).
        [
            0xd35d438dc58f0d9d,
            0x0a78eb28f5c70b3d,
            0x666ea36f7879462c,
            0x0e0a77c19a07df2f,
        ],
        [
            0xf32cfc5b538afa89,
            0xb5e71911d44501fb,
            0x47ab1eff0a417ff6,
            0x06d89f71cab8351f,
        ],
    ]
}

#[test]
fn mul_schedule_matches_reference_on_edge_corpus() {
    let corpus = edge_corpus();
    for (i, a) in corpus.iter().enumerate() {
        for (j, b) in corpus.iter().enumerate() {
            assert_eq!(
                interpret_mont4_mul(*a, *b, BN254_P, BN254_P_INV),
                reference_mont_mul(*a, *b, BN254_P, BN254_P_INV),
                "edge pair ({i}, {j})",
            );
        }
    }
}

#[test]
fn sqr_schedule_matches_mul_and_reference_on_edge_corpus() {
    for (i, a) in edge_corpus().iter().enumerate() {
        let squared = interpret_mont4_sqr(*a, BN254_P, BN254_P_INV);
        assert_eq!(
            squared,
            reference_mont_mul(*a, *a, BN254_P, BN254_P_INV),
            "edge square {i} vs reference",
        );
        assert_eq!(
            squared,
            interpret_mont4_mul(*a, *a, BN254_P, BN254_P_INV),
            "edge square {i} vs mul schedule",
        );
    }
}

#[test]
fn a64_schedule_matches_reference_on_edge_corpus() {
    let corpus = edge_corpus();
    for (i, a) in corpus.iter().enumerate() {
        for (j, b) in corpus.iter().enumerate() {
            assert_eq!(
                interpret_mont4_a64(*a, *b, BN254_P, BN254_P_INV),
                reference_mont_mul(*a, *b, BN254_P, BN254_P_INV),
                "edge pair ({i}, {j})",
            );
        }
    }
}

#[test]
fn schedules_match_reference_on_random_residues() {
    let mut state = 0x0123_4567_89ab_cdefu64;
    for case in 0..20_000 {
        let a = next_residue(&mut state);
        let b = next_residue(&mut state);
        let product = interpret_mont4_mul(a, b, BN254_P, BN254_P_INV);
        assert_eq!(
            product,
            reference_mont_mul(a, b, BN254_P, BN254_P_INV),
            "case {case}",
        );
        assert!(!gte(&product, &BN254_P), "unreduced product, case {case}");
        assert_eq!(
            interpret_mont4_sqr(a, BN254_P, BN254_P_INV),
            reference_mont_mul(a, a, BN254_P, BN254_P_INV),
            "square case {case}",
        );
        assert_eq!(
            interpret_mont4_a64(a, b, BN254_P, BN254_P_INV),
            product,
            "a64 case {case}",
        );
    }
}

/// The AArch64 leaf's schedule tolerates a first operand up to 2^256 while
/// `b` stays below p (`src/fp/aarch64.rs`): its single-chain rows absorb the
/// wider products, the fifth accumulator word plus the CSET bit giving the
/// reduction row 2^321 of headroom. This is spare margin, not a relied-on
/// path -- `Fp::from_raw` reduces before the leaf and the wrapper contract
/// requires both operands below p. The x86-64 dual-chain schedule is NOT in
/// this test: its 2^320 bound needs both operands below p, and the
/// interpreter's flags-clear assertions fire for a widened `a`.
#[test]
fn a64_schedule_accepts_widened_first_operand() {
    let mut state = 0xc0de_1234_5678_9abcu64;
    for case in 0..2_000 {
        let a = next_raw(&mut state);
        let b = next_residue(&mut state);
        assert_eq!(
            interpret_mont4_a64(a, b, BN254_P, BN254_P_INV),
            reference_mont_mul(a, b, BN254_P, BN254_P_INV),
            "widened case {case}",
        );
    }
}

#[test]
fn mul_schedule_is_commutative() {
    let mut state = 0xfeed_face_dead_beefu64;
    for _ in 0..2_000 {
        let a = next_residue(&mut state);
        let b = next_residue(&mut state);
        assert_eq!(
            interpret_mont4_mul(a, b, BN254_P, BN254_P_INV),
            interpret_mont4_mul(b, a, BN254_P, BN254_P_INV),
        );
    }
}

/// The production pair counts (sos2/sos4 single lane, sosd2..sosd8 lanes)
/// plus the largest count the kernel contract covers. Counts are even: the
/// inner walk takes two pairs per iteration, and the interpreter's trip
/// proof rejects odd counts.
const SOS_PAIR_COUNTS: [usize; 5] = [2, 4, 6, 8, 10];

#[test]
fn sos_schedule_matches_reference_on_random_pairs() {
    let mut state = 0x1f83_d9ab_fb41_bd6bu64;
    for &count in &SOS_PAIR_COUNTS {
        for case in 0..2_000 {
            let pairs: Vec<([u64; 4], [u64; 4])> = (0..count)
                .map(|_| (next_residue(&mut state), next_residue(&mut state)))
                .collect();
            let out = interpret_sos(&pairs, BN254_P, BN254_P_INV);
            assert_eq!(
                out,
                reference_sos(&pairs, BN254_P, BN254_P_INV),
                "T = {count}, case {case}",
            );
            assert!(!gte(&out, &BN254_P), "unreduced output, T = {count}");
        }
    }
}

/// Operands may equal p (the `negp` image of zero); saturating every pair at
/// p maximizes the accumulator against the claimed 2^325 bound.
#[test]
fn sos_schedule_matches_reference_on_edge_pairs() {
    let corpus = {
        let mut corpus = edge_corpus();
        corpus.push(BN254_P);
        corpus
    };
    for (i, a) in corpus.iter().enumerate() {
        for (j, b) in corpus.iter().enumerate() {
            for &count in &SOS_PAIR_COUNTS {
                let pairs = vec![(*a, *b); count];
                assert_eq!(
                    interpret_sos(&pairs, BN254_P, BN254_P_INV),
                    reference_sos(&pairs, BN254_P, BN254_P_INV),
                    "edge pair ({i}, {j}), T = {count}",
                );
            }
        }
    }
}

/// A product padded with a zero pair is a Montgomery product: the rolled
/// loop must agree with the straight-line mul schedule everywhere.
#[test]
fn sos_schedule_with_zero_padded_pair_matches_mul_schedule() {
    let mut state = 0x4528_21e6_38d0_1377u64;
    for case in 0..5_000 {
        let a = next_residue(&mut state);
        let b = next_residue(&mut state);
        assert_eq!(
            interpret_sos(&[(a, b), ([0; 4], [0; 4])], BN254_P, BN254_P_INV),
            interpret_mont4_mul(a, b, BN254_P, BN254_P_INV),
            "case {case}",
        );
    }
}

#[test]
fn sosd2_schedule_matches_reference_on_random_residues() {
    let mut state = 0x2b7e_1516_28ae_d2a6u64;
    for case in 0..2_000 {
        let x0 = next_residue(&mut state);
        let x1 = next_residue(&mut state);
        let y0 = next_residue(&mut state);
        let y1 = next_residue(&mut state);
        let (lane0, lane1) = interpret_sosd2_small(x0, x1, y0, y1, BN254_P, BN254_P_INV);
        let (ref0, ref1) = reference_sosd2(x0, x1, y0, y1, BN254_P, BN254_P_INV);
        assert_eq!((lane0, lane1), (ref0, ref1), "case {case}");
        assert!(!gte(&lane0, &BN254_P), "unreduced lane0, case {case}");
        assert!(!gte(&lane1, &BN254_P), "unreduced lane1, case {case}");
    }
}

/// Operands may equal p (the `negp` image of zero maximizes ny1); the edge
/// palette drives the extreme carries through both lanes' chains.
#[test]
fn sosd2_schedule_matches_reference_on_edge_operands() {
    let corpus = {
        let mut corpus = edge_corpus();
        corpus.push(BN254_P);
        corpus
    };
    for (i, a) in corpus.iter().enumerate() {
        for (j, b) in corpus.iter().enumerate() {
            for (x0, x1, y0, y1) in [(*a, *b, *b, *a), (*a, *a, *b, *b), (*b, *a, *b, *a)] {
                assert_eq!(
                    interpret_sosd2_small(x0, x1, y0, y1, BN254_P, BN254_P_INV),
                    reference_sosd2(x0, x1, y0, y1, BN254_P, BN254_P_INV),
                    "edge pair ({i}, {j})",
                );
            }
        }
    }
}

/// The dedicated dual-lane schedule and the rolled SoS schedule must agree
/// lane for lane: both claim the same Longa Alg. 2 semantics.
#[test]
fn sosd2_schedule_matches_sos_schedule() {
    let mut state = 0x3243_f6a8_885a_308du64;
    for case in 0..2_000 {
        let x0 = next_residue(&mut state);
        let x1 = next_residue(&mut state);
        let y0 = next_residue(&mut state);
        let y1 = next_residue(&mut state);
        let (lane0, lane1) = interpret_sosd2_small(x0, x1, y0, y1, BN254_P, BN254_P_INV);
        let mut ny1 = [0u64; 4];
        let mut borrow = false;
        for k in 0..4 {
            let (mid, b1) = BN254_P[k].overflowing_sub(y1[k]);
            let (low, b2) = mid.overflowing_sub(borrow as u64);
            ny1[k] = low;
            borrow = b1 | b2;
        }
        assert!(!borrow);
        assert_eq!(
            lane0,
            interpret_sos(&[(x0, y0), (x1, ny1)], BN254_P, BN254_P_INV),
            "lane0 case {case}",
        );
        assert_eq!(
            lane1,
            interpret_sos(&[(x0, y1), (x1, y0)], BN254_P, BN254_P_INV),
            "lane1 case {case}",
        );
    }
}

fn next_fp6(state: &mut u64) -> Fp6Limbs {
    core::array::from_fn(|_| next_residue(state))
}

#[test]
fn sosd6_schedule_matches_reference_on_random_residues() {
    let mut state = 0xc0ac_29b7_c97c_50ddu64;
    for case in 0..2_000 {
        let xs = next_fp6(&mut state);
        let ys = next_fp6(&mut state);
        let (lane0, lane1) = interpret_sosd6(&xs, &ys, BN254_P, BN254_P_INV);
        assert_eq!(
            (lane0, lane1),
            reference_sosd6(&xs, &ys, BN254_P, BN254_P_INV),
            "case {case}",
        );
        assert!(!gte(&lane0, &BN254_P), "unreduced lane0, case {case}");
        assert!(!gte(&lane1, &BN254_P), "unreduced lane1, case {case}");
    }
}

/// Operands may equal p (the `negp` image of zero); saturating slots at the
/// edge palette drives the extreme carries through both lanes' chains and
/// the shared top word.
#[test]
fn sosd6_schedule_matches_reference_on_edge_operands() {
    let corpus = {
        let mut corpus = edge_corpus();
        corpus.push(BN254_P);
        corpus
    };
    let mut state = 0x9c30_d539_2af2_6013u64;
    for (i, e) in corpus.iter().enumerate() {
        let uniform = ([*e; 6], [*e; 6]);
        assert_eq!(
            interpret_sosd6(&uniform.0, &uniform.1, BN254_P, BN254_P_INV),
            reference_sosd6(&uniform.0, &uniform.1, BN254_P, BN254_P_INV),
            "saturated edge {i}",
        );
        // Rotate the edge through every x and y slot against random fills.
        for slot in 0..12 {
            let mut xs = next_fp6(&mut state);
            let mut ys = next_fp6(&mut state);
            if slot < 6 {
                xs[slot] = *e;
            } else {
                ys[slot - 6] = *e;
            }
            assert_eq!(
                interpret_sosd6(&xs, &ys, BN254_P, BN254_P_INV),
                reference_sosd6(&xs, &ys, BN254_P, BN254_P_INV),
                "edge {i}, slot {slot}",
            );
        }
    }
}

/// The dedicated dual-lane T = 6 schedule and the rolled SoS schedule must
/// agree lane for lane: both claim the same Longa Alg. 2 semantics.
#[test]
fn sosd6_schedule_matches_sos_schedule() {
    let mut state = 0xbe54_66cf_34e9_0c6cu64;
    for case in 0..2_000 {
        let xs = next_fp6(&mut state);
        let ys = next_fp6(&mut state);
        let (lane0, lane1) = interpret_sosd6(&xs, &ys, BN254_P, BN254_P_INV);
        let mut pairs0 = Vec::new();
        let mut pairs1 = Vec::new();
        for i in 0..3 {
            pairs0.push((xs[2 * i], ys[2 * i]));
            pairs0.push((xs[2 * i + 1], negp(ys[2 * i + 1], BN254_P)));
            pairs1.push((xs[2 * i], ys[2 * i + 1]));
            pairs1.push((xs[2 * i + 1], ys[2 * i]));
        }
        assert_eq!(
            lane0,
            interpret_sos(&pairs0, BN254_P, BN254_P_INV),
            "lane0 case {case}",
        );
        assert_eq!(
            lane1,
            interpret_sos(&pairs1, BN254_P, BN254_P_INV),
            "lane1 case {case}",
        );
    }
}

#[test]
fn fp6_schedule_matches_reference_on_random_operands() {
    let mut state = 0x6a09_e667_f3bc_c908u64;
    for case in 0..500 {
        let a = next_fp6(&mut state);
        let b = next_fp6(&mut state);
        let out = interpret_fp6_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU);
        assert_eq!(
            out,
            reference_fp6_mul(&a, &b, BN254_P, BN254_P_INV),
            "case {case}",
        );
        for (i, component) in out.iter().enumerate() {
            assert!(
                !gte(component, &BN254_P),
                "unreduced output {i}, case {case}"
            );
        }
    }
}

/// Edge palette: every Fp slot cycles through the extreme corpus (zero, one,
/// p-1, dense sub-p limbs, Montgomery R and R^2), plus targeted xi edges --
/// b components with re = 0 and im = p-1 drive `9*re - im` maximally negative
/// (underflow without the +p route), im = 0 sends the negp rows to exactly p,
/// and re = p-1, im = 0 maximizes the 9A + C value against the 10p bound.
#[test]
fn fp6_schedule_matches_reference_on_edge_operands() {
    let corpus = edge_corpus();
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let mut state = 0xbb67_ae85_84ca_a73bu64;
    let mut cases: Vec<(Fp6Limbs, Fp6Limbs)> = Vec::new();
    // Rotate the corpus through all six slots of both operands.
    for (i, value) in corpus.iter().enumerate() {
        let mut a = next_fp6(&mut state);
        let mut b = next_fp6(&mut state);
        for slot in 0..6 {
            if (i + slot) % 2 == 0 {
                a[slot] = *value;
            } else {
                b[slot] = *value;
            }
        }
        cases.push((a, b));
    }
    // Targeted xi edges on b1 and b2 = the xi-scaled components.
    let zero = [0u64; 4];
    for (re, im) in [
        (zero, p_minus_one),
        (p_minus_one, zero),
        (zero, zero),
        (p_minus_one, p_minus_one),
    ] {
        let a = next_fp6(&mut state);
        cases.push((
            a,
            [
                next_residue(&mut state),
                next_residue(&mut state),
                re,
                im,
                re,
                im,
            ],
        ));
    }
    // All-extreme operands.
    cases.push(([zero; 6], [zero; 6]));
    cases.push(([p_minus_one; 6], [p_minus_one; 6]));
    for (index, (a, b)) in cases.iter().enumerate() {
        assert_eq!(
            interpret_fp6_mul(a, b, BN254_P, BN254_P_INV, BN254_MU),
            reference_fp6_mul(a, b, BN254_P, BN254_P_INV),
            "edge case {index}",
        );
    }
}

/// The fp6 leaf and the composed path must agree lane for lane: each output
/// component is the pair of T = 6 SoS lanes the production sosd6 dispatch
/// would compute from xi-prescaled operands.
#[test]
fn fp6_schedule_matches_composed_sos_schedule() {
    let mut state = 0x3c6e_f372_fe94_f82bu64;
    for case in 0..200 {
        let a = next_fp6(&mut state);
        let b = next_fp6(&mut state);
        let out = interpret_fp6_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU);
        let (x1re, x1im) = reference_xi(b[2], b[3], BN254_P);
        let (x2re, x2im) = reference_xi(b[4], b[5], BN254_P);
        let y: [[([u64; 4], [u64; 4]); 3]; 3] = [
            [(b[0], b[1]), (x2re, x2im), (x1re, x1im)],
            [(b[2], b[3]), (b[0], b[1]), (x2re, x2im)],
            [(b[4], b[5]), (b[2], b[3]), (b[0], b[1])],
        ];
        for component in 0..3 {
            let mut real_pairs = Vec::new();
            let mut imag_pairs = Vec::new();
            for i in 0..3 {
                let (y_re, y_im) = y[component][i];
                real_pairs.push((a[2 * i], y_re));
                real_pairs.push((a[2 * i + 1], negp(y_im, BN254_P)));
                imag_pairs.push((a[2 * i], y_im));
                imag_pairs.push((a[2 * i + 1], y_re));
            }
            assert_eq!(
                out[2 * component],
                interpret_sos(&real_pairs, BN254_P, BN254_P_INV),
                "real lane of component {component}, case {case}",
            );
            assert_eq!(
                out[2 * component + 1],
                interpret_sos(&imag_pairs, BN254_P, BN254_P_INV),
                "imag lane of component {component}, case {case}",
            );
        }
    }
}

fn next_fp12(state: &mut u64) -> Fp12Limbs {
    core::array::from_fn(|_| next_residue(state))
}

fn next_coeffs(state: &mut u64) -> [[u64; 4]; 6] {
    core::array::from_fn(|_| next_residue(state))
}

#[test]
fn fp12_034_schedule_matches_reference_on_random_operands() {
    let mut state = 0xa54f_f53a_5f1d_36f1u64;
    for case in 0..500 {
        let f = next_fp12(&mut state);
        let c = next_coeffs(&mut state);
        let want = reference_fp12_034(&f, &c, BN254_P, BN254_P_INV);
        let out = interpret_fp12_034(&f, &c, BN254_P, BN254_P_INV, BN254_MU, false);
        assert_eq!(out, want, "case {case}");
        for (i, component) in out.iter().enumerate() {
            assert!(
                !gte(component, &BN254_P),
                "unreduced output {i}, case {case}"
            );
        }
        assert_eq!(
            interpret_fp12_034(&f, &c, BN254_P, BN254_P_INV, BN254_MU, true),
            want,
            "in-place (z == f) case {case}",
        );
    }
}

/// Edge palette: the extreme corpus rotates through all twelve f slots and
/// all six coefficient slots; zero coefficients (c0, c3, c4, and all three
/// at once -- the line shapes ell() can degenerate to, and negp(0) = p
/// rows); f patterned as the first-iteration line_value output; targeted xi
/// edges on c3/c4 (re = 0, im = p-1 underflows 9re - im without the +p
/// route); all-extreme operands.
#[test]
fn fp12_034_schedule_matches_reference_on_edge_operands() {
    let corpus = edge_corpus();
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let zero = [0u64; 4];
    let mut state = 0x510e_527f_ade6_82d1u64;
    let mut cases: Vec<(Fp12Limbs, [[u64; 4]; 6])> = Vec::new();
    for (i, value) in corpus.iter().enumerate() {
        let mut f = next_fp12(&mut state);
        let mut c = next_coeffs(&mut state);
        for slot in 0..12 {
            if (i + slot) % 2 == 0 {
                f[slot] = *value;
            } else {
                c[slot % 6] = *value;
            }
        }
        cases.push((f, c));
    }
    // Zero coefficients: every subset a line evaluation could degenerate to.
    for mask in 1..8u32 {
        let f = next_fp12(&mut state);
        let mut c = next_coeffs(&mut state);
        for coeff in 0..3 {
            if mask & (1 << coeff) != 0 {
                c[2 * coeff] = zero;
                c[2 * coeff + 1] = zero;
            }
        }
        cases.push((f, c));
    }
    // The first Miller iteration's accumulator: a line_value image (sparse
    // f with exactly the c0/c3/c4 slots populated, the rest zero).
    let mut sparse = [zero; 12];
    sparse[0] = next_residue(&mut state);
    sparse[1] = next_residue(&mut state);
    sparse[6] = next_residue(&mut state);
    sparse[7] = next_residue(&mut state);
    sparse[8] = next_residue(&mut state);
    sparse[9] = next_residue(&mut state);
    cases.push((sparse, next_coeffs(&mut state)));
    // xi edges on the scaled coefficients c3 and c4.
    for (re, im) in [
        (zero, p_minus_one),
        (p_minus_one, zero),
        (zero, zero),
        (p_minus_one, p_minus_one),
    ] {
        let f = next_fp12(&mut state);
        cases.push((
            f,
            [
                next_residue(&mut state),
                next_residue(&mut state),
                re,
                im,
                re,
                im,
            ],
        ));
    }
    cases.push(([zero; 12], [zero; 6]));
    cases.push(([p_minus_one; 12], [p_minus_one; 6]));
    for (index, (f, c)) in cases.iter().enumerate() {
        let want = reference_fp12_034(f, c, BN254_P, BN254_P_INV);
        assert_eq!(
            interpret_fp12_034(f, c, BN254_P, BN254_P_INV, BN254_MU, false),
            want,
            "edge case {index}",
        );
        assert_eq!(
            interpret_fp12_034(f, c, BN254_P, BN254_P_INV, BN254_MU, true),
            want,
            "in-place edge case {index}",
        );
    }
}

/// The 034 leaf and the composed path must agree lane for lane: each output
/// component is the pair of T = 6 SoS lanes the production sosd6 dispatch
/// would compute from xi-prescaled coefficients.
#[test]
fn fp12_034_schedule_matches_composed_sos_schedule() {
    let mut state = 0x9b05_688c_2b3e_6c1fu64;
    for case in 0..200 {
        let f = next_fp12(&mut state);
        let c = next_coeffs(&mut state);
        let out = interpret_fp12_034(&f, &c, BN254_P, BN254_P_INV, BN254_MU, false);
        let (x3re, x3im) = reference_xi(c[2], c[3], BN254_P);
        let (x4re, x4im) = reference_xi(c[4], c[5], BN254_P);
        let fp2 = |i: usize| (f[2 * i], f[2 * i + 1]);
        let (a0, a1, a2) = (fp2(0), fp2(1), fp2(2));
        let (b0, b1, b2) = (fp2(3), fp2(4), fp2(5));
        let c0 = (c[0], c[1]);
        let c3 = (c[2], c[3]);
        let c4 = (c[4], c[5]);
        let rows = [
            [(a0, c0), (b1, (x4re, x4im)), (b2, (x3re, x3im))],
            [(a1, c0), (b0, c3), (b2, (x4re, x4im))],
            [(a2, c0), (b0, c4), (b1, c3)],
            [(a0, c3), (a2, (x4re, x4im)), (b0, c0)],
            [(a0, c4), (a1, c3), (b1, c0)],
            [(a1, c4), (a2, c3), (b2, c0)],
        ];
        for (component, products) in rows.iter().enumerate() {
            let mut real_pairs = Vec::new();
            let mut imag_pairs = Vec::new();
            for ((x_re, x_im), (y_re, y_im)) in products {
                real_pairs.push((*x_re, *y_re));
                real_pairs.push((*x_im, negp(*y_im, BN254_P)));
                imag_pairs.push((*x_re, *y_im));
                imag_pairs.push((*x_im, *y_re));
            }
            assert_eq!(
                out[2 * component],
                interpret_sos(&real_pairs, BN254_P, BN254_P_INV),
                "real lane of component {component}, case {case}",
            );
            assert_eq!(
                out[2 * component + 1],
                interpret_sos(&imag_pairs, BN254_P, BN254_P_INV),
                "imag lane of component {component}, case {case}",
            );
        }
    }
}

/// Compare one fp12_sqr input against both references (composed SoS rows
/// and the bound-asserting lazy DAG), in both aliasing shapes.
fn check_fp12_sqr(f: &Fp12Limbs, tag: &str) {
    let composed = reference_fp12_sqr_composed(f, BN254_P, BN254_P_INV);
    let lazy = lazy::reference_fp12_sqr(f, BN254_P, BN254_P_INV, BN254_MU);
    assert_eq!(lazy, composed, "lazy/composed reference divergence, {tag}");
    let out = interpret_fp12_sqr(f, BN254_P, BN254_P_INV, BN254_MU, false);
    assert_eq!(out, composed, "{tag}");
    for (i, component) in out.iter().enumerate() {
        assert!(!gte(component, &BN254_P), "unreduced output {i}, {tag}");
    }
    assert_eq!(
        interpret_fp12_sqr(f, BN254_P, BN254_P_INV, BN254_MU, true),
        composed,
        "in-place (z == f) {tag}",
    );
}

#[test]
fn fp12_sqr_schedule_matches_references_on_random_operands() {
    let mut state = 0xcbbb_9d5d_c105_9ed8u64;
    for case in 0..300 {
        let f = next_fp12(&mut state);
        check_fp12_sqr(&f, &format!("case {case}"));
    }
}

/// Edge palette: the extreme corpus rotates through all twelve f slots;
/// targeted xi edges on b.c2 (the iteration-0 xi site: re = 0, im = p-1
/// drives 9re - im maximally negative, im = 0 exercises negp exactly at p);
/// line_value-shaped sparse accumulators (early Miller iterations); all-zero
/// and all-(p-1) operands saturating every product, guard and reduction.
#[test]
fn fp12_sqr_schedule_matches_references_on_edge_operands() {
    let corpus = edge_corpus();
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let zero = [0u64; 4];
    let mut state = 0x629a_292a_367c_d507u64;
    let mut cases: Vec<Fp12Limbs> = Vec::new();
    for (i, value) in corpus.iter().enumerate() {
        let mut f = next_fp12(&mut state);
        for (slot, target) in f.iter_mut().enumerate() {
            if (i + slot) % 2 == 0 {
                *target = *value;
            }
        }
        cases.push(f);
    }
    // xi edges on b.c2 = slots 10/11 (and V.c2 indirectly via products).
    for (re, im) in [
        (zero, p_minus_one),
        (p_minus_one, zero),
        (zero, zero),
        (p_minus_one, p_minus_one),
    ] {
        let mut f = next_fp12(&mut state);
        f[10] = re;
        f[11] = im;
        cases.push(f);
    }
    // The first Miller iterations' accumulator: a line_value image (sparse
    // f with exactly the c0/c3/c4 slots populated).
    let mut sparse = [zero; 12];
    for slot in [0, 1, 6, 7, 8, 9] {
        sparse[slot] = next_residue(&mut state);
    }
    cases.push(sparse);
    // The identity (the Miller accumulator's initial value) and extremes.
    let mut one = [zero; 12];
    one[0] = [1, 0, 0, 0];
    cases.push(one);
    cases.push([zero; 12]);
    cases.push([p_minus_one; 12]);
    for (index, f) in cases.iter().enumerate() {
        check_fp12_sqr(f, &format!("edge case {index}"));
    }
}

/// The fp12_sqr leaf and the composed path must agree lane for lane with the
/// production sosd8/sosd6 dispatch, executed through the interpreted rolled
/// SoS schedule.
#[test]
fn fp12_sqr_schedule_matches_composed_sos_schedule() {
    let mut state = 0x452e_6dcd_a2c1_2c85u64;
    for case in 0..100 {
        let f = next_fp12(&mut state);
        let out = interpret_fp12_sqr(&f, BN254_P, BN254_P_INV, BN254_MU, false);
        let fp2 = |i: usize| (f[2 * i], f[2 * i + 1]);
        let (a0, a1, a2) = (fp2(0), fp2(1), fp2(2));
        let (b0, b1, b2) = (fp2(3), fp2(4), fp2(5));
        let dbl = |w: ([u64; 4], [u64; 4])| (double_mod(w.0, BN254_P), double_mod(w.1, BN254_P));
        let xi = |w: ([u64; 4], [u64; 4])| reference_xi(w.0, w.1, BN254_P);
        let da0 = dbl(a0);
        let da1 = dbl(a1);
        let da2 = dbl(a2);
        let g = dbl(b0);
        let x = xi(da1);
        let e = xi(a2);
        let y = xi(b1);
        let h = xi(b2);
        let z = xi(g);
        let ff = dbl(y);
        let rows: [Vec<(Fp2Val, Fp2Val)>; 6] = [
            vec![(a0, a0), (x, a2), (y, b1), (z, b2)],
            vec![(da0, a1), (e, a2), (b0, b0), (ff, b2)],
            vec![(a1, a1), (da0, a2), (g, b1), (h, b2)],
            vec![(da0, b0), (da1, h), (da2, y)],
            vec![(da0, b1), (da1, b0), (da2, h)],
            vec![(da0, b2), (da1, b1), (da2, b0)],
        ];
        for (component, products) in rows.iter().enumerate() {
            let mut real_pairs = Vec::new();
            let mut imag_pairs = Vec::new();
            for ((x_re, x_im), (y_re, y_im)) in products {
                real_pairs.push((*x_re, *y_re));
                real_pairs.push((*x_im, negp(*y_im, BN254_P)));
                imag_pairs.push((*x_re, *y_im));
                imag_pairs.push((*x_im, *y_re));
            }
            assert_eq!(
                out[2 * component],
                interpret_sos(&real_pairs, BN254_P, BN254_P_INV),
                "real lane of component {component}, case {case}",
            );
            assert_eq!(
                out[2 * component + 1],
                interpret_sos(&imag_pairs, BN254_P, BN254_P_INV),
                "imag lane of component {component}, case {case}",
            );
        }
    }
}

/// Independent composed oracle for the whole Fp12 product, exactly the
/// production `Mul for Fp12` shape: Karatsuba over three Fp6 products
/// (through [`reference_fp6_mul`]), `z.a = t0 + mul_by_nonresidue(t1)`,
/// `z.b = (a0 + a1)(b0 + b1) - t0 - t1`, all single-width modular.
fn reference_fp12_mul_composed(a: &Fp12Limbs, b: &Fp12Limbs, p: [u64; 4], p_inv: u64) -> Fp12Limbs {
    let a0: Fp6Limbs = core::array::from_fn(|i| a[i]);
    let a1: Fp6Limbs = core::array::from_fn(|i| a[6 + i]);
    let b0: Fp6Limbs = core::array::from_fn(|i| b[i]);
    let b1: Fp6Limbs = core::array::from_fn(|i| b[6 + i]);
    let t0 = reference_fp6_mul(&a0, &b0, p, p_inv);
    let t1 = reference_fp6_mul(&a1, &b1, p, p_inv);
    let s1: Fp6Limbs = core::array::from_fn(|i| add_mod(a0[i], a1[i], p));
    let s2: Fp6Limbs = core::array::from_fn(|i| add_mod(b0[i], b1[i], p));
    let cross = reference_fp6_mul(&s1, &s2, p, p_inv);
    // mul_by_nonresidue over Fp6: (c0, c1, c2) -> (xi*c2, c0, c1).
    let (xr, xim) = reference_xi(t1[4], t1[5], p);
    let shifted = [xr, xim, t1[0], t1[1], t1[2], t1[3]];
    core::array::from_fn(|i| {
        if i < 6 {
            add_mod(t0[i], shifted[i], p)
        } else {
            sub_mod(sub_mod(cross[i - 6], t0[i - 6], p), t1[i - 6], p)
        }
    })
}

/// Compare one fp12_mul input pair against both references (composed Fp6
/// Karatsuba and the bound-asserting lazy DAG), in all three aliasing
/// shapes (distinct z, z == a, z == b).
fn check_fp12_mul(a: &Fp12Limbs, b: &Fp12Limbs, tag: &str) {
    let composed = reference_fp12_mul_composed(a, b, BN254_P, BN254_P_INV);
    let lazy = lazy::reference_fp12_mul(a, b, BN254_P, BN254_P_INV, BN254_MU);
    assert_eq!(lazy, composed, "lazy/composed reference divergence, {tag}");
    let out = interpret_fp12_mul(a, b, BN254_P, BN254_P_INV, BN254_MU, 0);
    assert_eq!(out, composed, "{tag}");
    for (i, component) in out.iter().enumerate() {
        assert!(!gte(component, &BN254_P), "unreduced output {i}, {tag}");
    }
    assert_eq!(
        interpret_fp12_mul(a, b, BN254_P, BN254_P_INV, BN254_MU, 1),
        composed,
        "in-place (z == a) {tag}",
    );
    assert_eq!(
        interpret_fp12_mul(a, b, BN254_P, BN254_P_INV, BN254_MU, 2),
        composed,
        "in-place (z == b) {tag}",
    );
}

#[test]
fn fp12_mul_schedule_matches_references_on_random_operands() {
    let mut state = 0x71c9_4a13_66ab_20f7u64;
    for case in 0..200 {
        let a = next_fp12(&mut state);
        let b = next_fp12(&mut state);
        check_fp12_mul(&a, &b, &format!("case {case}"));
    }
}

/// Edge palette: the extreme corpus rotates through the slots of both
/// operands; targeted xi edges on a1.c2/b1.c2 (which drive the BD.c
/// mulVadd site and the product-level xi rows); the a == b diagonal
/// (kernel must equal the square); sparse Miller-shaped operands; the
/// identity; all-zero and all-(p-1) operands saturating every product,
/// guard, negation and reduction.
#[test]
fn fp12_mul_schedule_matches_references_on_edge_operands() {
    let corpus = edge_corpus();
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let zero = [0u64; 4];
    let mut state = 0x1b2c_57d0_9a44_ce13u64;
    let mut cases: Vec<(Fp12Limbs, Fp12Limbs)> = Vec::new();
    for (i, value) in corpus.iter().enumerate() {
        let mut a = next_fp12(&mut state);
        let mut b = next_fp12(&mut state);
        for slot in 0..12 {
            if (i + slot) % 2 == 0 {
                a[slot] = *value;
            } else {
                b[slot] = *value;
            }
        }
        cases.push((a, b));
    }
    // xi edges on the BD.c site (a1.c2 = slots 10/11 of a, times b1.c2).
    for (re, im) in [
        (zero, p_minus_one),
        (p_minus_one, zero),
        (zero, zero),
        (p_minus_one, p_minus_one),
    ] {
        let mut a = next_fp12(&mut state);
        let mut b = next_fp12(&mut state);
        a[10] = re;
        a[11] = im;
        b[10] = re;
        b[11] = im;
        cases.push((a, b));
    }
    // The a == b diagonal: the product must equal the square.
    let d = next_fp12(&mut state);
    cases.push((d, d));
    // Miller shapes: sparse line-value accumulator times a dense operand,
    // and the identity on either side.
    let mut sparse = [zero; 12];
    for slot in [0, 1, 6, 7, 8, 9] {
        sparse[slot] = next_residue(&mut state);
    }
    cases.push((sparse, next_fp12(&mut state)));
    let mut one = [zero; 12];
    one[0] = [1, 0, 0, 0];
    cases.push((one, next_fp12(&mut state)));
    cases.push((next_fp12(&mut state), one));
    cases.push(([zero; 12], next_fp12(&mut state)));
    cases.push(([p_minus_one; 12], [p_minus_one; 12]));
    for (index, (a, b)) in cases.iter().enumerate() {
        check_fp12_mul(a, b, &format!("edge case {index}"));
    }
}

/// The fp12_mul leaf and the composed path must agree component for
/// component with the production dispatch (Karatsuba over the Fp6 leaf),
/// executed through the interpreted fp6_mul schedule.
#[test]
fn fp12_mul_schedule_matches_composed_fp6_schedule() {
    let mut state = 0x3f84_d5b5_b547_1b9fu64;
    for case in 0..50 {
        let a = next_fp12(&mut state);
        let b = next_fp12(&mut state);
        let out = interpret_fp12_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU, 0);
        let a0: Fp6Limbs = core::array::from_fn(|i| a[i]);
        let a1: Fp6Limbs = core::array::from_fn(|i| a[6 + i]);
        let b0: Fp6Limbs = core::array::from_fn(|i| b[i]);
        let b1: Fp6Limbs = core::array::from_fn(|i| b[6 + i]);
        let t0 = interpret_fp6_mul(&a0, &b0, BN254_P, BN254_P_INV, BN254_MU);
        let t1 = interpret_fp6_mul(&a1, &b1, BN254_P, BN254_P_INV, BN254_MU);
        let s1: Fp6Limbs = core::array::from_fn(|i| add_mod(a0[i], a1[i], BN254_P));
        let s2: Fp6Limbs = core::array::from_fn(|i| add_mod(b0[i], b1[i], BN254_P));
        let cross = interpret_fp6_mul(&s1, &s2, BN254_P, BN254_P_INV, BN254_MU);
        let (xr, xim) = reference_xi(t1[4], t1[5], BN254_P);
        let shifted = [xr, xim, t1[0], t1[1], t1[2], t1[3]];
        for i in 0..6 {
            assert_eq!(
                out[i],
                add_mod(t0[i], shifted[i], BN254_P),
                "z.a component {i}, case {case}",
            );
            assert_eq!(
                out[6 + i],
                sub_mod(sub_mod(cross[i], t0[i], BN254_P), t1[i], BN254_P),
                "z.b component {i}, case {case}",
            );
        }
    }
}

/// Independent composed oracle for the Granger-Scott cyclotomic square,
/// exactly the production `cyclotomic_square_composed` shape: three Fp4
/// squares through [`reference_fp4_sqr`], xi*t5 single-width, z-combines
/// `z = 2*(t -+ r) + t`, output (z0, z4, z3, z2, z1, z5) in repr(C) order.
fn reference_cyc_sqr_composed(f: &Fp12Limbs, p: [u64; 4], p_inv: u64) -> Fp12Limbs {
    let fp2 = |i: usize| [f[2 * i], f[2 * i + 1]];
    let (r0, r4, r3) = (fp2(0), fp2(1), fp2(2));
    let (r2, r1, r5) = (fp2(3), fp2(4), fp2(5));
    let q0 = reference_fp4_sqr(&r0, &r1, p, p_inv);
    let q1 = reference_fp4_sqr(&r2, &r3, p, p_inv);
    let q2 = reference_fp4_sqr(&r4, &r5, p, p_inv);
    let (t0, t1) = ([q0[0], q0[1]], [q0[2], q0[3]]);
    let (t2, t3) = ([q1[0], q1[1]], [q1[2], q1[3]]);
    let (t4, t5) = ([q2[0], q2[1]], [q2[2], q2[3]]);
    let (x5re, x5im) = reference_xi(t5[0], t5[1], p);
    let xt5 = [x5re, x5im];
    let combine = |tv: [[u64; 4]; 2], rv: [[u64; 4]; 2], sub: bool| -> [[u64; 4]; 2] {
        core::array::from_fn(|h| {
            let opener = if sub {
                sub_mod(tv[h], rv[h], p)
            } else {
                add_mod(tv[h], rv[h], p)
            };
            add_mod(double_mod(opener, p), tv[h], p)
        })
    };
    let z0 = combine(t0, r0, true);
    let z1 = combine(t1, r1, false);
    let z2 = combine(xt5, r2, false);
    let z3 = combine(t4, r3, true);
    let z4 = combine(t2, r4, true);
    let z5 = combine(t3, r5, false);
    [
        z0[0], z0[1], z4[0], z4[1], z3[0], z3[1], z2[0], z2[1], z1[0], z1[1], z5[0], z5[1],
    ]
}

/// Compare one cyc_sqr input against both references (composed Fp4 squares
/// and the bound-asserting lazy DAG), in both aliasing shapes.
fn check_cyc_sqr(f: &Fp12Limbs, tag: &str) {
    let composed = reference_cyc_sqr_composed(f, BN254_P, BN254_P_INV);
    let lazy = lazy::reference_cyc_sqr(f, BN254_P, BN254_P_INV, BN254_MU);
    assert_eq!(lazy, composed, "lazy/composed reference divergence, {tag}");
    let out = interpret_cyc_sqr(f, BN254_P, BN254_P_INV, BN254_MU, false);
    assert_eq!(out, composed, "{tag}");
    for (i, component) in out.iter().enumerate() {
        assert!(!gte(component, &BN254_P), "unreduced output {i}, {tag}");
    }
    assert_eq!(
        interpret_cyc_sqr(f, BN254_P, BN254_P_INV, BN254_MU, true),
        composed,
        "in-place (z == f) {tag}",
    );
}

#[test]
fn cyc_sqr_schedule_matches_references_on_random_operands() {
    let mut state = 0x9159_015a_3070_dd17u64;
    for case in 0..300 {
        let f = next_fp12(&mut state);
        check_cyc_sqr(&f, &format!("case {case}"));
    }
}

/// Edge palette: the extreme corpus rotates through all twelve f slots;
/// targeted xi edges on the x1 operands r1, r3, r5 (their squares feed the
/// nine-fold: im = p-1 maximizes the negation rows, im = 0 sends them to
/// exactly p*2^256); the s = x0 + x1 wrap cases (x0 = x1 = p-1); the
/// identity, all-zero and all-(p-1) operands saturating every product,
/// guard and reduction. Arbitrary (non-cyclotomic) inputs are the point:
/// the leaf must match the composed formula everywhere.
#[test]
fn cyc_sqr_schedule_matches_references_on_edge_operands() {
    let corpus = edge_corpus();
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let zero = [0u64; 4];
    let mut state = 0x8f46_2907_35a1_29b4u64;
    let mut cases: Vec<Fp12Limbs> = Vec::new();
    for (i, value) in corpus.iter().enumerate() {
        let mut f = next_fp12(&mut state);
        for (slot, target) in f.iter_mut().enumerate() {
            if (i + slot) % 2 == 0 {
                *target = *value;
            }
        }
        cases.push(f);
    }
    // xi edges on the x1 operands: r1 = slots 8/9, r3 = slots 4/5,
    // r5 = slots 10/11 of repr(C) f.
    for slots in [[8, 9], [4, 5], [10, 11]] {
        for (re, im) in [
            (zero, p_minus_one),
            (p_minus_one, zero),
            (zero, zero),
            (p_minus_one, p_minus_one),
        ] {
            let mut f = next_fp12(&mut state);
            f[slots[0]] = re;
            f[slots[1]] = im;
            cases.push(f);
        }
    }
    // The identity (pow_x's frequent accumulator value) and extremes.
    let mut one = [zero; 12];
    one[0] = [1, 0, 0, 0];
    cases.push(one);
    cases.push([zero; 12]);
    cases.push([p_minus_one; 12]);
    for (index, f) in cases.iter().enumerate() {
        check_cyc_sqr(f, &format!("edge case {index}"));
    }
}

/// The cyc_sqr leaf and the composed path must agree pairing for pairing
/// with the production fp4_square dispatch, computed through the SoS row
/// reference, plus the single-width combine references.
#[test]
fn cyc_sqr_schedule_matches_composed_fp4_reference() {
    let mut state = 0x6b8b_2f68_29c1_35d9u64;
    for case in 0..100 {
        let f = next_fp12(&mut state);
        let out = interpret_cyc_sqr(&f, BN254_P, BN254_P_INV, BN254_MU, false);
        let fp2 = |i: usize| [f[2 * i], f[2 * i + 1]];
        let (r0, r4, r3) = (fp2(0), fp2(1), fp2(2));
        let (r2, r1, r5) = (fp2(3), fp2(4), fp2(5));
        let q0 = reference_fp4_sqr(&r0, &r1, BN254_P, BN254_P_INV);
        let q1 = reference_fp4_sqr(&r2, &r3, BN254_P, BN254_P_INV);
        let q2 = reference_fp4_sqr(&r4, &r5, BN254_P, BN254_P_INV);
        let (x5re, x5im) = reference_xi(q2[2], q2[3], BN254_P);
        let combine = |tv: [[u64; 4]; 2], rv: [[u64; 4]; 2], sub: bool| -> [[u64; 4]; 2] {
            core::array::from_fn(|h| {
                let opener = if sub {
                    sub_mod(tv[h], rv[h], BN254_P)
                } else {
                    add_mod(tv[h], rv[h], BN254_P)
                };
                add_mod(double_mod(opener, BN254_P), tv[h], BN254_P)
            })
        };
        let expect = [
            combine([q0[0], q0[1]], r0, true),
            combine([q1[0], q1[1]], r4, true),
            combine([q2[0], q2[1]], r3, true),
            combine([x5re, x5im], r2, false),
            combine([q0[2], q0[3]], r1, false),
            combine([q1[2], q1[3]], r5, false),
        ];
        for (component, z) in expect.into_iter().enumerate() {
            assert_eq!(
                [out[2 * component], out[2 * component + 1]],
                z,
                "component {component}, case {case}",
            );
        }
    }
}

#[test]
fn kernelgen_constants_match_production_constants() {
    assert_eq!(BN254_P, helius_bn254::consts::P);
    assert_eq!(BN254_P_INV, helius_bn254::consts::P_INV);
    assert_eq!(BN254_MU, helius_bn254::consts::P_MU_310);
}

/// The generated schedules must agree with the production portable oracle on
/// this host, whatever its architecture: the interpreters execute the exact
/// emitted operation sequences with bit-accurate carry-flag semantics.
#[test]
fn interpreted_schedules_match_portable_oracle() {
    use helius_bn254::Fp;
    use helius_bn254::consts::{P, P_INV};

    let mut state = 0x5851_f42d_4c95_7f2du64;
    for _ in 0..1_000 {
        let a = next_residue(&mut state);
        let b = next_residue(&mut state);
        let oracle = Fp::from_raw_canonical(a) * Fp::from_raw_canonical(b);
        let interpreted = interpret_mont4_mul(a, b, P, P_INV);
        assert_eq!(Fp::from_raw_canonical(interpreted), oracle);
        let interpreted_a64 = interpret_mont4_a64(a, b, P, P_INV);
        assert_eq!(Fp::from_raw_canonical(interpreted_a64), oracle);
        let square_oracle = Fp::from_raw_canonical(a).square();
        let interpreted_square = interpret_mont4_sqr(a, P, P_INV);
        assert_eq!(Fp::from_raw_canonical(interpreted_square), square_oracle);
    }
}

/// Regeneration determinism: the build script must render the identical text
/// on every host and every run (no timestamps, paths, or host data).
#[test]
fn rendered_files_are_deterministic_and_sized() {
    let rendered = kernelgen::render::render_mont4_x86_64();
    assert_eq!(
        rendered,
        kernelgen::render::render_mont4_x86_64(),
        "x86-64 rendering must be pure",
    );
    // One pass over the registry: header sizes, the op-cache byte budgets
    // (the frontend thesis in numbers: rolled kernels stay well under
    // typical op-cache reach), and the exact per-kernel back-edge counts
    // (mont4 kernels pin zero: straight lines, no control flow at all).
    let kernels = &kernelgen::render::KERNELS;
    let label_pos = |symbol: &str| -> usize {
        rendered
            .find(&format!("\n{symbol}:\n"))
            .unwrap_or_else(|| panic!("{symbol} body missing"))
    };
    for ((i, spec), (instructions, bytes)) in kernels
        .iter()
        .enumerate()
        .zip(kernelgen::render::kernel_sizes())
    {
        assert!(rendered.contains(spec.symbol), "{} missing", spec.symbol);
        assert!(
            rendered.contains(&format!("{instructions} instructions, {bytes} bytes")),
            "{} header sizes missing",
            spec.symbol,
        );
        if let Some(cap) = spec.max_bytes {
            assert!(
                bytes <= cap,
                "{} must stay op-cache compact ({bytes} > {cap} bytes)",
                spec.symbol,
            );
        }
        let start = label_pos(spec.symbol);
        let end = kernels
            .get(i + 1)
            .map_or(rendered.len(), |next| label_pos(next.symbol));
        assert_eq!(
            rendered[start..end].matches("jne").count(),
            spec.back_edges,
            "{} must have exactly its counted back edges",
            spec.symbol,
        );
    }
    // Leaf property: no calls anywhere in the file.
    assert!(!rendered.contains("call"), "kernels must remain leaves");
    assert!(!rendered.contains("jmp"), "only conditional back edges");

    let rendered_a64 = kernelgen::a64::render::render_mont4_aarch64();
    assert_eq!(
        rendered_a64,
        kernelgen::a64::render::render_mont4_aarch64(),
        "aarch64 rendering must be pure",
    );
    let (instructions, bytes) = kernelgen::a64::render::kernel_size();
    assert_eq!(bytes, 4 * instructions, "A64 instructions are 4 bytes");
    assert!(rendered_a64.contains(kernelgen::a64::render::MONT4_SYMBOL));
    assert!(
        rendered_a64.contains(&format!("{instructions} instructions, {bytes} bytes")),
        "a64 header sizes missing",
    );
    // Leaf property: the only branch is the counted round loop. (Match with
    // surrounding spaces: `.globl` would otherwise hit the "bl" pattern.)
    assert!(!rendered_a64.contains(" bl "), "kernel must remain a leaf");
    assert!(!rendered_a64.contains(" blr "), "kernel must remain a leaf");
    assert_eq!(rendered_a64.matches("b.ne").count(), 1);
}

// ===========================================================================
// mu E-bucket verification: the xi pass's quotient estimate, exhaustive over
// every reachable top-bits bucket of its whole domain v < 10p.
//
// The schedule (`xi_scale_pass`) reduces value = 9A + C < 10p with
// E = floor(value / 2^252), read as `shld rbx, v3, 4` over the top limbs
// (E = (v4 << 4) | (v3 >> 60)), and q = floor(E * mu / 2^58) for
// mu = floor(2^310 / p). Within one bucket q is constant and v - q*p is
// increasing in v, so the two bucket endpoints bound every interior value:
// no-underflow at the low end and the 1.33p ceiling at the high end prove
// the whole bucket, and sweeping every bucket proves the whole domain.
// ===========================================================================

/// Five-limb little-endian value: the xi pass's 9A + C accumulator domain.
type U320 = [u64; 5];

fn u320_from4(x: &[u64; 4]) -> U320 {
    [x[0], x[1], x[2], x[3], 0]
}

fn u320_lt(a: &U320, b: &U320) -> bool {
    for k in (0..5).rev() {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

fn u320_sub(a: &U320, b: &U320) -> (U320, bool) {
    let mut out = [0u64; 5];
    let mut borrow = false;
    for k in 0..5 {
        let (mid, b1) = a[k].overflowing_sub(b[k]);
        let (low, b2) = mid.overflowing_sub(borrow as u64);
        out[k] = low;
        borrow = b1 | b2;
    }
    (out, borrow)
}

/// `k * a`, returning the overflow limb (0 for every use below).
fn u320_mul_small(k: u64, a: &U320) -> (U320, u64) {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for (slot, &limb) in out.iter_mut().zip(a) {
        let v = k as u128 * limb as u128 + carry;
        *slot = v as u64;
        carry = v >> 64;
    }
    (out, carry as u64)
}

fn u320_divmod_small(a: &U320, k: u64) -> (U320, u64) {
    let mut quotient = [0u64; 5];
    let mut remainder: u128 = 0;
    for i in (0..5).rev() {
        let current = (remainder << 64) | a[i] as u128;
        quotient[i] = (current / k as u128) as u64;
        remainder = current % k as u128;
    }
    (quotient, remainder as u64)
}

/// The schedule's exact bucket function: `shld rbx, v3, 4` over (v4, v3).
fn e_bucket(v: &U320) -> u64 {
    (v[4] << 4) | (v[3] >> 60)
}

/// Lowest value of bucket E: E * 2^252.
fn bucket_floor(e: u64) -> U320 {
    [0, 0, 0, (e & 15) << 60, e >> 4]
}

/// Replicate the kernel's whole mu reduction for one domain value and assert
/// every documented claim: E fits five bits, q <= 10, the estimate never
/// overshoots (no borrow), the remainder fits four limbs and stays below
/// 4p/3 (checked exactly as 3r < 4p), and one conditional subtraction
/// reaches canonical. Returns the canonical residue.
fn check_mu_reduction(v: &U320) -> [u64; 4] {
    let e = e_bucket(v);
    assert!(e < 32, "E = {e} does not fit five bits: REAL BUG");
    let q = ((e as u128 * BN254_MU as u128) >> 58) as u64;
    assert!(
        q <= 10,
        "q = {q} exceeds the claimed <= 10 at E = {e}: REAL BUG"
    );
    let p5 = u320_from4(&BN254_P);
    let (qp, overflow) = u320_mul_small(q, &p5);
    assert_eq!(overflow, 0, "q*p overflows five limbs");
    let (r, borrow) = u320_sub(v, &qp);
    assert!(
        !borrow,
        "quotient estimate overshoots at v = {v:x?} (E = {e}, q = {q}): REAL BUG",
    );
    assert_eq!(
        r[4], 0,
        "v - q*p spills the fifth limb at v = {v:x?} (E = {e}, q = {q}): REAL BUG",
    );
    let (three_r, c3) = u320_mul_small(3, &r);
    let (four_p, c4) = u320_mul_small(4, &p5);
    assert_eq!(c3, 0);
    assert_eq!(c4, 0);
    assert!(
        u320_lt(&three_r, &four_p),
        "pre-csub remainder >= 4p/3 at v = {v:x?} (E = {e}, q = {q}): REAL BUG",
    );
    let mut out = [r[0], r[1], r[2], r[3]];
    if gte(&out, &BN254_P) {
        out = sub_mod(out, BN254_P, BN254_P);
    }
    assert!(
        !gte(&out, &BN254_P),
        "post-csub residue not canonical at v = {v:x?}: REAL BUG",
    );
    out
}

/// Split a reachable re-lane value v in [1, 10p - 9] into the xi pass's
/// operand shape v = 9A + C with A canonical and C = p - im in [1, p], so
/// the kernel's real lane computes exactly v.
fn xi_operands_for(v: &U320) -> ([u64; 4], [u64; 4]) {
    let p5 = u320_from4(&BN254_P);
    let (a5, c5) = if u320_lt(v, &p5) || v == &p5 {
        ([0u64; 5], *v)
    } else {
        // A = ceil((v - p) / 9) keeps C = v - 9A within (0, p].
        let (t, borrow) = u320_sub(v, &p5);
        assert!(!borrow);
        let (mut a5, remainder) = u320_divmod_small(&t, 9);
        if remainder != 0 {
            let mut carry = 1u64;
            for limb in &mut a5 {
                let (sum, overflow) = limb.overflowing_add(carry);
                *limb = sum;
                carry = overflow as u64;
            }
            assert_eq!(carry, 0);
        }
        let (nine_a, overflow) = u320_mul_small(9, &a5);
        assert_eq!(overflow, 0);
        let (c5, borrow) = u320_sub(v, &nine_a);
        assert!(!borrow, "C = v - 9A must be nonnegative");
        (a5, c5)
    };
    assert_eq!(a5[4], 0);
    assert_eq!(c5[4], 0);
    let a = [a5[0], a5[1], a5[2], a5[3]];
    let c = [c5[0], c5[1], c5[2], c5[3]];
    assert!(!gte(&a, &BN254_P), "A must be canonical");
    assert_ne!(c, [0; 4], "C must be at least 1 (im = p - C canonical)");
    // Reconstruction: 9A + C == v exactly.
    let (nine_a, _) = u320_mul_small(9, &u320_from4(&a));
    let mut rebuilt = nine_a;
    let mut carry = 0u128;
    for (slot, &limb) in rebuilt.iter_mut().zip(u320_from4(&c).iter()) {
        let sum = *slot as u128 + limb as u128 + carry;
        *slot = sum as u64;
        carry = sum >> 64;
    }
    assert_eq!(&rebuilt, v, "operand split must reconstruct v");
    (a, negp(c, BN254_P))
}

#[test]
fn mu_e_buckets_are_exhaustively_safe() {
    let p5 = u320_from4(&BN254_P);
    let (ten_p, overflow) = u320_mul_small(10, &p5);
    assert_eq!(overflow, 0, "10p fits five limbs");
    let (v_max, borrow) = u320_sub(&ten_p, &[1, 0, 0, 0, 0]);
    assert!(!borrow);
    let e_max = e_bucket(&v_max);
    // Pin the bucket census: 31 reachable buckets (E in 0..=30); E = 31
    // starts at or above 10p and never occurs.
    assert_eq!(e_max, 30, "bucket census changed; re-derive this sweep");
    assert!(
        !u320_lt(&bucket_floor(31), &ten_p),
        "E = 31 must be unreachable below 10p",
    );
    let mut state = 0x853c_49e6_748f_ea9bu64;
    for e in 0..=e_max {
        let lo = bucket_floor(e);
        let hi = {
            let (ceiling, borrow) = u320_sub(&bucket_floor(e + 1), &[1, 0, 0, 0, 0]);
            assert!(!borrow);
            if u320_lt(&v_max, &ceiling) {
                v_max
            } else {
                ceiling
            }
        };
        assert!(!u320_lt(&hi, &lo), "bucket {e} must be nonempty");
        assert_eq!(e_bucket(&lo), e);
        assert_eq!(e_bucket(&hi), e);
        // The endpoints bound the whole bucket (q constant, v - q*p
        // increasing in v); interior samples are belt and braces.
        check_mu_reduction(&lo);
        check_mu_reduction(&hi);
        for _ in 0..64 {
            let mut v = [
                next_raw(&mut state)[0],
                next_raw(&mut state)[0],
                next_raw(&mut state)[0],
                ((e & 15) << 60) | (next_raw(&mut state)[0] >> 4),
                e >> 4,
            ];
            if u320_lt(&v_max, &v) {
                v = v_max;
            }
            assert_eq!(e_bucket(&v), e);
            check_mu_reduction(&v);
        }
    }
}

/// The bucket model above must be the machine's model: per bucket, both
/// reachable endpoints are lowered to real (A, im) operands and pushed
/// through the interpreted fp6 kernel, whose xi pass runs the exact shld /
/// mulx / shr / sbb sequence with the interpreter's claim assertions armed.
/// `reference_xi` (full reduction by repeated subtraction) ties the model,
/// the schedule, and the composed oracle to one canonical value.
#[test]
fn mu_e_bucket_operands_drive_the_interpreted_xi_pass() {
    let p5 = u320_from4(&BN254_P);
    let (ten_p, _) = u320_mul_small(10, &p5);
    // Reachable re-lane values: v = 9A + C <= 9(p-1) + p = 10p - 9.
    let (v_top, borrow) = u320_sub(&ten_p, &[9, 0, 0, 0, 0]);
    assert!(!borrow);
    let e_max = e_bucket(&v_top);
    assert_eq!(e_max, 30, "the top bucket must stay reachable");
    let mut state = 0xc4ce_b9fe_1a85_ec53u64;
    for e in 0..=e_max {
        let lo = {
            let floor = bucket_floor(e);
            if floor == [0; 5] {
                [1, 0, 0, 0, 0]
            } else {
                floor
            }
        };
        let hi = {
            let (ceiling, borrow) = u320_sub(&bucket_floor(e + 1), &[1, 0, 0, 0, 0]);
            assert!(!borrow);
            if u320_lt(&v_top, &ceiling) {
                v_top
            } else {
                ceiling
            }
        };
        for v in [lo, hi] {
            let (a_operand, im) = xi_operands_for(&v);
            let want = check_mu_reduction(&v);
            let (xi_re, _) = reference_xi(a_operand, im, BN254_P);
            assert_eq!(
                xi_re, want,
                "reference_xi disagrees with the mu model at bucket {e}",
            );
            let a = next_fp6(&mut state);
            let mut b = next_fp6(&mut state);
            b[2] = a_operand;
            b[3] = im;
            assert_eq!(
                interpret_fp6_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU),
                reference_fp6_mul(&a, &b, BN254_P, BN254_P_INV),
                "bucket {e} operand diverged through the interpreted fp6 kernel",
            );
        }
    }
}

// ===========================================================================
// Adversarial aliasing: every whole-tower leaf whose contract permits
// z == input, checked as direct bitwise equality between the aliased and
// distinct-output runs (not through a reference, so a staging misorder that
// perturbs both runs identically against the oracle still cannot hide).
// The coefficient block of the 034 leaves can never alias f at the ABI:
// the production wrappers stage c by value (pinned in source below), so the
// adversarial c case here is value aliasing -- c bytes equal to f's own
// c0/c3/c4 slots, exactly what a caller deriving the line from f produces.
// ===========================================================================

/// Aliasing corpus: extremes in every slot, sparse Miller shapes, the
/// identity, and random fills.
fn aliasing_corpus(state: &mut u64) -> Vec<Fp12Limbs> {
    let p_minus_one = {
        let mut value = BN254_P;
        value[0] -= 1;
        value
    };
    let zero = [0u64; 4];
    let mut cases: Vec<Fp12Limbs> = Vec::new();
    cases.push([zero; 12]);
    let mut one = [zero; 12];
    one[0] = [1, 0, 0, 0];
    cases.push(one);
    cases.push([p_minus_one; 12]);
    for (i, value) in edge_corpus().iter().enumerate() {
        let mut f = next_fp12(state);
        f[i % 12] = *value;
        cases.push(f);
    }
    let mut sparse = [zero; 12];
    for slot in [0, 1, 6, 7, 8, 9] {
        sparse[slot] = next_residue(state);
    }
    cases.push(sparse);
    for _ in 0..24 {
        cases.push(next_fp12(state));
    }
    cases
}

#[test]
fn fp12_034_leaf_agrees_bitwise_under_z_f_aliasing() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for (index, f) in aliasing_corpus(&mut state).iter().enumerate() {
        // Independent coefficients, then coefficients whose values are f's
        // own c0/c3/c4 slots (the staged-by-value image of a line derived
        // from f itself).
        let independent = next_coeffs(&mut state);
        let from_f = [f[0], f[1], f[6], f[7], f[8], f[9]];
        for (shape, c) in [("independent", independent), ("c-from-f", from_f)] {
            let plain = interpret_fp12_034(f, &c, BN254_P, BN254_P_INV, BN254_MU, false);
            assert_eq!(
                interpret_fp12_034(f, &c, BN254_P, BN254_P_INV, BN254_MU, true),
                plain,
                "v1 leaf aliasing divergence, case {index} ({shape})",
            );
        }
    }
}

#[test]
fn fp12_sqr_and_cyc_sqr_agree_bitwise_under_z_f_aliasing() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for (index, f) in aliasing_corpus(&mut state).iter().enumerate() {
        let plain = interpret_fp12_sqr(f, BN254_P, BN254_P_INV, BN254_MU, false);
        assert_eq!(
            interpret_fp12_sqr(f, BN254_P, BN254_P_INV, BN254_MU, true),
            plain,
            "fp12_sqr aliasing divergence, case {index}",
        );
        let plain = interpret_cyc_sqr(f, BN254_P, BN254_P_INV, BN254_MU, false);
        assert_eq!(
            interpret_cyc_sqr(f, BN254_P, BN254_P_INV, BN254_MU, true),
            plain,
            "cyc_sqr aliasing divergence, case {index}",
        );
    }
}

/// fp12_mul allows all three output placements (distinct z, z == a the
/// production MulAssign shape, z == b); all must agree bitwise. The value
/// diagonal a == b runs through every mode too: address-identical a == b is
/// not constructible in the interpreter frame (a and b own distinct
/// buffers), and the production wrapper cannot produce it either --
/// `MulAssign for Fp12` takes rhs by value, so the kernel always sees a
/// separate rhs copy.
#[test]
fn fp12_mul_alias_modes_agree_bitwise() {
    let mut state = 0xd1b5_4a32_d192_ed03u64;
    let corpus = aliasing_corpus(&mut state);
    for (index, f) in corpus.iter().enumerate() {
        let partner = corpus[(index + 7) % corpus.len()];
        for (shape, a, b) in [("pair", *f, partner), ("diagonal", *f, *f)] {
            let plain = interpret_fp12_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU, 0);
            assert_eq!(
                interpret_fp12_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU, 1),
                plain,
                "fp12_mul z == a divergence, case {index} ({shape})",
            );
            assert_eq!(
                interpret_fp12_mul(&a, &b, BN254_P, BN254_P_INV, BN254_MU, 2),
                plain,
                "fp12_mul z == b divergence, case {index} ({shape})",
            );
        }
    }
}

/// The leaves that forbid output aliasing get that guarantee from their
/// wrappers, not from luck: pin the wrapper shapes in source. fp6_mul must
/// write into a fresh `MaybeUninit` local (its contract says z never
/// aliases an input); the 034 wrapper must stage the coefficients by
/// value into a local `[Fp2; 3]` (so the c block can never alias f); and
/// `mul_by_034_assign` must take the coefficients by value, making a c/f
/// overlap inexpressible for any caller.
#[test]
fn wrapper_aliasing_contracts_hold_in_source() {
    let backend = include_str!("../src/fp/x86_64.rs");
    let window = |name: &str| -> &str {
        let start = backend
            .find(name)
            .unwrap_or_else(|| panic!("{name} not found in fp/x86_64.rs"));
        &backend[start..backend.len().min(start + 3000)]
    };
    assert!(
        window("fn fp6_mul(").contains("MaybeUninit"),
        "fn fp6_mul( must write into a fresh local, never an input",
    );
    let body = window("fn fp12_034_assign(");
    assert!(
        body.contains("let coefficients = [*c0, *c3, *c4];"),
        "fn fp12_034_assign( must stage the coefficients by value",
    );
    assert!(
        body.contains("coefficients.as_ptr()"),
        "fn fp12_034_assign( must pass the staged copy, never a caller pointer",
    );
    let fp12 = include_str!("../src/fp12.rs");
    assert!(
        fp12.contains("pub fn mul_by_034_assign(&mut self, c0: Fp2, c3: Fp2, c4: Fp2)"),
        "mul_by_034_assign must take coefficients by value (c/f overlap inexpressible)",
    );
}
