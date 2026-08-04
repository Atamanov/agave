//! Sums-of-products Montgomery kernels (Longa, ePrint 2022/367, Alg. 2, B=1).
//!
//! `sosT` computes `(sum_{i<T} a_i*b_i)*R^{-1} mod p` with one interleaved CIOS
//! reduction over the whole sum instead of T separate Montgomery reductions.
//! Subtracted terms enter as `negp(x) = p - x`.
//!
//! Bounds, for operands <= p (limb count n = 4, word w = 2^64, R = 2^256,
//! p < 0.1891*2^256): between rounds the accumulator u_j = (X_j + Q_j*p)/w^j
//! with X_j = sum_i (a_i mod w^j)*b_i < T*w^j*p and Q_j < w^j, so
//! u_j < (T+1)*p. The in-round peak before the shift is bounded by
//! u_j + sum_i a_{i,j}*b_i + q*p < (T+1)*p*w:
//! * T <= 4: (T+1)p < 2^256, peak < 5p*2^64 = 0.945*2^320. A five-limb
//!   accumulator suffices and the inter-round value fits four limbs.
//! * T = 6: 7p ~ 1.32*2^256, peak < 7p*2^64 < 2^321. Six limbs.
//!
//! The final value is exactly (X + m*p)/R with m < R, hence
//! u < p + X/R <= p*(1 + T*p/R) < p*(1 + 0.1891*T): one conditional
//! subtraction reaches [0, p) for T <= 4, two for T <= 10.

use crate::consts::P;
#[cfg(any(test, not(helius_sosd2_active)))]
use crate::consts::P_INV;
#[cfg(any(test, not(helius_sosd2_active)))]
use crate::limb::sub_mod;
use crate::limb::{gt, sub_noborrow};

#[cfg(any(
    test,
    not(helius_fp6_active),
    not(helius_fp12_sqr_active),
    not(helius_fp12_034_active),
))]
type Limbs = [u64; 4];

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct SosProduct<'a> {
    left: &'a Limbs,
    right: &'a Limbs,
}

#[cfg(test)]
impl<'a> SosProduct<'a> {
    pub(crate) const fn new(left: &'a Limbs, right: &'a Limbs) -> Self {
        Self { left, right }
    }
}

#[cfg(any(
    test,
    not(helius_fp6_active),
    not(helius_fp12_sqr_active),
    not(helius_fp12_034_active),
))]
#[derive(Clone, Copy)]
pub(crate) struct Fp2Product<'a> {
    pub(crate) x0: &'a Limbs,
    pub(crate) x1: &'a Limbs,
    pub(crate) y0: &'a Limbs,
    pub(crate) y1: &'a Limbs,
}

#[cfg(any(
    test,
    not(helius_fp6_active),
    not(helius_fp12_sqr_active),
    not(helius_fp12_034_active),
))]
impl<'a> Fp2Product<'a> {
    pub(crate) const fn new(x0: &'a Limbs, x1: &'a Limbs, y0: &'a Limbs, y1: &'a Limbs) -> Self {
        Self { x0, x1, y0, y1 }
    }
}

/// `p - x` for `x in [0, p]`; feeds subtracted terms into a sum of products.
/// Maps 0 to p, which the kernels accept (operand bound is <= p).
#[inline(always)]
pub fn negp(x: &[u64; 4]) -> [u64; 4] {
    debug_assert!(!gt(x, &P));
    sub_noborrow(&P, x)
}

// Four limbs times one word is five limbs; one carry chain so the carry stays
// in flags (same shape as fp/portable.rs).
#[cfg(any(test, not(helius_sosd2_active)))]
macro_rules! mul_word {
    ($b:expr, $a:expr) => {{
        let b = $b;
        let a = $a;
        let (r0, h0) = b[0].carrying_mul(a, 0);
        let (l1, h1) = b[1].carrying_mul(a, 0);
        let (l2, h2) = b[2].carrying_mul(a, 0);
        let (l3, h3) = b[3].carrying_mul(a, 0);
        let (r1, carry) = h0.carrying_add(l1, false);
        let (r2, carry) = h1.carrying_add(l2, carry);
        let (r3, carry) = h2.carrying_add(l3, carry);
        let (r4, overflow) = h3.carrying_add(0, carry);
        debug_assert!(!overflow, "four limbs times one limb fits five limbs");
        (r0, r1, r2, r3, r4)
    }};
}

// Accumulate a five-limb row; the carry cannot leave the fifth limb while the
// in-round peak stays below 2^320 (T <= 4).
#[cfg(any(test, not(helius_sosd2_active)))]
macro_rules! acc_row5 {
    ($t0:ident, $t1:ident, $t2:ident, $t3:ident, $t4:ident, $row:expr) => {{
        let (r0, r1, r2, r3, r4) = $row;
        let (s0, c) = $t0.carrying_add(r0, false);
        let (s1, c) = $t1.carrying_add(r1, c);
        let (s2, c) = $t2.carrying_add(r2, c);
        let (s3, c) = $t3.carrying_add(r3, c);
        let (s4, c) = $t4.carrying_add(r4, c);
        debug_assert!(!c, "five-limb accumulator bound (T <= 4 products)");
        $t0 = s0;
        $t1 = s1;
        $t2 = s2;
        $t3 = s3;
        $t4 = s4;
    }};
}

// Six-limb accumulator variant; the row carry spills into the sixth limb.
#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
macro_rules! acc_row6 {
    ($t0:ident, $t1:ident, $t2:ident, $t3:ident, $t4:ident, $t5:ident, $row:expr) => {{
        let (r0, r1, r2, r3, r4) = $row;
        let (s0, c) = $t0.carrying_add(r0, false);
        let (s1, c) = $t1.carrying_add(r1, c);
        let (s2, c) = $t2.carrying_add(r2, c);
        let (s3, c) = $t3.carrying_add(r3, c);
        let (s4, c) = $t4.carrying_add(r4, c);
        let (s5, c) = $t5.carrying_add(0, c);
        debug_assert!(!c, "six-limb accumulator bound");
        $t0 = s0;
        $t1 = s1;
        $t2 = s2;
        $t3 = s3;
        $t4 = s4;
        $t5 = s5;
    }};
}

// One CIOS round over source limb $j: accumulate a_i[j]*b_i for every product,
// cancel the low limb with q*p, shift the accumulator one limb right.
#[cfg(any(test, not(helius_sosd2_active)))]
macro_rules! round5 {
    ($t0:ident, $t1:ident, $t2:ident, $t3:ident, $t4:ident, $j:expr, $(($a:expr, $b:expr)),+) => {{
        $(acc_row5!($t0, $t1, $t2, $t3, $t4, mul_word!($b, $a[$j]));)+
        let q = $t0.wrapping_mul(P_INV);
        acc_row5!($t0, $t1, $t2, $t3, $t4, mul_word!(&P, q));
        debug_assert_eq!($t0, 0, "Montgomery factor cancels the low limb");
        $t0 = $t1;
        $t1 = $t2;
        $t2 = $t3;
        $t3 = $t4;
        $t4 = 0;
    }};
}

#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
macro_rules! round6 {
    ($t0:ident, $t1:ident, $t2:ident, $t3:ident, $t4:ident, $t5:ident, $j:expr,
     $(($a:expr, $b:expr)),+) => {{
        $(acc_row6!($t0, $t1, $t2, $t3, $t4, $t5, mul_word!($b, $a[$j]));)+
        let q = $t0.wrapping_mul(P_INV);
        acc_row6!($t0, $t1, $t2, $t3, $t4, $t5, mul_word!(&P, q));
        debug_assert_eq!($t0, 0, "Montgomery factor cancels the low limb");
        $t0 = $t1;
        $t1 = $t2;
        $t2 = $t3;
        $t3 = $t4;
        $t4 = $t5;
        $t5 = 0;
    }};
}

#[cfg(any(test, not(helius_sosd2_active)))]
macro_rules! debug_assert_operands {
    ($($x:expr),+) => {
        $(debug_assert!(!gt($x, &P), "SoS operand exceeds p");)+
    };
}

// Dual-lane complex kernels: both Fp components of `sum_i x_i*y_i` over Fp2
// (`lane0 = sum x_{i0}*y_{i0} - x_{i1}*y_{i1}`, `lane1 = sum x_{i0}*y_{i1} +
// x_{i1}*y_{i0}`) in one call, rounds of the two lanes interleaved. Each
// single-lane sosT body is one serial carry chain far longer than the OoO
// window, so two sequential calls cannot overlap; adjacent per-lane rounds
// keep both independent chains in flight (~2x ILP, same instruction count).
// Per-lane accumulation order and bounds are identical to the sosT kernels.

/// Dual-lane Fp2 product: `(x0 + x1u)*(y0 + y1u)`, T = 2 per lane.
#[cfg(any(test, not(helius_sosd2_active)))]
#[inline(never)]
pub(crate) fn sosd2_portable(
    x0: &[u64; 4],
    x1: &[u64; 4],
    y0: &[u64; 4],
    y1: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    debug_assert_operands!(x0, x1, y0, y1);
    let ny1 = negp(y1);
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut u0, mut u1, mut u2, mut u3, mut u4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    // Small kernel: unrolled rounds (latency-shaped; footprint is modest).
    round5!(t0, t1, t2, t3, t4, 0, (x0, y0), (x1, &ny1));
    round5!(u0, u1, u2, u3, u4, 0, (x0, y1), (x1, y0));
    round5!(t0, t1, t2, t3, t4, 1, (x0, y0), (x1, &ny1));
    round5!(u0, u1, u2, u3, u4, 1, (x0, y1), (x1, y0));
    round5!(t0, t1, t2, t3, t4, 2, (x0, y0), (x1, &ny1));
    round5!(u0, u1, u2, u3, u4, 2, (x0, y1), (x1, y0));
    round5!(t0, t1, t2, t3, t4, 3, (x0, y0), (x1, &ny1));
    round5!(u0, u1, u2, u3, u4, 3, (x0, y1), (x1, y0));
    debug_assert_eq!(t4, 0, "final value < 2p fits four limbs");
    debug_assert_eq!(u4, 0, "final value < 2p fits four limbs");
    let c0 = sub_mod(&[t0, t1, t2, t3], &P, &P);
    let c1 = sub_mod(&[u0, u1, u2, u3], &P, &P);
    debug_assert!(gt(&P, &c0) && gt(&P, &c1));
    (c0, c1)
}

/// Dual-lane sum of two Fp2 products, T = 4 per lane.
#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
#[inline(never)]
pub(crate) fn sosd4_portable(
    x00: &[u64; 4],
    x01: &[u64; 4],
    y00: &[u64; 4],
    y01: &[u64; 4],
    x10: &[u64; 4],
    x11: &[u64; 4],
    y10: &[u64; 4],
    y11: &[u64; 4],
) -> ([u64; 4], [u64; 4]) {
    debug_assert_operands!(x00, x01, y00, y01, x10, x11, y10, y11);
    let ny01 = negp(y01);
    let ny11 = negp(y11);
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut u0, mut u1, mut u2, mut u3, mut u4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    macro_rules! rounds {
        ($j:expr) => {
            round5!(
                t0,
                t1,
                t2,
                t3,
                t4,
                $j,
                (x00, y00),
                (x01, &ny01),
                (x10, y10),
                (x11, &ny11)
            );
            round5!(
                u0,
                u1,
                u2,
                u3,
                u4,
                $j,
                (x00, y01),
                (x01, y00),
                (x10, y11),
                (x11, y10)
            );
        };
    }
    // Small kernel: unrolled rounds (latency-shaped; footprint is modest).
    rounds!(0);
    rounds!(1);
    rounds!(2);
    rounds!(3);
    debug_assert_eq!(t4, 0, "final value < 2p fits four limbs");
    debug_assert_eq!(u4, 0, "final value < 2p fits four limbs");
    let c0 = sub_mod(&[t0, t1, t2, t3], &P, &P);
    let c1 = sub_mod(&[u0, u1, u2, u3], &P, &P);
    debug_assert!(gt(&P, &c0) && gt(&P, &c1));
    (c0, c1)
}

/// Dual-lane sum of three Fp2 products, T = 6 per lane.
#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
#[inline(never)]
pub(crate) fn sosd6_portable(products: [Fp2Product<'_>; 3]) -> ([u64; 4], [u64; 4]) {
    let [
        Fp2Product {
            x0: x00,
            x1: x01,
            y0: y00,
            y1: y01,
        },
        Fp2Product {
            x0: x10,
            x1: x11,
            y0: y10,
            y1: y11,
        },
        Fp2Product {
            x0: x20,
            x1: x21,
            y0: y20,
            y1: y21,
        },
    ] = products;
    debug_assert_operands!(x00, x01, y00, y01, x10, x11, y10, y11, x20, x21, y20, y21);
    let ny01 = negp(y01);
    let ny11 = negp(y11);
    let ny21 = negp(y21);
    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut u0, mut u1, mut u2, mut u3, mut u4, mut u5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    macro_rules! rounds {
        ($j:expr) => {
            round6!(
                t0,
                t1,
                t2,
                t3,
                t4,
                t5,
                $j,
                (x00, y00),
                (x01, &ny01),
                (x10, y10),
                (x11, &ny11),
                (x20, y20),
                (x21, &ny21)
            );
            round6!(
                u0,
                u1,
                u2,
                u3,
                u4,
                u5,
                $j,
                (x00, y01),
                (x01, y00),
                (x10, y11),
                (x11, y10),
                (x20, y21),
                (x21, y20)
            );
        };
    }
    // Opaque trip count: the rolled 4-round loop keeps this body ~1/4 the
    // size so the big kernels stay L1I/op-cache resident (pairing hot path
    // is frontend-footprint-bound on x86).
    for j in 0..core::hint::black_box(4usize) {
        rounds!(j);
    }
    debug_assert_eq!(t5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(t4, 0, "final value < 3p < 2^256 fits four limbs");
    debug_assert_eq!(u5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(u4, 0, "final value < 3p < 2^256 fits four limbs");
    let c0 = sub_mod(&sub_mod(&[t0, t1, t2, t3], &P, &P), &P, &P);
    let c1 = sub_mod(&sub_mod(&[u0, u1, u2, u3], &P, &P), &P, &P);
    debug_assert!(gt(&P, &c0) && gt(&P, &c1));
    (c0, c1)
}

/// Dual-lane sum of four Fp2 products, T = 8 per lane.
#[cfg(test)]
#[inline(never)]
pub(crate) fn sosd8_portable(products: [Fp2Product<'_>; 4]) -> ([u64; 4], [u64; 4]) {
    let [
        Fp2Product {
            x0: x00,
            x1: x01,
            y0: y00,
            y1: y01,
        },
        Fp2Product {
            x0: x10,
            x1: x11,
            y0: y10,
            y1: y11,
        },
        Fp2Product {
            x0: x20,
            x1: x21,
            y0: y20,
            y1: y21,
        },
        Fp2Product {
            x0: x30,
            x1: x31,
            y0: y30,
            y1: y31,
        },
    ] = products;
    debug_assert_operands!(
        x00, x01, y00, y01, x10, x11, y10, y11, x20, x21, y20, y21, x30, x31, y30, y31
    );
    let ny01 = negp(y01);
    let ny11 = negp(y11);
    let ny21 = negp(y21);
    let ny31 = negp(y31);
    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut u0, mut u1, mut u2, mut u3, mut u4, mut u5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    macro_rules! rounds {
        ($j:expr) => {
            round6!(
                t0,
                t1,
                t2,
                t3,
                t4,
                t5,
                $j,
                (x00, y00),
                (x01, &ny01),
                (x10, y10),
                (x11, &ny11),
                (x20, y20),
                (x21, &ny21),
                (x30, y30),
                (x31, &ny31)
            );
            round6!(
                u0,
                u1,
                u2,
                u3,
                u4,
                u5,
                $j,
                (x00, y01),
                (x01, y00),
                (x10, y11),
                (x11, y10),
                (x20, y21),
                (x21, y20),
                (x30, y31),
                (x31, y30)
            );
        };
    }
    // Opaque trip count: the rolled 4-round loop keeps this body ~1/4 the
    // size so the big kernels stay L1I/op-cache resident (pairing hot path
    // is frontend-footprint-bound on x86).
    for j in 0..core::hint::black_box(4usize) {
        rounds!(j);
    }
    debug_assert_eq!(t5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(t4, 0, "final value < 3p < 2^256 fits four limbs");
    debug_assert_eq!(u5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(u4, 0, "final value < 3p < 2^256 fits four limbs");
    let c0 = sub_mod(&sub_mod(&[t0, t1, t2, t3], &P, &P), &P, &P);
    let c1 = sub_mod(&sub_mod(&[u0, u1, u2, u3], &P, &P), &P, &P);
    debug_assert!(gt(&P, &c0) && gt(&P, &c1));
    (c0, c1)
}

/// `(a0*b0 + a1*b1)*R^{-1} mod p`, canonical output. Final value < 1.379p.
#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
#[inline(never)]
pub(crate) fn sos2_portable(
    a0: &[u64; 4],
    b0: &[u64; 4],
    a1: &[u64; 4],
    b1: &[u64; 4],
) -> [u64; 4] {
    debug_assert_operands!(a0, b0, a1, b1);
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    round5!(t0, t1, t2, t3, t4, 0, (a0, b0), (a1, b1));
    round5!(t0, t1, t2, t3, t4, 1, (a0, b0), (a1, b1));
    round5!(t0, t1, t2, t3, t4, 2, (a0, b0), (a1, b1));
    round5!(t0, t1, t2, t3, t4, 3, (a0, b0), (a1, b1));
    debug_assert_eq!(t4, 0, "final value < 2p fits four limbs");
    let out = sub_mod(&[t0, t1, t2, t3], &P, &P);
    debug_assert!(gt(&P, &out));
    out
}

/// `(sum_{i<4} a_i*b_i)*R^{-1} mod p`, canonical. Final value < 1.757p.
#[cfg(any(
    test,
    not(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))
))]
#[inline(never)]
pub(crate) fn sos4_portable(
    a0: &[u64; 4],
    b0: &[u64; 4],
    a1: &[u64; 4],
    b1: &[u64; 4],
    a2: &[u64; 4],
    b2: &[u64; 4],
    a3: &[u64; 4],
    b3: &[u64; 4],
) -> [u64; 4] {
    debug_assert_operands!(a0, b0, a1, b1, a2, b2, a3, b3);
    let (mut t0, mut t1, mut t2, mut t3, mut t4) = (0u64, 0u64, 0u64, 0u64, 0u64);
    round5!(
        t0,
        t1,
        t2,
        t3,
        t4,
        0,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3)
    );
    round5!(
        t0,
        t1,
        t2,
        t3,
        t4,
        1,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3)
    );
    round5!(
        t0,
        t1,
        t2,
        t3,
        t4,
        2,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3)
    );
    round5!(
        t0,
        t1,
        t2,
        t3,
        t4,
        3,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3)
    );
    debug_assert_eq!(t4, 0, "final value < 2p fits four limbs");
    let out = sub_mod(&[t0, t1, t2, t3], &P, &P);
    debug_assert!(gt(&P, &out));
    out
}

/// `(sum_{i<6} a_i*b_i)*R^{-1} mod p`, canonical. Six-limb accumulator; final
/// value < 2.135p, two conditional subtractions.
#[cfg(test)]
#[inline(never)]
pub fn sos6(products: [SosProduct<'_>; 6]) -> [u64; 4] {
    let [
        SosProduct {
            left: a0,
            right: b0,
        },
        SosProduct {
            left: a1,
            right: b1,
        },
        SosProduct {
            left: a2,
            right: b2,
        },
        SosProduct {
            left: a3,
            right: b3,
        },
        SosProduct {
            left: a4,
            right: b4,
        },
        SosProduct {
            left: a5,
            right: b5,
        },
    ] = products;
    debug_assert_operands!(a0, b0, a1, b1, a2, b2, a3, b3, a4, b4, a5, b5);
    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        0,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        1,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        2,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        3,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5)
    );
    debug_assert_eq!(t5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(t4, 0, "final value < 3p < 2^256 fits four limbs");
    let out = sub_mod(&sub_mod(&[t0, t1, t2, t3], &P, &P), &P, &P);
    debug_assert!(gt(&P, &out));
    out
}

/// `(sum_{i<8} a_i*b_i)*R^{-1} mod p`, canonical. Six-limb accumulator; between
/// rounds u < 9p < 2^260, in-round peak < 9p*2^64 < 2^324; final value
/// < p*(1 + 8*0.1891) < 2.513p, two conditional subtractions.
#[cfg(test)]
#[inline(never)]
pub fn sos8(products: [SosProduct<'_>; 8]) -> [u64; 4] {
    let [
        SosProduct {
            left: a0,
            right: b0,
        },
        SosProduct {
            left: a1,
            right: b1,
        },
        SosProduct {
            left: a2,
            right: b2,
        },
        SosProduct {
            left: a3,
            right: b3,
        },
        SosProduct {
            left: a4,
            right: b4,
        },
        SosProduct {
            left: a5,
            right: b5,
        },
        SosProduct {
            left: a6,
            right: b6,
        },
        SosProduct {
            left: a7,
            right: b7,
        },
    ] = products;
    debug_assert_operands!(
        a0, b0, a1, b1, a2, b2, a3, b3, a4, b4, a5, b5, a6, b6, a7, b7
    );
    let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        0,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5),
        (a6, b6),
        (a7, b7)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        1,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5),
        (a6, b6),
        (a7, b7)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        2,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5),
        (a6, b6),
        (a7, b7)
    );
    round6!(
        t0,
        t1,
        t2,
        t3,
        t4,
        t5,
        3,
        (a0, b0),
        (a1, b1),
        (a2, b2),
        (a3, b3),
        (a4, b4),
        (a5, b5),
        (a6, b6),
        (a7, b7)
    );
    debug_assert_eq!(t5, 0, "final value < 3p fits five limbs");
    debug_assert_eq!(t4, 0, "final value < 3p < 2^256 fits four limbs");
    let out = sub_mod(&sub_mod(&[t0, t1, t2, t3], &P, &P), &P, &P);
    debug_assert!(gt(&P, &out));
    out
}

// Tier dispatch: on the x86-64 ADX tier every production SoS entry point
// routes to the rolled `helius_sos_x86` leaf (one op-cache-resident loop for
// the whole tower; see build/schedule.rs); everywhere else, and under
// force-portable, the unrolled portable kernels above are the
// implementation. Purely compile-time -- no runtime dispatch exists.

macro_rules! dispatch_sos {
    ($($(#[$meta:meta])* fn $name:ident / $portable:ident ($($arg:ident),+) -> $ret:ty;)+) => {
        $(
            $(#[$meta])*
            #[inline(always)]
            pub fn $name($($arg: &[u64; 4]),+) -> $ret {
                #[cfg(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))]
                {
                    crate::fp::x86_64::$name($($arg),+)
                }
                #[cfg(not(all(helius_mont4_x86_64_adx, not(feature = "force-portable"))))]
                {
                    $portable($($arg),+)
                }
            }
        )+
    };
}

/// Dual-lane Fp2 product. Portable dual-lane on every tier by default: it
/// ties the generated leaf through the full pairing on Zen 4 and beats it on
/// Granite Rapids, where Intel schedules the compiled body better. A build
/// with `HELIUS_SOSD2_ASM=1` dispatches to the x86 leaf instead (kernel-level
/// win on Zen 4; see build.rs).
#[inline(always)]
pub fn sosd2(x0: &[u64; 4], x1: &[u64; 4], y0: &[u64; 4], y1: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    #[cfg(helius_sosd2_active)]
    {
        crate::fp::x86_64::sosd2(x0, x1, y0, y1)
    }
    #[cfg(not(helius_sosd2_active))]
    {
        sosd2_portable(x0, x1, y0, y1)
    }
}

dispatch_sos! {
    #[cfg(any(test, not(helius_cyc_sqr_active)))]
    fn sos2 / sos2_portable (a0, b0, a1, b1) -> [u64; 4];
    #[cfg(any(test, not(helius_cyc_sqr_active)))]
    fn sos4 / sos4_portable (a0, b0, a1, b1, a2, b2, a3, b3) -> [u64; 4];
    fn sosd4 / sosd4_portable (x00, x01, y00, y01, x10, x11, y10, y11) -> ([u64; 4], [u64; 4]);
}

/// Dual-lane sum of three Fp2 products, T = 6 per lane: the tower's hottest
/// dual-lane shape (six per composed Fp12 square and per mul_by_034, three
/// per Fp6 mul). On the ADX tier the composed route -- two serial
/// `helius_sos_x86` walks -- is the default; a build with
/// `HELIUS_SOSD6_ASM=1` dispatches to the dedicated leaf that interleaves
/// both lanes' carry chains and computes the `p - y` images in-kernel
/// (default off pending measurement; see build.rs).
#[inline(always)]
#[cfg(any(
    test,
    not(helius_fp6_active),
    not(helius_fp12_sqr_active),
    not(helius_fp12_034_active),
))]
pub fn sosd6(products: [Fp2Product<'_>; 3]) -> ([u64; 4], [u64; 4]) {
    #[cfg(helius_sosd6_active)]
    {
        crate::fp::x86_64::sosd6_leaf(products)
    }
    // Activation implies the ADX tier without force-portable, so the two
    // conditions below split the remaining space exactly.
    #[cfg(all(
        helius_mont4_x86_64_adx,
        not(feature = "force-portable"),
        not(helius_sosd6_active)
    ))]
    {
        crate::fp::x86_64::sosd6(products)
    }
    #[cfg(not(all(helius_mont4_x86_64_adx, not(feature = "force-portable"))))]
    {
        sosd6_portable(products)
    }
}

/// Dual-lane sum of four Fp2 products. No production caller since the Fp12
/// square dropped to 6-product rows; kept for the kernel differential tests.
#[cfg(test)]
#[inline(always)]
pub fn sosd8(products: [Fp2Product<'_>; 4]) -> ([u64; 4], [u64; 4]) {
    #[cfg(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))]
    {
        crate::fp::x86_64::sosd8(products)
    }
    #[cfg(not(all(helius_mont4_x86_64_adx, not(feature = "force-portable"))))]
    {
        sosd8_portable(products)
    }
}
