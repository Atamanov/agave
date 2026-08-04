//! Portable fully-unrolled CIOS Montgomery mul/sqr.

use crate::consts::{P, P_INV};
use crate::fp::Fp;

// A four-limb value times one word is a five-limb value. Build it as one
// carry chain so the compiler can keep the carry in the machine flags.
macro_rules! mul_word {
    (($a0:expr, $a1:expr, $a2:expr, $a3:expr), $b:expr) => {{
        let (r0, h0) = $a0.carrying_mul($b, 0);
        let (l1, h1) = $a1.carrying_mul($b, 0);
        let (l2, h2) = $a2.carrying_mul($b, 0);
        let (l3, h3) = $a3.carrying_mul($b, 0);
        let (r1, carry) = h0.carrying_add(l1, false);
        let (r2, carry) = h1.carrying_add(l2, carry);
        let (r3, carry) = h2.carrying_add(l3, carry);
        let (r4, overflow) = h3.carrying_add(0, carry);
        debug_assert!(!overflow, "four limbs times one limb fits five limbs");
        (r0, r1, r2, r3, r4)
    }};
}

// Add two five-limb rows and return the sixth carry bit separately. Passing
// the boolean from one `carrying_add` into the next is what forms `adds`/`adcs`
// on AArch64; converting it to a u64 between limbs would force `cset` traffic.
macro_rules! add_wide {
    (
        ($a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr),
        ($b0:expr, $b1:expr, $b2:expr, $b3:expr, $b4:expr)
    ) => {{
        let (r0, carry) = $a0.carrying_add($b0, false);
        let (r1, carry) = $a1.carrying_add($b1, carry);
        let (r2, carry) = $a2.carrying_add($b2, carry);
        let (r3, carry) = $a3.carrying_add($b3, carry);
        let (r4, carry) = $a4.carrying_add($b4, carry);
        ((r0, r1, r2, r3, r4), carry)
    }};
}

// One macro expansion is one fixed CIOS row: add `a * b_limb`, cancel the
// low word with `m * P`, then shift the five-word accumulator. Keeping the row
// structural (rather than indexing through loops) exposes all 32 products and
// both carry chains to LLVM while keeping the four rounds mechanically equal.
macro_rules! cios_round {
    (
        ($t0:expr, $t1:expr, $t2:expr, $t3:expr, $t4:expr),
        $b:expr,
        ($a0:expr, $a1:expr, $a2:expr, $a3:expr),
        ($p0:expr, $p1:expr, $p2:expr, $p3:expr),
        $inv:expr
    ) => {{
        let (r0, r1, r2, r3, r4) = mul_word!(($a0, $a1, $a2, $a3), $b);
        let ((t0, t1, t2, t3, t4), overflow) =
            add_wide!(($t0, $t1, $t2, $t3, $t4), (r0, r1, r2, r3, r4));
        debug_assert!(!overflow, "CIOS product row fits the fifth limb");

        let m = t0.wrapping_mul($inv);
        let (q0, q1, q2, q3, q4) = mul_word!(($p0, $p1, $p2, $p3), m);
        let ((discard, t0, t1, t2, t3), t4) = add_wide!((t0, t1, t2, t3, t4), (q0, q1, q2, q3, q4));
        debug_assert_eq!(discard, 0, "Montgomery factor cancels the low limb");

        (t0, t1, t2, t3, u64::from(t4))
    }};
}

#[inline(always)]
pub fn mont_sqr(a: &[u64; 4]) -> Fp {
    mont_mul(a, a)
}

// This is deliberately one compiler-visible leaf. Inlining a fully unrolled
// four-limb kernel into every Fp/Fp2 formula multiplies text size and makes LTO
// spend minutes optimizing clones; the call boundary also matches the native
// backend, so backend comparisons measure arithmetic rather than layout.
#[inline(never)]
pub fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Fp {
    debug_assert!(!crate::limb::gte(a, &P));
    debug_assert!(!crate::limb::gte(b, &P));
    let (a0, a1, a2, a3) = (a[0], a[1], a[2], a[3]);
    let (b0, b1, b2, b3) = (b[0], b[1], b[2], b[3]);
    let (p0, p1, p2, p3) = (P[0], P[1], P[2], P[3]);
    let inv = P_INV;

    let (t0, t1, t2, t3, t4) = cios_round!(
        (0u64, 0u64, 0u64, 0u64, 0u64),
        b0,
        (a0, a1, a2, a3),
        (p0, p1, p2, p3),
        inv
    );
    let (t0, t1, t2, t3, t4) = cios_round!(
        (t0, t1, t2, t3, t4),
        b1,
        (a0, a1, a2, a3),
        (p0, p1, p2, p3),
        inv
    );
    let (t0, t1, t2, t3, t4) = cios_round!(
        (t0, t1, t2, t3, t4),
        b2,
        (a0, a1, a2, a3),
        (p0, p1, p2, p3),
        inv
    );
    let (t0, t1, t2, t3, t4) = cios_round!(
        (t0, t1, t2, t3, t4),
        b3,
        (a0, a1, a2, a3),
        (p0, p1, p2, p3),
        inv
    );

    let (d0, borrow) = t0.borrowing_sub(p0, false);
    let (d1, borrow) = t1.borrowing_sub(p1, borrow);
    let (d2, borrow) = t2.borrowing_sub(p2, borrow);
    let (d3, borrow) = t3.borrowing_sub(p3, borrow);
    if t4 != 0 || !borrow {
        Fp([d0, d1, d2, d3])
    } else {
        Fp([t0, t1, t2, t3])
    }
}
