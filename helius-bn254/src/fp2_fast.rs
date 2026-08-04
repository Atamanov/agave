//! Monomorphized Fp2 ops over raw limb pairs for the G2 and Miller hot paths.
//!
//! `F2 = ([u64; 4], [u64; 4])` carries canonical Montgomery limbs (< p) in
//! and out of every op; the fused muls/squares are the dual SoS kernels, and
//! `mont_mul` binds to the target's tier at compile time. On x86 the small
//! add/sub bodies are outlined so the Miller loop stays inside the 32KB L1I;
//! `g2_fast` and `pairing::miller` build entirely on this module.

use crate::consts::P;
use crate::fp::Fp;
// Tower/miller: shared out-of-line asm (keeps miller I-cache tight).
#[cfg(all(
    target_arch = "aarch64",
    target_vendor = "apple",
    not(feature = "force-portable"),
))]
use crate::fp::aarch64::mont_mul;
#[cfg(not(any(
    all(
        target_arch = "aarch64",
        target_vendor = "apple",
        not(feature = "force-portable")
    ),
    all(helius_mont4_x86_64_adx, not(feature = "force-portable"))
)))]
use crate::fp::portable::mont_mul;
#[cfg(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))]
use crate::fp::x86_64::mont_mul;
use crate::fp2::Fp2;
use crate::limb::{add_mod, sub_mod};

pub type F2 = ([u64; 4], [u64; 4]); // (c0, c1)

#[inline(always)]
fn fm(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, b).0
}
#[inline(always)]
fn fa(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    add_mod(a, b, &P)
}
#[inline(always)]
fn fsub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    sub_mod(a, b, &P)
}
#[inline(always)]
fn fd(a: &[u64; 4]) -> [u64; 4] {
    fa(a, a)
}
#[inline(always)]
fn fneg(a: &[u64; 4]) -> [u64; 4] {
    // Plain p-a is wrong at zero (p-0 = p needs a reduce). sub_mod(0, a)
    // gives -a mod p and maps zero to zero.
    fsub(&[0; 4], a)
}

#[inline(always)]
pub fn f2_from(f: Fp2) -> F2 {
    (f.c0.0, f.c1.0)
}
#[inline(always)]
pub fn f2_to(f: F2) -> Fp2 {
    Fp2 {
        c0: Fp(f.0),
        c1: Fp(f.1),
    }
}

// x86: outlined. Inlined copies of the two add/sub reduction chains compile
// to interleaved cmp/setb flag rematerialization inside the big Miller bodies
// (~200B per site); one shared out-of-line body per op keeps the per-iteration
// code footprint inside the 32KB L1I. aarch64 (192KB L1I) keeps them inline.
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_add(a: F2, b: F2) -> F2 {
    (fa(&a.0, &b.0), fa(&a.1, &b.1))
}
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_sub(a: F2, b: F2) -> F2 {
    (fsub(&a.0, &b.0), fsub(&a.1, &b.1))
}
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_dbl(a: F2) -> F2 {
    (fd(&a.0), fd(&a.1))
}
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_neg(a: F2) -> F2 {
    (fneg(&a.0), fneg(&a.1))
}

/// Schoolbook sums-of-products (4M, 2 interleaved reductions):
/// `c0 = a0*b0 - a1*b1`, `c1 = a0*b1 + a1*b0`; both lanes in one dual kernel.
#[inline(always)]
pub fn f2_mul(a: F2, b: F2) -> F2 {
    crate::fp::sos::sosd2(&a.0, &a.1, &b.0, &b.1)
}

/// SoS square: `c0 = a0^2 - a1^2`, `c1 = a0*a1 + a1*a0` (4M, 2 reductions,
/// no modular add/sub); both lanes in one dual kernel.
#[inline(always)]
pub fn f2_sqr(a: F2) -> F2 {
    crate::fp::sos::sosd2(&a.0, &a.1, &a.0, &a.1)
}

/// Karatsuba: 3 Montgomery products + 3 reductions vs `f2_mul`'s fused
/// 4 + 2, for five extra modular add/subs. Canonical in/out. Intel converts
/// widening products to cycles nearly 1:1, so ADX+Intel builds route the
/// Miller G2-step muls here; other tiers keep the fused dual kernel. Also
/// the differential-test reference.
#[cfg(any(test, all(helius_x86_intel, not(feature = "force-portable"))))]
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_mul_karatsuba(a: F2, b: F2) -> F2 {
    let t0 = fm(&a.0, &b.0);
    let t1 = fm(&a.1, &b.1);
    let t2 = fm(&fa(&a.0, &a.1), &fa(&b.0, &b.1));
    (fsub(&t0, &t1), fsub(&fsub(&t2, &t0), &t1))
}

/// (a+bu)^2 = (a+b)(a-b) + 2ab u: 2 Montgomery products + 2 reductions vs
/// `f2_sqr`'s fused 4 + 2, for three extra modular add/subs. Canonical
/// in/out. The ADX tier routes the Miller G2-step squares here (mont_mul
/// dominates there); other tiers keep the fused dual kernel.
#[cfg(any(test, all(helius_mont4_x86_64_adx, not(feature = "force-portable"))))]
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
pub fn f2_sqr_lazy(a: F2) -> F2 {
    let ab = fm(&a.0, &a.1);
    (fm(&fa(&a.0, &a.1), &fsub(&a.0, &a.1)), fd(&ab))
}

#[inline(always)]
pub fn f2_mul_fp(a: F2, f: &[u64; 4]) -> F2 {
    (fm(&a.0, f), fm(&a.1, f))
}

#[inline(always)]
pub fn f2_is_zero(a: F2) -> bool {
    (a.0[0] | a.0[1] | a.0[2] | a.0[3] | a.1[0] | a.1[1] | a.1[2] | a.1[3]) == 0
}

#[inline(always)]
pub fn f2_is_one(a: F2) -> bool {
    use crate::consts::MONT_ONE;
    a.0 == MONT_ONE && (a.1[0] | a.1[1] | a.1[2] | a.1[3]) == 0
}

#[inline(always)]
pub fn f2_one() -> F2 {
    use crate::consts::MONT_ONE;
    (MONT_ONE, [0; 4])
}
