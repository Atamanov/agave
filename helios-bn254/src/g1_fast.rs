//! Hot-path G1 Jacobian mixed-add / double on raw limbs (EFD a=0 formulas).
//!
//! Monomorphized bodies behind `G1Projective::double`/`add_mixed`: canonical
//! Montgomery limbs in and out, identity encoded as `z = 0`, and `mont_mul`/
//! `mont_sqr` bound to the target's tier at compile time. The scalar-mul and
//! MSM inner loops spend their time here.

use crate::consts::{MONT_ONE, P};
use crate::fp::Fp;
use crate::g1::{G1Affine, G1Projective};
use crate::limb::{add_mod, is_zero, sub_mod};

#[cfg(all(
    target_arch = "aarch64",
    target_vendor = "apple",
    not(feature = "force-portable"),
))]
use crate::fp::aarch64::{mont_mul, mont_sqr};
#[cfg(any(
    not(target_arch = "aarch64"),
    not(target_vendor = "apple"),
    feature = "force-portable",
))]
use crate::fp::portable::{mont_mul, mont_sqr};

#[inline(always)]
fn fmul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, b).0
}
#[inline(always)]
fn fsqr(a: &[u64; 4]) -> [u64; 4] {
    mont_sqr(a).0
}
#[inline(always)]
fn fadd(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    add_mod(a, b, &P)
}
#[inline(always)]
fn fsub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    sub_mod(a, b, &P)
}
#[inline(always)]
fn fdbl(a: &[u64; 4]) -> [u64; 4] {
    fadd(a, a)
}
#[inline(always)]
fn is_one(a: &[u64; 4]) -> bool {
    a == &MONT_ONE
}

#[inline(always)]
pub fn g1_dbl_raw(x: [u64; 4], y: [u64; 4], z: [u64; 4]) -> ([u64; 4], [u64; 4], [u64; 4]) {
    if is_zero(&z) {
        return (x, y, z);
    }
    let pz_one = is_one(&z);
    let x2 = fsqr(&x);
    let mut y2 = fsqr(&y);
    let mut xy = fmul(&x, &y2);
    xy = fdbl(&xy);
    xy = fdbl(&xy);
    y2 = fsqr(&y2);
    let t = fadd(&fdbl(&x2), &x2);
    let mut x3 = fsqr(&t);
    x3 = fsub(&x3, &xy);
    x3 = fsub(&x3, &xy);
    let z3 = if pz_one {
        fdbl(&y)
    } else {
        fdbl(&fmul(&y, &z))
    };
    let mut y3 = fmul(&t, &fsub(&xy, &x3));
    y3 = fsub(&y3, &fdbl(&fdbl(&fdbl(&y2))));
    (x3, y3, z3)
}

#[inline(always)]
pub fn g1_madd_raw(
    x1: [u64; 4],
    y1: [u64; 4],
    z1: [u64; 4],
    x2: [u64; 4],
    y2: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    if is_zero(&z1) {
        return (x2, y2, MONT_ONE);
    }
    if is_one(&z1) {
        return g1_madd_z_one(x1, y1, x2, y2);
    }
    g1_madd_general(x1, y1, z1, x2, y2)
}

#[inline(always)]
fn g1_madd_z_one(
    x1: [u64; 4],
    y1: [u64; 4],
    x2: [u64; 4],
    y2: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    let h = fsub(&x2, &x1);
    let r = fsub(&y2, &y1);
    if is_zero(&h) {
        if is_zero(&r) {
            return g1_dbl_raw(x1, y1, MONT_ONE);
        }
        return ([0; 4], MONT_ONE, [0; 4]);
    }
    let z3 = h;
    let mut h3 = fsqr(&h);
    let mut ry = fsqr(&r);
    let mut u1h = fmul(&x1, &h3);
    h3 = fmul(&h3, &h);
    ry = fsub(&ry, &u1h);
    ry = fsub(&ry, &u1h);
    let x3 = fsub(&ry, &h3);
    u1h = fsub(&u1h, &x3);
    u1h = fmul(&u1h, &r);
    h3 = fmul(&h3, &y1);
    let y3 = fsub(&u1h, &h3);
    (x3, y3, z3)
}

#[inline(always)]
fn g1_madd_general(
    x1: [u64; 4],
    y1: [u64; 4],
    z1: [u64; 4],
    x2: [u64; 4],
    y2: [u64; 4],
) -> ([u64; 4], [u64; 4], [u64; 4]) {
    let r_z2 = fsqr(&z1);
    let h = fsub(&fmul(&x2, &r_z2), &x1);
    let r = fsub(&fmul(&fmul(&r_z2, &z1), &y2), &y1);
    if is_zero(&h) {
        if is_zero(&r) {
            return g1_dbl_raw(x1, y1, z1);
        }
        return ([0; 4], MONT_ONE, [0; 4]);
    }
    let z3 = fmul(&z1, &h);
    let mut h3 = fsqr(&h);
    let mut ry = fsqr(&r);
    let mut u1h = fmul(&x1, &h3);
    h3 = fmul(&h3, &h);
    ry = fsub(&ry, &u1h);
    ry = fsub(&ry, &u1h);
    let x3 = fsub(&ry, &h3);
    u1h = fsub(&u1h, &x3);
    u1h = fmul(&u1h, &r);
    h3 = fmul(&h3, &y1);
    let y3 = fsub(&u1h, &h3);
    (x3, y3, z3)
}

impl G1Projective {
    /// EFD dbl-2009-l on raw limbs; the body behind [`G1Projective::double`].
    #[inline(always)]
    pub(crate) fn double_fast(self) -> Self {
        let (x, y, z) = g1_dbl_raw(self.x.0, self.y.0, self.z.0);
        Self {
            x: Fp(x),
            y: Fp(y),
            z: Fp(z),
        }
    }

    /// EFD madd-2007-bl on raw limbs; the body behind
    /// [`G1Projective::add_mixed`].
    #[inline(always)]
    pub(crate) fn add_mixed_fast(self, other: G1Affine) -> Self {
        if other.infinity {
            return self;
        }
        let (x, y, z) = g1_madd_raw(self.x.0, self.y.0, self.z.0, other.x.0, other.y.0);
        Self {
            x: Fp(x),
            y: Fp(y),
            z: Fp(z),
        }
    }
}
