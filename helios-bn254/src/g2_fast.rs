//! Hot-path G2 Jacobian mixed-add / double over `fp2_fast` limbs.
//!
//! Monomorphized bodies behind `G2Projective::double`/`add_mixed`: the same
//! EFD a=0 formulas as `g1_fast`, lifted to Fp2 through the `F2` raw-limb
//! ops so G2 scalar multiplication never routes through the operator tower.
//! Identity is encoded as `z = 0`; all values stay canonical.

use crate::fp2_fast::{
    f2_add, f2_dbl, f2_from, f2_is_one, f2_is_zero, f2_mul, f2_one, f2_sqr, f2_sub, f2_to,
};
use crate::g2::{G2Affine, G2Projective};

#[inline(always)]
pub fn g2_dbl(p: G2Projective) -> G2Projective {
    if p.is_identity() {
        return p;
    }
    let x = f2_from(p.x);
    let y = f2_from(p.y);
    let z = f2_from(p.z);
    let pz1 = f2_is_one(z);
    let x2 = f2_sqr(x);
    let mut y2 = f2_sqr(y);
    let mut xy = f2_mul(x, y2);
    xy = f2_dbl(xy);
    xy = f2_dbl(xy);
    y2 = f2_sqr(y2);
    let t = f2_add(f2_dbl(x2), x2);
    let mut x3 = f2_sqr(t);
    x3 = f2_sub(x3, xy);
    x3 = f2_sub(x3, xy);
    let z3 = if pz1 { f2_dbl(y) } else { f2_dbl(f2_mul(y, z)) };
    let mut y3 = f2_mul(t, f2_sub(xy, x3));
    y3 = f2_sub(y3, f2_dbl(f2_dbl(f2_dbl(y2))));
    G2Projective {
        x: f2_to(x3),
        y: f2_to(y3),
        z: f2_to(z3),
    }
}

#[inline(always)]
pub fn g2_madd(p: G2Projective, q: G2Affine) -> G2Projective {
    if q.infinity {
        return p;
    }
    if p.is_identity() {
        return q.to_curve();
    }
    let x1 = f2_from(p.x);
    let y1 = f2_from(p.y);
    let z1 = f2_from(p.z);
    let x2 = f2_from(q.x);
    let y2 = f2_from(q.y);
    let pz1 = f2_is_one(z1);
    let rz2 = if pz1 { f2_one() } else { f2_sqr(z1) };
    let u1 = x1;
    let h = if pz1 {
        f2_sub(x2, u1)
    } else {
        f2_sub(f2_mul(x2, rz2), u1)
    };
    let s1 = y1;
    let r = if pz1 {
        f2_sub(y2, s1)
    } else {
        f2_sub(f2_mul(f2_mul(rz2, z1), y2), s1)
    };
    if f2_is_zero(h) {
        if f2_is_zero(r) {
            return g2_dbl(p);
        }
        return G2Projective::identity();
    }
    let z3 = if pz1 { h } else { f2_mul(z1, h) };
    let mut h3 = f2_sqr(h);
    let mut ry = f2_sqr(r);
    let mut u1h = f2_mul(u1, h3);
    h3 = f2_mul(h3, h);
    ry = f2_sub(ry, u1h);
    ry = f2_sub(ry, u1h);
    let x3 = f2_sub(ry, h3);
    u1h = f2_sub(u1h, x3);
    u1h = f2_mul(u1h, r);
    h3 = f2_mul(h3, s1);
    let y3 = f2_sub(u1h, h3);
    G2Projective {
        x: f2_to(x3),
        y: f2_to(y3),
        z: f2_to(z3),
    }
}

impl G2Projective {
    /// EFD dbl-2009-l over Fp2 on raw limbs; the body behind
    /// [`G2Projective::double`].
    #[inline(always)]
    pub(crate) fn double_fast(self) -> Self {
        g2_dbl(self)
    }
    /// EFD madd-2007-bl over Fp2 on raw limbs; the body behind
    /// [`G2Projective::add_mixed`].
    #[inline(always)]
    pub(crate) fn add_mixed_fast(self, other: G2Affine) -> Self {
        g2_madd(self, other)
    }
}
