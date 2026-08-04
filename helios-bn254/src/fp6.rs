//! Cubic extension `Fp6 = Fp2[v]/(v^3 - xi)` with `xi = 9 + u`.
//!
//! Middle layer of the pairing tower. Multiplication flattens to the
//! sums-of-products kernels (`sosd4`/`sosd6`): each output Fp component is
//! one interleaved reduction over 4 or 6 products, never a chain of Fp2 ops.
//! The full product dispatches to the whole-Fp6 x86 leaf under
//! `helios_fp6_active`, with the composed SoS path as reference. `repr(C)`
//! pins the 24-limb layout that kernel ABI reads.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::fp::Fp;
use crate::fp::sos::{sosd4, sosd6};
use crate::fp2::Fp2;

/// `c0 + c1 v + c2 v^2`.
// repr(C): the fp6 kernel ABI reads Fp6/Fp2/Fp as 24 contiguous limbs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp6 {
    /// Constant coefficient.
    pub c0: Fp2,
    /// Coefficient of `v`.
    pub c1: Fp2,
    /// Coefficient of `v^2`.
    pub c2: Fp2,
}

impl Fp6 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        c0: Fp2::ZERO,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };
    /// Multiplicative identity.
    pub const ONE: Self = Self {
        c0: Fp2::ONE,
        c1: Fp2::ZERO,
        c2: Fp2::ZERO,
    };

    /// `c0 + c1*v + c2*v^2` from components.
    #[inline]
    pub const fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Self { c0, c1, c2 }
    }

    /// True iff all components are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    /// `2 * self`.
    #[inline]
    pub fn double(self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
            c2: self.c2.double(),
        }
    }

    /// Additive inverse.
    #[inline]
    pub fn neg(self) -> Self {
        Self {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
        }
    }

    /// Multiply by `v` (non-residue for Fp12): `v * (c0 + c1 v + c2 v^2) = xi c2 + c0 v + c1 v^2`.
    #[inline(always)]
    pub fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// `self^2` (Devegili et al. cubic squaring).
    #[inline(always)]
    pub fn square(self) -> Self {
        let s0 = self.c0.square();
        let ab = self.c0 * self.c1;
        let s1 = ab.double();
        let s2 = (self.c0 - self.c1 + self.c2).square();
        let bc = self.c1 * self.c2;
        let s3 = bc.double();
        let s4 = self.c2.square();

        Self {
            c0: s0 + s3.mul_by_nonresidue(),
            c1: s1 + s4.mul_by_nonresidue(),
            c2: s1 + s2 + s3 - s0 - s4,
        }
    }

    /// Variable-time multiplicative inverse (Devegili et al., as in mcl);
    /// `None` for zero.
    pub fn invert(self) -> Option<Self> {
        let c0 = self.c0.square() - (self.c1 * self.c2).mul_by_nonresidue();
        let c1 = self.c2.square().mul_by_nonresidue() - (self.c0 * self.c1);
        let c2 = self.c1.square() - (self.c0 * self.c2);
        let t = ((self.c2 * c1) + (self.c1 * c2)).mul_by_nonresidue() + (self.c0 * c0);
        let t = t.invert()?;
        Some(Self {
            c0: c0 * t,
            c1: c1 * t,
            c2: c2 * t,
        })
    }

    /// Sparse: multiply by `c0 + c1 v` (c2 = 0). Matches arkworks `mul_by_01`.
    ///
    /// SoS schoolbook: `r0 = a0*c0 + a2*(xic1)`, `r1 = a0*c1 + a1*c0`,
    /// `r2 = a1*c1 + a2*c0`; each Fp component is one 4-product interleaved
    /// reduction.
    #[inline(always)]
    pub fn mul_by_01(self, c0: Fp2, c1: Fp2) -> Self {
        let x1 = c1.mul_by_nonresidue();
        let (a00, a01) = (&self.c0.c0.0, &self.c0.c1.0);
        let (a10, a11) = (&self.c1.c0.0, &self.c1.c1.0);
        let (a20, a21) = (&self.c2.c0.0, &self.c2.c1.0);
        let (b0, b1) = (&c0.c0.0, &c0.c1.0);
        let (g0, g1) = (&c1.c0.0, &c1.c1.0);
        let (x0, xi1) = (&x1.c0.0, &x1.c1.0);
        let r0 = sosd4(a00, a01, b0, b1, a20, a21, x0, xi1);
        let r1 = sosd4(a00, a01, g0, g1, a10, a11, b0, b1);
        let r2 = sosd4(a10, a11, g0, g1, a20, a21, b0, b1);
        Self {
            c0: Fp2::new(Fp(r0.0), Fp(r0.1)),
            c1: Fp2::new(Fp(r1.0), Fp(r1.1)),
            c2: Fp2::new(Fp(r2.0), Fp(r2.1)),
        }
    }

    /// Karatsuba-style `mul_by_01`: differential reference for the SoS body.
    #[cfg(test)]
    pub fn mul_by_01_karatsuba(self, c0: Fp2, c1: Fp2) -> Self {
        let a_a = self.c0 * c0;
        let b_b = self.c1 * c1;

        let mut t1 = (self.c1 + self.c2) * c1 - b_b;
        t1 = t1.mul_by_nonresidue() + a_a;

        let t3 = (self.c0 + self.c2) * c0 - a_a + b_b;
        let t2 = (self.c0 + self.c1) * (c0 + c1) - a_a - b_b;

        Self {
            c0: t1,
            c1: t2,
            c2: t3,
        }
    }

    /// Sparse: multiply by `c1 * v` only.
    pub fn mul_by_1(self, c1: Fp2) -> Self {
        let b_b = self.c1 * c1;
        let mut t1 = (self.c1 + self.c2) * c1 - b_b;
        t1 = t1.mul_by_nonresidue();
        let t2 = (self.c0 + self.c1) * c1 - b_b;
        Self {
            c0: t1,
            c1: t2,
            c2: b_b,
        }
    }
}

impl Add for Fp6 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
        }
    }
}
impl AddAssign for Fp6 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Fp6 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
            c2: self.c2 - rhs.c2,
        }
    }
}
impl SubAssign for Fp6 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Fp6 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        // Whole-Fp6 leaf (HELIOS_FP6_ASM=1): same math as the composed path
        // below, one call instead of six sosd6 lane dispatches plus two Rust
        // xi scalings; the composed path stays the reference.
        #[cfg(helios_fp6_active)]
        {
            crate::fp::x86_64::fp6_mul(&self, &rhs)
        }
        #[cfg(not(helios_fp6_active))]
        {
            self.mul_sosd6(rhs)
        }
    }
}

impl Fp6 {
    /// Composed multiplication: SoS schoolbook (Longa 2022/367 Eq. 9), xi
    /// folded into precomputed rows: c0 = a0*b0 + a1*(xib2) + a2*(xib1),
    /// c1 = a0*b1 + a1*b0 + a2*(xib2), c2 = a0*b2 + a1*b1 + a2*b0. Each Fp
    /// component is one 6-product interleaved reduction (36M + 6R total, no
    /// modular add/subs beyond the two xi chains). Reference semantics for
    /// the whole-Fp6 x86 leaf, which computes exactly this in one call.
    #[cfg_attr(all(helios_fp6_active, not(test)), allow(dead_code))]
    #[inline(always)]
    pub(crate) fn mul_sosd6(self, rhs: Self) -> Self {
        let xb1 = rhs.c1.mul_by_nonresidue();
        let xb2 = rhs.c2.mul_by_nonresidue();
        let (a00, a01) = (&self.c0.c0.0, &self.c0.c1.0);
        let (a10, a11) = (&self.c1.c0.0, &self.c1.c1.0);
        let (a20, a21) = (&self.c2.c0.0, &self.c2.c1.0);
        let (b00, b01) = (&rhs.c0.c0.0, &rhs.c0.c1.0);
        let (b10, b11) = (&rhs.c1.c0.0, &rhs.c1.c1.0);
        let (b20, b21) = (&rhs.c2.c0.0, &rhs.c2.c1.0);
        let (x10, x11) = (&xb1.c0.0, &xb1.c1.0);
        let (x20, x21) = (&xb2.c0.0, &xb2.c1.0);
        let r0 = sosd6(a00, a01, b00, b01, a10, a11, x20, x21, a20, a21, x10, x11);
        let r1 = sosd6(a00, a01, b10, b11, a10, a11, b00, b01, a20, a21, x20, x21);
        let r2 = sosd6(a00, a01, b20, b21, a10, a11, b10, b11, a20, a21, b00, b01);
        Self {
            c0: Fp2::new(Fp(r0.0), Fp(r0.1)),
            c1: Fp2::new(Fp(r1.0), Fp(r1.1)),
            c2: Fp2::new(Fp(r2.0), Fp(r2.1)),
        }
    }
}

impl Fp6 {
    /// Karatsuba multiplication: differential reference for `mul_sosd6`.
    #[cfg(test)]
    pub fn mul_karatsuba(self, rhs: Self) -> Self {
        let a = self;
        let b = rhs;
        let t0 = a.c0 * b.c0;
        let t1 = a.c1 * b.c1;
        let t2 = a.c2 * b.c2;

        Self {
            c0: ((a.c1 + a.c2) * (b.c1 + b.c2) - t1 - t2).mul_by_nonresidue() + t0,
            c1: (a.c0 + a.c1) * (b.c0 + b.c1) - t0 - t1 + t2.mul_by_nonresidue(),
            c2: (a.c0 + a.c2) * (b.c0 + b.c2) - t0 + t1 - t2,
        }
    }
}
impl MulAssign for Fp6 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Fp6 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Fp6::neg(self)
    }
}

impl From<Fp2> for Fp6 {
    fn from(c0: Fp2) -> Self {
        Self {
            c0,
            c1: Fp2::ZERO,
            c2: Fp2::ZERO,
        }
    }
}
