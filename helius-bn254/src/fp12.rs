//! Degree-12 extension `Fp12 = Fp6[w]/(w^2 - v)`; GT elements live here.
//!
//! Owns the pairing-side exponentiation machinery: complex squaring, sparse
//! `mul_by_034`, Granger-Scott cyclotomic squaring, Karabina compression,
//! `pow_x`, and the Frobenius maps. The gamma tables and seed recodings are
//! compile-time pinned to their `const_tower` derivations. Hot ops dispatch
//! to whole-op x86 leaves under the `helius_*_active` cfgs, each with its
//! composed SoS path as reference semantics. `repr(C)` pins the 48-limb
//! layout the fp12 kernel ABI reads.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::fp::Fp;
#[cfg(any(test, not(helius_fp12_sqr_active), not(helius_fp12_034_active),))]
use crate::fp::sos::Fp2Product;
use crate::fp2::Fp2;
use crate::fp6::Fp6;

/// `c0 + c1 * w`, `w^2 = v`.
// repr(C): the fp12_034 kernel ABI reads Fp12 as 48 contiguous limbs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp12 {
    /// Constant coefficient.
    pub c0: Fp6,
    /// Coefficient of `w`.
    pub c1: Fp6,
}

impl Fp12 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        c0: Fp6::ZERO,
        c1: Fp6::ZERO,
    };
    /// Multiplicative identity; also the GT identity for pairing products.
    pub const ONE: Self = Self {
        c0: Fp6::ONE,
        c1: Fp6::ZERO,
    };

    /// `c0 + c1*w` from components.
    #[inline]
    pub const fn new(c0: Fp6, c1: Fp6) -> Self {
        Self { c0, c1 }
    }

    /// True iff both components are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// True iff the element is one (the GT identity).
    #[inline]
    pub fn is_one(&self) -> bool {
        self.c0 == Fp6::ONE && self.c1.is_zero()
    }

    /// Conjugate over Fp6: `c0 - c1*w`; equals `a^{p^6}`.
    #[inline]
    pub fn conjugate(self) -> Self {
        Self {
            c0: self.c0,
            c1: -self.c1,
        }
    }

    /// `2 * self`.
    #[inline]
    pub fn double(self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    /// `(a + b*w)^2 = (a^2 + v*b^2) + 2ab*w`, complex squaring through the
    /// shared product `ab`: with `s = a + b`, `t = a + v*b`, the result is
    /// `(s*t - ab - v*ab) + 2ab*w`. Each Fp component of `ab` and `s*t` is a
    /// 6-product interleaved reduction over pre-added canonical operands
    /// (72M + 12R total); the combines are single modular add/subs.
    /// Outlined: one shared body keeps the miller/final-exp hot loop inside
    /// L1I on x86 (the unrolled SoS bodies thrash the 32KB cache if inlined).
    #[inline(always)]
    pub fn square(self) -> Self {
        let mut out = self;
        out.square_in_place();
        out
    }

    /// In-place [`Self::square`]: reads operands from and writes the result to
    /// `self`, avoiding the two 384-byte ABI copies of the by-value form in
    /// the Miller/final-exp hot loops.
    #[inline(never)]
    pub fn square_in_place(&mut self) {
        // Whole-op lazy double-width leaf (HELIUS_FP12_SQR_ASM=1): mcl's
        // 36-product shape; the composed path below stays the reference.
        #[cfg(helius_fp12_sqr_active)]
        {
            crate::fp::x86_64::fp12_sqr_assign(self);
        }
        #[cfg(not(helius_fp12_sqr_active))]
        {
            self.square_in_place_sos();
        }
    }

    /// Composed [`Self::square_in_place`]: complex squaring over the shared
    /// product `ab`, flattened SoS (72 products + 12 interleaved reductions):
    /// six sosd6 rows compute `ab = a*b` and `s*t` with `s = a + b`,
    /// `t = a + v*b`, then `res0 = s*t - ab - v*ab`, `res1 = 2ab` are cheap
    /// modular combines. A standalone 6-product row per res0 component does
    /// not exist: `r00 = a0^2 + xi*(2a1a2 + b1^2 + 2b0b2)` is a rank-6
    /// quadratic form equivalent to `<1,xi> + H + H`, and three products of
    /// linear forms sum to a hyperbolic form, which needs `-xi` (a nonsquare,
    /// as `-1` is square in Fp2) to be square; sharing `ab` with res1 is the
    /// only way down from the 8-product rows.
    /// Reference semantics for the whole-op lazy x86 leaf, which computes
    /// exactly this value with 36 products + 12 reductions.
    #[cfg(any(test, not(helius_fp12_sqr_active)))]
    #[inline(always)]
    pub(crate) fn square_in_place_sos(&mut self) {
        use crate::fp::sos::sosd6;
        let a = &self.c0;
        let b = &self.c1;
        // Pre-adds and xi chains, all reduced mod p (sosd6 needs operands <= p):
        let y = b.c1.mul_by_nonresidue(); // xi*b1
        let h = b.c2.mul_by_nonresidue(); // xi*b2
        let s0 = a.c0 + b.c0;
        let s1 = a.c1 + b.c1;
        let s2 = a.c2 + b.c2;
        let t0 = a.c0 + h; // (v*b)_0 = xi*b2
        let t1 = a.c1 + b.c0;
        let t2 = a.c2 + b.c1;
        let xt1 = t1.mul_by_nonresidue();
        let xt2 = t2.mul_by_nonresidue();

        let (a00, a01) = (&a.c0.c0.0, &a.c0.c1.0);
        let (a10, a11) = (&a.c1.c0.0, &a.c1.c1.0);
        let (a20, a21) = (&a.c2.c0.0, &a.c2.c1.0);
        let (b00, b01) = (&b.c0.c0.0, &b.c0.c1.0);
        let (b10, b11) = (&b.c1.c0.0, &b.c1.c1.0);
        let (b20, b21) = (&b.c2.c0.0, &b.c2.c1.0);
        let (y0, y1) = (&y.c0.0, &y.c1.0);
        let (h0, h1) = (&h.c0.0, &h.c1.0);
        let (s00, s01) = (&s0.c0.0, &s0.c1.0);
        let (s10, s11) = (&s1.c0.0, &s1.c1.0);
        let (s20, s21) = (&s2.c0.0, &s2.c1.0);
        let (t00, t01) = (&t0.c0.0, &t0.c1.0);
        let (t10, t11) = (&t1.c0.0, &t1.c1.0);
        let (t20, t21) = (&t2.c0.0, &t2.c1.0);
        let (u0, u1) = (&xt1.c0.0, &xt1.c1.0);
        let (w0, w1) = (&xt2.c0.0, &xt2.c1.0);

        // ab = a*b, schoolbook with xi folded: ab0 = a0*b0 + a1*(xib2) +
        // a2*(xib1), ab1 = a0*b1 + a1*b0 + a2*(xib2), ab2 = a0*b2 + a1*b1 +
        // a2*b0. Same rows over (s, t) for s*t.
        let ab0 = sosd6([
            Fp2Product::new(a00, a01, b00, b01),
            Fp2Product::new(a10, a11, h0, h1),
            Fp2Product::new(a20, a21, y0, y1),
        ]);
        let ab1 = sosd6([
            Fp2Product::new(a00, a01, b10, b11),
            Fp2Product::new(a10, a11, b00, b01),
            Fp2Product::new(a20, a21, h0, h1),
        ]);
        let ab2 = sosd6([
            Fp2Product::new(a00, a01, b20, b21),
            Fp2Product::new(a10, a11, b10, b11),
            Fp2Product::new(a20, a21, b00, b01),
        ]);
        let st0 = sosd6([
            Fp2Product::new(s00, s01, t00, t01),
            Fp2Product::new(s10, s11, w0, w1),
            Fp2Product::new(s20, s21, u0, u1),
        ]);
        let st1 = sosd6([
            Fp2Product::new(s00, s01, t10, t11),
            Fp2Product::new(s10, s11, t00, t01),
            Fp2Product::new(s20, s21, w0, w1),
        ]);
        let st2 = sosd6([
            Fp2Product::new(s00, s01, t20, t21),
            Fp2Product::new(s10, s11, t10, t11),
            Fp2Product::new(s20, s21, t00, t01),
        ]);

        let ab0 = Fp2::new(Fp(ab0.0), Fp(ab0.1));
        let ab1 = Fp2::new(Fp(ab1.0), Fp(ab1.1));
        let ab2 = Fp2::new(Fp(ab2.0), Fp(ab2.1));
        let st0 = Fp2::new(Fp(st0.0), Fp(st0.1));
        let st1 = Fp2::new(Fp(st1.0), Fp(st1.1));
        let st2 = Fp2::new(Fp(st2.0), Fp(st2.1));

        // res0 = s*t - ab - v*ab with (v*ab) = (xi*ab2, ab0, ab1); res1 = 2ab.
        self.c0 = Fp6::new(
            st0 - ab0 - ab2.mul_by_nonresidue(),
            st1 - ab1 - ab0,
            st2 - ab2 - ab1,
        );
        self.c1 = Fp6::new(ab0.double(), ab1.double(), ab2.double());
    }

    /// Fully flattened body (3 sosd8 + 3 sosd6, 84 products): differential
    /// reference for the 72-product complex-squaring form.
    #[cfg(test)]
    pub(crate) fn square_in_place_sos_d8(&mut self) {
        use crate::fp::sos::{sosd6, sosd8};
        let a = &self.c0;
        let b = &self.c1;
        // Row precomputations (xi chains and doublings, all reduced mod p):
        let da0 = a.c0.double();
        let da1 = a.c1.double();
        let da2 = a.c2.double();
        let g = b.c0.double();
        let x = da1.mul_by_nonresidue(); // xi*2a1
        let e = a.c2.mul_by_nonresidue(); // xi*a2
        let y = b.c1.mul_by_nonresidue(); // xi*b1
        let h = b.c2.mul_by_nonresidue(); // xi*b2
        let z = g.mul_by_nonresidue(); // xi*2b0
        let f = y.double(); // xi*2b1

        let (a00, a01) = (&a.c0.c0.0, &a.c0.c1.0);
        let (a10, a11) = (&a.c1.c0.0, &a.c1.c1.0);
        let (a20, a21) = (&a.c2.c0.0, &a.c2.c1.0);
        let (b00, b01) = (&b.c0.c0.0, &b.c0.c1.0);
        let (b10, b11) = (&b.c1.c0.0, &b.c1.c1.0);
        let (b20, b21) = (&b.c2.c0.0, &b.c2.c1.0);
        let (d0, d1) = (&da0.c0.0, &da0.c1.0);
        let (da10, da11) = (&da1.c0.0, &da1.c1.0);
        let (da20, da21) = (&da2.c0.0, &da2.c1.0);
        let (g0, g1) = (&g.c0.0, &g.c1.0);
        let (x0, x1) = (&x.c0.0, &x.c1.0);
        let (e0, e1) = (&e.c0.0, &e.c1.0);
        let (y0, y1) = (&y.c0.0, &y.c1.0);
        let (h0, h1) = (&h.c0.0, &h.c1.0);
        let (z0, z1) = (&z.c0.0, &z.c1.0);
        let (f0, f1) = (&f.c0.0, &f.c1.0);

        // res0 = a^2 + v*b^2, with a^2 = (a0^2 + xi*2a1a2) + (2a0a1 + xia2^2)v +
        // (a1^2 + 2a0a2)v^2 and v*b^2 = xi(b1^2 + 2b0b2) + (b0^2 + xi*2b1b2)v +
        // (2b0b1 + xib2^2)v^2.
        let r00 = sosd8([
            Fp2Product::new(a00, a01, a00, a01),
            Fp2Product::new(x0, x1, a20, a21),
            Fp2Product::new(y0, y1, b10, b11),
            Fp2Product::new(z0, z1, b20, b21),
        ]);
        let r01 = sosd8([
            Fp2Product::new(d0, d1, a10, a11),
            Fp2Product::new(e0, e1, a20, a21),
            Fp2Product::new(b00, b01, b00, b01),
            Fp2Product::new(f0, f1, b20, b21),
        ]);
        let r02 = sosd8([
            Fp2Product::new(a10, a11, a10, a11),
            Fp2Product::new(d0, d1, a20, a21),
            Fp2Product::new(g0, g1, b10, b11),
            Fp2Product::new(h0, h1, b20, b21),
        ]);

        // res1 = (2a)*b, schoolbook with xi folded: r10 = 2a0*b0 + 2a1*(xib2) +
        // 2a2*(xib1), r11 = 2a0*b1 + 2a1*b0 + 2a2*(xib2), r12 = 2a0*b2 +
        // 2a1*b1 + 2a2*b0.
        let r10 = sosd6([
            Fp2Product::new(d0, d1, b00, b01),
            Fp2Product::new(da10, da11, h0, h1),
            Fp2Product::new(da20, da21, y0, y1),
        ]);
        let r11 = sosd6([
            Fp2Product::new(d0, d1, b10, b11),
            Fp2Product::new(da10, da11, b00, b01),
            Fp2Product::new(da20, da21, h0, h1),
        ]);
        let r12 = sosd6([
            Fp2Product::new(d0, d1, b20, b21),
            Fp2Product::new(da10, da11, b10, b11),
            Fp2Product::new(da20, da21, b00, b01),
        ]);

        self.c0 = Fp6::new(
            Fp2::new(Fp(r00.0), Fp(r00.1)),
            Fp2::new(Fp(r01.0), Fp(r01.1)),
            Fp2::new(Fp(r02.0), Fp(r02.1)),
        );
        self.c1 = Fp6::new(
            Fp2::new(Fp(r10.0), Fp(r10.1)),
            Fp2::new(Fp(r11.0), Fp(r11.1)),
            Fp2::new(Fp(r12.0), Fp(r12.1)),
        );
    }

    /// Composed full product: Karatsuba over three Fp6 products (each an
    /// Fp6 leaf or SoS dispatch, 108 products + 18 reductions total).
    /// Reference semantics for the whole-op lazy x86 leaf, which computes
    /// exactly this value with 54 products + 12 reductions.
    #[cfg(any(test, not(helius_fp12_mul_active)))]
    #[inline(always)]
    pub(crate) fn mul_composed(self, rhs: Self) -> Self {
        let a = self.c0;
        let b = self.c1;
        let c = rhs.c0;
        let d = rhs.c1;
        let t0 = a * c;
        let t1 = b * d;
        Self {
            c0: t0 + t1.mul_by_nonresidue(),
            c1: (a + b) * (c + d) - t0 - t1,
        }
    }

    /// Complex squaring over Karatsuba Fp6 muls: differential reference.
    #[cfg(test)]
    pub fn square_karatsuba(self) -> Self {
        let a = self.c0;
        let b = self.c1;
        let ab = a.mul_karatsuba(b);
        Self {
            c0: (a + b).mul_karatsuba(a + b.mul_by_nonresidue()) - ab - ab.mul_by_nonresidue(),
            c1: ab.double(),
        }
    }

    /// SoS Fp4 square: `(r0 + r1*y)^2` with `y^2 = xi`, i.e.
    /// `t0 = r0^2 + xir1^2 = r0*r0 + (xir1)*r1`, `t1 = 2r0r1 = (2r0)*r1`.
    #[cfg(any(test, not(helius_cyc_sqr_active)))]
    #[inline(always)]
    fn fp4_square_sos(r0: Fp2, r1: Fp2) -> (Fp2, Fp2) {
        // Single-lane kernels: the dual variants spill their two accumulator
        // sets on x86 (16 GPRs) and measurably slow the pow_x chain.
        use crate::fp::sos::{negp, sos2, sos4};
        let x = r1.mul_by_nonresidue();
        let d = r0.double();
        let (r00, r01) = (&r0.c0.0, &r0.c1.0);
        let (r10, r11) = (&r1.c0.0, &r1.c1.0);
        let (x0, x1) = (&x.c0.0, &x.c1.0);
        let (d0, d1) = (&d.c0.0, &d.c1.0);
        let nr01 = negp(r01);
        let nr11 = negp(r11);
        let t0 = Fp2::new(
            Fp(sos4(r00, r00, r01, &nr01, x0, r10, x1, &nr11)),
            Fp(sos4(r00, r01, r01, r00, x0, r11, x1, r10)),
        );
        let t1 = Fp2::new(Fp(sos2(d0, r10, d1, &nr11)), Fp(sos2(d0, r11, d1, r10)));
        (t0, t1)
    }

    /// Granger-Scott cyclotomic square (valid after easy final exp).
    /// Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions.
    /// Kept inline: pow_x calls it in a tight dependent chain, and the
    /// outlined form pays a 384-byte copy in and out per call.
    #[inline(always)]
    pub fn cyclotomic_square(self) -> Self {
        // Whole-op lazy double-width leaf (HELIUS_CYC_SQR_ASM=1): mcl's
        // 18-product fasterSqr shape, updating in place (z == f); the
        // composed path below stays the reference.
        #[cfg(helius_cyc_sqr_active)]
        {
            let mut out = self;
            crate::fp::x86_64::cyc_sqr_assign(&mut out);
            out
        }
        #[cfg(not(helius_cyc_sqr_active))]
        {
            self.cyclotomic_square_composed()
        }
    }

    /// Composed [`Self::cyclotomic_square`]: three Fp4 squares over the SoS
    /// leaves plus the single-width z-combines. Reference semantics for the
    /// whole-op lazy x86 leaf, which computes exactly this value with 18
    /// products + 12 reductions.
    #[cfg(any(test, not(helius_cyc_sqr_active)))]
    #[inline(always)]
    pub(crate) fn cyclotomic_square_composed(self) -> Self {
        // Mapping (arkworks): r0=c0.c0, r4=c0.c1, r3=c0.c2, r2=c1.c0, r1=c1.c1, r5=c1.c2
        let r0 = self.c0.c0;
        let r4 = self.c0.c1;
        let r3 = self.c0.c2;
        let r2 = self.c1.c0;
        let r1 = self.c1.c1;
        let r5 = self.c1.c2;

        let (t0, t1) = Self::fp4_square_sos(r0, r1);
        let (t2, t3) = Self::fp4_square_sos(r2, r3);
        let (t4, t5) = Self::fp4_square_sos(r4, r5);

        // z0 = 3*t0 - 2*r0
        let z0 = {
            let mut z = t0 - r0;
            z = z.double() + t0;
            z
        };
        // z1 = 3*t1 + 2*r1
        let z1 = {
            let mut z = t1 + r1;
            z = z.double() + t1;
            z
        };
        // z2 = 3*xi*t5 + 2*r2
        let z2 = {
            let tmp = t5.mul_by_nonresidue();
            let mut z = r2 + tmp;
            z = z.double() + tmp;
            z
        };
        // z3 = 3*t4 - 2*r3
        let z3 = {
            let mut z = t4 - r3;
            z = z.double() + t4;
            z
        };
        // z4 = 3*t2 - 2*r4
        let z4 = {
            let mut z = t2 - r4;
            z = z.double() + t2;
            z
        };
        // z5 = 3*t3 + 2*r5
        let z5 = {
            let mut z = r5 + t3;
            z = z.double() + t3;
            z
        };

        Self {
            c0: Fp6::new(z0, z4, z3),
            c1: Fp6::new(z2, z1, z5),
        }
    }

    /// Granger-Scott body over Karatsuba Fp4 squares: differential reference.
    #[cfg(test)]
    pub fn cyclotomic_square_karatsuba(self) -> Self {
        let r0 = self.c0.c0;
        let r4 = self.c0.c1;
        let r3 = self.c0.c2;
        let r2 = self.c1.c0;
        let r1 = self.c1.c1;
        let r5 = self.c1.c2;

        let fp4 = |a: Fp2, b: Fp2| {
            let tmp = a * b;
            (
                (a + b) * (b.mul_by_nonresidue() + a) - tmp - tmp.mul_by_nonresidue(),
                tmp.double(),
            )
        };
        let (t0, t1) = fp4(r0, r1);
        let (t2, t3) = fp4(r2, r3);
        let (t4, t5) = fp4(r4, r5);

        let z0 = {
            let mut z = t0 - r0;
            z = z.double() + t0;
            z
        };
        let z1 = {
            let mut z = t1 + r1;
            z = z.double() + t1;
            z
        };
        let z2 = {
            let tmp = t5.mul_by_nonresidue();
            let mut z = r2 + tmp;
            z = z.double() + tmp;
            z
        };
        let z3 = {
            let mut z = t4 - r3;
            z = z.double() + t4;
            z
        };
        let z4 = {
            let mut z = t2 - r4;
            z = z.double() + t2;
            z
        };
        let z5 = {
            let mut z = r5 + t3;
            z = z.double() + t3;
            z
        };

        Self {
            c0: Fp6::new(z0, z4, z3),
            c1: Fp6::new(z2, z1, z5),
        }
    }

    /// Variable-time multiplicative inverse; `None` for zero.
    pub fn invert(self) -> Option<Self> {
        let t = (self.c0.square() - self.c1.square().mul_by_nonresidue()).invert()?;
        Some(Self {
            c0: self.c0 * t,
            c1: -(self.c1 * t),
        })
    }

    /// Sparse mul by `c0 + c3*w + c4*w*v` (arkworks `mul_by_034`, D-type lines).
    ///
    /// SoS schoolbook over the whole sparse product (Longa 2022/367): with
    /// `self = a + b*w`, `other = C0 + (C3 + C4*v)*w` and `w^2 = v`, `v^3 = xi`:
    ///   r0 = a0*C0 + b1*(xiC4) + b2*(xiC3)      r3 = a0*C3 + a2*(xiC4) + b0*C0
    ///   r1 = a1*C0 + b0*C3 + b2*(xiC4)         r4 = a0*C4 + a1*C3 + b1*C0
    ///   r2 = a2*C0 + b0*C4 + b1*C3            r5 = a1*C4 + a2*C3 + b2*C0
    /// Each Fp component is one 6-product interleaved reduction: 72M + 12R
    /// replaces 39 full Montgomery muls + ~30 modular add/subs.
    #[inline(always)]
    pub fn mul_by_034(self, c0: Fp2, c3: Fp2, c4: Fp2) -> Self {
        let mut out = self;
        out.mul_by_034_assign(c0, c3, c4);
        out
    }

    /// In-place [`Self::mul_by_034`]: avoids the two 384-byte ABI copies of
    /// the by-value form (one call per Miller line evaluation).
    #[inline(never)]
    pub fn mul_by_034_assign(&mut self, c0: Fp2, c3: Fp2, c4: Fp2) {
        // Whole-op leaf (HELIUS_FP12_034_ASM=1): same math as the composed
        // path below, one call instead of six sosd6 lane dispatches plus
        // two Rust xi scalings.
        #[cfg(helius_fp12_034_active)]
        {
            crate::fp::x86_64::fp12_034_assign(self, &c0, &c3, &c4);
        }
        #[cfg(not(helius_fp12_034_active))]
        {
            self.mul_by_034_assign_sosd6(c0, c3, c4);
        }
    }

    /// Composed `mul_by_034`: six sosd6 dispatches over the row lists in
    /// [`Self::mul_by_034`]'s doc. Reference semantics for the whole-op x86
    /// leaf, which computes exactly this in one call.
    #[cfg(any(test, not(helius_fp12_034_active)))]
    #[inline(always)]
    pub(crate) fn mul_by_034_assign_sosd6(&mut self, c0: Fp2, c3: Fp2, c4: Fp2) {
        use crate::fp::sos::sosd6;
        let x3 = c3.mul_by_nonresidue();
        let x4 = c4.mul_by_nonresidue();
        let (a00, a01) = (&self.c0.c0.c0.0, &self.c0.c0.c1.0);
        let (a10, a11) = (&self.c0.c1.c0.0, &self.c0.c1.c1.0);
        let (a20, a21) = (&self.c0.c2.c0.0, &self.c0.c2.c1.0);
        let (b00, b01) = (&self.c1.c0.c0.0, &self.c1.c0.c1.0);
        let (b10, b11) = (&self.c1.c1.c0.0, &self.c1.c1.c1.0);
        let (b20, b21) = (&self.c1.c2.c0.0, &self.c1.c2.c1.0);
        let (c00, c01) = (&c0.c0.0, &c0.c1.0);
        let (c30, c31) = (&c3.c0.0, &c3.c1.0);
        let (c40, c41) = (&c4.c0.0, &c4.c1.0);
        let (x30, x31) = (&x3.c0.0, &x3.c1.0);
        let (x40, x41) = (&x4.c0.0, &x4.c1.0);
        let r00 = sosd6([
            Fp2Product::new(a00, a01, c00, c01),
            Fp2Product::new(b10, b11, x40, x41),
            Fp2Product::new(b20, b21, x30, x31),
        ]);
        let r01 = sosd6([
            Fp2Product::new(a10, a11, c00, c01),
            Fp2Product::new(b00, b01, c30, c31),
            Fp2Product::new(b20, b21, x40, x41),
        ]);
        let r02 = sosd6([
            Fp2Product::new(a20, a21, c00, c01),
            Fp2Product::new(b00, b01, c40, c41),
            Fp2Product::new(b10, b11, c30, c31),
        ]);
        let r10 = sosd6([
            Fp2Product::new(a00, a01, c30, c31),
            Fp2Product::new(a20, a21, x40, x41),
            Fp2Product::new(b00, b01, c00, c01),
        ]);
        let r11 = sosd6([
            Fp2Product::new(a00, a01, c40, c41),
            Fp2Product::new(a10, a11, c30, c31),
            Fp2Product::new(b10, b11, c00, c01),
        ]);
        let r12 = sosd6([
            Fp2Product::new(a10, a11, c40, c41),
            Fp2Product::new(a20, a21, c30, c31),
            Fp2Product::new(b20, b21, c00, c01),
        ]);
        self.c0 = Fp6::new(
            Fp2::new(Fp(r00.0), Fp(r00.1)),
            Fp2::new(Fp(r01.0), Fp(r01.1)),
            Fp2::new(Fp(r02.0), Fp(r02.1)),
        );
        self.c1 = Fp6::new(
            Fp2::new(Fp(r10.0), Fp(r10.1)),
            Fp2::new(Fp(r11.0), Fp(r11.1)),
            Fp2::new(Fp(r12.0), Fp(r12.1)),
        );
    }

    /// Karatsuba `mul_by_034`: differential reference for the SoS bodies.
    #[cfg(test)]
    pub fn mul_by_034_karatsuba(self, c0: Fp2, c3: Fp2, c4: Fp2) -> Self {
        let a = Fp6 {
            c0: self.c0.c0 * c0,
            c1: self.c0.c1 * c0,
            c2: self.c0.c2 * c0,
        };
        let b = self.c1.mul_by_01_karatsuba(c3, c4);
        let e = (self.c0 + self.c1).mul_by_01_karatsuba(c0 + c3, c4);
        let c1 = e - a - b;
        let c0 = b.mul_by_nonresidue() + a;
        Self { c0, c1 }
    }

    /// Frobenius endomorphism `a -> a^p` via precomputed coefficients.
    pub fn frobenius_map(self) -> Self {
        frobenius_p(self)
    }

    /// `a -> a^{p^2}`.
    pub fn frobenius_map_squared(self) -> Self {
        frobenius_p2(self)
    }

    /// `a -> a^{p^3}`.
    pub fn frobenius_map_cubed(self) -> Self {
        frobenius_p3(self)
    }

    /// `self^e` by square-and-multiply (variable-time).
    pub fn pow_u64(self, mut e: u64) -> Self {
        let mut base = self;
        let mut acc = Self::ONE;
        while e > 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base = base.square();
            e >>= 1;
        }
        acc
    }

    /// `self^e` for `e` given as bits, LSB first (variable-time).
    pub fn pow_bits(self, bits: &[bool]) -> Self {
        let mut acc = Self::ONE;
        for &bit in bits.iter().rev() {
            acc = acc.square();
            if bit {
                acc *= self;
            }
        }
        acc
    }

    /// `self^e` for little-endian 64-bit limbs.
    pub(crate) fn pow_limbs(self, limbs: &[u64]) -> Self {
        let mut acc = Self::ONE;
        for limb in limbs.iter().rev() {
            for bit in (0..64).rev() {
                acc = acc.square();
                if limb & (1 << bit) != 0 {
                    acc *= self;
                }
            }
        }
        acc
    }

    /// `x = 4965661367192848881` via signed 4-bit windows over Granger-Scott
    /// cyclotomic squares: 63 squares + 16 full muls, vs 62 + 24 for the plain
    /// NAF ladder. Valid on cyclotomic-subgroup elements (use after easy part).
    pub fn pow_x(self) -> Self {
        let x2 = self.cyclotomic_square();
        let x3 = x2 * self;
        let x5 = x3 * x2;
        let x7 = x5 * x2;
        let tab = [self, x3, x5, x7];
        // Top digit of X_W4 is 1, so start from `self` directly.
        let mut acc = tab[0];
        for &d in X_W4.iter().rev().skip(1) {
            acc = acc.cyclotomic_square();
            if d != 0 {
                let t = tab[(d.unsigned_abs() / 2) as usize];
                acc *= if d < 0 { t.conjugate() } else { t };
            }
        }
        acc
    }

    /// Karabina compressed cyclotomic squarings (eprint 2010/542) over the NAF
    /// of x, one batched Fp2 inversion for decompression. On x's dense NAF
    /// (HW 24) the 23 decompressions plus the inversion outweigh the 6->4 Fp2
    /// muls saved per square, so this measures slower than `pow_x`; kept for
    /// evaluation. Degenerate inputs fall back to the Granger-Scott ladder.
    #[cfg(test)]
    fn pow_x_karabina(self) -> Self {
        let mut rec = [(Compressed::ZERO, false); X_NAF_TAIL_NONZERO];
        let mut den = [Fp2::ZERO; X_NAF_TAIL_NONZERO];
        let mut c = Compressed::from_fp12(&self);
        let mut n = 0;
        for &d in X_NAF.iter().skip(1) {
            c = c.square();
            if d != 0 {
                den[n] = c.g1_den();
                if den[n].is_zero() {
                    // g2 = g3 = 0 mid-chain (identity-like input): decompression
                    // is undefined, use the full-form ladder.
                    return self.pow_x_naf();
                }
                rec[n] = (c, d < 0);
                n += 1;
            }
        }

        // Montgomery-batched inversion of all g1 denominators.
        let mut pfx = [Fp2::ZERO; X_NAF_TAIL_NONZERO];
        let mut prod = Fp2::ONE;
        for k in 0..n {
            pfx[k] = prod;
            prod *= den[k];
        }
        // All factors are nonzero, so the product is invertible.
        let mut inv = match prod.invert() {
            Some(v) => v,
            None => return self.pow_x_naf(),
        };

        let mut acc = match X_NAF[0] {
            0 => Self::ONE,
            d if d < 0 => self.conjugate(),
            _ => self,
        };
        for k in (0..n).rev() {
            let (v, neg) = rec[k];
            let mut t = v.decompress(inv * pfx[k]);
            if neg {
                t = t.conjugate(); // unitary inv on cyclotomic
            }
            acc *= t;
            inv *= den[k];
        }
        acc
    }

    /// Granger-Scott square-and-multiply ladder over the NAF of x.
    /// Reference path; fallback for inputs Karabina decompression cannot handle.
    #[cfg(test)]
    fn pow_x_naf(self) -> Self {
        let mut acc = Self::ONE;
        for &d in X_NAF.iter().rev() {
            acc = acc.cyclotomic_square();
            if d > 0 {
                acc *= self;
            } else if d < 0 {
                acc *= self.conjugate(); // unitary inv on cyclotomic
            }
        }
        acc
    }

    /// Golden-vector loader in mcl tower coeff order:
    /// a0.re,a0.im, a1.re,a1.im, a2..., b0..., b1..., b2...
    #[cfg(test)]
    pub fn from_mcl_dec_coeffs(coeffs: &[&str; 12]) -> Option<Self> {
        let p = |i: usize| -> Option<Fp2> {
            Some(Fp2::new(
                Fp::from_str_radix(coeffs[i], 10)?,
                Fp::from_str_radix(coeffs[i + 1], 10)?,
            ))
        };
        Some(Self {
            c0: Fp6::new(p(0)?, p(2)?, p(4)?),
            c1: Fp6::new(p(6)?, p(8)?, p(10)?),
        })
    }
}

/// NAF digits of `x = BN_X = 4965661367192848881`, LSB first (HW 24).
/// Pinned below to `const_tower::naf63(BN_X)`.
const X_NAF: &[i8] = &[
    1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, -1, 0, 1, 0, 1, 0, 1, 0, 0, 1,
    0, 0, 0, 1, 0, -1, 0, -1, 0, -1, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0,
    0, 1,
];

/// Signed 4-bit window digits of x (odd digits, |d| <= 7), LSB first.
/// 14 nonzero digits, top digit 1. Pinned below to `const_tower::wnaf4_63(BN_X)`.
pub(crate) const X_W4: &[i8] = &[
    1, 0, 0, 0, -1, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 7, 0, 0, 0, 0, 5, 0, 0, 0, 0, 1,
    0, 0, 0, -3, 0, 0, 0, -5, 0, 0, 0, 5, 0, 0, 0, 0, 3, 0, 0, 0, -3, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0,
    1,
];

/// Nonzero NAF digits above position 0; each records one compressed value.
#[cfg(test)]
const X_NAF_TAIL_NONZERO: usize = {
    let mut n = 0;
    let mut i = 1;
    while i < X_NAF.len() {
        if X_NAF[i] != 0 {
            n += 1;
        }
        i += 1;
    }
    n
};

/// Karabina compressed cyclotomic element `(g2, g3, g4, g5)` (eprint 2010/542)
/// in the Fp4-pair basis `alpha = (g0 + g1 w) + (g2 + g3 w)s + (g4 + g5 w)s^2`:
/// g2 = c1.c0, g3 = c0.c2, g4 = c0.c1, g5 = c1.c2.
/// Formulas require cyclotomic-subgroup membership.
#[cfg(test)]
#[derive(Clone, Copy)]
struct Compressed {
    g2: Fp2,
    g3: Fp2,
    g4: Fp2,
    g5: Fp2,
}

#[cfg(test)]
impl Compressed {
    const ZERO: Self = Self {
        g2: Fp2::ZERO,
        g3: Fp2::ZERO,
        g4: Fp2::ZERO,
        g5: Fp2::ZERO,
    };

    #[inline]
    fn from_fp12(f: &Fp12) -> Self {
        Self {
            g2: f.c1.c0,
            g3: f.c0.c2,
            g4: f.c0.c1,
            g5: f.c1.c2,
        }
    }

    /// Compressed cyclotomic square: 4 Fp2 muls (vs 6 in Granger-Scott).
    #[inline]
    fn square(self) -> Self {
        // A_ij = (gi + gj)(gi + xi gj), B_ij = gi*gj, A - (xi+1)B = gi^2 + xi gj^2
        let b45 = self.g4 * self.g5;
        let a45 = (self.g4 + self.g5) * (self.g4 + self.g5.mul_by_nonresidue());
        let b23 = self.g2 * self.g3;
        let a23 = (self.g2 + self.g3) * (self.g2 + self.g3.mul_by_nonresidue());
        let c45 = a45 - b45 - b45.mul_by_nonresidue();
        let c23 = a23 - b23 - b23.mul_by_nonresidue();
        let xb45 = b45.mul_by_nonresidue();
        Self {
            // h2 = 2(g2 + 3xi g4 g5)
            g2: (self.g2 + xb45.double() + xb45).double(),
            // h3 = 3(g4^2 + xi g5^2) - 2 g3
            g3: c45.double() + c45 - self.g3.double(),
            // h4 = 3(g2^2 + xi g3^2) - 2 g4
            g4: c23.double() + c23 - self.g4.double(),
            // h5 = 2(g5 + 3 g2 g3)
            g5: (self.g5 + b23.double() + b23).double(),
        }
    }

    /// Denominator of the g1 recovery: `4 g2`, or `g3` when g2 = 0.
    /// Zero only for degenerate elements (e.g. the identity).
    #[inline]
    fn g1_den(&self) -> Fp2 {
        if self.g2.is_zero() {
            self.g3
        } else {
            self.g2.double().double()
        }
    }

    /// Karabina decompression given `den_inv = g1_den()^{-1}`.
    fn decompress(&self, den_inv: Fp2) -> Fp12 {
        let g1 = if self.g2.is_zero() {
            // g1 = 2 g4 g5 / g3
            (self.g4 * self.g5).double() * den_inv
        } else {
            // g1 = (xi g5^2 + 3 g4^2 - 2 g3) / (4 g2)
            let s4 = self.g4.square();
            (self.g5.square().mul_by_nonresidue() + s4.double() + s4 - self.g3.double()) * den_inv
        };
        // g0 = xi(2 g1^2 + g2 g5 - 3 g3 g4) + 1
        let g3g4 = self.g3 * self.g4;
        let mut g0 =
            (g1.square().double() + self.g2 * self.g5 - g3g4.double() - g3g4).mul_by_nonresidue();
        g0.c0 += Fp::ONE;
        Fp12 {
            c0: Fp6::new(g0, self.g4, self.g3),
            c1: Fp6::new(self.g2, g1, self.g5),
        }
    }
}

/// Already-Montgomery Fp2 constant (no conversion cost).
#[inline(always)]
const fn fp2_mont(c0: [u64; 4], c1: [u64; 4]) -> Fp2 {
    Fp2::new(Fp::from_raw_canonical(c0), Fp::from_raw_canonical(c1))
}

/// gamma_{1,j} = xi^(j(p-1)/6) in Montgomery form (raw*R mod p, precomputed):
/// with w^6 = xi, (c*w^j)^p = conj(c)*gamma_{1,j}*w^j. Pinned below to the
/// compile-time derivation in `const_tower`.
#[inline(always)]
const fn gamma1(j: usize) -> Fp2 {
    match j {
        1 => fp2_mont(
            [
                12653890742059813127,
                14585784200204367754,
                1278438861261381767,
                212598772761311868,
            ],
            [
                11683091849979440498,
                14992204589386555739,
                15866167890766973222,
                1200023580730561873,
            ],
        ),
        2 => fp2_mont(
            [
                13075984984163199792,
                3782902503040509012,
                8791150885551868305,
                1825854335138010348,
            ],
            [
                7963664994991228759,
                12257807996192067905,
                13179524609921305146,
                2767831111890561987,
            ],
        ),
        3 => fp2_mont(
            [
                16482010305593259561,
                13488546290961988299,
                3578621962720924518,
                2681173117283399901,
            ],
            [
                11661927080404088775,
                553939530661941723,
                7860678177968807019,
                3208568454732775116,
            ],
        ),
        4 => fp2_mont(
            [
                8314163329781907090,
                11942187022798819835,
                11282677263046157209,
                1576150870752482284,
            ],
            [
                6763840483288992073,
                7118829427391486816,
                4016233444936635065,
                2630958277570195709,
            ],
        ),
        5 => fp2_mont(
            [
                14515217250696892391,
                16303087968080972555,
                3656613296917993960,
                1345095164996126785,
            ],
            [
                957117326806663081,
                367382125163301975,
                15253872307375509749,
                3396254757538665050,
            ],
        ),
        _ => Fp2::ONE,
    }
}

/// gamma_{2,j} = xi^(j(p^2-1)/6) = gamma_{1,j}*conj(gamma_{1,j}), in Fp,
/// Montgomery form. Pinned below to the compile-time derivation in
/// `const_tower`.
#[inline(always)]
const fn gamma2(j: usize) -> Fp2 {
    match j {
        1 => fp2_mont(
            [
                14595462726357228530,
                17349508522658994025,
                1017833795229664280,
                299787779797702374,
            ],
            [0, 0, 0, 0],
        ),
        2 => fp2_mont(
            [
                3697675806616062876,
                9065277094688085689,
                6918009208039626314,
                2775033306905974752,
            ],
            [0, 0, 0, 0],
        ),
        3 => fp2_mont(
            [
                7548957153968385962,
                10162512645738643279,
                5900175412809962033,
                2475245527108272378,
            ],
            [0, 0, 0, 0],
        ),
        4 => fp2_mont(
            [
                8183898218631979349,
                12014359695528440611,
                12263358156045030468,
                3187210487005268291,
            ],
            [0, 0, 0, 0],
        ),
        5 => fp2_mont(
            [
                634941064663593387,
                1851847049789797332,
                6363182743235068435,
                711964959896995913,
            ],
            [0, 0, 0, 0],
        ),
        _ => Fp2::ONE,
    }
}

/// Compile-time pin: the gamma tables and seed recodings above are exactly
/// their first-principles derivations from P, xi, and BN_X (see
/// `const_tower`). Editing either side alone fails the build.
const _: () = {
    use crate::const_tower::{GAMMA1, GAMMA2, naf63, wnaf4_63};
    use crate::consts::derive::eq4;
    let mut j = 1;
    while j <= 5 {
        let g = gamma1(j);
        assert!(eq4(g.c0.0, GAMMA1[j - 1].0) && eq4(g.c1.0, GAMMA1[j - 1].1));
        let g = gamma2(j);
        assert!(eq4(g.c0.0, GAMMA2[j - 1]) && eq4(g.c1.0, [0; 4]));
        j += 1;
    }
    let naf = naf63(crate::consts::BN_X);
    let w4 = wnaf4_63(crate::consts::BN_X);
    assert!(X_NAF.len() == 63 && X_W4.len() == 63);
    let mut i = 0;
    while i < 63 {
        assert!(X_NAF[i] == naf[i] && X_W4[i] == w4[i]);
        i += 1;
    }
};

fn frobenius_p(f: Fp12) -> Fp12 {
    let a = f.c0;
    let b = f.c1;
    let c0 = Fp6 {
        c0: a.c0.frobenius_map(),
        c1: a.c1.frobenius_map() * gamma1(2),
        c2: a.c2.frobenius_map() * gamma1(4),
    };
    let c1 = Fp6 {
        c0: b.c0.frobenius_map() * gamma1(1),
        c1: b.c1.frobenius_map() * gamma1(3),
        c2: b.c2.frobenius_map() * gamma1(5),
    };
    Fp12 { c0, c1 }
}

fn frobenius_p2(f: Fp12) -> Fp12 {
    let a = f.c0;
    let b = f.c1;
    let c0 = Fp6 {
        c0: a.c0,
        c1: a.c1 * gamma2(2),
        c2: a.c2 * gamma2(4),
    };
    let c1 = Fp6 {
        c0: b.c0 * gamma2(1),
        c1: b.c1 * gamma2(3),
        c2: b.c2 * gamma2(5),
    };
    Fp12 { c0, c1 }
}

fn frobenius_p3(f: Fp12) -> Fp12 {
    // gamma_{3,j} = gamma_{1,j} * gamma_{2,j}: no third table needed.
    let a = f.c0;
    let b = f.c1;
    let g = |j| gamma1(j) * gamma2(j);
    let c0 = Fp6 {
        c0: a.c0.frobenius_map(),
        c1: a.c1.frobenius_map() * g(2),
        c2: a.c2.frobenius_map() * g(4),
    };
    let c1 = Fp6 {
        c0: b.c0.frobenius_map() * g(1),
        c1: b.c1.frobenius_map() * g(3),
        c2: b.c2.frobenius_map() * g(5),
    };
    Fp12 { c0, c1 }
}

impl Add for Fp12 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}
impl AddAssign for Fp12 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Fp12 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}
impl SubAssign for Fp12 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Fp12 {
    type Output = Self;
    fn mul(mut self, rhs: Self) -> Self {
        self *= rhs;
        self
    }
}
impl MulAssign for Fp12 {
    fn mul_assign(&mut self, rhs: Self) {
        // Whole-op lazy double-width leaf (HELIUS_FP12_MUL_ASM=1): mcl's
        // 54-product shape; the composed path below stays the reference.
        #[cfg(helius_fp12_mul_active)]
        {
            crate::fp::x86_64::fp12_mul_assign(self, &rhs);
        }
        #[cfg(not(helius_fp12_mul_active))]
        {
            *self = self.mul_composed(rhs);
        }
    }
}
impl Neg for Fp12 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fr::Fr;
    use crate::g1::G1Projective;
    use crate::g2::{G2Affine, G2Projective};
    use crate::pairing::miller_loop;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// Random Miller-loop output through the easy part: cyclotomic element.
    fn random_cyclotomic(rng: &mut StdRng) -> Fp12 {
        let a = Fr::from_u64(rng.next_u64() | 1);
        let b = Fr::from_u64(rng.next_u64() | 1);
        let p = G1Projective::generator().mul(a).to_affine();
        let q = G2Projective::from(G2Affine::test_generator())
            .mul(b)
            .to_affine();
        let f = miller_loop(&p, &q);
        let r = f.conjugate() * f.invert().unwrap();
        r.frobenius_map_squared() * r
    }

    #[test]
    fn compressed_square_matches_granger_scott() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..16 {
            let mut e = random_cyclotomic(&mut rng);
            for _ in 0..8 {
                let full = e.cyclotomic_square();
                let c = Compressed::from_fp12(&e).square();
                assert_eq!(c.g2, full.c1.c0);
                assert_eq!(c.g3, full.c0.c2);
                assert_eq!(c.g4, full.c0.c1);
                assert_eq!(c.g5, full.c1.c2);
                e = full;
            }
        }
    }

    #[test]
    fn decompress_recovers_cyclotomic_element() {
        let mut rng = StdRng::seed_from_u64(8);
        for _ in 0..32 {
            let e = random_cyclotomic(&mut rng);
            let c = Compressed::from_fp12(&e);
            let inv = c.g1_den().invert().unwrap();
            assert_eq!(c.decompress(inv), e);
        }
    }

    #[test]
    fn pow_x_variants_match_on_easy_part_outputs() {
        let mut rng = StdRng::seed_from_u64(9);
        for _ in 0..500 {
            let e = random_cyclotomic(&mut rng);
            let want = e.pow_x_naf();
            assert_eq!(e.pow_x(), want);
            assert_eq!(e.pow_x_karabina(), want);
            let c = e.conjugate();
            let want = c.pow_x_naf();
            assert_eq!(c.pow_x(), want);
            assert_eq!(c.pow_x_karabina(), want);
        }
    }

    #[test]
    fn pow_x_degenerate_inputs() {
        assert_eq!(Fp12::ONE.pow_x(), Fp12::ONE);
        assert_eq!(Fp12::ONE.pow_x_karabina(), Fp12::ONE); // fallback path
        assert_eq!(Fp12::ZERO.pow_x(), Fp12::ZERO.pow_x_naf());
        assert_eq!(Fp12::ZERO.pow_x_karabina(), Fp12::ZERO.pow_x_naf());
    }

    /// Defining equations of the Frobenius maps (hence the gamma tables):
    /// frobenius_map(f) = f^p, and the p^2/p^3 variants are its iterates.
    #[test]
    fn frobenius_maps_are_pth_powers() {
        use crate::consts::P;
        let p_bits: alloc::vec::Vec<bool> =
            (0..256).map(|i| (P[i / 64] >> (i % 64)) & 1 == 1).collect();
        let mut rng = StdRng::seed_from_u64(11);
        for _ in 0..4 {
            let mut c = [Fp2::ZERO; 6];
            for v in c.iter_mut() {
                *v = Fp2::new(Fp::from_u64(rng.next_u64()), Fp::from_u64(rng.next_u64()));
            }
            let f = Fp12::new(Fp6::new(c[0], c[1], c[2]), Fp6::new(c[3], c[4], c[5]));
            let fp = f.frobenius_map();
            assert_eq!(fp, f.pow_bits(&p_bits));
            assert_eq!(f.frobenius_map_squared(), fp.frobenius_map());
            assert_eq!(f.frobenius_map_cubed(), fp.frobenius_map().frobenius_map());
        }
    }

    #[test]
    fn decompress_exceptional_branch_formula() {
        // Cyclotomic elements with g2 = 0 are a negligible-probability slice;
        // exercise the branch on a synthetic tuple against the raw formulas.
        let mut rng = StdRng::seed_from_u64(10);
        let e = random_cyclotomic(&mut rng);
        let c = Compressed {
            g2: Fp2::ZERO,
            ..Compressed::from_fp12(&e)
        };
        assert_eq!(c.g1_den(), c.g3);
        let inv = c.g3.invert().unwrap();
        let out = c.decompress(inv);
        let g1 = (c.g4 * c.g5).double() * inv;
        assert_eq!(out.c1.c1, g1);
        let mut g0 =
            (g1.square().double() - (c.g3 * c.g4).double() - c.g3 * c.g4).mul_by_nonresidue();
        g0.c0 += Fp::ONE;
        assert_eq!(out.c0.c0, g0);
        assert_eq!(out.c1.c0, Fp2::ZERO);
    }
}
