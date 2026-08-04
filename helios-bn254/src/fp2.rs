//! Quadratic extension `Fp2 = Fp[u]/(u^2 + 1)`.
//!
//! Base of the pairing tower. Mul and square are the dual SoS kernels (one
//! interleaved reduction per output component); components stay canonical.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::fp::Fp;

/// `c0 + c1 * u`, `u^2 = -1`.
// repr(C): the fp6 kernel ABI reads Fp6/Fp2/Fp as 24 contiguous limbs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp2 {
    /// Real component.
    pub c0: Fp,
    /// Coefficient of `u`.
    pub c1: Fp,
}

impl Fp2 {
    /// Additive identity.
    pub const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };
    /// Multiplicative identity.
    pub const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    /// `c0 + c1*u` from components.
    #[inline]
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    /// True iff both components are zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// `2 * self`.
    /// x86: outlined shared body (footprint; see `fp2_fast`).
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    #[cfg_attr(not(target_arch = "x86_64"), inline)]
    pub fn double(self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    /// Complex conjugate `c0 - c1*u`; equals the Frobenius map on Fp2.
    #[inline]
    pub fn conjugate(self) -> Self {
        Self {
            c0: self.c0,
            c1: -self.c1,
        }
    }

    /// Additive inverse.
    #[inline]
    pub fn neg(self) -> Self {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }

    /// `self^2`.
    #[inline(always)]
    pub fn square(self) -> Self {
        // SoS (Longa 2022/367): c0 = a^2 - b^2, c1 = a*b + b*a; both lanes in
        // one dual kernel so the two carry chains overlap.
        let (c0, c1) = crate::fp::sos::sosd2(&self.c0.0, &self.c1.0, &self.c0.0, &self.c1.0);
        Self {
            c0: Fp(c0),
            c1: Fp(c1),
        }
    }

    /// Multiply by non-residue `xi = 9 + u`.
    /// x86: outlined shared body (footprint; see `fp2_fast`).
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    #[cfg_attr(not(target_arch = "x86_64"), inline(always))]
    pub fn mul_by_nonresidue(self) -> Self {
        // 9x = ((x<<3)+x) via doubles: 8x+x
        let t0 = self.c0.double().double().double() + self.c0;
        let t1 = self.c1.double().double().double() + self.c1;
        Self {
            c0: t0 - self.c1,
            c1: t1 + self.c0,
        }
    }

    /// Variable-time multiplicative inverse; `None` for zero.
    pub fn invert(self) -> Option<Self> {
        // 1/(a+bu) = (a-bu)/(a^2+b^2)
        let t = (self.c0.square() + self.c1.square()).invert()?;
        Some(Self {
            c0: self.c0 * t,
            c1: -(self.c1 * t),
        })
    }

    /// Frobenius endomorphism `a -> a^p`; conjugation on Fp2.
    pub fn frobenius_map(self) -> Self {
        self.conjugate()
    }

    /// Scale both components by an Fp element.
    #[inline(always)]
    pub fn mul_by_fp(self, f: Fp) -> Self {
        Self {
            c0: self.c0 * f,
            c1: self.c1 * f,
        }
    }

    /// Parse `(c0, c1)` from decimal strings.
    pub fn from_str_pair(a: &str, b: &str) -> Option<Self> {
        Some(Self {
            c0: Fp::from_str_radix(a, 10)?,
            c1: Fp::from_str_radix(b, 10)?,
        })
    }

    /// Field norm to Fp: `c0^2 + c1^2`.
    pub fn norm(self) -> Fp {
        self.c0.square() + self.c1.square()
    }

    /// Variable-time square root; `None` for non-residues.
    pub fn sqrt(self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::ZERO);
        }
        if self.c1.is_zero() {
            return if let Some(s) = self.c0.sqrt() {
                Some(Self::new(s, Fp::ZERO))
            } else {
                // -1 nonsquare in Fp => sqrt(a) = u * sqrt(-a)
                let s = (-self.c0).sqrt()?;
                Some(Self::new(Fp::ZERO, s))
            };
        }
        // Complex method: n = sqrt(norm), l0 = sqrt((a +/- n)/2), l1 = b/(2*l0).
        let n = self.norm().sqrt()?;
        let inv2 = Fp::from_u64(2).invert().unwrap();
        let l0 = ((self.c0 + n) * inv2)
            .sqrt()
            .or_else(|| ((self.c0 - n) * inv2).sqrt())?;
        let l1 = self.c1 * l0.double().invert()?;
        let cand = Self::new(l0, l1);
        if cand.square() == self {
            Some(cand)
        } else {
            None
        }
    }
}

impl Add for Fp2 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}
impl AddAssign for Fp2 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Fp2 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}
impl SubAssign for Fp2 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Fp2 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        // Schoolbook SoS (Longa 2022/367): c0 = a*c - b*d, c1 = a*d + b*c;
        // 4M with one interleaved reduction per component beats Karatsuba's
        // 3M + 3 reductions + 5 modular add/subs. Dual kernel: both lanes.
        let (c0, c1) = crate::fp::sos::sosd2(&self.c0.0, &self.c1.0, &rhs.c0.0, &rhs.c1.0);
        Self {
            c0: Fp(c0),
            c1: Fp(c1),
        }
    }
}
impl MulAssign for Fp2 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Fp2 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Fp2::neg(self)
    }
}

impl From<Fp> for Fp2 {
    fn from(c0: Fp) -> Self {
        Self { c0, c1: Fp::ZERO }
    }
}

impl From<u64> for Fp2 {
    fn from(v: u64) -> Self {
        Self::from(Fp::from_u64(v))
    }
}
