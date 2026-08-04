//! G1: E(Fp): y^2 = x^3 + 3.
//! Jacobian coordinates (X:Y:Z) <-> affine (X/Z^2, Y/Z^3). EFD a=0 formulas.

use crate::fp::Fp;
use crate::fr::Fr;

/// Affine G1 point. Fields are unvalidated: safe code can build off-curve
/// values; the byte facade ([`crate::batch`]) is the checked entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine {
    /// x-coordinate.
    pub x: Fp,
    /// y-coordinate.
    pub y: Fp,
    /// Point-at-infinity flag; when set the coordinates are ignored.
    pub infinity: bool,
}

/// Jacobian G1 point `(X : Y : Z)`; the identity has `Z = 0`.
/// Fields are unvalidated, as for [`G1Affine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Projective {
    /// Jacobian X.
    pub x: Fp,
    /// Jacobian Y.
    pub y: Fp,
    /// Jacobian Z; zero encodes the identity.
    pub z: Fp,
}

impl G1Affine {
    /// Standard generator `(1, 2)`.
    pub fn generator() -> Self {
        Self {
            x: Fp::from_u64(1),
            y: Fp::from_u64(2),
            infinity: false,
        }
    }

    /// Point at infinity.
    pub fn identity() -> Self {
        Self {
            x: Fp::ZERO,
            y: Fp::ONE,
            infinity: true,
        }
    }

    /// True iff this is the point at infinity.
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    /// Curve membership check `y^2 = x^3 + 3`; infinity passes.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        self.y.square() == self.x.square() * self.x + Fp::from_u64(3)
    }

    /// Return the additive inverse.
    fn negate(self) -> Self {
        if self.infinity {
            self
        } else {
            Self {
                x: self.x,
                y: -self.y,
                infinity: false,
            }
        }
    }

    /// Lift to Jacobian coordinates.
    pub fn to_curve(self) -> G1Projective {
        if self.infinity {
            G1Projective::identity()
        } else {
            G1Projective {
                x: self.x,
                y: self.y,
                z: Fp::ONE,
            }
        }
    }
}

impl G1Projective {
    /// Jacobian identity: `Z = 0`.
    pub fn identity() -> Self {
        Self {
            x: Fp::ZERO,
            y: Fp::ONE,
            z: Fp::ZERO,
        }
    }

    /// Standard generator in Jacobian coordinates.
    pub fn generator() -> Self {
        G1Affine::generator().to_curve()
    }

    /// True iff this is the identity (`Z = 0`).
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// EFD dbl-2009-l (Jacobian, a = 0).
    #[inline(always)]
    pub fn double(self) -> Self {
        self.double_fast()
    }

    /// EFD add-2007-bl (Jacobian, a = 0).
    #[inline(always)]
    fn add_complete(self, other: Self) -> Self {
        if self.is_identity() {
            return other;
        }
        if other.is_identity() {
            return self;
        }
        // Z1Z1 = Z1^2, Z2Z2 = Z2^2
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        // U1 = X1*Z2Z2, U2 = X2*Z1Z1
        let u1 = self.x * z2z2;
        let u2 = other.x * z1z1;
        // S1 = Y1*Z2*Z2Z2, S2 = Y2*Z1*Z1Z1
        let s1 = self.y * other.z * z2z2;
        let s2 = other.y * self.z * z1z1;

        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            }
            return Self::identity();
        }

        // H = U2-U1
        let h = u2 - u1;
        // I = (2*H)^2
        let i = h.double().square();
        // J = H*I
        let j = h * i;
        // r = 2*(S2-S1)
        let r = (s2 - s1).double();
        // V = U1*I
        let v = u1 * i;
        // X3 = r^2-J-2*V
        let x3 = r.square() - j - v.double();
        // Y3 = r*(V-X3)-2*S1*J
        let y3 = r * (v - x3) - (s1 * j).double();
        // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
        let z3 = ((self.z + other.z).square() - z1z1 - z2z2) * h;
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// EFD madd-2007-bl (mixed Jacobian-affine).
    #[inline(always)]
    pub fn add_mixed(self, other: G1Affine) -> Self {
        self.add_mixed_fast(other)
    }

    /// Return the additive inverse.
    fn negate(self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }

    /// Normalize to affine via one variable-time inversion.
    ///
    /// The `unwrap` is unreachable: the guard maps `z == 0` (any hand-built
    /// X, Y included) to the affine identity, and every nonzero canonical
    /// `Fp` is invertible, so no constructible value reaches `invert` with
    /// zero.
    pub fn to_affine(self) -> G1Affine {
        if self.is_identity() {
            return G1Affine::identity();
        }
        let Some(zinv) = self.z.invert() else {
            return G1Affine::identity();
        };
        let zinv2 = zinv.square();
        G1Affine {
            x: self.x * zinv2,
            y: self.y * zinv2 * zinv,
            infinity: false,
        }
    }

    /// Multiply by a public scalar with width-4 wNAF.
    #[inline]
    fn scale(self, scalar: Fr) -> Self {
        crate::wnaf::mul_group::<Self, 4, 4, 257>(self, scalar)
    }
}

impl core::ops::Neg for G1Affine {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        self.negate()
    }
}

impl core::ops::Add for G1Projective {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add_complete(rhs)
    }
}

impl core::ops::Neg for G1Projective {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self.negate()
    }
}

impl core::ops::Mul<Fr> for G1Projective {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Fr) -> Self {
        self.scale(rhs)
    }
}

impl From<G1Affine> for G1Projective {
    fn from(a: G1Affine) -> Self {
        a.to_curve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Z = 0` encodes the identity no matter what X, Y hold: a hand-built
    /// degenerate projective normalizes to infinity instead of reaching the
    /// inversion, so `to_affine` has no panicking input.
    #[test]
    fn to_affine_maps_any_z_zero_to_identity() {
        let degenerate = G1Projective {
            x: Fp::from_u64(7),
            y: Fp::from_u64(11),
            z: Fp::ZERO,
        };
        assert_eq!(degenerate.to_affine(), G1Affine::identity());
    }
}
