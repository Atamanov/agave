//! G2: twist E'(Fp2): y^2 = x^3 + b', b' = 3/(9+u).
//! Jacobian coordinates (X:Y:Z) over Fp2. EFD a=0 formulas.

use crate::fp::Fp;
use crate::fp2::Fp2;
use crate::fr::Fr;

#[inline(always)]
fn twist_b() -> Fp2 {
    // Mont form of 3/(9+u)
    Fp2::new(
        Fp::from_raw_canonical([
            4321547867055981224,
            147241268046680925,
            2789960110459671136,
            2671978398120978541,
        ]),
        Fp::from_raw_canonical([
            4100506350182530919,
            7345568344173317438,
            15513160039642431658,
            90557763186888013,
        ]),
    )
}

/// Affine G2 point on the D-twist. Fields are unvalidated: safe code can
/// build off-curve/off-subgroup values; the byte facade ([`crate::batch`])
/// is the checked entry point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine {
    /// x-coordinate over Fp2.
    pub x: Fp2,
    /// y-coordinate over Fp2.
    pub y: Fp2,
    /// Point-at-infinity flag; when set the coordinates are ignored.
    pub infinity: bool,
}

/// Jacobian G2 point `(X : Y : Z)` over Fp2; the identity has `Z = 0`.
/// Fields are unvalidated, as for [`G2Affine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Projective {
    /// Jacobian X.
    pub x: Fp2,
    /// Jacobian Y.
    pub y: Fp2,
    /// Jacobian Z; zero encodes the identity.
    pub z: Fp2,
}

impl G2Affine {
    /// Point at infinity.
    pub fn identity() -> Self {
        Self {
            x: Fp2::ZERO,
            y: Fp2::ONE,
            infinity: true,
        }
    }

    /// True iff this is the point at infinity.
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    /// mcl BN_SNARK1 test point Q from `test/bn_test.cpp`.
    pub fn test_generator() -> Self {
        Self {
            x: Fp2::from_str_pair(
                "15267802884793550383558706039165621050290089775961208824303765753922461897946",
                "9034493566019742339402378670461897774509967669562610788113215988055021632533",
            )
            .unwrap(),
            y: Fp2::from_str_pair(
                "644888581738283025171396578091639672120333224302184904896215738366765861164",
                "20532875081203448695448744255224543661959516361327385779878476709582931298750",
            )
            .unwrap(),
            infinity: false,
        }
    }

    /// Standard G2 generator used by arkworks (for cross-checks).
    pub fn arkworks_generator() -> Self {
        // From ark-bn254 G2_GENERATOR
        Self {
            x: Fp2::from_str_pair(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
            y: Fp2::from_str_pair(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
            infinity: false,
        }
    }

    /// Twist-curve membership check `y^2 = x^3 + b'`; infinity passes.
    /// Does not check subgroup membership.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        self.y.square() == self.x.square() * self.x + twist_b()
    }

    /// Fast variable-time r-subgroup check for an already on-curve point.
    ///
    /// El Housni-Guillevic-Piellard (ePrint 2022/352) BN test:
    /// `[x+1]P + psi([x]P) + psi^2([x]P) == psi^3([2x]P)`.  On the r-subgroup psi acts
    /// as `[6x^2]` and the test scalar h(6x^2) equals r; soundness holds because
    /// gcd(Res(h, X^2-tX+p), c2) = 1 for the BN_SNARK1 seed, so no point of
    /// cofactor order can be killed by the test endomorphism.
    pub fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }

        let s = mul_by_bn_x(*self);
        let lhs = s.add_mixed(*self).add(psi(s)).add(psi_squared(s));
        lhs.equals_projective(&psi(psi_squared(s.double())))
    }

    /// Additive inverse.
    pub fn neg(self) -> Self {
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
    pub fn to_curve(self) -> G2Projective {
        if self.infinity {
            G2Projective::identity()
        } else {
            G2Projective {
                x: self.x,
                y: self.y,
                z: Fp2::ONE,
            }
        }
    }
}

impl G2Projective {
    /// Jacobian identity: `Z = 0`.
    pub fn identity() -> Self {
        Self {
            x: Fp2::ZERO,
            y: Fp2::ONE,
            z: Fp2::ZERO,
        }
    }

    /// True iff this is the identity (`Z = 0`).
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    /// EFD dbl-2009-l over Fp2.
    #[inline(always)]
    pub fn double(self) -> Self {
        self.double_fast()
    }

    /// EFD add-2007-bl over Fp2.
    #[inline(always)]
    pub fn add(self, other: Self) -> Self {
        if self.is_identity() {
            return other;
        }
        if other.is_identity() {
            return self;
        }
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x * z2z2;
        let u2 = other.x * z1z1;
        let s1 = self.y * other.z * z2z2;
        let s2 = other.y * self.z * z1z1;
        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            }
            return Self::identity();
        }
        let h = u2 - u1;
        let i = h.double().square();
        let j = h * i;
        let r = (s2 - s1).double();
        let v = u1 * i;
        let x3 = r.square() - j - v.double();
        let y3 = r * (v - x3) - (s1 * j).double();
        let z3 = ((self.z + other.z).square() - z1z1 - z2z2) * h;
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// EFD madd-2007-bl (mixed Jacobian-affine) over Fp2.
    #[inline(always)]
    pub fn add_mixed(self, other: G2Affine) -> Self {
        self.add_mixed_fast(other)
    }

    /// Additive inverse.
    pub fn neg(self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }

    /// Normalize to affine via one variable-time inversion.
    ///
    /// The `unwrap` is unreachable: the guard maps `z == 0` (any hand-built
    /// X, Y included) to the affine identity, and every nonzero `Fp2` is
    /// invertible because its norm `a^2 + b^2` vanishes only at zero (`-1`
    /// is a non-residue for `p = 3 mod 4`).
    pub fn to_affine(self) -> G2Affine {
        if self.is_identity() {
            return G2Affine::identity();
        }
        let zinv = self.z.invert().unwrap();
        let zinv2 = zinv.square();
        G2Affine {
            x: self.x * zinv2,
            y: self.y * zinv2 * zinv,
            infinity: false,
        }
    }

    /// wNAF-4 scalar multiplication (variable-time).
    #[inline]
    pub fn mul(self, scalar: Fr) -> Self {
        crate::wnaf::mul_group::<Self, 4, 4, 257>(self, scalar)
    }

    /// Variable-time multiplication by little-endian machine words.
    /// Test-only reference ladder for differential checks.
    #[cfg(test)]
    pub(crate) fn mul_words(self, scalar: &[u64]) -> Self {
        let mut acc = Self::identity();
        for word in scalar.iter().rev() {
            for bit in (0..64).rev() {
                acc = acc.double();
                if (word >> bit) & 1 == 1 {
                    acc = acc.add(self);
                }
            }
        }
        acc
    }

    /// Projective/projective equality without an inversion.
    pub(crate) fn equals_projective(&self, other: &Self) -> bool {
        if self.is_identity() {
            return other.is_identity();
        }
        if other.is_identity() {
            return false;
        }
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        self.x * z2z2 == other.x * z1z1 && self.y * z2z2 * other.z == other.y * z1z1 * self.z
    }
}

/// `xi^((p-1)/3)` in Montgomery form.
const PSI_X: Fp2 = Fp2::new(
    Fp::from_raw_canonical([
        0xb5773b104563ab30,
        0x347f91c8a9aa6454,
        0x7a007127242e0991,
        0x1956bcd8118214ec,
    ]),
    Fp::from_raw_canonical([
        0x6e849f1ea0aa4757,
        0xaa1c7b6d89f89141,
        0xb6e713cdfae0ca3a,
        0x26694fbb4e82ebc3,
    ]),
);

/// `xi^((p-1)/2)` in Montgomery form.
const PSI_Y: Fp2 = Fp2::new(
    Fp::from_raw_canonical([
        0xe4bbdd0c2936b629,
        0xbb30f162e133bacb,
        0x31a9d1b6f9645366,
        0x253570bea500f8dd,
    ]),
    Fp::from_raw_canonical([
        0xa1d77ce45ffe77c7,
        0x07affd117826d1db,
        0x6d16bd27bb7edc6b,
        0x2c87200285defecc,
    ]),
);

/// `PSI_X * conj(PSI_X)` in Fp: a primitive cube root of unity (Montgomery
/// form; equal to the G1 GLV beta).
const PSI2_X: Fp = Fp::from_raw_canonical([
    0x3350c88e13e80b9c,
    0x7dce557cdb5e56b9,
    0x6001b4b8b615564a,
    0x2682e617020217e0,
]);

/// `p`-power endomorphism on the BN254 twist, in Jacobian coordinates.
/// Conjugation commutes with x = X/Z^2, y = Y/Z^3, so conjugating all three
/// coordinates and scaling X, Y is the affine map.
#[inline]
fn psi(point: G2Projective) -> G2Projective {
    G2Projective {
        x: point.x.conjugate() * PSI_X,
        y: point.y.conjugate() * PSI_Y,
        z: point.z.conjugate(),
    }
}

/// `psi^2`: conjugations cancel, leaving `(x, y) -> (PSI2_X * x, -y)`.
#[inline]
fn psi_squared(point: G2Projective) -> G2Projective {
    G2Projective {
        x: point.x.mul_by_fp(PSI2_X),
        y: -point.y,
        z: point.z,
    }
}

/// `[x]P` for the BN seed `x = 0x44e992b44a6909f1` via its fixed NAF
/// (62 doubles, 23 mixed additions).
fn mul_by_bn_x(point: G2Affine) -> G2Projective {
    // NAF of x, most significant first, leading 1 folded into the accumulator.
    const NAF: [i8; 62] = crate::consts::derive::bn_x_naf_msb(crate::consts::BN_X);
    const _: () = assert!(crate::consts::derive::eq_i8(
        &NAF,
        &[
            0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, -1, 0, -1, 0, -1, 0,
            1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0,
            0, -1, 0, 0, 0, 1,
        ]
    ));
    let negated = point.neg();
    let mut acc = point.to_curve();
    for &digit in NAF.iter() {
        acc = acc.double();
        if digit == 1 {
            acc = acc.add_mixed(point);
        } else if digit == -1 {
            acc = acc.add_mixed(negated);
        }
    }
    acc
}

impl core::ops::Add for G2Projective {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        G2Projective::add(self, rhs)
    }
}

impl core::ops::Neg for G2Projective {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        G2Projective::neg(self)
    }
}

impl From<G2Affine> for G2Projective {
    fn from(a: G2Affine) -> Self {
        a.to_curve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    /// `6x^2 = t - 1`: the eigenvalue of `psi` on the r-subgroup.
    const SIX_X_SQUARED: [u64; 2] = crate::consts::derive::six_x_squared(crate::consts::BN_X);
    const _: () =
        assert!(SIX_X_SQUARED[0] == 0xf83e9682e87cfd46 && SIX_X_SQUARED[1] == 0x6f4d8248eeb859fb);

    /// G2 cofactor `c2 = #E'(Fp)/r = p + t - 1 = p + 6x^2` (little-endian).
    const C2: [u64; 4] =
        crate::consts::derive::add4(crate::consts::P, [SIX_X_SQUARED[0], SIX_X_SQUARED[1], 0, 0]);
    const _: () = assert!(crate::consts::derive::eq4(
        C2,
        [
            0x345f2299c0f9fa8d,
            0x06ceecda572a2489,
            0xb85045b68181585e,
            0x30644e72e131a029,
        ]
    ));

    /// Independent subgroup-check oracle: `[6x^2]P == psi(P)`.
    fn old_check(point: &G2Affine) -> bool {
        if point.infinity {
            return true;
        }
        point
            .to_curve()
            .mul_words(&SIX_X_SQUARED)
            .equals_projective(&psi(point.to_curve()))
    }

    fn naive_check(point: &G2Affine) -> bool {
        point.to_curve().mul_words(&crate::consts::R).is_identity()
    }

    fn assert_all_checks_agree(point: &G2Affine, expected: Option<bool>, context: &str) {
        let new = point.is_in_correct_subgroup_assuming_on_curve();
        assert_eq!(new, old_check(point), "{context}");
        assert_eq!(new, naive_check(point), "{context}");
        if let Some(expected) = expected {
            assert_eq!(new, expected, "{context}");
        }
    }

    fn random_fp(rng: &mut StdRng) -> Fp {
        Fp::from_u64(rng.next_u64()) * Fp::from_u64(rng.next_u64()) * Fp::from_u64(rng.next_u64())
            + Fp::from_u64(rng.next_u64())
    }

    /// Random on-curve point; off-subgroup with overwhelming probability.
    fn random_on_curve(rng: &mut StdRng) -> G2Affine {
        loop {
            let x = Fp2::new(random_fp(rng), random_fp(rng));
            if let Some(y) = (x.square() * x + twist_b()).sqrt() {
                let y = if rng.next_u32() & 1 == 1 { -y } else { y };
                let point = G2Affine {
                    x,
                    y,
                    infinity: false,
                };
                assert!(point.is_on_curve());
                return point;
            }
        }
    }

    /// Regenerates the fixed Fp2/Fp constants from first principles: the
    /// twist coefficient solves `b'*xi = 3` for `xi = 9+u`, and the psi
    /// coefficients are `xi^((p-1)/3)`, `xi^((p-1)/2)` with `PSI2_X` the Fp
    /// norm of the former.
    #[test]
    fn fixed_fp2_constants_regenerate() {
        let xi = Fp2::new(Fp::from_u64(crate::consts::XI_A), Fp::from_u64(1));
        assert_eq!(
            twist_b() * xi,
            Fp2::new(Fp::from_u64(crate::consts::G1_B), Fp::ZERO)
        );

        // (p-1)/3 and (p-1)/2 by short division (exactness asserted).
        let mut p_minus_1 = crate::consts::P;
        p_minus_1[0] -= 1;
        let div_exact = |n: [u64; 4], d: u64| {
            let mut out = [0u64; 4];
            let mut rem: u128 = 0;
            for i in (0..4).rev() {
                let cur = (rem << 64) | n[i] as u128;
                out[i] = (cur / d as u128) as u64;
                rem = cur % d as u128;
            }
            assert_eq!(rem, 0);
            out
        };
        let pow = |base: Fp2, exp: [u64; 4]| {
            let mut acc = Fp2::ONE;
            for i in (0..4).rev() {
                for j in (0..64).rev() {
                    acc = acc.square();
                    if (exp[i] >> j) & 1 == 1 {
                        acc *= base;
                    }
                }
            }
            acc
        };
        assert_eq!(pow(xi, div_exact(p_minus_1, 3)), PSI_X);
        assert_eq!(pow(xi, div_exact(p_minus_1, 2)), PSI_Y);
        assert_eq!(PSI_X * PSI_X.conjugate(), Fp2::new(PSI2_X, Fp::ZERO));
    }

    /// `Z = 0` encodes the identity no matter what X, Y hold, so `to_affine`
    /// has no panicking input (mirrors the G1 pin).
    #[test]
    fn to_affine_maps_any_z_zero_to_identity() {
        let degenerate = G2Projective {
            x: Fp2::new(Fp::from_u64(7), Fp::from_u64(13)),
            y: Fp2::new(Fp::from_u64(11), Fp::from_u64(17)),
            z: Fp2::ZERO,
        };
        assert_eq!(degenerate.to_affine(), G2Affine::identity());
    }

    #[test]
    fn psi_helpers_are_consistent() {
        let mut rng = StdRng::seed_from_u64(0x0705_5100_2022_0352);
        for _ in 0..20 {
            let p = random_on_curve(&mut rng).to_curve();
            let p1 = psi(p);
            assert_eq!(psi(p1).to_affine(), psi_squared(p).to_affine());
            assert_eq!(psi(psi_squared(p)).to_affine(), psi_squared(p1).to_affine());
        }
    }

    #[test]
    fn mul_by_bn_x_matches_generic_ladder() {
        let mut rng = StdRng::seed_from_u64(0x0705_5100_2022_0353);
        for _ in 0..10 {
            let p = random_on_curve(&mut rng);
            assert_eq!(
                mul_by_bn_x(p).to_affine(),
                p.to_curve().mul_words(&[crate::consts::BN_X]).to_affine()
            );
        }
    }

    #[test]
    fn subgroup_check_accepts_members() {
        let mut rng = StdRng::seed_from_u64(0x0705_5100_2022_0354);
        assert_all_checks_agree(&G2Affine::identity(), Some(true), "identity");
        for generator in [G2Affine::test_generator(), G2Affine::arkworks_generator()] {
            assert_all_checks_agree(&generator, Some(true), "generator");
            for i in 0..25 {
                let scalar = Fr::from_u64(rng.next_u64()) * Fr::from_u64(rng.next_u64());
                let point = generator.to_curve().mul(scalar).to_affine();
                assert_all_checks_agree(&point, Some(true), &format!("multiple {i}"));
            }
        }
        // Cofactor-cleared random points land in the subgroup.
        for i in 0..10 {
            let cleared = random_on_curve(&mut rng).to_curve().mul_words(&C2);
            assert_all_checks_agree(&cleared.to_affine(), Some(true), &format!("cleared {i}"));
        }
    }

    #[test]
    fn subgroup_check_rejects_adversarial_points() {
        let mut rng = StdRng::seed_from_u64(0x0705_5100_2022_0355);
        for i in 0..200 {
            let point = random_on_curve(&mut rng);
            assert_all_checks_agree(&point, None, &format!("random {i}"));
            assert!(!point.is_in_correct_subgroup_assuming_on_curve());

            // Pure cofactor-order component: rejected unless it collapsed to O.
            let cofactor_part = point.to_curve().mul_words(&crate::consts::R);
            let expected = cofactor_part.is_identity();
            assert_all_checks_agree(
                &cofactor_part.to_affine(),
                Some(expected),
                &format!("cofactor {i}"),
            );
        }
    }
}
