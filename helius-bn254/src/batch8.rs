//! 8-wide multi-pairing tower (radix-52 AVX-512 IFMA).
//!
//! Eight independent pairings ride the eight IFMA lanes; every Fp2/Fp6/Fp12
//! op is 8-wide, operands stay in the radix-52 Montgomery domain for the
//! whole computation (one conversion pair per pairing), and no cross-lane
//! movement ever occurs. Exists only under `cfg(helius_avx512_ifma)`. The
//! tower mirrors the scalar formulas exactly; every layer is
//! differential-tested against eight scalar ops. `multi_pairing8` is the
//! production batch-verify entry (8-wide Miller loops, one shared scalar
//! final exponentiation); `pairing8`/`final_exp8` stay as the 8-wide oracle.

use {alloc::vec::Vec, core::ops::Neg};

use crate::consts::ATE_LOOP_COUNT;
use crate::fp::Fp;
use crate::fp::avx512ifma::FpVec8;
#[cfg(test)]
use crate::fp12::X_W4;
use crate::pairing::miller::{PreparedFp2x52, PreparedG2, mul_by_char, twist_b_f2};
use crate::{Fp2, Fp6, Fp12, G1Affine, G2Affine};

/// `c0 + c1 u`, `u^2 = -1`, eight lanes.
#[derive(Clone, Copy)]
pub(crate) struct Fp2x8 {
    c0: FpVec8,
    c1: FpVec8,
}

impl Fp2x8 {
    pub(crate) fn load(v: &[Fp2; 8]) -> Self {
        Self {
            c0: FpVec8::load(&core::array::from_fn(|i| v[i].c0)),
            c1: FpVec8::load(&core::array::from_fn(|i| v[i].c1)),
        }
    }

    pub(crate) fn store(&self) -> [Fp2; 8] {
        let (c0, c1) = (self.c0.store(), self.c1.store());
        core::array::from_fn(|i| Fp2::new(c0[i], c1[i]))
    }

    fn load_prepared(values: &[PreparedFp2x52; 8]) -> Self {
        Self {
            c0: FpVec8::load_radix52_montgomery(&core::array::from_fn(|lane| values[lane].0)),
            c1: FpVec8::load_radix52_montgomery(&core::array::from_fn(|lane| values[lane].1)),
        }
    }

    #[inline(always)]
    fn add(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.add(&o.c0),
            c1: self.c1.add(&o.c1),
        }
    }

    #[inline(always)]
    fn sub(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.sub(&o.c0),
            c1: self.c1.sub(&o.c1),
        }
    }

    #[inline(always)]
    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    #[inline(always)]
    fn double(&self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    /// `c0 = a0*b0 - a1*b1`, `c1 = a0*b1 + a1*b0`; two folded reductions.
    #[inline(always)]
    fn mul(&self, o: &Self) -> Self {
        let nb1 = o.c1.neg();
        Self {
            c0: FpVec8::sos_mac(&[self.c0, self.c1], &[o.c0, nb1]),
            c1: FpVec8::sos_mac(&[self.c0, self.c1], &[o.c1, o.c0]),
        }
    }

    /// `c0 = (a0+a1)(a0-a1)`, `c1 = 2 a0 a1`: two plain products where the
    /// two-term sum-of-products form pays half again as much multiply work.
    #[inline(always)]
    fn square(&self) -> Self {
        Self {
            c0: self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1)),
            c1: self.c0.mul(&self.c1).double(),
        }
    }

    /// Multiply by `xi = 9 + u`: `c0 = 9 a0 - a1`, `c1 = 9 a1 + a0`.
    #[inline(always)]
    fn mul_by_nonresidue(&self) -> Self {
        let nine = |x: &FpVec8| x.double().double().double().add(x);
        Self {
            c0: nine(&self.c0).sub(&self.c1),
            c1: nine(&self.c1).add(&self.c0),
        }
    }

    #[inline(always)]
    fn mul_by_fp(&self, f: &FpVec8) -> Self {
        Self {
            c0: self.c0.mul(f),
            c1: self.c1.mul(f),
        }
    }

    #[inline(always)]
    fn blend(&self, other: &Self, mask: u8) -> Self {
        Self {
            c0: self.c0.blend(&other.c0, mask),
            c1: self.c1.blend(&other.c1, mask),
        }
    }
}

/// One Fp2 sum of three products `l0*r0 + l1*r1 + l2*r2` as two `sos_mac(6)`
/// (real folds the imag*imag terms with a negated operand; imag is the
/// all-positive cross terms). One folded reduction per Fp output component --
/// the scalar `sosd6` lazy reduction, lane-parallel. The tower's fused muls and
/// the sparse `mul_by_034` route through this.
#[inline(always)]
fn fp2_sum3(l0: &Fp2x8, r0: &Fp2x8, l1: &Fp2x8, r1: &Fp2x8, l2: &Fp2x8, r2: &Fp2x8) -> Fp2x8 {
    let a = [l0.c0, l0.c1, l1.c0, l1.c1, l2.c0, l2.c1];
    Fp2x8 {
        c0: FpVec8::sos_mac(
            &a,
            &[r0.c0, r0.c1.neg(), r1.c0, r1.c1.neg(), r2.c0, r2.c1.neg()],
        ),
        c1: FpVec8::sos_mac(&a, &[r0.c1, r0.c0, r1.c1, r1.c0, r2.c1, r2.c0]),
    }
}

/// `c0 + c1 v + c2 v^2`, `v^3 = xi`, eight lanes.
#[derive(Clone, Copy)]
pub(crate) struct Fp6x8 {
    c0: Fp2x8,
    c1: Fp2x8,
    c2: Fp2x8,
}

impl Fp6x8 {
    #[cfg(test)]
    fn load(v: &[Fp6; 8]) -> Self {
        Self {
            c0: Fp2x8::load(&core::array::from_fn(|i| v[i].c0)),
            c1: Fp2x8::load(&core::array::from_fn(|i| v[i].c1)),
            c2: Fp2x8::load(&core::array::from_fn(|i| v[i].c2)),
        }
    }

    fn store(&self) -> [Fp6; 8] {
        let (c0, c1, c2) = (self.c0.store(), self.c1.store(), self.c2.store());
        core::array::from_fn(|i| Fp6::new(c0[i], c1[i], c2[i]))
    }

    #[inline(always)]
    fn add(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.add(&o.c0),
            c1: self.c1.add(&o.c1),
            c2: self.c2.add(&o.c2),
        }
    }

    #[inline(always)]
    fn sub(&self, o: &Self) -> Self {
        Self {
            c0: self.c0.sub(&o.c0),
            c1: self.c1.sub(&o.c1),
            c2: self.c2.sub(&o.c2),
        }
    }

    #[cfg(test)]
    #[inline(always)]
    fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    /// `v * (c0 + c1 v + c2 v^2) = xi c2 + c0 v + c1 v^2`.
    #[inline(always)]
    fn mul_by_nonresidue(&self) -> Self {
        Self {
            c0: self.c2.mul_by_nonresidue(),
            c1: self.c0,
            c2: self.c1,
        }
    }

    /// Fused sum-of-products (matches the scalar `Fp6` product, `xi` folded):
    /// `c0 = a0*b0 + a1*(xi b2) + a2*(xi b1)`, `c1 = a0*b1 + a1*b0 + a2*(xi b2)`,
    /// `c2 = a0*b2 + a1*b1 + a2*b0`.
    ///
    /// Each output Fp component is one `sos_mac` over six Fp products (the
    /// scalar `sosd6` lazy reduction, lane-parallel), so an Fp6 mul costs
    /// six `sos_mac(6)` instead of the eighteen `sos_mac(2)` a composed Fp2
    /// product tree would pay -- a third of the Montgomery reductions.
    #[cfg(test)]
    #[inline(always)]
    fn mul(&self, o: &Self) -> Self {
        let x1 = o.c1.mul_by_nonresidue();
        let x2 = o.c2.mul_by_nonresidue();
        let (a0, a1, a2) = (&self.c0, &self.c1, &self.c2);
        Self {
            c0: fp2_sum3(a0, &o.c0, a1, &x2, a2, &x1),
            c1: fp2_sum3(a0, &o.c1, a1, &o.c0, a2, &x2),
            c2: fp2_sum3(a0, &o.c2, a1, &o.c1, a2, &o.c0),
        }
    }

    /// Devegili cubic squaring (matches the scalar `Fp6::square`).
    #[inline(always)]
    fn square(&self) -> Self {
        let s0 = self.c0.square();
        let s1 = self.c0.mul(&self.c1).double();
        let s2 = self.c0.sub(&self.c1).add(&self.c2).square();
        let s3 = self.c1.mul(&self.c2).double();
        let s4 = self.c2.square();
        Self {
            c0: s0.add(&s3.mul_by_nonresidue()),
            c1: s1.add(&s4.mul_by_nonresidue()),
            c2: s1.add(&s2).add(&s3).sub(&s0).sub(&s4),
        }
    }
}

/// `c0 + c1 w`, `w^2 = v`, eight lanes.
#[derive(Clone, Copy)]
pub(crate) struct Fp12x8 {
    c0: Fp6x8,
    c1: Fp6x8,
}

impl Fp12x8 {
    #[cfg(test)]
    pub(crate) fn load(v: &[Fp12; 8]) -> Self {
        Self {
            c0: Fp6x8::load(&core::array::from_fn(|i| v[i].c0)),
            c1: Fp6x8::load(&core::array::from_fn(|i| v[i].c1)),
        }
    }

    pub(crate) fn store(&self) -> [Fp12; 8] {
        let (c0, c1) = (self.c0.store(), self.c1.store());
        core::array::from_fn(|i| Fp12::new(c0[i], c1[i]))
    }

    #[cfg(test)]
    #[inline(always)]
    fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    /// Karatsuba over Fp6: `c0 = a0 b0 + v a1 b1`,
    /// `c1 = (a0+a1)(b0+b1) - a0 b0 - a1 b1`.
    #[cfg(test)]
    #[inline(always)]
    fn mul(&self, o: &Self) -> Self {
        let t0 = self.c0.mul(&o.c0);
        let t1 = self.c1.mul(&o.c1);
        let cross = self.c0.add(&self.c1).mul(&o.c0.add(&o.c1));
        Self {
            c0: t0.add(&t1.mul_by_nonresidue()),
            c1: cross.sub(&t0).sub(&t1),
        }
    }

    /// Karatsuba squaring over Fp6: `t0 = a0^2`, `t1 = a1^2`,
    /// `c0 = t0 + v t1`, `c1 = (a0+a1)^2 - t0 - t1 = 2 a0 a1`.  Three Fp6
    /// squares beat complex squaring's two Fp6 muls: the multiply ports are
    /// the bottleneck, and the Devegili square carries a third less multiply
    /// work than a fused mul while its extra reductions ride the add ports.
    #[inline(always)]
    fn square(&self) -> Self {
        let t0 = self.c0.square();
        let t1 = self.c1.square();
        let c1 = self.c0.add(&self.c1).square().sub(&t0).sub(&t1);
        Self {
            c0: t0.add(&t1.mul_by_nonresidue()),
            c1,
        }
    }
}

// --- Constructors and constants the Miller loop needs ---------------------

impl Fp2x8 {
    fn zero() -> Self {
        Self {
            c0: FpVec8::zero(),
            c1: FpVec8::zero(),
        }
    }
    fn one() -> Self {
        Self {
            c0: FpVec8::load(&[Fp::ONE; 8]),
            c1: FpVec8::zero(),
        }
    }
    /// Broadcast one Fp2 constant into all eight lanes.
    fn broadcast(c: Fp2) -> Self {
        Self::load(&[c; 8])
    }
}

impl Fp6x8 {
    fn zero() -> Self {
        Self {
            c0: Fp2x8::zero(),
            c1: Fp2x8::zero(),
            c2: Fp2x8::zero(),
        }
    }
}

impl Fp12x8 {
    fn one() -> Self {
        Self {
            c0: Fp6x8 {
                c0: Fp2x8::one(),
                c1: Fp2x8::zero(),
                c2: Fp2x8::zero(),
            },
            c1: Fp6x8::zero(),
        }
    }

    /// Sparse multiply by `c0 + c3 w + c4 w v` (mirrors the scalar
    /// `mul_by_034`): with `self = a + b w`, `a = (a0,a1,a2)`, `b = (b0,b1,b2)`,
    /// `xic3 = xi c3`, `xic4 = xi c4`.
    #[inline(always)]
    fn mul_by_034(&self, c0: &Fp2x8, c3: &Fp2x8, c4: &Fp2x8) -> Self {
        let xic3 = c3.mul_by_nonresidue();
        let xic4 = c4.mul_by_nonresidue();
        let (a0, a1, a2) = (&self.c0.c0, &self.c0.c1, &self.c0.c2);
        let (b0, b1, b2) = (&self.c1.c0, &self.c1.c1, &self.c1.c2);
        Self {
            c0: Fp6x8 {
                c0: fp2_sum3(a0, c0, b1, &xic4, b2, &xic3),
                c1: fp2_sum3(a1, c0, b0, c3, b2, &xic4),
                c2: fp2_sum3(a2, c0, b0, c4, b1, c3),
            },
            c1: Fp6x8 {
                c0: fp2_sum3(a0, c3, a2, &xic4, b0, c0),
                c1: fp2_sum3(a0, c4, a1, c3, b1, c0),
                c2: fp2_sum3(a1, c4, a2, c3, b2, c0),
            },
        }
    }
}

/// Eight homogeneous projective points on the twist, one per pairing lane.
struct G2x8 {
    x: Fp2x8,
    y: Fp2x8,
    z: Fp2x8,
}

/// One line's three sparse Fp2 coefficients, eight lanes.
type EllCoeff8 = (Fp2x8, Fp2x8, Fp2x8);

impl G2x8 {
    fn from_affine(qx: Fp2x8, qy: Fp2x8) -> Self {
        Self {
            x: qx,
            y: qy,
            z: Fp2x8::one(),
        }
    }

    /// Doubling with D-type line coefficients `(-h, 3j, i)`. `inv2` broadcasts
    /// `2^-1 mod p` for the two exact field halvings.
    fn double_in_place(&mut self, twist_b: &Fp2x8, inv2: &FpVec8) -> EllCoeff8 {
        let a = self.x.mul(&self.y).mul_by_fp(inv2);
        let b = self.y.square();
        let c = self.z.square();
        let e = twist_b.mul(&c.double().add(&c)); // twist_b * 3c
        let f = e.double().add(&e); // 3e
        let g = b.add(&f).mul_by_fp(inv2);
        let h = self.y.add(&self.z).square().sub(&b.add(&c));
        let i = e.sub(&b);
        let j = self.x.square();
        let e_sq = e.square();
        let new_x = a.mul(&b.sub(&f));
        let new_y = g.square().sub(&e_sq.double().add(&e_sq)); // g^2 - 3 e^2
        let new_z = b.mul(&h);
        self.x = new_x;
        self.y = new_y;
        self.z = new_z;
        (h.neg(), j.double().add(&j), i)
    }

    /// Mixed addition of an affine `q`, line coefficients `(lambda, -theta, j)`.
    fn add_in_place(&mut self, qx: &Fp2x8, qy: &Fp2x8) -> EllCoeff8 {
        let theta = self.y.sub(&qy.mul(&self.z));
        let lambda = self.x.sub(&qx.mul(&self.z));
        let c = theta.square();
        let d = lambda.square();
        let e = lambda.mul(&d);
        let f = self.z.mul(&c);
        let g = self.x.mul(&d);
        let h = e.add(&f).sub(&g.double());
        let new_y = theta.mul(&g.sub(&h)).sub(&e.mul(&self.y));
        self.x = lambda.mul(&h);
        self.y = new_y;
        self.z = self.z.mul(&e);
        let jj = theta.mul(qx).sub(&lambda.mul(qy));
        (lambda, theta.neg(), jj)
    }
}

/// Sparse Fp12 line materialized directly (first Miller iteration).
fn line_value8(coeffs: &EllCoeff8, px: &FpVec8, py: &FpVec8) -> Fp12x8 {
    let c0 = coeffs.0.mul_by_fp(py);
    let c3 = coeffs.1.mul_by_fp(px);
    let c4 = coeffs.2;
    Fp12x8 {
        c0: Fp6x8 {
            c0,
            c1: Fp2x8::zero(),
            c2: Fp2x8::zero(),
        },
        c1: Fp6x8 {
            c0: c3,
            c1: c4,
            c2: Fp2x8::zero(),
        },
    }
}

#[inline(always)]
fn ell8(f: &mut Fp12x8, coeffs: &EllCoeff8, px: &FpVec8, py: &FpVec8) {
    let c0 = coeffs.0.mul_by_fp(py);
    let c3 = coeffs.1.mul_by_fp(px);
    let c4 = coeffs.2;
    *f = f.mul_by_034(&c0, &c3, &c4);
}

#[inline]
fn select_prepared_coefficients(
    computed: EllCoeff8,
    registered: &[Option<&PreparedG2>; 8],
    registered_mask: u8,
    coefficient_index: usize,
) -> EllCoeff8 {
    if registered_mask == 0 {
        return computed;
    }
    let coefficients: [(PreparedFp2x52, PreparedFp2x52, PreparedFp2x52); 8] =
        core::array::from_fn(|lane| {
            registered[lane]
                .map(|prepared| prepared.coefficients_ifma[coefficient_index])
                .unwrap_or((([0; 5], [0; 5]), ([0; 5], [0; 5]), ([0; 5], [0; 5])))
        });
    let prepared = (
        Fp2x8::load_prepared(&core::array::from_fn(|lane| coefficients[lane].0)),
        Fp2x8::load_prepared(&core::array::from_fn(|lane| coefficients[lane].1)),
        Fp2x8::load_prepared(&core::array::from_fn(|lane| coefficients[lane].2)),
    );
    (
        computed.0.blend(&prepared.0, registered_mask),
        computed.1.blend(&prepared.1, registered_mask),
        computed.2.blend(&prepared.2, registered_mask),
    )
}

/// 8-wide optimal-ate Miller loop: eight independent pairings, one per lane,
/// all following the same ate schedule in lockstep. Inputs must be
/// non-identity (the batch-verify caller filters identities).
pub(crate) fn miller8(p: &[G1Affine; 8], q: &[G2Affine; 8]) -> Fp12x8 {
    let px = FpVec8::load(&core::array::from_fn(|i| p[i].x));
    let py = FpVec8::load(&core::array::from_fn(|i| p[i].y));
    let qx = Fp2x8::load(&core::array::from_fn(|i| q[i].x));
    let qy = Fp2x8::load(&core::array::from_fn(|i| q[i].y));
    let nqy = qy.neg();

    let twist_b = {
        let tb = twist_b_f2();
        Fp2x8::broadcast(Fp2::new(Fp(tb.0), Fp(tb.1)))
    };
    let inv2 = FpVec8::load(&[Fp::INV_TWO; 8]);

    // Frobenius endpoints, computed scalar-side per lane.
    let q1: [G2Affine; 8] = core::array::from_fn(|i| mul_by_char(q[i]));
    let q2: [G2Affine; 8] = core::array::from_fn(|i| mul_by_char(q1[i]).neg());
    let q1x = Fp2x8::load(&core::array::from_fn(|i| q1[i].x));
    let q1y = Fp2x8::load(&core::array::from_fn(|i| q1[i].y));
    let q2x = Fp2x8::load(&core::array::from_fn(|i| q2[i].x));
    let q2y = Fp2x8::load(&core::array::from_fn(|i| q2[i].y));

    let mut r = G2x8::from_affine(qx, qy);
    let mut f = Fp12x8::one();
    let ate = &ATE_LOOP_COUNT;
    for i in (1..ate.len()).rev() {
        if i != ate.len() - 1 {
            f = f.square();
        }
        let coeffs = r.double_in_place(&twist_b, &inv2);
        if i == ate.len() - 1 {
            f = line_value8(&coeffs, &px, &py);
        } else {
            ell8(&mut f, &coeffs, &px, &py);
        }
        match ate[i - 1] {
            1 => {
                let coeffs = r.add_in_place(&qx, &qy);
                ell8(&mut f, &coeffs, &px, &py);
            }
            -1 => {
                let coeffs = r.add_in_place(&qx, &nqy);
                ell8(&mut f, &coeffs, &px, &py);
            }
            _ => {}
        }
    }
    let coeffs = r.add_in_place(&q1x, &q1y);
    ell8(&mut f, &coeffs, &px, &py);
    let coeffs = r.add_in_place(&q2x, &q2y);
    ell8(&mut f, &coeffs, &px, &py);
    f
}

/// Eight-lane Miller loop with authenticated prepared schedules injected into
/// selected lanes. Dummy G2 states keep the vector control flow uniform; each
/// dummy line is replaced in registers before it can affect the Fp12 lane.
fn miller8_mixed(
    p: &[G1Affine; 8],
    q: &[G2Affine; 8],
    registered: &[Option<&PreparedG2>; 8],
) -> Fp12x8 {
    let registered_mask = registered
        .iter()
        .enumerate()
        .fold(0u8, |mask, (lane, prepared)| {
            if prepared.is_some() {
                mask | (1u8 << lane)
            } else {
                mask
            }
        });
    let px = FpVec8::load(&core::array::from_fn(|lane| p[lane].x));
    let py = FpVec8::load(&core::array::from_fn(|lane| p[lane].y));
    let qx = Fp2x8::load(&core::array::from_fn(|lane| q[lane].x));
    let qy = Fp2x8::load(&core::array::from_fn(|lane| q[lane].y));
    let nqy = qy.neg();
    let twist_b = {
        let value = twist_b_f2();
        Fp2x8::broadcast(Fp2::new(Fp(value.0), Fp(value.1)))
    };
    let inv2 = FpVec8::load(&[Fp::INV_TWO; 8]);
    let q1: [G2Affine; 8] = core::array::from_fn(|lane| mul_by_char(q[lane]));
    let q2: [G2Affine; 8] = core::array::from_fn(|lane| mul_by_char(q1[lane]).neg());
    let q1x = Fp2x8::load(&core::array::from_fn(|lane| q1[lane].x));
    let q1y = Fp2x8::load(&core::array::from_fn(|lane| q1[lane].y));
    let q2x = Fp2x8::load(&core::array::from_fn(|lane| q2[lane].x));
    let q2y = Fp2x8::load(&core::array::from_fn(|lane| q2[lane].y));

    let mut r = G2x8::from_affine(qx, qy);
    let mut f = Fp12x8::one();
    let mut coefficient_index = 0usize;
    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        if i != ATE_LOOP_COUNT.len() - 1 {
            f = f.square();
        }
        let computed = r.double_in_place(&twist_b, &inv2);
        let coefficients =
            select_prepared_coefficients(computed, registered, registered_mask, coefficient_index);
        coefficient_index += 1;
        if i == ATE_LOOP_COUNT.len() - 1 {
            f = line_value8(&coefficients, &px, &py);
        } else {
            ell8(&mut f, &coefficients, &px, &py);
        }
        let computed = match ATE_LOOP_COUNT[i - 1] {
            1 => Some(r.add_in_place(&qx, &qy)),
            -1 => Some(r.add_in_place(&qx, &nqy)),
            _ => None,
        };
        if let Some(computed) = computed {
            let coefficients = select_prepared_coefficients(
                computed,
                registered,
                registered_mask,
                coefficient_index,
            );
            coefficient_index += 1;
            ell8(&mut f, &coefficients, &px, &py);
        }
    }
    for computed in [r.add_in_place(&q1x, &q1y), r.add_in_place(&q2x, &q2y)] {
        let coefficients =
            select_prepared_coefficients(computed, registered, registered_mask, coefficient_index);
        coefficient_index += 1;
        ell8(&mut f, &coefficients, &px, &py);
    }
    debug_assert_eq!(
        coefficient_index,
        crate::pairing::miller::PREPARED_G2_COEFFICIENTS
    );
    f
}

// The full eight-lane pairing is a differential test oracle. Production uses
// one scalar final exponentiation for the combined Miller product.

/// SoS Fp4 square `(r0 + r1 y)^2`, `y^2 = xi`: `t0 = r0^2 + xi r1^2`,
/// `t1 = (r0+r1)^2 - r0^2 - r1^2 = 2 r0 r1`.  Three Fp2 squares and no Fp2
/// mul: both outputs reuse the component squares.
#[cfg(test)]
#[inline(always)]
fn fp4_square8(r0: &Fp2x8, r1: &Fp2x8) -> (Fp2x8, Fp2x8) {
    let s0 = r0.square();
    let s1 = r1.square();
    let t0 = s0.add(&s1.mul_by_nonresidue());
    let t1 = r0.add(r1).square().sub(&s0).sub(&s1);
    (t0, t1)
}

impl Fp12x8 {
    /// Apply a scalar Fp12 map per lane (store, map, load). Used for the
    /// constant-heavy Frobenius maps and the one-time inversion, which are cold
    /// (a handful of calls per pairing, none in the pow_x hot loop).
    #[cfg(test)]
    #[inline]
    fn map_scalar(&self, f: impl Fn(Fp12) -> Fp12) -> Self {
        let s = self.store();
        Self::load(&core::array::from_fn(|i| f(s[i])))
    }

    /// Granger-Scott cyclotomic square (valid after the easy part). Mirrors the
    /// scalar `cyclotomic_square`; `fp4_square8` replaces the scalar SoS kernels.
    #[cfg(test)]
    #[inline(always)]
    fn cyclotomic_square(&self) -> Self {
        let r0 = self.c0.c0;
        let r4 = self.c0.c1;
        let r3 = self.c0.c2;
        let r2 = self.c1.c0;
        let r1 = self.c1.c1;
        let r5 = self.c1.c2;
        let (t0, t1) = fp4_square8(&r0, &r1);
        let (t2, t3) = fp4_square8(&r2, &r3);
        let (t4, t5) = fp4_square8(&r4, &r5);
        let z0 = t0.sub(&r0).double().add(&t0); // 3 t0 - 2 r0
        let z1 = t1.add(&r1).double().add(&t1); // 3 t1 + 2 r1
        let tmp = t5.mul_by_nonresidue();
        let z2 = r2.add(&tmp).double().add(&tmp); // 2 r2 + 3 xi t5
        let z3 = t4.sub(&r3).double().add(&t4);
        let z4 = t2.sub(&r4).double().add(&t2);
        let z5 = r5.add(&t3).double().add(&t3);
        Self {
            c0: Fp6x8 {
                c0: z0,
                c1: z4,
                c2: z3,
            },
            c1: Fp6x8 {
                c0: z2,
                c1: z1,
                c2: z5,
            },
        }
    }

    /// `self^x`, `x = BN_X`, over signed 4-bit windows of cyclotomic squares
    /// (mirrors the scalar `pow_x`).
    #[cfg(test)]
    fn pow_x(&self) -> Self {
        let x2 = self.cyclotomic_square();
        let x3 = x2.mul(self);
        let x5 = x3.mul(&x2);
        let x7 = x5.mul(&x2);
        let tab = [*self, x3, x5, x7];
        let mut acc = tab[0];
        for &d in X_W4.iter().rev().skip(1) {
            acc = acc.cyclotomic_square();
            if d != 0 {
                let t = tab[(d.unsigned_abs() / 2) as usize];
                acc = acc.mul(&if d < 0 { t.conjugate() } else { t });
            }
        }
        acc
    }

    /// `f^{-x}`; X is positive for BN_SNARK1, so this is the unitary inverse of
    /// `f^x`.
    #[cfg(test)]
    #[inline]
    fn exp_by_neg_x(&self) -> Self {
        self.pow_x().conjugate()
    }
}

/// 8-wide final exponentiation `f^{(p^12-1)/r}`: easy part then the
/// Fuentes-Castaneda hard part, mirroring the scalar `final_exponentiation`.
/// The inversion and Frobenius maps run scalar-side per lane (cold path).
#[cfg(test)]
pub(crate) fn final_exp8(f: &Fp12x8) -> Fp12x8 {
    // Easy: f^{(p^6-1)(p^2+1)}.
    let f1 = f.conjugate();
    let f2 = f.map_scalar(|x| x.invert().expect("final exp input is nonzero"));
    let t = f1.mul(&f2); // f^{p^6-1}
    let r = t.map_scalar(Fp12::frobenius_map_squared).mul(&t);

    // Hard part (Fuentes-Castaneda).
    let y0 = r.exp_by_neg_x();
    let y1 = y0.cyclotomic_square();
    let y2 = y1.cyclotomic_square();
    let y3 = y2.mul(&y1);
    let y4 = y3.exp_by_neg_x();
    let y5 = y4.cyclotomic_square();
    let y6 = y5.exp_by_neg_x();
    let y3c = y3.conjugate();
    let y6c = y6.conjugate();
    let y7 = y6c.mul(&y4);
    let y8 = y7.mul(&y3c);
    let y9 = y8.mul(&y1);
    let y10 = y8.mul(&y4);
    let y11 = y10.mul(&r);
    let y12 = y9.map_scalar(Fp12::frobenius_map);
    let y13 = y12.mul(&y11);
    let y8f = y8.map_scalar(Fp12::frobenius_map_squared);
    let y14 = y8f.mul(&y13);
    let y15 = r.conjugate().mul(&y9).map_scalar(Fp12::frobenius_map_cubed);
    y15.mul(&y14)
}

/// 8-wide full pairing: `miller8` then `final_exp8`.
#[cfg(test)]
pub(crate) fn pairing8(p: &[G1Affine; 8], q: &[G2Affine; 8]) -> Fp12x8 {
    final_exp8(&miller8(p, q))
}

/// Product of Miller-loop outputs using the 8-wide IFMA path.
///
/// Inputs must be non-identity and validated by the public byte facade. This
/// split is also the exact standalone-final-exponentiation benchmark seam.
pub(crate) fn multi_miller8(pairs: &[(G1Affine, G2Affine)]) -> Fp12 {
    use crate::pairing::miller::miller_loop;

    let mut acc = Fp12::ONE;
    let mut chunks = pairs.chunks_exact(8);
    for chunk in &mut chunks {
        let p = core::array::from_fn(|i| chunk[i].0);
        let q = core::array::from_fn(|i| chunk[i].1);
        for f in miller8(&p, &q).store() {
            acc *= f;
        }
    }
    for &(p, q) in chunks.remainder() {
        acc *= miller_loop(&p, &q);
    }
    acc
}

#[derive(Clone, Copy)]
enum MixedPair<'a> {
    Full(&'a G1Affine, &'a G2Affine),
    Registered(&'a G1Affine, &'a PreparedG2),
}

/// Mixed full/prepared Miller product using IFMA for every complete group of
/// eight lanes and the scalar mixed loop only for the final remainder.
pub(crate) fn multi_miller8_mixed(
    full: &[(&G1Affine, &G2Affine)],
    registered: &[(&G1Affine, &PreparedG2)],
) -> Fp12 {
    use crate::pairing::miller::multi_miller_loop_mixed;

    let lanes: Vec<_> = full
        .iter()
        .map(|&(p, q)| MixedPair::Full(p, q))
        .chain(
            registered
                .iter()
                .map(|&(p, prepared)| MixedPair::Registered(p, prepared)),
        )
        .collect();
    let dummy_q = G2Affine::arkworks_generator();
    let mut acc = Fp12::ONE;
    let mut chunks = lanes.chunks_exact(8);
    for chunk in &mut chunks {
        let p = core::array::from_fn(|lane| match chunk[lane] {
            MixedPair::Full(p, _) | MixedPair::Registered(p, _) => *p,
        });
        let q = core::array::from_fn(|lane| match chunk[lane] {
            MixedPair::Full(_, q) => *q,
            MixedPair::Registered(_, _) => dummy_q,
        });
        let prepared = core::array::from_fn(|lane| match chunk[lane] {
            MixedPair::Full(_, _) => None,
            MixedPair::Registered(_, prepared) => Some(prepared),
        });
        for value in miller8_mixed(&p, &q, &prepared).store() {
            acc *= value;
        }
    }
    let mut remainder_full = Vec::new();
    let mut remainder_registered = Vec::new();
    for lane in chunks.remainder() {
        match *lane {
            MixedPair::Full(p, q) => remainder_full.push((p, q)),
            MixedPair::Registered(p, prepared) => remainder_registered.push((p, prepared)),
        }
    }
    if !remainder_full.is_empty() || !remainder_registered.is_empty() {
        acc *= multi_miller_loop_mixed(&remainder_full, &remainder_registered);
    }
    acc
}

/// Batch multi-pairing `prod_i e(p_i, q_i)`, the batch-verification primitive.
/// The Miller loops run 8-wide and share a single final exponentiation.
pub(crate) fn multi_pairing8(pairs: &[(G1Affine, G2Affine)]) -> Fp12 {
    crate::pairing::final_exponentiation(&multi_miller8(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fp::Fp;
    use core::ops::Mul;

    fn residue(state: &mut u64) -> Fp {
        use crate::limb;
        let mut v = [0u64; 4];
        for limb in &mut v {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *limb = *state;
        }
        while limb::gte(&v, &crate::consts::P) {
            v = limb::sub_noborrow(&v, &crate::consts::P);
        }
        Fp(v)
    }

    fn rfp2(s: &mut u64) -> Fp2 {
        Fp2::new(residue(s), residue(s))
    }
    fn rfp6(s: &mut u64) -> Fp6 {
        Fp6::new(rfp2(s), rfp2(s), rfp2(s))
    }
    fn rfp12(s: &mut u64) -> Fp12 {
        Fp12::new(rfp6(s), rfp6(s))
    }

    #[test]
    fn fp2x8_matches_scalar() {
        let mut s = 0x1111_2222_3333_4444u64;
        for _ in 0..4096 {
            let a: [Fp2; 8] = core::array::from_fn(|_| rfp2(&mut s));
            let b: [Fp2; 8] = core::array::from_fn(|_| rfp2(&mut s));
            let (va, vb) = (Fp2x8::load(&a), Fp2x8::load(&b));
            let mul = va.mul(&vb).store();
            let sqr = va.square().store();
            let nr = va.mul_by_nonresidue().store();
            let add = va.add(&vb).store();
            let sub = va.sub(&vb).store();
            for i in 0..8 {
                assert_eq!(mul[i], a[i] * b[i], "mul lane {i}");
                assert_eq!(sqr[i], a[i].square(), "sqr lane {i}");
                assert_eq!(nr[i], a[i].mul_by_nonresidue(), "nonresidue lane {i}");
                assert_eq!(add[i], a[i] + b[i], "add lane {i}");
                assert_eq!(sub[i], a[i] - b[i], "sub lane {i}");
            }
        }
    }

    #[test]
    fn fp6x8_matches_scalar() {
        let mut s = 0x5555_6666_7777_8888u64;
        for _ in 0..4096 {
            let a: [Fp6; 8] = core::array::from_fn(|_| rfp6(&mut s));
            let b: [Fp6; 8] = core::array::from_fn(|_| rfp6(&mut s));
            let (va, vb) = (Fp6x8::load(&a), Fp6x8::load(&b));
            let mul = va.mul(&vb).store();
            let sqr = va.square().store();
            let nr = va.mul_by_nonresidue().store();
            for i in 0..8 {
                assert_eq!(mul[i], a[i] * b[i], "mul lane {i}");
                assert_eq!(sqr[i], a[i].square(), "sqr lane {i}");
                assert_eq!(nr[i], a[i].mul_by_nonresidue(), "nonresidue lane {i}");
            }
        }
    }

    #[test]
    fn fp12x8_matches_scalar() {
        let mut s = 0x9999_aaaa_bbbb_ccccu64;
        for _ in 0..4096 {
            let a: [Fp12; 8] = core::array::from_fn(|_| rfp12(&mut s));
            let b: [Fp12; 8] = core::array::from_fn(|_| rfp12(&mut s));
            let (va, vb) = (Fp12x8::load(&a), Fp12x8::load(&b));
            let mul = va.mul(&vb).store();
            let sqr = va.square().store();
            let conj = va.conjugate().store();
            for i in 0..8 {
                assert_eq!(mul[i], a[i] * b[i], "mul lane {i}");
                assert_eq!(sqr[i], a[i].square(), "sqr lane {i}");
                assert_eq!(conj[i], a[i].conjugate(), "conj lane {i}");
            }
        }
    }

    #[test]
    fn miller8_matches_scalar() {
        use crate::Fr;
        use crate::pairing::miller::miller_loop;
        use crate::{G1Projective, G2Projective};

        let g1 = G1Projective::generator();
        let g2 = G2Projective::from(G2Affine::test_generator());
        let p: [G1Affine; 8] =
            core::array::from_fn(|i| g1.mul(Fr::from_raw([1 + i as u64, 3, 0, 0])).to_affine());
        let q: [G2Affine; 8] =
            core::array::from_fn(|i| g2.mul(Fr::from_raw([2 + i as u64, 5, 0, 0])).to_affine());
        let got = miller8(&p, &q).store();
        for i in 0..8 {
            assert_eq!(got[i], miller_loop(&p[i], &q[i]), "lane {i}");
        }
    }

    #[test]
    fn mixed_miller8_matches_scalar_for_registry_splits() {
        use crate::Fr;
        use crate::pairing::miller::prepare_g2;
        use crate::{G1Projective, G2Projective};

        // Unoptimized AVX-512 field kernels have a much larger compiler-created
        // stack frame than release builtins. Give this debug differential test
        // an explicit stack so its exact cargo-test invocation is reliable.
        std::thread::Builder::new()
            .name("mixed-miller8-differential".to_owned())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let g1 = G1Projective::generator();
                let g2 = G2Projective::from(G2Affine::test_generator());
                let p: [G1Affine; 8] = core::array::from_fn(|index| {
                    g1.mul(Fr::from_raw([1 + index as u64, 7, 0, 0]))
                        .to_affine()
                });
                let q: [G2Affine; 8] = core::array::from_fn(|index| {
                    g2.mul(Fr::from_raw([3 + index as u64, 9, 0, 0]))
                        .to_affine()
                });
                // Each prepared schedule owns roughly 37 KiB of authenticated
                // backend state. Construct the fixture directly on the heap.
                let prepared: Vec<PreparedG2> = q.iter().map(prepare_g2).collect();

                for full_count in [0usize, 2, 5, 8] {
                    let full: Vec<_> = (0..full_count)
                        .map(|index| (&p[index], &q[index]))
                        .collect();
                    let registered: Vec<_> = (full_count..8)
                        .map(|index| (&p[index], &prepared[index]))
                        .collect();
                    let got = mixed_ifma_product(&full, &registered);
                    let expected = mixed_scalar_product(&full, &registered);
                    assert_eq!(
                        got,
                        expected,
                        "full={full_count}, registered={}",
                        8usize.saturating_sub(full_count),
                    );
                }
            })
            .expect("spawn mixed Miller differential")
            .join()
            .expect("mixed Miller differential panicked");
    }

    // Keep the two large arithmetic kernels out of the fixture's stack frame.
    // The production hot path likewise passes prepared schedules by reference;
    // it never copies the registry's serialized schedule into a stack array.
    #[inline(never)]
    fn mixed_ifma_product(
        full: &[(&G1Affine, &G2Affine)],
        registered: &[(&G1Affine, &PreparedG2)],
    ) -> Fp12 {
        multi_miller8_mixed(full, registered)
    }

    #[inline(never)]
    fn mixed_scalar_product(
        full: &[(&G1Affine, &G2Affine)],
        registered: &[(&G1Affine, &PreparedG2)],
    ) -> Fp12 {
        crate::pairing::miller::multi_miller_loop_mixed(full, registered)
    }

    #[test]
    #[ignore = "manual: cargo test --release --features std -- --ignored miller8_bench --nocapture"]
    fn miller8_throughput() {
        use crate::Fr;
        use crate::pairing::miller::miller_loop;
        use crate::{G1Projective, G2Projective};
        use std::hint::black_box;
        use std::time::Instant;

        let g1 = G1Projective::generator();
        let g2 = G2Projective::from(G2Affine::test_generator());
        let p: [G1Affine; 8] =
            core::array::from_fn(|i| g1.mul(Fr::from_raw([1 + i as u64, 3, 0, 0])).to_affine());
        let q: [G2Affine; 8] =
            core::array::from_fn(|i| g2.mul(Fr::from_raw([2 + i as u64, 5, 0, 0])).to_affine());
        let reps = 1_000usize;

        let start = Instant::now();
        for _ in 0..reps {
            let f = miller8(black_box(&p), black_box(&q));
            black_box(&f);
        }
        let ifma = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!(
            "miller8 (8 pairings): {:.0} ns = {:.0} ns/pairing",
            ifma,
            ifma / 8.0
        );

        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..8 {
                black_box(miller_loop(black_box(&p[i]), black_box(&q[i])));
            }
        }
        let scalar = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!(
            "scalar miller x8: {:.0} ns = {:.0} ns/pairing",
            scalar,
            scalar / 8.0
        );
        std::println!(
            "ifma/scalar: {:.2}x per pairing; mcl single miller ~185300 ns/pairing",
            ifma / scalar
        );
    }

    fn test_pairs() -> ([G1Affine; 8], [G2Affine; 8]) {
        use crate::Fr;
        use crate::{G1Projective, G2Projective};
        let g1 = G1Projective::generator();
        let g2 = G2Projective::from(G2Affine::test_generator());
        let p = core::array::from_fn(|i| g1.mul(Fr::from_raw([1 + i as u64, 3, 0, 0])).to_affine());
        let q = core::array::from_fn(|i| g2.mul(Fr::from_raw([2 + i as u64, 5, 0, 0])).to_affine());
        (p, q)
    }

    #[test]
    fn pairing8_matches_scalar() {
        use crate::pairing::pairing;
        let (p, q) = test_pairs();
        let got = pairing8(&p, &q).store();
        for i in 0..8 {
            assert_eq!(got[i], pairing(&p[i], &q[i]), "lane {i}");
        }
    }

    #[test]
    #[ignore = "manual: cargo test --release --features std -- --ignored pairing8_throughput --nocapture"]
    fn pairing8_throughput() {
        use crate::pairing::pairing;
        use std::hint::black_box;
        use std::time::Instant;

        let (p, q) = test_pairs();
        let reps = 500usize;
        let start = Instant::now();
        for _ in 0..reps {
            let f = pairing8(black_box(&p), black_box(&q));
            black_box(&f);
        }
        let ifma = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!(
            "pairing8 (8 pairings): {:.0} ns = {:.0} ns/pairing",
            ifma,
            ifma / 8.0
        );

        let start = Instant::now();
        for _ in 0..reps {
            for i in 0..8 {
                black_box(pairing(black_box(&p[i]), black_box(&q[i])));
            }
        }
        let scalar = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!(
            "scalar pairing x8: {:.0} ns = {:.0} ns/pairing",
            scalar,
            scalar / 8.0
        );
        std::println!(
            "ifma/scalar: {:.2}x per pairing; mcl single pairing ~411686 ns/pairing",
            ifma / scalar
        );
    }

    #[test]
    fn multi_pairing8_matches_scalar() {
        use crate::Fr;
        use crate::pairing::multi_pairing;
        use crate::{G1Projective, G2Projective};

        let g1 = G1Projective::generator();
        let g2 = G2Projective::from(G2Affine::test_generator());
        // Distinct per-term Q keeps multi_pairing on its heterogeneous
        // multi_miller_loop path, so it is a faithful oracle for the 8-wide
        // product. N sweeps across the chunk_exact(8) boundary: full groups,
        // pure tail (< 8), and group + tail remainders.
        for &n in &[1usize, 2, 7, 8, 9, 16, 53] {
            let pairs: Vec<(G1Affine, G2Affine)> = (0..n)
                .map(|i| {
                    let a = g1.mul(Fr::from_raw([1 + i as u64, 3, 0, 0])).to_affine();
                    let b = g2.mul(Fr::from_raw([2 + i as u64, 5, 0, 0])).to_affine();
                    (a, b)
                })
                .collect();
            let refs: Vec<(&G1Affine, &G2Affine)> = pairs.iter().map(|(a, b)| (a, b)).collect();
            assert_eq!(multi_pairing8(&pairs), multi_pairing(&refs), "n={n}");
        }
    }

    #[test]
    #[ignore = "manual: cargo test --release --features std -- --ignored multi_pairing8_throughput --nocapture"]
    fn multi_pairing8_throughput() {
        use crate::Fr;
        use crate::pairing::multi_pairing;
        use crate::{G1Projective, G2Projective};
        use std::hint::black_box;
        use std::time::Instant;

        let g1 = G1Projective::generator();
        let g2 = G2Projective::from(G2Affine::test_generator());
        // mcl millerLoopVec shares one final exp: n Miller + 1 final exp.
        let mcl_ns = |n: usize| (n as f64 * 185300.0 + 226100.0) / n as f64;

        for &n in &[8usize, 64usize] {
            let pairs: Vec<(G1Affine, G2Affine)> = (0..n)
                .map(|i| {
                    let a = g1.mul(Fr::from_raw([1 + i as u64, 3, 0, 0])).to_affine();
                    let b = g2.mul(Fr::from_raw([2 + i as u64, 5, 0, 0])).to_affine();
                    (a, b)
                })
                .collect();
            let refs: Vec<(&G1Affine, &G2Affine)> = pairs.iter().map(|(a, b)| (a, b)).collect();
            let reps = if n <= 8 { 500 } else { 80 };

            let start = Instant::now();
            for _ in 0..reps {
                black_box(multi_pairing8(black_box(&pairs)));
            }
            let ifma = start.elapsed().as_nanos() as f64 / reps as f64 / n as f64;

            let start = Instant::now();
            for _ in 0..reps {
                black_box(multi_pairing(black_box(&refs)));
            }
            let scalar = start.elapsed().as_nanos() as f64 / reps as f64 / n as f64;
            std::println!(
                "batch {n:3}: multi_pairing8 {ifma:.0} ns/pair | scalar {scalar:.0} | \
                 mcl ~{:.0} -> {:.2}x vs scalar, {:.2}x vs mcl",
                mcl_ns(n),
                scalar / ifma,
                mcl_ns(n) / ifma,
            );
        }
    }
}
