//! Miller loop for optimal Ate pairing on BN254 (D-type twist).
//!
//! Line formulas from eprint 2013/722; the G2 arithmetic runs on the
//! monomorphized `fp2_fast` limbs with per-tier choices for the G2-step
//! square and mul. The single-pair loop is software-pipelined, but the
//! operation sequences on `f` and `r` are unchanged, so results are
//! bit-identical on every tier. The twist and psi constants are compile-time
//! pinned to their `const_tower` derivations.

use alloc::vec::Vec;

use crate::consts::ATE_LOOP_COUNT;
use crate::fp::Fp;
use crate::fp2::Fp2;
use crate::fp2_fast::{F2, f2_add, f2_dbl, f2_from, f2_mul_fp, f2_neg, f2_one, f2_sub, f2_to};
// G2-step square: the lazy 2-product form wins on the ADX tier where
// mont_mul dominates; other tiers keep the fused dual kernel.
#[cfg(not(all(helius_mont4_x86_64_adx, not(feature = "force-portable"))))]
use crate::fp2_fast::f2_sqr as f2_sqr_g2;
#[cfg(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))]
use crate::fp2_fast::f2_sqr_lazy as f2_sqr_g2;
// G2-step mul: Intel converts widening products to cycles nearly 1:1, so the
// 3-product Karatsuba beats the fused 4-product sosd2 there despite its five
// extra modular add/subs; AMD and the other tiers keep the fused dual kernel.
#[cfg(not(all(helius_x86_intel, not(feature = "force-portable"))))]
use crate::fp2_fast::f2_mul as f2_mul_g2;
#[cfg(all(helius_x86_intel, not(feature = "force-portable")))]
use crate::fp2_fast::f2_mul_karatsuba as f2_mul_g2;
use crate::fp12::Fp12;
use crate::g1::G1Affine;
use crate::g2::G2Affine;

/// Homogeneous projective point on the twist.
struct G2Hom {
    x: F2,
    y: F2,
    z: F2,
}

type EllCoeff = (F2, F2, F2);

/// Number of D-twist line triples in one non-identity BN254 G2 schedule.
pub(crate) const PREPARED_G2_COEFFICIENTS: usize = 87;
pub(crate) const PREPARED_G2_SCALAR_BYTES: usize = PREPARED_G2_COEFFICIENTS * 3 * 2 * 32;
const PREPARED_G2_IFMA_BYTES: usize = PREPARED_G2_COEFFICIENTS * 3 * 2 * 5 * 8;
/// Backend state for scalar Montgomery coefficients plus their radix-52 IFMA
/// form. The latter removes every hot-path coefficient-domain conversion.
pub(crate) const PREPARED_G2_BYTES: usize = PREPARED_G2_SCALAR_BYTES + PREPARED_G2_IFMA_BYTES;

pub(crate) type PreparedFp2x52 = ([u64; 5], [u64; 5]);
pub(crate) type PreparedTriple52 = (PreparedFp2x52, PreparedFp2x52, PreparedFp2x52);

/// G2-only Miller line schedule. Coefficients are stored independently of G1
/// so one authenticated VK entry can serve arbitrary dynamic G1 operands.
#[derive(Clone, Debug)]
pub(crate) struct PreparedG2 {
    pub(crate) coefficients: Vec<(Fp2, Fp2, Fp2)>,
    pub(crate) coefficients_ifma: Vec<PreparedTriple52>,
}

impl PreparedG2 {
    /// Backend-versioned account form: explicit little-endian Montgomery limbs.
    pub(crate) fn to_registry_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(PREPARED_G2_BYTES);
        for triple in &self.coefficients {
            for coefficient in [triple.0, triple.1, triple.2] {
                for component in [coefficient.c0, coefficient.c1] {
                    for limb in component.to_montgomery_limbs() {
                        output.extend_from_slice(&limb.to_le_bytes());
                    }
                }
            }
        }
        for triple in &self.coefficients_ifma {
            for coefficient in [triple.0, triple.1, triple.2] {
                for component in [coefficient.0, coefficient.1] {
                    for limb in component {
                        output.extend_from_slice(&limb.to_le_bytes());
                    }
                }
            }
        }
        debug_assert_eq!(output.len(), PREPARED_G2_BYTES);
        output
    }

    /// Wire form for syscall consumers, the scalar-Montgomery block
    /// alone. The radix-52 IFMA form is derived on restore, so the two limb
    /// domains can never disagree and split a fleet with mixed IFMA support.
    pub(crate) fn to_scalar_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(PREPARED_G2_SCALAR_BYTES);
        for triple in &self.coefficients {
            for coefficient in [triple.0, triple.1, triple.2] {
                for component in [coefficient.c0, coefficient.c1] {
                    for limb in component.to_montgomery_limbs() {
                        output.extend_from_slice(&limb.to_le_bytes());
                    }
                }
            }
        }
        debug_assert_eq!(output.len(), PREPARED_G2_SCALAR_BYTES);
        output
    }

    /// Restore from the scalar-Montgomery wire block, deriving the IFMA form.
    /// Rejects non-canonical limbs; never returns an ill-defined schedule.
    pub(crate) fn from_scalar_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PREPARED_G2_SCALAR_BYTES {
            return None;
        }
        let coefficients = parse_scalar_block(bytes)?;
        let coefficients_ifma = coefficients
            .iter()
            .map(|triple| {
                (
                    fp2_to_ifma(triple.0),
                    fp2_to_ifma(triple.1),
                    fp2_to_ifma(triple.2),
                )
            })
            .collect();
        Some(Self {
            coefficients,
            coefficients_ifma,
        })
    }

    /// Restore an authenticated backend-versioned account schedule without
    /// repeating 522 canonical-to-Montgomery field conversions.
    pub(crate) fn from_registry_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PREPARED_G2_BYTES {
            return None;
        }
        let (scalar_bytes, ifma_bytes) = bytes.split_at(PREPARED_G2_SCALAR_BYTES);
        let coefficients = parse_scalar_block(scalar_bytes)?;
        let mut coefficients_ifma = Vec::with_capacity(PREPARED_G2_COEFFICIENTS);
        for triple in ifma_bytes.chunks_exact(3 * 2 * 5 * 8) {
            let mut fp2 = [([0u64; 5], [0u64; 5]); 3];
            for (output, encoded) in fp2.iter_mut().zip(triple.chunks_exact(2 * 5 * 8)) {
                let mut components = [[0u64; 5]; 2];
                for (component, encoded_component) in
                    components.iter_mut().zip(encoded.chunks_exact(5 * 8))
                {
                    for (limb, bytes) in component.iter_mut().zip(encoded_component.chunks_exact(8))
                    {
                        *limb = u64::from_le_bytes(bytes.try_into().ok()?);
                    }
                    if !radix52_montgomery_is_canonical(component) {
                        return None;
                    }
                }
                *output = (components[0], components[1]);
            }
            coefficients_ifma.push((fp2[0], fp2[1], fp2[2]));
        }
        (coefficients.len() == PREPARED_G2_COEFFICIENTS
            && coefficients_ifma.len() == PREPARED_G2_COEFFICIENTS)
            .then_some(Self {
                coefficients,
                coefficients_ifma,
            })
    }
}

fn parse_scalar_block(bytes: &[u8]) -> Option<Vec<(Fp2, Fp2, Fp2)>> {
    let mut coefficients = Vec::with_capacity(PREPARED_G2_COEFFICIENTS);
    for triple in bytes.chunks_exact(3 * 2 * 32) {
        let mut fp2 = [Fp2::ZERO; 3];
        for (output, encoded) in fp2.iter_mut().zip(triple.chunks_exact(64)) {
            let mut components = [Fp::ZERO; 2];
            for (component, encoded_component) in components.iter_mut().zip(encoded.chunks_exact(32))
            {
                let mut limbs = [0u64; 4];
                for (limb, bytes) in limbs.iter_mut().zip(encoded_component.chunks_exact(8)) {
                    *limb = u64::from_le_bytes(bytes.try_into().ok()?);
                }
                *component = Fp::from_montgomery_limbs(limbs)?;
            }
            let [c0, c1] = components;
            *output = Fp2::new(c0, c1);
        }
        coefficients.push((fp2[0], fp2[1], fp2[2]));
    }
    (coefficients.len() == PREPARED_G2_COEFFICIENTS).then_some(coefficients)
}

fn radix52_montgomery_is_canonical(limbs: &[u64; 5]) -> bool {
    const MASK52: u64 = (1u64 << 52) - 1;
    if limbs.iter().any(|limb| *limb > MASK52) {
        return false;
    }
    let raw = [
        limbs[0] | (limbs[1] << 52),
        (limbs[1] >> 12) | (limbs[2] << 40),
        (limbs[2] >> 24) | (limbs[3] << 28),
        (limbs[3] >> 36) | (limbs[4] << 16),
    ];
    Fp::from_montgomery_limbs(raw).is_some()
}

fn fp2_to_ifma(value: Fp2) -> PreparedFp2x52 {
    (
        value.c0.to_ifma_montgomery_limbs52(),
        value.c1.to_ifma_montgomery_limbs52(),
    )
}

/// `mul_by_034` operands: line coefficients with the G1 scalings applied.
type ScaledCoeffs = (Fp2, Fp2, Fp2);

/// One loop iteration's lines: the doubling line plus the NAF digit's
/// optional addition line, scaled and ready for `mul_by_034`.
type Lines = (ScaledCoeffs, Option<ScaledCoeffs>);

impl G2Hom {
    #[inline(always)]
    fn from_affine(q: &G2Affine) -> Self {
        Self {
            x: f2_from(q.x),
            y: f2_from(q.y),
            z: f2_one(),
        }
    }

    /// Double; D-type line coeffs (-h, 3j, i).
    #[inline(never)]
    fn double_in_place(&mut self) -> EllCoeff {
        let mut a = f2_mul_g2(self.x, self.y);
        a = f2_half(a);
        let b = f2_sqr_g2(self.y);
        let c = f2_sqr_g2(self.z);
        // e = twist_b * 3c
        let e = f2_mul_g2(twist_b_f2(), f2_add(f2_dbl(c), c));
        let f = f2_add(f2_dbl(e), e); // 3e
        let mut g = f2_add(b, f);
        g = f2_half(g);
        let h = f2_sub(f2_sqr_g2(f2_add(self.y, self.z)), f2_add(b, c));
        let i = f2_sub(e, b);
        let j = f2_sqr_g2(self.x);
        let e_square = f2_sqr_g2(e);

        self.x = f2_mul_g2(a, f2_sub(b, f));
        self.y = f2_sub(f2_sqr_g2(g), f2_add(f2_dbl(e_square), e_square));
        self.z = f2_mul_g2(b, h);

        (f2_neg(h), f2_add(f2_dbl(j), j), i)
    }

    /// Add affine q. D-type line coeffs (lambda, -theta, j).
    #[inline(never)]
    fn add_in_place(&mut self, qx: F2, qy: F2) -> EllCoeff {
        let theta = f2_sub(self.y, f2_mul_g2(qy, self.z));
        let lambda = f2_sub(self.x, f2_mul_g2(qx, self.z));
        let c = f2_sqr_g2(theta);
        let d = f2_sqr_g2(lambda);
        let e = f2_mul_g2(lambda, d);
        let f = f2_mul_g2(self.z, c);
        let g = f2_mul_g2(self.x, d);
        let h = f2_sub(f2_add(e, f), f2_dbl(g));
        self.x = f2_mul_g2(lambda, h);
        self.y = f2_sub(f2_mul_g2(theta, f2_sub(g, h)), f2_mul_g2(e, self.y));
        self.z = f2_mul_g2(self.z, e);
        let j = f2_sub(f2_mul_g2(theta, qx), f2_mul_g2(lambda, qy));
        (lambda, f2_neg(theta), j)
    }
}

/// D-twist coefficient b' = 3/xi = (27 - 3u)/82 in Montgomery form
/// (E': y^2 = x^3 + b'). Pinned below to `const_tower::TWIST_B`.
#[inline(always)]
pub(crate) const fn twist_b_f2() -> F2 {
    (
        [
            0x3bf938e377b802a8,
            0x020b1b273633535d,
            0x26b7edf049755260,
            0x2514c6324384a86d,
        ],
        [
            0x38e7ecccd1dcff67,
            0x65f0b37d93ce0d3e,
            0xd749d0dd22ac00aa,
            0x0141b9ce4a688d4d,
        ],
    )
}

/// Line coefficients scaled by the G1 anchor (`c0*py`, `c3*px`, `c4`): the
/// exact `mul_by_034` operands.
#[inline(never)]
fn scale_coeffs(coeffs: &EllCoeff, p: &G1Affine) -> ScaledCoeffs {
    (
        f2_to(f2_mul_fp(coeffs.0, &p.y.0)),
        f2_to(f2_mul_fp(coeffs.1, &p.x.0)),
        f2_to(coeffs.2),
    )
}

#[inline(never)]
fn ell(f: &mut Fp12, coeffs: &EllCoeff, p: &G1Affine) {
    let (c0, c3, c4) = scale_coeffs(coeffs, p);
    f.mul_by_034_assign(c0, c3, c4);
}

/// Materialize a D-twist line as the sparse Fp12 element consumed by
/// `mul_by_034`.  The first Miller iteration starts from one, so constructing
/// that line directly avoids a complete sparse multiplication by one.
#[inline(always)]
fn line_value(l: &ScaledCoeffs) -> Fp12 {
    use crate::fp6::Fp6;

    Fp12 {
        c0: Fp6::new(l.0, Fp2::ZERO, Fp2::ZERO),
        c1: Fp6::new(l.1, l.2, Fp2::ZERO),
    }
}

/// psi (untwist-Frobenius-twist) x-scale gamma_{1,2} = xi^((p-1)/3),
/// Montgomery. Pinned below to `const_tower::GAMMA1[1]`.
const FROB_TWIST_X: Fp2 = Fp2::new(
    Fp::from_raw_canonical([
        13075984984163199792,
        3782902503040509012,
        8791150885551868305,
        1825854335138010348,
    ]),
    Fp::from_raw_canonical([
        7963664994991228759,
        12257807996192067905,
        13179524609921305146,
        2767831111890561987,
    ]),
);

/// psi y-scale gamma_{1,3} = xi^((p-1)/2), Montgomery.
/// Pinned below to `const_tower::GAMMA1[2]`.
const FROB_TWIST_Y: Fp2 = Fp2::new(
    Fp::from_raw_canonical([
        16482010305593259561,
        13488546290961988299,
        3578621962720924518,
        2681173117283399901,
    ]),
    Fp::from_raw_canonical([
        11661927080404088775,
        553939530661941723,
        7860678177968807019,
        3208568454732775116,
    ]),
);

/// Compile-time pin: the twist and psi constants above are exactly their
/// first-principles derivations from P and xi (see `const_tower`).
const _: () = {
    use crate::const_tower::{GAMMA1, TWIST_B};
    use crate::consts::derive::eq4;
    let b = twist_b_f2();
    assert!(eq4(b.0, TWIST_B.0) && eq4(b.1, TWIST_B.1));
    assert!(eq4(FROB_TWIST_X.c0.0, GAMMA1[1].0) && eq4(FROB_TWIST_X.c1.0, GAMMA1[1].1));
    assert!(eq4(FROB_TWIST_Y.c0.0, GAMMA1[2].0) && eq4(FROB_TWIST_Y.c1.0, GAMMA1[2].1));
};

/// psi(x, y) = (conj(x)*gamma_{1,2}, conj(y)*gamma_{1,3}): the p-power
/// Frobenius endomorphism carried through the D-twist isomorphism.
#[inline(always)]
pub(crate) fn mul_by_char(q: G2Affine) -> G2Affine {
    G2Affine {
        x: q.x.conjugate() * FROB_TWIST_X,
        y: q.y.conjugate() * FROB_TWIST_Y,
        infinity: false,
    }
}

/// Exact halving mod p: even values shift; odd values shift `(v + p)`, whose
/// carry survives into the top bit. Valid on Montgomery form (division by 2 is
/// a field operation) and far cheaper than multiplying by `2^{-1}`.
#[inline(always)]
fn half4(v: &[u64; 4]) -> [u64; 4] {
    use crate::consts::P;
    if v[0] & 1 == 0 {
        [
            (v[0] >> 1) | (v[1] << 63),
            (v[1] >> 1) | (v[2] << 63),
            (v[2] >> 1) | (v[3] << 63),
            v[3] >> 1,
        ]
    } else {
        let (s0, c0) = v[0].carrying_add(P[0], false);
        let (s1, c1) = v[1].carrying_add(P[1], c0);
        let (s2, c2) = v[2].carrying_add(P[2], c1);
        let (s3, c3) = v[3].carrying_add(P[3], c2);
        [
            (s0 >> 1) | (s1 << 63),
            (s1 >> 1) | (s2 << 63),
            (s2 >> 1) | (s3 << 63),
            (s3 >> 1) | ((c3 as u64) << 63),
        ]
    }
}

/// x86: outlined shared body (footprint; see `fp2_fast`).
#[cfg_attr(target_arch = "x86_64", inline(never))]
#[cfg_attr(not(target_arch = "x86_64"), inline(always))]
fn f2_half(a: F2) -> F2 {
    (half4(&a.0), half4(&a.1))
}

/// Multiply `f` by one iteration's lines (doubling line, then the digit's
/// addition line if present).
#[inline(always)]
fn apply_lines(f: &mut Fp12, lines: &Lines) {
    let (d, a) = lines;
    f.mul_by_034_assign(d.0, d.1, d.2);
    if let Some(a) = a {
        f.mul_by_034_assign(a.0, a.1, a.2);
    }
}

/// Optimal Ate Miller loop.
///
/// Software-pipelined: each iteration's G2 double/add and G1 scalings are
/// computed one iteration early, between `square_in_place` and the sparse
/// muls consuming the previous lines. Every f-chain op is far larger than
/// the OoO window, so only source order can overlap the f-independent G2
/// work with that serial chain; the operation sequences on `f` and `r` are
/// unchanged, results are bit-identical on every tier.
pub fn miller_loop(p: &G1Affine, q: &G2Affine) -> Fp12 {
    if p.is_identity() || q.is_identity() {
        return Fp12::ONE;
    }

    let mut r = G2Hom::from_affine(q);
    let qx = f2_from(q.x);
    let qy = f2_from(q.y);
    let nqy = f2_neg(qy);

    // Scaled lines for one loop iteration given its NAF digit.
    let lines = |r: &mut G2Hom, digit: i8| -> Lines {
        let d = scale_coeffs(&r.double_in_place(), p);
        let a = match digit {
            1 => Some(scale_coeffs(&r.add_in_place(qx, qy), p)),
            -1 => Some(scale_coeffs(&r.add_in_place(qx, nqy), p)),
            _ => None,
        };
        (d, a)
    };

    let ate = &ATE_LOOP_COUNT;
    let n = ate.len();

    // Iteration n-1: f starts at one, so the doubling line IS f; there is no
    // preceding square to shadow yet.
    let (first_d, first_a) = lines(&mut r, ate[n - 2]);
    let mut f = line_value(&first_d);
    if let Some(a) = &first_a {
        f.mul_by_034_assign(a.0, a.1, a.2);
    }

    let mut pending = lines(&mut r, ate[n - 3]);
    for i in (2..n - 1).rev() {
        f.square_in_place();
        let next = lines(&mut r, ate[i - 2]);
        apply_lines(&mut f, &pending);
        pending = next;
    }

    // Final iteration (i = 1) with the two Frobenius additions pipelined in:
    // their G2 adds are f-independent too, so they issue in the same shadow.
    let q1 = mul_by_char(*q);
    let q2 = -mul_by_char(q1);
    f.square_in_place();
    let l1 = scale_coeffs(&r.add_in_place(f2_from(q1.x), f2_from(q1.y)), p);
    apply_lines(&mut f, &pending);
    let l2 = scale_coeffs(&r.add_in_place(f2_from(q2.x), f2_from(q2.y)), p);
    f.mul_by_034_assign(l1.0, l1.1, l1.2);
    f.mul_by_034_assign(l2.0, l2.1, l2.2);

    f
}

/// Fused Miller loop over several pairs sharing one Fp12 accumulator;
/// callers filter identity pairs and apply the final exponentiation.
pub(crate) fn prepare_g2(q: &G2Affine) -> PreparedG2 {
    assert!(!q.is_identity(), "prepared G2 must be non-identity");
    let mut r = G2Hom::from_affine(q);
    let qx = f2_from(q.x);
    let qy = f2_from(q.y);
    let nqy = f2_neg(qy);
    let mut coefficients = Vec::with_capacity(PREPARED_G2_COEFFICIENTS);
    let mut push = |coefficient: EllCoeff| {
        coefficients.push((
            f2_to(coefficient.0),
            f2_to(coefficient.1),
            f2_to(coefficient.2),
        ));
    };
    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        push(r.double_in_place());
        match ATE_LOOP_COUNT[i - 1] {
            1 => push(r.add_in_place(qx, qy)),
            -1 => push(r.add_in_place(qx, nqy)),
            _ => {}
        }
    }
    let q1 = mul_by_char(*q);
    let q2 = -mul_by_char(q1);
    push(r.add_in_place(f2_from(q1.x), f2_from(q1.y)));
    push(r.add_in_place(f2_from(q2.x), f2_from(q2.y)));
    assert_eq!(coefficients.len(), PREPARED_G2_COEFFICIENTS);
    let coefficients_ifma = coefficients
        .iter()
        .map(|triple| {
            (
                fp2_to_ifma(triple.0),
                fp2_to_ifma(triple.1),
                fp2_to_ifma(triple.2),
            )
        })
        .collect();
    PreparedG2 {
        coefficients,
        coefficients_ifma,
    }
}

fn ell_prepared(f: &mut Fp12, coeffs: &(Fp2, Fp2, Fp2), p: &G1Affine) {
    f.mul_by_034_assign(coeffs.0.mul_by_fp(p.y), coeffs.1.mul_by_fp(p.x), coeffs.2);
}

fn first_or_multiply(f: &mut Fp12, initialized: &mut bool, coeffs: &(Fp2, Fp2, Fp2), p: &G1Affine) {
    if *initialized {
        ell_prepared(f, coeffs, p);
    } else {
        let scaled = (coeffs.0.mul_by_fp(p.y), coeffs.1.mul_by_fp(p.x), coeffs.2);
        *f = line_value(&scaled);
        *initialized = true;
    }
}

/// Mixed Miller product over ordinary G2 points and authenticated prepared
/// schedules. Registered operands execute no G2 subgroup predicate and no G2
/// double/add line preparation on this hot path.
pub(crate) fn multi_miller_loop_mixed(
    full: &[(&G1Affine, &G2Affine)],
    registered: &[(&G1Affine, &PreparedG2)],
) -> Fp12 {
    struct FullState<'a> {
        p: &'a G1Affine,
        r: G2Hom,
        qx: F2,
        qy: F2,
        nqy: F2,
        q: G2Affine,
    }
    let mut full_states = Vec::with_capacity(full.len());
    for &(p, q) in full {
        if p.is_identity() || q.is_identity() {
            continue;
        }
        let qx = f2_from(q.x);
        let qy = f2_from(q.y);
        full_states.push(FullState {
            p,
            r: G2Hom::from_affine(q),
            qx,
            qy,
            nqy: f2_neg(qy),
            q: *q,
        });
    }
    let registered: Vec<_> = registered
        .iter()
        .copied()
        .filter(|(p, _)| !p.is_identity())
        .collect();
    if full_states.is_empty() && registered.is_empty() {
        return Fp12::ONE;
    }

    let mut f = Fp12::ONE;
    let mut initialized = false;
    let mut prepared_index = 0usize;
    for i in (1..ATE_LOOP_COUNT.len()).rev() {
        if i != ATE_LOOP_COUNT.len() - 1 {
            f.square_in_place();
        }
        for state in &mut full_states {
            let coefficient = state.r.double_in_place();
            let coefficient = (
                f2_to(coefficient.0),
                f2_to(coefficient.1),
                f2_to(coefficient.2),
            );
            first_or_multiply(&mut f, &mut initialized, &coefficient, state.p);
        }
        for (p, prepared) in &registered {
            first_or_multiply(
                &mut f,
                &mut initialized,
                &prepared.coefficients[prepared_index],
                p,
            );
        }
        prepared_index += 1;
        if let digit @ (1 | -1) = ATE_LOOP_COUNT[i - 1] {
            for state in &mut full_states {
                let coefficient = if digit == 1 {
                    state.r.add_in_place(state.qx, state.qy)
                } else {
                    state.r.add_in_place(state.qx, state.nqy)
                };
                ell(&mut f, &coefficient, state.p);
            }
            for (p, prepared) in &registered {
                ell_prepared(&mut f, &prepared.coefficients[prepared_index], p);
            }
            prepared_index += 1;
        }
    }
    for state in &mut full_states {
        let q1 = mul_by_char(state.q);
        let q2 = -mul_by_char(q1);
        let coefficient = state.r.add_in_place(f2_from(q1.x), f2_from(q1.y));
        ell(&mut f, &coefficient, state.p);
        let coefficient = state.r.add_in_place(f2_from(q2.x), f2_from(q2.y));
        ell(&mut f, &coefficient, state.p);
    }
    for (p, prepared) in &registered {
        ell_prepared(&mut f, &prepared.coefficients[prepared_index], p);
        ell_prepared(&mut f, &prepared.coefficients[prepared_index + 1], p);
    }
    prepared_index += 2;
    debug_assert_eq!(prepared_index, PREPARED_G2_COEFFICIENTS);
    f
}

/// Fused Miller loop over several ordinary affine pairs.
pub fn multi_miller_loop(pairs: &[(&G1Affine, &G2Affine)]) -> Fp12 {
    struct State<'a> {
        p: &'a G1Affine,
        r: G2Hom,
        qx: F2,
        qy: F2,
        nqy: F2,
        q: G2Affine,
    }

    let mut states = Vec::with_capacity(pairs.len());
    for &(p, q) in pairs {
        if p.is_identity() || q.is_identity() {
            continue;
        }
        let qx = f2_from(q.x);
        let qy = f2_from(q.y);
        states.push(State {
            p,
            r: G2Hom::from_affine(q),
            qx,
            qy,
            nqy: f2_neg(qy),
            q: *q,
        });
    }
    if states.is_empty() {
        return Fp12::ONE;
    }

    let mut f = Fp12::ONE;
    let ate = &ATE_LOOP_COUNT;
    for i in (1..ate.len()).rev() {
        if i != ate.len() - 1 {
            f.square_in_place();
        }
        for (state_index, state) in states.iter_mut().enumerate() {
            let coeffs = state.r.double_in_place();
            if i == ate.len() - 1 && state_index == 0 {
                f = line_value(&scale_coeffs(&coeffs, state.p));
            } else {
                ell(&mut f, &coeffs, state.p);
            }
        }
        match ate[i - 1] {
            1 => {
                for state in &mut states {
                    let coeffs = state.r.add_in_place(state.qx, state.qy);
                    ell(&mut f, &coeffs, state.p);
                }
            }
            -1 => {
                for state in &mut states {
                    let coeffs = state.r.add_in_place(state.qx, state.nqy);
                    ell(&mut f, &coeffs, state.p);
                }
            }
            _ => {}
        }
    }

    for state in &mut states {
        let q1 = mul_by_char(state.q);
        let q2 = -mul_by_char(q1);
        let coeffs = state.r.add_in_place(f2_from(q1.x), f2_from(q1.y));
        ell(&mut f, &coeffs, state.p);
        let coeffs = state.r.add_in_place(f2_from(q2.x), f2_from(q2.y));
        ell(&mut f, &coeffs, state.p);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fr::Fr;
    use crate::g1::G1Projective;
    use crate::g2::G2Projective;
    use core::ops::Mul;

    /// psi acts on G2 as multiplication by p. For BN curves p - r = 6x^2
    /// (p = 36x^4+36x^3+24x^2+6x+1, r = 36x^4+36x^3+18x^2+6x+1), so
    /// psi(Q) = [6x^2 mod r]Q, recomputed here from the seed alone.
    #[test]
    fn mul_by_char_is_multiplication_by_p_on_g2() {
        let x = u128::from(crate::consts::BN_X);
        let s = 6 * x * x;
        let scalar = Fr::from_raw([s as u64, (s >> 64) as u64, 0, 0]);
        for q in [G2Affine::test_generator(), G2Affine::arkworks_generator()] {
            let want = G2Projective::from(q).mul(scalar).to_affine();
            assert_eq!(mul_by_char(q), want);
        }
    }

    /// psi output stays on the twist y^2 = x^3 + 3/xi with the derived twist_b.
    #[test]
    fn mul_by_char_lands_on_twist_curve() {
        let b = f2_to(twist_b_f2());
        let q = mul_by_char(G2Affine::test_generator());
        assert_eq!(q.y.square(), q.x.square() * q.x + b);
    }

    #[test]
    fn authenticated_prepared_schedule_round_trips_and_matches_full_miller() {
        let p1 = G1Affine::generator();
        let p2 = G1Projective::from(p1).mul(Fr::from_u64(2)).to_affine();
        let q1 = G2Affine::arkworks_generator();
        let q2 = G2Projective::from(q1).mul(Fr::from_u64(3)).to_affine();
        let prepared = prepare_g2(&q2);
        let bytes = prepared.to_registry_bytes();
        assert_eq!(bytes.len(), PREPARED_G2_BYTES);
        let restored = PreparedG2::from_registry_bytes(&bytes).unwrap();

        let ordinary = [(&p1, &q1), (&p2, &q2)];
        assert_eq!(
            multi_miller_loop_mixed(&[(&p1, &q1)], &[(&p2, &restored)]),
            multi_miller_loop(&ordinary),
        );
        assert_eq!(
            multi_miller_loop_mixed(&[], &[(&p1, &prepare_g2(&q1)), (&p2, &restored)]),
            multi_miller_loop(&ordinary),
        );

        let mut noncanonical = bytes;
        noncanonical[..32].fill(0xff);
        assert!(PreparedG2::from_registry_bytes(&noncanonical).is_none());
        assert!(PreparedG2::from_registry_bytes(&noncanonical[..32]).is_none());
    }

    #[test]
    fn scalar_wire_restore_derives_the_exact_ifma_schedule() {
        let q = G2Projective::from(G2Affine::arkworks_generator())
            .mul(Fr::from_u64(5))
            .to_affine();
        let prepared = prepare_g2(&q);
        let bytes = prepared.to_scalar_bytes();
        assert_eq!(bytes.len(), PREPARED_G2_SCALAR_BYTES);
        let restored = PreparedG2::from_scalar_bytes(&bytes).unwrap();
        assert_eq!(restored.coefficients, prepared.coefficients);
        assert_eq!(restored.coefficients_ifma, prepared.coefficients_ifma);
        assert_eq!(restored.to_registry_bytes(), prepared.to_registry_bytes());

        let p = G1Affine::generator();
        assert_eq!(
            multi_miller_loop_mixed(&[], &[(&p, &restored)]),
            multi_miller_loop(&[(&p, &q)]),
        );

        let mut noncanonical = bytes.clone();
        noncanonical[..32].fill(0xff);
        assert!(PreparedG2::from_scalar_bytes(&noncanonical).is_none());
        assert!(PreparedG2::from_scalar_bytes(&bytes[..bytes.len() - 1]).is_none());
        let mut extended = bytes;
        extended.push(0);
        assert!(PreparedG2::from_scalar_bytes(&extended).is_none());
    }
}
