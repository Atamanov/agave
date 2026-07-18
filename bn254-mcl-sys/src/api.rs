//! Safe typed layer over the raw mcl FFI.
//!
//! Every function calls [`ensure_init`] first, so callers never observe an
//! uninitialized library. Wire values are big-endian; mcl field elements
//! serialize little-endian canonical (Montgomery-free) values, so every
//! conversion reverses byte order at this boundary.
//!
//! Canonicality is the CALLER's job: the byte-setters here require their
//! input to already be a canonical value (< p, < r). mcl's own setters
//! silently mask or reduce out-of-range input, which would turn a
//! NonCanonical rejection into a wrong answer; callers therefore range-check
//! in Rust (against [`FQ_MODULUS_BE`] / [`FR_MODULUS_BE`]) before calling in.
//! Debug builds assert the precondition.

use {
    crate::{
        MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR, MclFp, MclFp2, MclFr, MclG1, MclG2, MclGT,
        mclBn_finalExp, mclBn_init, mclBn_millerLoopVec, mclBn_verifyOrderG2, mclBnFp_serialize,
        mclBnFp_setLittleEndian, mclBnFr_add, mclBnFr_inv, mclBnFr_isEqual, mclBnFr_isZero,
        mclBnFr_mul, mclBnFr_neg, mclBnFr_serialize, mclBnFr_setLittleEndian, mclBnFr_sqr,
        mclBnFr_sub, mclBnG1_isEqual, mclBnG1_isValid, mclBnG1_isZero, mclBnG1_mul, mclBnG1_mulVec,
        mclBnG1_neg, mclBnG1_normalize, mclBnG2_isEqual, mclBnG2_isValid, mclBnG2_isValidOrder,
        mclBnG2_isZero, mclBnG2_neg, mclBnG2_normalize, mclBnGT_isOne,
    },
    std::sync::Once,
};

/// BN254 base-field modulus p, big-endian; the exclusive upper bound for a
/// canonical coordinate limb.
pub const FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 scalar-field modulus r, big-endian; the exclusive upper bound for a
/// canonical scalar.
pub const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Initialize mcl for BN_SNARK1 exactly once. A nonzero rc is a build/config
/// mismatch (MCLBN_COMPILED_TIME_VAR vs the compiled library), not an input
/// error, so it panics. Also switches the G2 order verification OFF so that
/// `mclBnG2_isValid` means on-curve only; subgroup membership stays available
/// through `mclBnG2_isValidOrder` (mcl keeps the order for it). This pins the
/// on-curve / in-subgroup split the syscall error taxonomy needs.
pub fn ensure_init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: plain c_int arguments; guarded by Once so the non-reentrant
        // global init runs exactly once.
        let rc = unsafe { mclBn_init(MCL_BN_SNARK1, MCLBN_COMPILED_TIME_VAR) };
        assert_eq!(rc, 0, "mclBn_init(BN_SNARK1) failed: rc = {rc}");
        // SAFETY: called after successful init, inside the same Once.
        unsafe { mclBn_verifyOrderG2(0) };
    });
}

// ---------------------------------------------------------------------------
// field element conversions

/// Fp from 32 canonical big-endian bytes. Caller guarantees value < p; the
/// underlying setter would silently mask a larger value.
pub fn fp_from_be(bytes: &[u8; 32]) -> MclFp {
    ensure_init();
    debug_assert!(*bytes < FQ_MODULUS_BE, "caller must range-check < p");
    let mut le = *bytes;
    le.reverse();
    let mut x = MclFp::default();
    // SAFETY: le is a live 32-byte buffer; setLittleEndian reads exactly
    // bufSize bytes and cannot fail for bufSize <= 32.
    let rc = unsafe { mclBnFp_setLittleEndian(&mut x, le.as_ptr(), le.len()) };
    debug_assert_eq!(rc, 0);
    x
}

/// Canonical big-endian bytes of an Fp value.
pub fn fp_to_be(x: &MclFp) -> [u8; 32] {
    ensure_init();
    let mut out = [0u8; 32];
    // SAFETY: out is a live 32-byte buffer; serialize writes exactly 32
    // bytes for the 256-bit build and returns the written size.
    let n = unsafe { mclBnFp_serialize(out.as_mut_ptr(), out.len(), x) };
    debug_assert_eq!(n, 32);
    out.reverse();
    out
}

/// Fr from 32 canonical big-endian bytes. Caller guarantees value < r.
pub fn fr_from_be(bytes: &[u8; 32]) -> MclFr {
    ensure_init();
    debug_assert!(*bytes < FR_MODULUS_BE, "caller must range-check < r");
    let mut le = *bytes;
    le.reverse();
    let mut x = MclFr::default();
    // SAFETY: le is a live 32-byte buffer; setLittleEndian reads exactly
    // bufSize bytes and cannot fail for bufSize <= 32.
    let rc = unsafe { mclBnFr_setLittleEndian(&mut x, le.as_ptr(), le.len()) };
    debug_assert_eq!(rc, 0);
    x
}

/// Canonical big-endian bytes of an Fr value.
pub fn fr_to_be(x: &MclFr) -> [u8; 32] {
    ensure_init();
    let mut out = [0u8; 32];
    // SAFETY: out is a live 32-byte buffer; serialize writes exactly 32
    // bytes for the 256-bit build.
    let n = unsafe { mclBnFr_serialize(out.as_mut_ptr(), out.len(), x) };
    debug_assert_eq!(n, 32);
    out.reverse();
    out
}

// ---------------------------------------------------------------------------
// Fr arithmetic

macro_rules! fr_binop {
    ($name:ident, $ffi:ident, $doc:literal) => {
        #[doc = $doc]
        pub fn $name(x: &MclFr, y: &MclFr) -> MclFr {
            ensure_init();
            let mut z = MclFr::default();
            // SAFETY: all three pointers reference live MclFr values; the op
            // only writes z.
            unsafe { $ffi(&mut z, x, y) };
            z
        }
    };
}

fr_binop!(fr_add, mclBnFr_add, "x + y in Fr.");
fr_binop!(fr_sub, mclBnFr_sub, "x - y in Fr.");
fr_binop!(fr_mul, mclBnFr_mul, "x * y in Fr.");

/// x^2 in Fr.
pub fn fr_sqr(x: &MclFr) -> MclFr {
    ensure_init();
    let mut y = MclFr::default();
    // SAFETY: both pointers reference live MclFr values; only y is written.
    unsafe { mclBnFr_sqr(&mut y, x) };
    y
}

/// -x in Fr.
pub fn fr_neg(x: &MclFr) -> MclFr {
    ensure_init();
    let mut y = MclFr::default();
    // SAFETY: both pointers reference live MclFr values; only y is written.
    unsafe { mclBnFr_neg(&mut y, x) };
    y
}

/// x^-1 in Fr. Caller guarantees x != 0 (mcl maps 0 to 0, a wrong "inverse").
pub fn fr_inv(x: &MclFr) -> MclFr {
    ensure_init();
    debug_assert!(!fr_is_zero(x), "caller must reject zero before inverting");
    let mut y = MclFr::default();
    // SAFETY: both pointers reference live MclFr values; only y is written.
    unsafe { mclBnFr_inv(&mut y, x) };
    y
}

/// x == 0 in Fr.
pub fn fr_is_zero(x: &MclFr) -> bool {
    ensure_init();
    // SAFETY: x references a live MclFr value; pure read.
    (unsafe { mclBnFr_isZero(x) }) == 1
}

/// x == y in Fr.
pub fn fr_eq(x: &MclFr, y: &MclFr) -> bool {
    ensure_init();
    // SAFETY: both pointers reference live MclFr values; pure read.
    (unsafe { mclBnFr_isEqual(x, y) }) == 1
}

// ---------------------------------------------------------------------------
// G1

/// G1 point from canonical affine coordinates (z = 1). Caller guarantees the
/// coordinates came from `fp_from_be`; on-curve is NOT checked here.
pub fn g1_affine(x: MclFp, y: MclFp) -> MclG1 {
    ensure_init();
    MclG1 { x, y, z: fp_one() }
}

/// The point at infinity (z = 0, mcl's cleared representation).
pub fn g1_infinity() -> MclG1 {
    MclG1::default()
}

/// Normalized affine coordinates, or None for infinity.
pub fn g1_xy(p: &MclG1) -> Option<(MclFp, MclFp)> {
    ensure_init();
    if g1_is_zero(p) {
        return None;
    }
    let mut n = MclG1::default();
    // SAFETY: both pointers reference live MclG1 values; only n is written.
    unsafe { mclBnG1_normalize(&mut n, p) };
    Some((n.x, n.y))
}

/// p is the point at infinity.
pub fn g1_is_zero(p: &MclG1) -> bool {
    ensure_init();
    // SAFETY: p references a live MclG1 value; pure read.
    (unsafe { mclBnG1_isZero(p) }) == 1
}

/// p satisfies the G1 curve equation (or is infinity). Order is NOT part of
/// this check: mcl's BN init leaves G1 order verification off, and the G1
/// cofactor is 1 anyway.
pub fn g1_is_on_curve(p: &MclG1) -> bool {
    ensure_init();
    // SAFETY: p references a live MclG1 value; pure read.
    (unsafe { mclBnG1_isValid(p) }) == 1
}

/// p == q as group elements (projective-aware).
pub fn g1_eq(p: &MclG1, q: &MclG1) -> bool {
    ensure_init();
    // SAFETY: both pointers reference live MclG1 values; pure read.
    (unsafe { mclBnG1_isEqual(p, q) }) == 1
}

/// -p in G1.
pub fn g1_neg(p: &MclG1) -> MclG1 {
    ensure_init();
    let mut y = MclG1::default();
    // SAFETY: both pointers reference live MclG1 values; only y is written.
    unsafe { mclBnG1_neg(&mut y, p) };
    y
}

/// scalar * point in G1.
pub fn g1_mul(p: &MclG1, s: &MclFr) -> MclG1 {
    ensure_init();
    let mut z = MclG1::default();
    // SAFETY: all pointers reference live values; only z is written.
    unsafe { mclBnG1_mul(&mut z, p, s) };
    z
}

/// Multi-scalar multiplication: sum of scalars[i] * points[i] via mcl's
/// internal GLV/Pippenger dispatch. Points may be normalized in place (the C
/// API takes them mutably). Requires equal nonzero lengths.
pub fn g1_mul_vec(points: &mut [MclG1], scalars: &[MclFr]) -> MclG1 {
    ensure_init();
    assert_eq!(points.len(), scalars.len());
    assert!(!points.is_empty());
    let mut z = MclG1::default();
    // SAFETY: points and scalars are live slices of exactly n elements with
    // the #[repr(C)] layouts mcl expects; mcl reads scalars, may normalize
    // points in place, and writes z.
    unsafe { mclBnG1_mulVec(&mut z, points.as_mut_ptr(), scalars.as_ptr(), points.len()) };
    z
}

// ---------------------------------------------------------------------------
// G2

/// G2 point from canonical affine coordinates (z = 1). Caller guarantees the
/// limbs came from `fp_from_be`; on-curve is NOT checked here.
pub fn g2_affine(x0: MclFp, x1: MclFp, y0: MclFp, y1: MclFp) -> MclG2 {
    ensure_init();
    MclG2 {
        x: MclFp2 { d: [x0, x1] },
        y: MclFp2 { d: [y0, y1] },
        z: MclFp2 {
            d: [fp_one(), MclFp::default()],
        },
    }
}

/// The point at infinity (z = 0).
pub fn g2_infinity() -> MclG2 {
    MclG2::default()
}

/// Normalized affine coordinates ((x0, x1), (y0, y1)), or None for infinity.
#[allow(clippy::type_complexity)]
pub fn g2_xy(p: &MclG2) -> Option<((MclFp, MclFp), (MclFp, MclFp))> {
    ensure_init();
    if g2_is_zero(p) {
        return None;
    }
    let mut n = MclG2::default();
    // SAFETY: both pointers reference live MclG2 values; only n is written.
    unsafe { mclBnG2_normalize(&mut n, p) };
    Some(((n.x.d[0], n.x.d[1]), (n.y.d[0], n.y.d[1])))
}

/// p is the point at infinity.
pub fn g2_is_zero(p: &MclG2) -> bool {
    ensure_init();
    // SAFETY: p references a live MclG2 value; pure read.
    (unsafe { mclBnG2_isZero(p) }) == 1
}

/// p satisfies the twist curve equation (or is infinity). On-curve ONLY:
/// `ensure_init` switches mcl's G2 order verification off, keeping the
/// on-curve / in-subgroup split observable.
pub fn g2_is_on_curve(p: &MclG2) -> bool {
    ensure_init();
    // SAFETY: p references a live MclG2 value; pure read.
    (unsafe { mclBnG2_isValid(p) }) == 1
}

/// p is in the r-order subgroup. Caller guarantees p is ON THE TWIST CURVE
/// (mcl multiplies by r with curve formulas, meaningless off-curve); this
/// layer never calls it before an on-curve check.
pub fn g2_is_in_subgroup(p: &MclG2) -> bool {
    ensure_init();
    debug_assert!(g2_is_on_curve(p), "subgroup check requires on-curve input");
    // SAFETY: p references a live MclG2 value; pure read.
    (unsafe { mclBnG2_isValidOrder(p) }) == 1
}

/// p == q as group elements (projective-aware).
pub fn g2_eq(p: &MclG2, q: &MclG2) -> bool {
    ensure_init();
    // SAFETY: both pointers reference live MclG2 values; pure read.
    (unsafe { mclBnG2_isEqual(p, q) }) == 1
}

/// -p in G2.
pub fn g2_neg(p: &MclG2) -> MclG2 {
    ensure_init();
    let mut y = MclG2::default();
    // SAFETY: both pointers reference live MclG2 values; only y is written.
    unsafe { mclBnG2_neg(&mut y, p) };
    y
}

// ---------------------------------------------------------------------------
// pairing

/// Product of Miller loops over the given pairs. Requires equal nonzero
/// lengths; infinity members must be filtered by the caller beforehand (the
/// syscall skips such pairs in Rust, never relying on mcl's convention).
pub fn miller_loop_vec(g1s: &[MclG1], g2s: &[MclG2]) -> MclGT {
    ensure_init();
    assert_eq!(g1s.len(), g2s.len());
    assert!(!g1s.is_empty());
    let mut z = MclGT::default();
    // SAFETY: g1s and g2s are live slices of exactly n elements with the
    // #[repr(C)] layouts mcl expects; mcl only writes z.
    unsafe { mclBn_millerLoopVec(&mut z, g1s.as_ptr(), g2s.as_ptr(), g1s.len()) };
    z
}

/// Final exponentiation of a Miller-loop output.
pub fn final_exp(x: &MclGT) -> MclGT {
    ensure_init();
    let mut y = MclGT::default();
    // SAFETY: both pointers reference live MclGT values; only y is written.
    unsafe { mclBn_finalExp(&mut y, x) };
    y
}

/// x == 1 in GT.
pub fn gt_is_one(x: &MclGT) -> bool {
    ensure_init();
    // SAFETY: x references a live MclGT value; pure read.
    (unsafe { mclBnGT_isOne(x) }) == 1
}

// ---------------------------------------------------------------------------

/// Montgomery-form 1 for affine z coordinates.
fn fp_one() -> MclFp {
    let mut x = MclFp::default();
    // SAFETY: a 1-byte buffer holding 1; setLittleEndian reads exactly one
    // byte and cannot fail.
    let rc = unsafe { mclBnFp_setLittleEndian(&mut x, [1u8].as_ptr(), 1) };
    debug_assert_eq!(rc, 0);
    x
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        ark_std::rand::{SeedableRng, rngs::StdRng},
    };

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xa17b428)
    }

    fn fq_be(x: &Fq) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&x.into_bigint().to_bytes_be());
        out
    }

    fn fr_be(x: &Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&x.into_bigint().to_bytes_be());
        out
    }

    fn g1_from_ark(p: &G1Affine) -> MclG1 {
        match p.xy() {
            Some((x, y)) => g1_affine(fp_from_be(&fq_be(&x)), fp_from_be(&fq_be(&y))),
            None => g1_infinity(),
        }
    }

    fn g2_from_ark(p: &G2Affine) -> MclG2 {
        match p.xy() {
            Some((x, y)) => g2_affine(
                fp_from_be(&fq_be(&x.c0)),
                fp_from_be(&fq_be(&x.c1)),
                fp_from_be(&fq_be(&y.c0)),
                fp_from_be(&fq_be(&y.c1)),
            ),
            None => g2_infinity(),
        }
    }

    /// Deterministic on-twist point outside the r-order subgroup (twist
    /// cofactor ~2^254, so small-x lifts almost surely qualify).
    fn non_subgroup_g2() -> G2Affine {
        for k in 0u64.. {
            let x = Fq2::new(Fq::from(k), Fq::zero());
            if let Some(point) = G2Affine::get_point_from_x_unchecked(x, true) {
                assert!(point.is_on_curve());
                if !point.is_in_correct_subgroup_assuming_on_curve() {
                    return point;
                }
            }
        }
        unreachable!("BN254 twist has non-subgroup points with small x");
    }

    #[test]
    fn test_moduli_match_arkworks() {
        let mut p = [0u8; 32];
        p.copy_from_slice(&Fq::MODULUS.to_bytes_be());
        assert_eq!(p, FQ_MODULUS_BE);
        let mut r = [0u8; 32];
        r.copy_from_slice(&Fr::MODULUS.to_bytes_be());
        assert_eq!(r, FR_MODULUS_BE);
    }

    #[test]
    fn test_field_roundtrip_at_limb_boundaries() {
        // 0, 1, limb carries, and top-of-range values for both fields
        let mut edges: Vec<Fq> = vec![
            Fq::zero(),
            Fq::from(1u64),
            Fq::from(u64::MAX),
            -Fq::from(1u64),
        ];
        let two_64 = Fq::from(u64::MAX) + Fq::from(1u64);
        edges.push(two_64);
        edges.push(two_64 * two_64);
        edges.push(two_64 * two_64 * two_64);
        for x in &edges {
            let be = fq_be(x);
            assert_eq!(fp_to_be(&fp_from_be(&be)), be, "fp {x}");
        }
        for x in [Fr::zero(), Fr::from(1u64), -Fr::from(1u64)] {
            let be = fr_be(&x);
            assert_eq!(fr_to_be(&fr_from_be(&be)), be, "fr {x}");
        }
    }

    #[test]
    fn test_fr_ops_match_arkworks() {
        let mut rng = rng();
        for _ in 0..16 {
            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let (ma, mb) = (fr_from_be(&fr_be(&a)), fr_from_be(&fr_be(&b)));
            assert_eq!(fr_to_be(&fr_add(&ma, &mb)), fr_be(&(a + b)));
            assert_eq!(fr_to_be(&fr_sub(&ma, &mb)), fr_be(&(a - b)));
            assert_eq!(fr_to_be(&fr_mul(&ma, &mb)), fr_be(&(a * b)));
            assert_eq!(fr_to_be(&fr_sqr(&ma)), fr_be(&(a * a)));
            assert_eq!(fr_to_be(&fr_neg(&ma)), fr_be(&(-a)));
            use ark_ff::Field;
            assert_eq!(fr_to_be(&fr_inv(&ma)), fr_be(&a.inverse().unwrap()));
        }
        assert!(fr_is_zero(&fr_from_be(&[0u8; 32])));
        assert!(!fr_is_zero(&fr_from_be(&fr_be(&Fr::from(1u64)))));
    }

    #[test]
    fn test_g1_roundtrip_and_infinity_convention() {
        let mut rng = rng();
        for _ in 0..16 {
            let p = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
            let m = g1_from_ark(&p);
            assert!(!g1_is_zero(&m));
            assert!(g1_is_on_curve(&m));
            let (x, y) = g1_xy(&m).unwrap();
            let (px, py) = p.xy().unwrap();
            assert_eq!(fp_to_be(&x), fq_be(&px));
            assert_eq!(fp_to_be(&y), fq_be(&py));
        }
        // z = 0 is infinity in both directions
        let inf = g1_infinity();
        assert!(g1_is_zero(&inf));
        assert!(g1_xy(&inf).is_none());
        assert!(g1_is_on_curve(&inf));
        // and a computed infinity ([1]P + [-1]P through mulVec) reads as zero
        let p = g1_from_ark(&(G1Projective::generator() * Fr::rand(&mut rng)).into_affine());
        let one = fr_from_be(&fr_be(&Fr::from(1u64)));
        let sum = g1_mul_vec(&mut [p, g1_neg(&p)], &[one, one]);
        assert!(g1_is_zero(&sum));
    }

    #[test]
    fn test_g1_rejects_off_curve() {
        let mut rng = rng();
        let p = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
        let (x, y) = p.xy().unwrap();
        let off = g1_affine(
            fp_from_be(&fq_be(&x)),
            fp_from_be(&fq_be(&(y + Fq::from(1u64)))),
        );
        assert!(!g1_is_on_curve(&off));
    }

    #[test]
    fn test_g1_mul_and_mul_vec_match_arkworks() {
        let mut rng = rng();
        let base = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
        let s = Fr::rand(&mut rng);
        let expected = (base * s).into_affine();
        let got = g1_mul(&g1_from_ark(&base), &fr_from_be(&fr_be(&s)));
        assert!(g1_eq(&got, &g1_from_ark(&expected)));

        for n in [1usize, 2, 3, 17, 50] {
            let bases: Vec<G1Affine> = (0..n)
                .map(|_| (G1Projective::generator() * Fr::rand(&mut rng)).into_affine())
                .collect();
            let exps: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let expected = G1Projective::msm(&bases, &exps).unwrap().into_affine();
            let mut mp: Vec<MclG1> = bases.iter().map(g1_from_ark).collect();
            let ms: Vec<MclFr> = exps.iter().map(|e| fr_from_be(&fr_be(e))).collect();
            let got = g1_mul_vec(&mut mp, &ms);
            assert!(g1_eq(&got, &g1_from_ark(&expected)), "n = {n}");
        }
    }

    #[test]
    fn test_g2_roundtrip_curve_and_subgroup_split() {
        let mut rng = rng();
        for _ in 0..8 {
            let p = (G2Projective::generator() * Fr::rand(&mut rng)).into_affine();
            let m = g2_from_ark(&p);
            assert!(!g2_is_zero(&m));
            assert!(g2_is_on_curve(&m));
            assert!(g2_is_in_subgroup(&m));
            let ((x0, x1), (y0, y1)) = g2_xy(&m).unwrap();
            let (px, py) = p.xy().unwrap();
            assert_eq!(fp_to_be(&x0), fq_be(&px.c0));
            assert_eq!(fp_to_be(&x1), fq_be(&px.c1));
            assert_eq!(fp_to_be(&y0), fq_be(&py.c0));
            assert_eq!(fp_to_be(&y1), fq_be(&py.c1));
        }
        let inf = g2_infinity();
        assert!(g2_is_zero(&inf));
        assert!(g2_xy(&inf).is_none());

        // on-curve but non-subgroup: is_on_curve TRUE (order verification is
        // off), is_in_subgroup FALSE -- semantic equality with arkworks'
        // is_in_correct_subgroup_assuming_on_curve
        let t = non_subgroup_g2();
        assert!(t.is_on_curve());
        assert!(!t.is_in_correct_subgroup_assuming_on_curve());
        let mt = g2_from_ark(&t);
        assert!(g2_is_on_curve(&mt), "verifyOrderG2(0) must be in effect");
        assert!(!g2_is_in_subgroup(&mt));
        let neg = g2_neg(&mt);
        assert!(!g2_is_in_subgroup(&neg));

        // off-curve
        let p = (G2Projective::generator() * Fr::rand(&mut rng)).into_affine();
        let (x, y) = p.xy().unwrap();
        let off = g2_affine(
            fp_from_be(&fq_be(&x.c0)),
            fp_from_be(&fq_be(&x.c1)),
            fp_from_be(&fq_be(&(y.c0 + Fq::from(1u64)))),
            fp_from_be(&fq_be(&y.c1)),
        );
        assert!(!g2_is_on_curve(&off));
    }

    #[test]
    fn test_g2_subgroup_matches_arkworks_on_curve_samples() {
        // random on-curve lifts without cofactor clearing are almost surely
        // outside the subgroup; cleared ones are inside
        let mut rng = rng();
        let mut rejected = 0;
        for i in 0..24 {
            let x = Fq2::new(Fq::rand(&mut rng), Fq::rand(&mut rng));
            let Some(p) = G2Affine::get_point_from_x_unchecked(x, i % 2 == 0) else {
                continue;
            };
            let expected = p.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(g2_is_in_subgroup(&g2_from_ark(&p)), expected);
            rejected += usize::from(!expected);
            let cleared = p.clear_cofactor();
            assert!(g2_is_in_subgroup(&g2_from_ark(&cleared)));
        }
        assert!(rejected > 0, "sampling never left the subgroup");
    }

    #[test]
    fn test_pairing_matches_bilinearity_and_arkworks_verdict() {
        let mut rng = rng();
        let a = Fr::rand(&mut rng);
        let p = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
        let q = (G2Projective::generator() * Fr::rand(&mut rng)).into_affine();
        let ap = (p * a).into_affine();
        let aq = (q * a).into_affine();

        // e(aP, Q) * e(-P, aQ) == 1
        let g1s = [g1_from_ark(&ap), g1_neg(&g1_from_ark(&p))];
        let g2s = [g2_from_ark(&q), g2_from_ark(&aq)];
        let f = final_exp(&miller_loop_vec(&g1s, &g2s));
        assert!(gt_is_one(&f));

        // a single real pair is not the identity
        let f = final_exp(&miller_loop_vec(&[g1_from_ark(&p)], &[g2_from_ark(&q)]));
        assert!(!gt_is_one(&f));

        // agreement with the arkworks verdict on a telescoping product
        use {ark_ec::pairing::Pairing, ark_ff::One};
        let expected = ark_bn254::Bn254::multi_pairing([ap, -p], [q, aq])
            .0
            .is_one();
        let ours = gt_is_one(&final_exp(&miller_loop_vec(&g1s, &g2s)));
        assert_eq!(ours, expected);
    }
}
