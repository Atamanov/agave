//! Variable-time G1 multi-scalar multiplication.
//!
//! BN254's efficiently-computable endomorphism splits every 254-bit scalar
//! into two signed components of at most 127 bits.  Tiny MSMs use a joint
//! width-5 NAF over those components; larger MSMs use a signed Pippenger
//! schedule.  The implementation is intentionally variable-time: the Agave
//! verification workload operates exclusively on public inputs.

use alloc::{vec, vec::Vec};

use crate::{
    Fp, G1Affine, G1Projective,
    consts::{BN_X, derive},
    wnaf::{WnafDigit, recode_u128},
};

/// `beta * x` is the G1 endomorphism whose eigenvalue is `GLV_LAMBDA`.
/// `beta = -(18x^3+18x^2+9x+2) mod p`, the cube root of unity paired with
/// `lambda = -(36x^3+18x^2+6x+2) mod r` (see [`derive::glv_beta_mont`]).
/// Stored in Montgomery form to make applying it one base-field multiply.
const BETA_MONT: Fp = Fp::from_raw_canonical(derive::glv_beta_mont());
const _: () = assert!(derive::eq4(
    derive::glv_beta_mont(),
    [
        0x3350_c88e_13e8_0b9c,
        0x7dce_557c_db5e_56b9,
        0x6001_b4b8_b615_564a,
        0x2682_e617_0202_17e0,
    ]
));

const SCALAR_MODULUS: [u64; 4] = crate::consts::R;

#[cfg(test)]
const BASE_MODULUS: [u64; 4] = crate::consts::P;

/// `ceil(r/2) = (r+1)/2` (r odd): nearest-integer rounding threshold.
const HALF_SCALAR_MODULUS_CEIL: [u64; 4] = derive::add4_small(derive::shr4(SCALAR_MODULUS, 1), 1);
const _: () = assert!(derive::eq4(
    HALF_SCALAR_MODULUS_CEIL,
    [
        0xa1f0_fac9_f800_0001,
        0x9419_f424_3cdc_b848,
        0xdc28_22db_40c0_ac2e,
        0x1832_2739_7098_d014,
    ]
));

// GLV lattice basis, rows v1 = (B00, -|B01|) and v2 = (|B01|, |B11|) with
// B00 = 6x^2+2x, |B01| = 2x+1, |B11| = 6x^2+4x+1 in the BN seed. Both rows lie
// in the lattice {(a, b) : a + b*lambda = 0 mod r} (asserted at runtime by
// `glv_constants_satisfy_defining_identities`) and det = B00*|B11| + |B01|^2
// equals r exactly (const-asserted below), so the basis is full and the
// ~sqrt(r)-sized components give 127-bit splits. Matches the arkworks BN254 GLV
// configuration.
const BASIS_00: [u64; 2] = derive::u128_limbs(derive::poly2_u128(BN_X, [0, 2, 6]));
const BASIS_01_ABS: u64 = 2 * BN_X + 1;
const BASIS_11_ABS: [u64; 2] = derive::u128_limbs(derive::poly2_u128(BN_X, [1, 4, 6]));
const _: () = assert!(BASIS_00[0] == 0x8211_bbeb_7d4f_1128 && BASIS_00[1] == 0x6f4d_8248_eeb8_59fc);
const _: () = assert!(BASIS_01_ABS == 0x89d3_2568_94d2_13e3);
const _: () =
    assert!(BASIS_11_ABS[0] == 0x0be4_e154_1221_250b && BASIS_11_ABS[1] == 0x6f4d_8248_eeb8_59fd);
const _: () = assert!(derive::eq4(
    derive::glv_det(BASIS_00, BASIS_01_ABS, BASIS_11_ABS),
    SCALAR_MODULUS
));

// floor(BASIS_* * 2^256 / r), by const long division.  Multiplication by
// these reciprocals gives a quotient at most one below the exact quotient; a
// six-limb remainder fixes that possible error and performs nearest-integer
// rounding.
const RECIP_BASIS_11: [u64; 3] = derive::floor_mul_2_256_div(BASIS_11_ABS, SCALAR_MODULUS);
const RECIP_BASIS_01: [u64; 3] = derive::floor_mul_2_256_div([BASIS_01_ABS, 0], SCALAR_MODULUS);
const _: () = assert!(
    RECIP_BASIS_11[0] == 0x5398_fd03_00ff_6565
        && RECIP_BASIS_11[1] == 0x4cce_f014_a773_d2d2
        && RECIP_BASIS_11[2] == 0x0000_0000_0000_0002
);
const _: () = assert!(
    RECIP_BASIS_01[0] == 0xd91d_232e_c7e0_b3d7
        && RECIP_BASIS_01[1] == 0x0000_0000_0000_0002
        && RECIP_BASIS_01[2] == 0
);

#[derive(Clone, Copy, Debug)]
struct SignedScalar {
    magnitude: u128,
    negative: bool,
}

impl SignedScalar {
    const ZERO: Self = Self {
        magnitude: 0,
        negative: false,
    };
}

#[derive(Clone, Copy)]
struct GlvTerm {
    point: G1Affine,
    scalar: u128,
    carry: u128,
}

const G1_PROJECTIVE_IDENTITY: G1Projective = G1Projective {
    x: Fp::ZERO,
    y: Fp::ONE,
    z: Fp::ZERO,
};

const G1_AFFINE_IDENTITY: G1Affine = G1Affine {
    x: Fp::ZERO,
    y: Fp::ONE,
    infinity: true,
};

/// Compute `sum(points[i] * scalars[i])` for canonical scalar limbs.
pub(crate) fn msm_variable_time(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
    debug_assert_eq!(points.len(), scalars.len());
    // A joint NAF pays one batch inversion for affine lookup tables and has
    // only ~127 doublings.  Pippenger wins once the per-point table build no
    // longer amortizes.  Size classes keep the stack arrays (and their zero
    // initialization) proportional to n.
    // Crossover measured on Apple M4 with the co-Z table build: joint wNAF
    // beats Pippenger through n=80; Pippenger takes over at 96 where its
    // window widens to 6.
    match points.len() {
        0 => G1Projective::identity(),
        1..=2 => msm_joint_wnaf::<2, 16>(points, scalars),
        3..=4 => msm_joint_wnaf::<4, 32>(points, scalars),
        5..=8 => msm_joint_wnaf::<8, 64>(points, scalars),
        9..=16 => msm_joint_wnaf::<16, 128>(points, scalars),
        17..=32 => msm_joint_wnaf::<32, 256>(points, scalars),
        33..=48 => msm_joint_wnaf::<48, 384>(points, scalars),
        49..=64 => msm_joint_wnaf::<64, 512>(points, scalars),
        65..=80 => msm_joint_wnaf::<80, 640>(points, scalars),
        _ => msm_signed_pippenger(points, scalars),
    }
}

/// Co-Z addition (Goundar-Joye-Rivain ZADDU): for `a`, `b` sharing one Z,
/// returns `(a + b, a~, dx)` where `a~` is `a` rescaled to the sum's Z and
/// `dx = x_a - x_b` is the ratio between the output and input Z coordinates.
/// 5M+2S versus 11M+5S for a full Jacobian addition.  Requires distinct
/// non-identity summands (x1 != x2), which odd-multiple chains of a
/// prime-order point guarantee.
#[inline(always)]
fn zaddu(a: G1Projective, b: G1Projective) -> (G1Projective, G1Projective, Fp) {
    debug_assert_eq!(a.z, b.z);
    debug_assert!(a.x != b.x);
    let dx = a.x - b.x;
    let c = dx.square();
    let w1 = a.x * c;
    let w2 = b.x * c;
    let dy = a.y - b.y;
    let d = dy.square();
    let a1 = a.y * (w1 - w2);
    let x3 = d - w1 - w2;
    let y3 = dy * (w1 - x3) - a1;
    let z3 = a.z * dx;
    (
        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        },
        G1Projective {
            x: w1,
            y: a1,
            z: z3,
        },
        dx,
    )
}

/// Fill `table` with `[P, 3P, 5P, ...]` via an initial co-Z doubling (DBLU)
/// and a ZADDU chain, recording each step's Z ratio in `dx`:
/// `table[i].z = table[i-1].z * dx[i-1]`.  The caller rescales every entry to
/// the chain's final Z without an inversion.  `point` must not be the identity.
#[inline]
fn fill_odd_multiples(point: G1Affine, table: &mut [G1Projective], dx: &mut [Fp]) {
    debug_assert!(!point.infinity);
    debug_assert_eq!(dx.len() + 1, table.len());
    // DBLU from Z=1: dbl-2009-l with the input rescaled to 2P's Z for free:
    // X' = x*(2y)^2 = D, Y' = y*(2y)^3 = 8C.
    let a = point.x.square();
    let b = point.y.square();
    let c = b.square();
    let d = ((point.x + b).square() - a - c).double();
    let e = a + a + a;
    let x2 = e.square() - d.double();
    let c8 = c.double().double().double();
    let z2 = point.y.double();
    table[0] = G1Projective { x: d, y: c8, z: z2 };
    let mut two = G1Projective {
        x: x2,
        y: e * (d - x2) - c8,
        z: z2,
    };
    for i in 1..table.len() {
        let (sum, two_rescaled, step_dx) = zaddu(two, table[i - 1]);
        table[i] = sum;
        dx[i - 1] = step_dx;
        two = two_rescaled;
    }
}

/// Affine MSM result with a single variable-time inversion.
///
/// The byte facade needs an affine output immediately, so this converts the
/// accumulator directly instead of normalizing first and paying a second
/// inversion.  Binary GCD is valid here because all syscall inputs are public
/// and the entire MSM is already explicitly variable-time.
pub(crate) fn msm_variable_time_affine(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Affine {
    projective_to_affine_vartime(msm_variable_time(points, scalars))
}

const JOINT_WIDTH: usize = 5;
const JOINT_TABLE: usize = 1 << (JOINT_WIDTH - 2);
type JointDigits = crate::wnaf::WnafDigits<JOINT_WIDTH, 129>;

/// Stack-only GLV joint wNAF.  `CAP` bounds the point count; every buffer
/// lives in a fixed array because heap allocation is material at the us
/// scale of small MSMs.
fn msm_joint_wnaf<const CAP: usize, const CAP_TABLES: usize>(
    points: &[G1Affine],
    scalars: &[[u64; 4]],
) -> G1Projective {
    const {
        assert!(
            CAP_TABLES == CAP * JOINT_TABLE,
            "joint wNAF table capacity disagrees with point capacity"
        );
    }
    let n = points.len();
    debug_assert!(n != 0 && n <= CAP);

    let mut decomposed = [(SignedScalar::ZERO, SignedScalar::ZERO); CAP];
    let mut tables_projective = [G1_PROJECTIVE_IDENTITY; CAP_TABLES];
    let mut chain_dx = [[Fp::ZERO; JOINT_TABLE - 1]; CAP];
    let mut chain_z = [Fp::ONE; CAP];

    for (i, (point, scalar)) in points.iter().zip(scalars).enumerate() {
        decomposed[i] = decompose_scalar(*scalar);
        if point.infinity {
            continue;
        }
        let chain = &mut tables_projective[i * JOINT_TABLE..(i + 1) * JOINT_TABLE];
        fill_odd_multiples(*point, chain, &mut chain_dx[i]);
        chain_z[i] = chain[JOINT_TABLE - 1].z;
    }

    // Inversion-free normalization: rescale every entry to the global
    // Z_C = prod(chain_z) using the recorded ZADDU ratios and cross-chain
    // prefix/suffix products.  The rescaled (X, Y) pairs are affine points on
    // the isomorphic curve y^2 = x^3 + b*Z_C^6; the a = 0 add/double formulas
    // never reference b, so the main loop runs unchanged and the true result
    // is recovered by multiplying the accumulator's Z by Z_C once.
    let mut outer = [Fp::ONE; CAP];
    let mut product = Fp::ONE;
    for i in 0..n {
        outer[i] = product;
        product *= chain_z[i];
    }
    let z_global = product;
    let mut suffix = Fp::ONE;
    for i in (0..n).rev() {
        outer[i] *= suffix;
        suffix *= chain_z[i];
    }

    let mut tables = [G1_AFFINE_IDENTITY; CAP_TABLES];
    let mut endomorphism_tables = [G1_AFFINE_IDENTITY; CAP_TABLES];
    for c in 0..n {
        if points[c].infinity {
            continue;
        }
        let base = c * JOINT_TABLE;
        let mut scale = outer[c];
        for i in (0..JOINT_TABLE).rev() {
            let entry = tables_projective[base + i];
            let (x, y) = if scale == Fp::ONE {
                (entry.x, entry.y)
            } else {
                let scale_2 = scale.square();
                (entry.x * scale_2, entry.y * (scale_2 * scale))
            };
            tables[base + i] = G1Affine {
                x,
                y,
                infinity: false,
            };
            endomorphism_tables[base + i] = G1Affine {
                x: x * BETA_MONT,
                y,
                infinity: false,
            };
            if i > 0 {
                scale *= chain_dx[c][i - 1];
            }
        }
    }

    let mut digits = [(JointDigits::ZERO, JointDigits::ZERO); CAP];
    let mut max_len = 0usize;
    for (slot, (k1, k2)) in digits[..n].iter_mut().zip(&decomposed) {
        let (d1, n1) = recode_u128::<JOINT_WIDTH, 129>(k1.magnitude);
        let (d2, n2) = recode_u128::<JOINT_WIDTH, 129>(k2.magnitude);
        max_len = max_len.max(n1).max(n2);
        *slot = (d1, d2);
    }

    let mut acc = G1Projective::identity();
    for bit in (0..max_len).rev() {
        acc = acc.double();
        for i in 0..n {
            let table_offset = i * JOINT_TABLE;
            acc = add_wnaf_digit(
                acc,
                &tables[table_offset..table_offset + JOINT_TABLE],
                digits[i].0.digit(bit),
                decomposed[i].0.negative,
            );
            acc = add_wnaf_digit(
                acc,
                &endomorphism_tables[table_offset..table_offset + JOINT_TABLE],
                digits[i].1.digit(bit),
                decomposed[i].1.negative,
            );
        }
    }
    // Leave the isomorphic curve: (X, Y, Z) there is (X, Y, Z*Z_C) on the
    // real curve.  Z = 0 (identity) is preserved.
    acc.z *= z_global;
    acc
}

#[inline(always)]
fn add_wnaf_digit(
    acc: G1Projective,
    table: &[G1Affine],
    digit: WnafDigit<5>,
    component_negative: bool,
) -> G1Projective {
    let Some(index) = digit.table_index() else {
        return acc;
    };
    let negative = digit.is_negative() ^ component_negative;
    let mut point = table[index];
    if negative {
        point = -point;
    }
    acc.add_mixed(point)
}

fn msm_signed_pippenger(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
    msm_signed_pippenger_with_width(points, scalars, msm_width(points.len()))
}

/// Window width for the path the dispatch will actually take: the batch-affine
/// bucket path has cheaper bucket adds, which shifts its optimum toward wider
/// windows earlier than the Jacobian schedule.
fn msm_width(n: usize) -> usize {
    #[cfg(not(all(helius_avx512_ifma, not(feature = "force-portable"))))]
    if n >= BATCH_AFFINE_MIN_N {
        return batch_affine_width(n);
    }
    pippenger_width(n)
}

#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
#[inline]
fn batch_affine_width(n: usize) -> usize {
    match n {
        0..=767 => pippenger_width(n),
        768..=1279 => 9,
        _ => 10,
    }
}

fn msm_signed_pippenger_with_width(
    points: &[G1Affine],
    scalars: &[[u64; 4]],
    width: usize,
) -> G1Projective {
    #[cfg(all(helius_avx512_ifma, not(feature = "force-portable")))]
    return msm_signed_pippenger_with(points, scalars, width, accumulate_window_ifma);
    #[cfg(not(all(helius_avx512_ifma, not(feature = "force-portable"))))]
    if points.len() >= BATCH_AFFINE_MIN_N {
        return msm_signed_pippenger_batch_affine(points, scalars, width);
    }
    #[cfg(not(all(helius_avx512_ifma, not(feature = "force-portable"))))]
    msm_signed_pippenger_with(points, scalars, width, accumulate_window_scalar)
}

/// One window of bucket accumulation: consume the next signed digit of every
/// term and add the (sign-adjusted) point into its bucket.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
fn accumulate_window_scalar(
    buckets: &mut [G1Projective],
    terms: &mut [GlvTerm],
    width: usize,
    mask: u128,
    half: u128,
    radix: u128,
) {
    for term in terms {
        let digit = next_signed_digit(&mut term.scalar, &mut term.carry, width, mask, half, radix);
        if digit != 0 {
            let mut point = term.point;
            if digit < 0 {
                point = -point;
            }
            let index = digit.unsigned_abs() as usize - 1;
            buckets[index] = buckets[index].add_mixed(point);
        }
    }
}

/// AVX-512 IFMA window accumulation: gather up to eight independent bucket
/// updates (distinct buckets, non-identity, generic-case) and perform them as
/// one 8-lane batched mixed addition.  Cases the batch kernel excludes are
/// handled inline on the scalar path, so the result is identical to
/// [`accumulate_window_scalar`]:
/// - identity bucket: direct assignment;
/// - bucket already pending: immediate scalar add (group addition commutes
///   with the deferred batch update, which re-reads the bucket at flush);
/// - `h == 0` or identity-at-flush lanes: redone scalar from the untouched
///   bucket.
#[cfg(all(helius_avx512_ifma, not(feature = "force-portable")))]
fn accumulate_window_ifma(
    buckets: &mut [G1Projective],
    terms: &mut [GlvTerm],
    width: usize,
    mask: u128,
    half: u128,
    radix: u128,
) {
    let mut pending_idx = [0usize; 8];
    let mut pending_pts = [G1_AFFINE_IDENTITY; 8];
    let mut len = 0usize;
    for term in terms {
        let digit = next_signed_digit(&mut term.scalar, &mut term.carry, width, mask, half, radix);
        if digit == 0 {
            continue;
        }
        let mut point = term.point;
        if digit < 0 {
            point = -point;
        }
        let index = digit.unsigned_abs() as usize - 1;
        if buckets[index].is_identity() {
            buckets[index] = point.to_curve();
            continue;
        }
        if pending_idx[..len].contains(&index) {
            buckets[index] = buckets[index].add_mixed(point);
            continue;
        }
        pending_idx[len] = index;
        pending_pts[len] = point;
        len += 1;
        if len == 8 {
            flush_bucket_batch(buckets, &pending_idx, &pending_pts);
            len = 0;
        }
    }
    for lane in 0..len {
        buckets[pending_idx[lane]] = buckets[pending_idx[lane]].add_mixed(pending_pts[lane]);
    }
}

/// Apply eight pending bucket updates through the IFMA batch kernel.
/// `indices` are pairwise distinct; the referenced buckets were non-identity
/// at enqueue time but may have become identity since (cancellation on the
/// scalar conflict path), so re-check at flush.
#[cfg(all(helius_avx512_ifma, not(feature = "force-portable")))]
fn flush_bucket_batch(buckets: &mut [G1Projective], indices: &[usize; 8], points: &[G1Affine; 8]) {
    let mut skip: u8 = 0;
    for lane in 0..8 {
        if buckets[indices[lane]].is_identity() {
            skip |= 1 << lane;
        }
    }
    let x1 = core::array::from_fn(|i| buckets[indices[i]].x);
    let y1 = core::array::from_fn(|i| buckets[indices[i]].y);
    let z1 = core::array::from_fn(|i| buckets[indices[i]].z);
    let x2 = core::array::from_fn(|i| points[i].x);
    let y2 = core::array::from_fn(|i| points[i].y);
    // Excluded (skip / h == 0) lanes compute garbage but stay canonical
    // residues; their buckets are untouched and redone scalar below.
    let (x3, y3, z3, h_zero) = crate::fp::avx512ifma::g1_madd_batch8(&x1, &y1, &z1, &x2, &y2);
    for lane in 0..8 {
        let index = indices[lane];
        if (skip | h_zero) >> lane & 1 == 1 {
            buckets[index] = buckets[index].add_mixed(points[lane]);
        } else {
            buckets[index] = G1Projective {
                x: x3[lane],
                y: y3[lane],
                z: z3[lane],
            };
        }
    }
}

/// Point count at or above which the batch-affine bucket path beats plain
/// Jacobian mixed adds on the non-IFMA (aarch64/portable) build.
#[cfg(not(all(helius_avx512_ifma, not(feature = "force-portable"))))]
const BATCH_AFFINE_MIN_N: usize = 96;

/// Pending-add count that triggers one Montgomery-trick batch inversion.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
const BATCH_AFFINE_FLUSH: usize = 64;

/// Scratch for batch-affine bucket accumulation, allocated once per MSM and
/// reused across windows.  Between accumulate calls everything is drained.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
struct BatchAffineScratch {
    pending_bucket: Vec<u32>,
    pending_point: Vec<G1Affine>,
    pending_double: Vec<bool>,
    /// Lambda denominator of each pending add: `x2 - x1`, or `2*y` for a
    /// doubling.  Always nonzero by classification at enqueue time.
    denom: Vec<Fp>,
    prefix: Vec<Fp>,
    bucket_pending: Vec<bool>,
}

#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
impl BatchAffineScratch {
    fn new(buckets: usize) -> Self {
        Self {
            pending_bucket: Vec::with_capacity(BATCH_AFFINE_FLUSH),
            pending_point: Vec::with_capacity(BATCH_AFFINE_FLUSH),
            pending_double: Vec::with_capacity(BATCH_AFFINE_FLUSH),
            denom: Vec::with_capacity(BATCH_AFFINE_FLUSH),
            prefix: Vec::with_capacity(BATCH_AFFINE_FLUSH),
            bucket_pending: vec![false; buckets],
        }
    }
}

/// Add affine `point` into affine bucket `index`, classifying the addition
/// against the current bucket value.  Cases needing no inversion (empty
/// bucket, cancellation) apply immediately; the generic add and the doubling
/// enqueue their denominator for the next batch inversion.  The caller must
/// have excluded buckets with an add already pending: classification is only
/// valid while the bucket stays stable until the flush.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
fn batch_affine_add(
    buckets: &mut [G1Affine],
    scratch: &mut BatchAffineScratch,
    index: usize,
    point: G1Affine,
) {
    debug_assert!(!scratch.bucket_pending[index]);
    let bucket = buckets[index];
    if bucket.infinity {
        buckets[index] = point;
        return;
    }
    let (denom, double) = if bucket.x == point.x {
        if bucket.y != point.y {
            // Only two curve points share an x, so this is P + (-P).
            buckets[index] = G1_AFFINE_IDENTITY;
            return;
        }
        // E(Fp) has odd prime order, so no 2-torsion: y != 0.
        (bucket.y.double(), true)
    } else {
        (point.x - bucket.x, false)
    };
    scratch.pending_bucket.push(index as u32);
    scratch.pending_point.push(point);
    scratch.pending_double.push(double);
    scratch.denom.push(denom);
    scratch.bucket_pending[index] = true;
}

/// Apply every pending affine add with one batch inversion.
///
/// Validated points make each denominator nonzero. A zero product can only
/// come from an invalid typed point. That case uses complete projective adds
/// so the unchecked internal API does not panic.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
fn batch_affine_flush(buckets: &mut [G1Affine], scratch: &mut BatchAffineScratch) {
    let count = scratch.pending_bucket.len();
    if count == 0 {
        return;
    }
    scratch.prefix.clear();
    let mut product = Fp::ONE;
    for denom in &scratch.denom {
        scratch.prefix.push(product);
        product *= *denom;
    }
    let Some(mut inverse) = invert_fp_vartime(product) else {
        for i in 0..count {
            let index = scratch.pending_bucket[i] as usize;
            let sum = buckets[index]
                .to_curve()
                .add_mixed(scratch.pending_point[i]);
            buckets[index] = projective_to_affine_vartime(sum);
            scratch.bucket_pending[index] = false;
        }
        scratch.pending_bucket.clear();
        scratch.pending_point.clear();
        scratch.pending_double.clear();
        scratch.denom.clear();
        return;
    };
    for i in (0..count).rev() {
        let denom_inverse = inverse * scratch.prefix[i];
        inverse *= scratch.denom[i];
        let index = scratch.pending_bucket[i] as usize;
        let bucket = buckets[index];
        let point = scratch.pending_point[i];
        let (lambda, x_sum) = if scratch.pending_double[i] {
            let x2 = bucket.x.square();
            ((x2 + x2 + x2) * denom_inverse, bucket.x.double())
        } else {
            ((point.y - bucket.y) * denom_inverse, bucket.x + point.x)
        };
        // Never the identity: distinct x rules out P + (-P), and odd group
        // order rules out 2P = O.
        let x3 = lambda.square() - x_sum;
        buckets[index] = G1Affine {
            x: x3,
            y: lambda * (bucket.x - x3) - bucket.y,
            infinity: false,
        };
        scratch.bucket_pending[index] = false;
    }
    scratch.pending_bucket.clear();
    scratch.pending_point.clear();
    scratch.pending_double.clear();
    scratch.denom.clear();
}

/// One window of bucket accumulation into affine buckets: affine+affine adds
/// cost 5M+1S plus an amortized share of one batch inversion per
/// [`BATCH_AFFINE_FLUSH`] adds, versus 8M+3S for a Jacobian mixed add.
/// Conflict policy: an add whose bucket already has a pending add goes into
/// that bucket's Jacobian overflow slot via a plain mixed add, so the dense
/// case (many terms per bucket per flush) degrades to exactly the scalar
/// path's cost instead of queue churn.
// The window state (buckets, overflow, scratch) is deliberately unbundled:
// the accumulate-fn signature is shared across the three tier variants.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
fn accumulate_window_batch_affine(
    buckets: &mut [G1Affine],
    overflow: &mut [G1Projective],
    scratch: &mut BatchAffineScratch,
    terms: &mut [GlvTerm],
    width: usize,
    mask: u128,
    half: u128,
    radix: u128,
) {
    for term in terms {
        let digit = next_signed_digit(&mut term.scalar, &mut term.carry, width, mask, half, radix);
        if digit == 0 {
            continue;
        }
        let mut point = term.point;
        if digit < 0 {
            point = -point;
        }
        let index = digit.unsigned_abs() as usize - 1;
        if scratch.bucket_pending[index] {
            overflow[index] = overflow[index].add_mixed(point);
            continue;
        }
        batch_affine_add(buckets, scratch, index, point);
        if scratch.pending_bucket.len() == BATCH_AFFINE_FLUSH {
            batch_affine_flush(buckets, scratch);
        }
    }
    batch_affine_flush(buckets, scratch);
    debug_assert!(scratch.bucket_pending.iter().all(|pending| !pending));
}

/// Signed Pippenger with batch-affine bucket accumulation.  Identical
/// schedule to [`msm_signed_pippenger_with`]; only the bucket representation
/// (affine + Jacobian overflow slot) and the per-add cost differ, and the
/// window reduction's running accumulator gets mixed adds for free.
#[cfg(any(test, not(all(helius_avx512_ifma, not(feature = "force-portable")))))]
fn msm_signed_pippenger_batch_affine(
    points: &[G1Affine],
    scalars: &[[u64; 4]],
    width: usize,
) -> G1Projective {
    let mut terms = glv_terms(points, scalars);
    if terms.is_empty() {
        return G1Projective::identity();
    }

    let windows = 127usize.div_ceil(width);
    let half = 1usize << (width - 1);
    let radix = 1u128 << width;
    let mask = radix - 1;

    let mut buckets = vec![G1_AFFINE_IDENTITY; half];
    let mut overflow = vec![G1_PROJECTIVE_IDENTITY; half];
    let mut scratch = BatchAffineScratch::new(half);
    let mut window_sums = vec![G1Projective::identity(); windows];
    for (window, sum_slot) in window_sums.iter_mut().enumerate() {
        if window != 0 {
            buckets.fill(G1_AFFINE_IDENTITY);
            overflow.fill(G1_PROJECTIVE_IDENTITY);
        }
        accumulate_window_batch_affine(
            &mut buckets,
            &mut overflow,
            &mut scratch,
            &mut terms,
            width,
            mask,
            half as u128,
            radix,
        );
        let mut running = G1Projective::identity();
        let mut sum = G1Projective::identity();
        for (bucket, slot) in buckets.iter().zip(overflow.iter()).rev() {
            running = running.add_mixed(*bucket);
            if !slot.is_identity() {
                running = running + *slot;
            }
            sum = sum + running;
        }
        *sum_slot = sum;
    }
    debug_assert!(terms.iter().all(|term| term.scalar == 0 && term.carry == 0));

    let mut result = G1Projective::identity();
    for window in (0..windows).rev() {
        if window != windows - 1 {
            for _ in 0..width {
                result = result.double();
            }
        }
        result = result + window_sums[window];
    }
    result
}

fn glv_terms(points: &[G1Affine], scalars: &[[u64; 4]]) -> Vec<GlvTerm> {
    let mut terms = Vec::with_capacity(points.len() * 2);
    for (point, scalar) in points.iter().zip(scalars) {
        if point.infinity {
            continue;
        }
        let (k1, k2) = decompose_scalar(*scalar);
        push_term(&mut terms, *point, k1);
        push_term(&mut terms, endomorphism_affine(*point), k2);
    }
    terms
}

fn msm_signed_pippenger_with<F>(
    points: &[G1Affine],
    scalars: &[[u64; 4]],
    width: usize,
    mut accumulate: F,
) -> G1Projective
where
    F: FnMut(&mut [G1Projective], &mut [GlvTerm], usize, u128, u128, u128),
{
    let mut terms = glv_terms(points, scalars);
    if terms.is_empty() {
        return G1Projective::identity();
    }

    let windows = 127usize.div_ceil(width);
    let half = 1usize << (width - 1);
    let radix = 1u128 << width;
    let mask = radix - 1;

    // Balanced radix-2^w digits halve the bucket table.  Accumulation is
    // window-major so a single L1-resident bucket window is reused for every
    // window; the terms (with their per-term recoding carry) are re-streamed
    // once per window.  Recoding proceeds from low to high because each
    // digit's carry is consumed by the next window.
    let mut buckets = vec![G1Projective::identity(); half];
    let mut window_sums = vec![G1Projective::identity(); windows];
    for (window, sum_slot) in window_sums.iter_mut().enumerate() {
        if window != 0 {
            for bucket in &mut buckets {
                *bucket = G1Projective::identity();
            }
        }
        accumulate(&mut buckets, &mut terms, width, mask, half as u128, radix);
        let mut running = G1Projective::identity();
        let mut sum = G1Projective::identity();
        for bucket in buckets.iter().rev() {
            running = running + *bucket;
            sum = sum + running;
        }
        *sum_slot = sum;
    }
    debug_assert!(terms.iter().all(|term| term.scalar == 0 && term.carry == 0));

    let mut result = G1Projective::identity();
    for window in (0..windows).rev() {
        if window != windows - 1 {
            for _ in 0..width {
                result = result.double();
            }
        }
        result = result + window_sums[window];
    }
    result
}

#[inline(always)]
fn next_signed_digit(
    scalar: &mut u128,
    carry: &mut u128,
    width: usize,
    mask: u128,
    half: u128,
    radix: u128,
) -> i16 {
    let value = (*scalar & mask) + *carry;
    *scalar >>= width;
    // Keep the exact half-radix tie positive.  Besides avoiding a needless
    // carry, this guarantees that ceil(127 / width) windows consume every
    // scalar below 2^127 even when the final window has w-1 meaningful bits.
    if value > half {
        *carry = 1;
        value as i16 - radix as i16
    } else {
        *carry = 0;
        value as i16
    }
}

#[inline]
fn pippenger_width(n: usize) -> usize {
    match n {
        0..=7 => 3,
        8..=23 => 4,
        24..=95 => 5,
        96..=191 => 6,
        192..=383 => 7,
        384..=1_535 => 8,
        _ => 10,
    }
}

#[inline(always)]
fn push_term(terms: &mut Vec<GlvTerm>, mut point: G1Affine, scalar: SignedScalar) {
    if scalar.magnitude == 0 {
        return;
    }
    if scalar.negative {
        point = -point;
    }
    terms.push(GlvTerm {
        point,
        scalar: scalar.magnitude,
        carry: 0,
    });
}

#[inline(always)]
fn endomorphism_affine(mut point: G1Affine) -> G1Affine {
    if !point.infinity {
        point.x *= BETA_MONT;
    }
    point
}

/// Convert arbitrary Jacobian points with one inversion.  Retained for the
/// baseline differential oracle; the live small-MSM path rescales to a shared
/// Z instead and needs no inversion.  The `expect` is unreachable: only the
/// nonzero `z` of non-identity points enter the product, and Fp is a field.
#[cfg(test)]
fn batch_to_affine_into(points: &[G1Projective], prefix: &mut [Fp], output: &mut [G1Affine]) {
    debug_assert_eq!(points.len(), prefix.len());
    debug_assert_eq!(points.len(), output.len());
    let mut product = Fp::ONE;
    let mut nonzero = 0usize;
    for (point, slot) in points.iter().zip(prefix.iter_mut()) {
        *slot = product;
        if !point.is_identity() {
            product *= point.z;
            nonzero += 1;
        }
    }
    if nonzero == 0 {
        output.fill(G1_AFFINE_IDENTITY);
        return;
    }

    let mut inverse =
        invert_fp_vartime(product).expect("product of nonzero projective z coordinates is nonzero");
    for i in (0..points.len()).rev() {
        let point = points[i];
        if point.is_identity() {
            output[i] = G1_AFFINE_IDENTITY;
            continue;
        }
        let z_inverse = inverse * prefix[i];
        inverse *= point.z;
        let z_inverse_2 = z_inverse.square();
        output[i] = G1Affine {
            x: point.x * z_inverse_2,
            y: point.y * z_inverse_2 * z_inverse,
            infinity: false,
        };
    }
}

/// Single-point affine conversion with one variable-time inversion.
fn projective_to_affine_vartime(point: G1Projective) -> G1Affine {
    if point.is_identity() {
        return G1Affine::identity();
    }
    if point.z == Fp::ONE {
        return G1Affine {
            x: point.x,
            y: point.y,
            infinity: false,
        };
    }
    let Some(z_inverse) = invert_fp_vartime(point.z) else {
        return G1Affine::identity();
    };
    let z_inverse_2 = z_inverse.square();
    G1Affine {
        x: point.x * z_inverse_2,
        y: point.y * z_inverse_2 * z_inverse,
        infinity: false,
    }
}

/// Public-input-only variable-time inversion; per-arch dispatch between the
/// Kaliski and divsteps paths lives in [`Fp::invert`].
fn invert_fp_vartime(value: Fp) -> Option<Fp> {
    value.invert()
}

/// Bit-serial binary extended GCD kept as the differential-test oracle for
/// [`invert_fp_vartime`].
#[cfg(test)]
fn invert_fp_vartime_reference(value: Fp) -> Option<Fp> {
    let mut u = value.to_raw();
    if limbs_are_zero(&u) {
        return None;
    }
    let mut v = BASE_MODULUS;
    let mut x1 = [1u64, 0, 0, 0];
    let mut x2 = [0u64; 4];

    while !limbs_are_one(&u) && !limbs_are_one(&v) {
        while u[0] & 1 == 0 {
            shift_right_one(&mut u, 0);
            half_mod_p(&mut x1);
        }
        while v[0] & 1 == 0 {
            shift_right_one(&mut v, 0);
            half_mod_p(&mut x2);
        }
        if cmp_limbs(&u, &v).is_ge() {
            (u, _) = sub_wide(u, v);
            x1 = sub_mod_p(x1, x2);
        } else {
            (v, _) = sub_wide(v, u);
            x2 = sub_mod_p(x2, x1);
        }
    }
    let inverse = if limbs_are_one(&u) { x1 } else { x2 };
    Some(Fp::from_raw(inverse))
}

#[cfg(test)]
#[inline(always)]
fn limbs_are_zero(value: &[u64; 4]) -> bool {
    value[0] | value[1] | value[2] | value[3] == 0
}

#[cfg(test)]
#[inline(always)]
fn limbs_are_one(value: &[u64; 4]) -> bool {
    value[0] == 1 && value[1] | value[2] | value[3] == 0
}

#[cfg(test)]
#[inline(always)]
fn shift_right_one(value: &mut [u64; 4], high_bit: u64) {
    let mut carry = high_bit << 63;
    for limb in value.iter_mut().rev() {
        let next = *limb << 63;
        *limb = (*limb >> 1) | carry;
        carry = next;
    }
}

#[cfg(test)]
#[inline(always)]
fn half_mod_p(value: &mut [u64; 4]) {
    if value[0] & 1 == 0 {
        shift_right_one(value, 0);
        return;
    }
    let mut carry = 0u64;
    for i in 0..4 {
        let (sum, c1) = value[i].overflowing_add(BASE_MODULUS[i]);
        let (sum, c2) = sum.overflowing_add(carry);
        value[i] = sum;
        carry = (c1 | c2) as u64;
    }
    shift_right_one(value, carry);
}

#[cfg(test)]
#[inline(always)]
fn sub_mod_p(left: [u64; 4], right: [u64; 4]) -> [u64; 4] {
    let (mut difference, borrow) = sub_wide(left, right);
    if borrow != 0 {
        let mut carry = 0u64;
        for i in 0..4 {
            let (sum, c1) = difference[i].overflowing_add(BASE_MODULUS[i]);
            let (sum, c2) = sum.overflowing_add(carry);
            difference[i] = sum;
            carry = (c1 | c2) as u64;
        }
    }
    difference
}

/// Babai nearest-plane split: `k = k1 + lambda*k2 (mod r)`.
fn decompose_scalar(k: [u64; 4]) -> (SignedScalar, SignedScalar) {
    debug_assert!(cmp_limbs(&k, &SCALAR_MODULUS).is_lt());

    let q1 = rounded_mul_div_r(k, BASIS_11_ABS, RECIP_BASIS_11);
    let q2 = rounded_mul_div_r(k, [BASIS_01_ABS, 0], RECIP_BASIS_01);
    let q1_limbs = [q1 as u64, (q1 >> 64) as u64];
    let q2_limbs = [q2 as u64, (q2 >> 64) as u64];

    // k1 = k - (q1*B00 + q2*|B01|)
    let mut b1 = mul_wide::<2, 2, 4>(&q1_limbs, &BASIS_00);
    let q2_small = mul_wide::<2, 1, 3>(&q2_limbs, &[BASIS_01_ABS]);
    add_assign_wide(&mut b1, &q2_small);
    let k1 = signed_difference(&k, &b1);

    // k2 = q1*|B01| - q2*|B11|
    let q1_small = mul_wide::<2, 1, 3>(&q1_limbs, &[BASIS_01_ABS]);
    let q2_large = mul_wide::<2, 2, 4>(&q2_limbs, &BASIS_11_ABS);
    let mut q1_small_4 = [0u64; 4];
    q1_small_4[..3].copy_from_slice(&q1_small);
    let k2 = signed_difference(&q1_small_4, &q2_large);

    // Hard bound: the wNAF recoder's window count assumes < 2^127 components.
    assert!(
        k1.magnitude < (1u128 << 127),
        "GLV k1 exceeds lattice bound"
    );
    assert!(
        k2.magnitude < (1u128 << 127),
        "GLV k2 exceeds lattice bound"
    );
    (k1, k2)
}

#[cfg(test)]
/// Test-only observation point for source-fidelity audits of the private GLV
/// split. Exact `cfg(test)` keeps it out of release source and codegen metrics.
pub(crate) fn audit_decompose_scalar(k: [u64; 4]) -> ((bool, u128), (bool, u128)) {
    let (k1, k2) = decompose_scalar(k);
    ((k1.negative, k1.magnitude), (k2.negative, k2.magnitude))
}

fn rounded_mul_div_r(k: [u64; 4], coefficient: [u64; 2], reciprocal: [u64; 3]) -> u128 {
    let reciprocal_product = mul_wide::<4, 3, 7>(&k, &reciprocal);
    debug_assert_eq!(reciprocal_product[6], 0);
    let mut quotient = reciprocal_product[4] as u128 | ((reciprocal_product[5] as u128) << 64);

    let numerator = mul_wide::<4, 2, 6>(&k, &coefficient);
    let quotient_limbs = [quotient as u64, (quotient >> 64) as u64];
    let quotient_product = mul_wide::<2, 4, 6>(&quotient_limbs, &SCALAR_MODULUS);
    let (mut remainder, borrow) = sub_wide(numerator, quotient_product);
    debug_assert_eq!(borrow, 0);

    let modulus = padded_6(SCALAR_MODULUS);
    if cmp_limbs(&remainder, &modulus).is_ge() {
        (remainder, _) = sub_wide(remainder, modulus);
        quotient += 1;
    }
    if cmp_limbs(&remainder, &padded_6(HALF_SCALAR_MODULUS_CEIL)).is_ge() {
        quotient += 1;
    }
    quotient
}

#[inline(always)]
fn padded_6(value: [u64; 4]) -> [u64; 6] {
    [value[0], value[1], value[2], value[3], 0, 0]
}

fn signed_difference(left: &[u64; 4], right: &[u64; 4]) -> SignedScalar {
    let (negative, magnitude) = if cmp_limbs(left, right).is_lt() {
        let (magnitude, borrow) = sub_wide(*right, *left);
        debug_assert_eq!(borrow, 0);
        (true, magnitude)
    } else {
        let (magnitude, borrow) = sub_wide(*left, *right);
        debug_assert_eq!(borrow, 0);
        (false, magnitude)
    };
    // Hard assert: silently dropping high limbs would be a consensus-divergent
    // wrong MSM result if the Babai bound were ever broken by a constant edit.
    assert_eq!(
        magnitude[2] | magnitude[3],
        0,
        "GLV component exceeds 128 bits"
    );
    SignedScalar {
        magnitude: magnitude[0] as u128 | ((magnitude[1] as u128) << 64),
        negative,
    }
}

#[inline]
fn cmp_limbs<const N: usize>(left: &[u64; N], right: &[u64; N]) -> core::cmp::Ordering {
    for i in (0..N).rev() {
        match left[i].cmp(&right[i]) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

fn sub_wide<const N: usize>(left: [u64; N], right: [u64; N]) -> ([u64; N], u64) {
    let mut output = [0u64; N];
    let mut borrow = 0u64;
    for i in 0..N {
        let (a, b1) = left[i].overflowing_sub(right[i]);
        let (b, b2) = a.overflowing_sub(borrow);
        output[i] = b;
        borrow = (b1 | b2) as u64;
    }
    (output, borrow)
}

fn add_assign_wide<const N: usize, const M: usize>(left: &mut [u64; N], right: &[u64; M]) {
    let mut carry = 0u64;
    for i in 0..N {
        let rhs = if i < M { right[i] } else { 0 };
        let (a, c1) = left[i].overflowing_add(rhs);
        let (b, c2) = a.overflowing_add(carry);
        left[i] = b;
        carry = (c1 | c2) as u64;
    }
    debug_assert_eq!(carry, 0);
}

/// Schoolbook multiplication into an explicitly-sized little-endian output.
fn mul_wide<const A: usize, const B: usize, const O: usize>(
    left: &[u64; A],
    right: &[u64; B],
) -> [u64; O] {
    debug_assert!(O >= A + B);
    let mut output = [0u64; O];
    for i in 0..A {
        let mut carry = 0u64;
        for j in 0..B {
            let value =
                (left[i] as u128) * (right[j] as u128) + (output[i + j] as u128) + (carry as u128);
            output[i + j] = value as u64;
            carry = (value >> 64) as u64;
        }
        let mut index = i + B;
        while carry != 0 {
            let (value, overflow) = output[index].overflowing_add(carry);
            output[index] = value;
            carry = overflow as u64;
            index += 1;
        }
    }
    output
}

/// Independent baseline (heap-allocated joint wNAF with crossover at n=8,
/// term-major Pippenger): the differential oracle and A/B reference for the
/// production path.
#[cfg(test)]
mod baseline {
    use super::*;
    use core::ops::{Add, Neg};

    pub(super) fn msm_variable_time_old(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        debug_assert_eq!(points.len(), scalars.len());
        if points.is_empty() {
            return G1Projective::identity();
        }
        if points.len() <= 8 {
            msm_joint_wnaf_old(points, scalars)
        } else {
            msm_signed_pippenger_old(points, scalars)
        }
    }

    fn msm_joint_wnaf_old(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        const WIDTH: usize = 5;
        const TABLE_SIZE: usize = 1 << (WIDTH - 2);

        let mut decomposed = Vec::with_capacity(points.len());
        let mut tables_projective = Vec::with_capacity(points.len() * TABLE_SIZE);

        for (point, scalar) in points.iter().zip(scalars) {
            decomposed.push(decompose_scalar(*scalar));
            if point.infinity {
                tables_projective.extend((0..TABLE_SIZE).map(|_| G1Projective::identity()));
                continue;
            }

            let mut odd = point.to_curve();
            let two = odd.double();
            tables_projective.push(odd);
            for _ in 1..TABLE_SIZE {
                odd = odd.add(two);
                tables_projective.push(odd);
            }
        }

        let mut prefix = vec![Fp::ZERO; tables_projective.len()];
        let mut tables = vec![G1Affine::identity(); tables_projective.len()];
        batch_to_affine_into(&tables_projective, &mut prefix, &mut tables);
        let endomorphism_tables: Vec<_> = tables.iter().copied().map(endomorphism_affine).collect();

        let mut digits = Vec::with_capacity(points.len());
        let mut max_len = 0usize;
        for (k1, k2) in &decomposed {
            let (d1, n1) = recode_u128::<WIDTH, 129>(k1.magnitude);
            let (d2, n2) = recode_u128::<WIDTH, 129>(k2.magnitude);
            max_len = max_len.max(n1).max(n2);
            digits.push((d1, d2));
        }

        let mut acc = G1Projective::identity();
        for bit in (0..max_len).rev() {
            acc = acc.double();
            for i in 0..points.len() {
                let table_offset = i * TABLE_SIZE;
                acc = add_wnaf_digit(
                    acc,
                    &tables[table_offset..table_offset + TABLE_SIZE],
                    digits[i].0.digit(bit),
                    decomposed[i].0.negative,
                );
                acc = add_wnaf_digit(
                    acc,
                    &endomorphism_tables[table_offset..table_offset + TABLE_SIZE],
                    digits[i].1.digit(bit),
                    decomposed[i].1.negative,
                );
            }
        }
        acc
    }

    fn msm_signed_pippenger_old(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        let mut terms = Vec::with_capacity(points.len() * 2);
        for (point, scalar) in points.iter().zip(scalars) {
            if point.infinity {
                continue;
            }
            let (k1, k2) = decompose_scalar(*scalar);
            push_term(&mut terms, *point, k1);
            push_term(&mut terms, endomorphism_affine(*point), k2);
        }
        if terms.is_empty() {
            return G1Projective::identity();
        }

        let width = pippenger_width(points.len());
        let windows = 127usize.div_ceil(width);
        let half = 1usize << (width - 1);
        let radix = 1u128 << width;
        let mask = radix - 1;
        let mut buckets = vec![G1Projective::identity(); windows * half];

        for term in terms {
            let mut scalar = term.scalar;
            let mut carry = 0u128;
            for window in 0..windows {
                let digit =
                    next_signed_digit(&mut scalar, &mut carry, width, mask, half as u128, radix);
                if digit != 0 {
                    let mut point = term.point;
                    if digit < 0 {
                        point = point.neg();
                    }
                    let index = window * half + digit.unsigned_abs() as usize - 1;
                    buckets[index] = buckets[index].add_mixed(point);
                }
            }
            debug_assert_eq!(scalar, 0);
            debug_assert_eq!(carry, 0);
        }

        let mut result = G1Projective::identity();
        for window in (0..windows).rev() {
            if window != windows - 1 {
                for _ in 0..width {
                    result = result.double();
                }
            }
            let mut running = G1Projective::identity();
            let window_buckets = &buckets[window * half..(window + 1) * half];
            for bucket in window_buckets.iter().rev() {
                running = running.add(*bucket);
                result = result.add(running);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Fr;
    use core::ops::{Add, Mul, Neg};

    /// Forced-scalar window accumulation, for A/B against the IFMA path.
    fn msm_signed_pippenger_scalar(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        msm_signed_pippenger_with(
            points,
            scalars,
            pippenger_width(points.len()),
            accumulate_window_scalar,
        )
    }

    fn scalar_mul_signed(point: G1Projective, scalar: SignedScalar) -> G1Projective {
        let limbs = [
            scalar.magnitude as u64,
            (scalar.magnitude >> 64) as u64,
            0,
            0,
        ];
        let result = point.mul(Fr::from_raw(limbs));
        if scalar.negative {
            result.neg()
        } else {
            result
        }
    }

    fn reference(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        points
            .iter()
            .zip(scalars)
            .fold(G1Projective::identity(), |acc, (point, scalar)| {
                acc.add(point.to_curve().mul(Fr::from_raw(*scalar)))
            })
    }

    fn scalar_stream(count: usize) -> Vec<[u64; 4]> {
        let mut state = 0x6a09_e667_f3bc_c909u64;
        (0..count)
            .map(|_| {
                let mut limbs = [0u64; 4];
                for limb in &mut limbs {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *limb = state;
                }
                while cmp_limbs(&limbs, &SCALAR_MODULUS).is_ge() {
                    (limbs, _) = sub_wide(limbs, SCALAR_MODULUS);
                }
                limbs
            })
            .collect()
    }

    /// First-principles regeneration of the GLV constants: beta is a
    /// primitive cube root of unity in Fp, both basis rows lie in the lattice
    /// `{(a, b) : a + b*lambda = 0 mod r}` for `lambda = B00/|B01| mod r`
    /// with `lambda^2 + lambda + 1 = 0 mod r`, and the endomorphism
    /// `(x, y) -> (beta*x, y)` acts on G1 as `[lambda]`.
    #[test]
    fn glv_constants_satisfy_defining_identities() {
        let beta = BETA_MONT;
        assert_ne!(beta, Fp::ONE);
        assert_eq!(beta * beta * beta, Fp::ONE);
        assert_eq!(beta * beta + beta + Fp::ONE, Fp::ZERO);

        let fr2 = |limbs: [u64; 2]| Fr::from_raw([limbs[0], limbs[1], 0, 0]);
        let (b00, b01, b11) = (fr2(BASIS_00), fr2([BASIS_01_ABS, 0]), fr2(BASIS_11_ABS));
        // |B01| is a fixed nonzero lattice constant, so the inverse exists.
        let lambda = b00 * b01.invert().unwrap();
        assert_eq!(lambda * lambda + lambda + Fr::ONE, Fr::ZERO);
        assert_eq!(b00 - b01 * lambda, Fr::ZERO); // v1 = (B00, -|B01|)
        assert_eq!(b01 + b11 * lambda, Fr::ZERO); // v2 = (|B01|, |B11|)

        let generator = G1Affine::generator();
        assert_eq!(
            endomorphism_affine(generator).to_curve().to_affine(),
            generator.to_curve().mul(lambda).to_affine()
        );
    }

    /// `RECIP = floor(c*2^256 / r)` exactly: `RECIP*r <= c*2^256` and the
    /// remainder is below `r`. Independent multiply-compare recomputation of
    /// the const long division.
    #[test]
    fn glv_fixed_point_reciprocals_are_exact_floors() {
        for (coefficient, reciprocal) in [
            (BASIS_11_ABS, RECIP_BASIS_11),
            ([BASIS_01_ABS, 0], RECIP_BASIS_01),
        ] {
            let product = mul_wide::<3, 4, 7>(&reciprocal, &SCALAR_MODULUS);
            let shifted = [0, 0, 0, 0, coefficient[0], coefficient[1], 0];
            let (remainder, borrow) = sub_wide(shifted, product);
            assert_eq!(borrow, 0);
            let modulus_7 = [
                SCALAR_MODULUS[0],
                SCALAR_MODULUS[1],
                SCALAR_MODULUS[2],
                SCALAR_MODULUS[3],
                0,
                0,
                0,
            ];
            assert!(cmp_limbs(&remainder, &modulus_7).is_lt());
        }
    }

    #[test]
    fn endomorphism_and_decomposition_reconstruct_scalars() {
        let generator = G1Affine::generator();
        let cases = [
            vec![
                [0, 0, 0, 0],
                [1, 0, 0, 0],
                [u64::MAX, 0, 0, 0],
                HALF_SCALAR_MODULUS_CEIL,
                [
                    SCALAR_MODULUS[0] - 1,
                    SCALAR_MODULUS[1],
                    SCALAR_MODULUS[2],
                    SCALAR_MODULUS[3],
                ],
            ],
            scalar_stream(64),
        ]
        .concat();
        for scalar in cases {
            let expected = generator.to_curve().mul(Fr::from_raw(scalar));
            let (k1, k2) = decompose_scalar(scalar);
            let actual = scalar_mul_signed(generator.to_curve(), k1).add(scalar_mul_signed(
                endomorphism_affine(generator).to_curve(),
                k2,
            ));
            assert_eq!(
                actual.to_affine(),
                expected.to_affine(),
                "scalar={scalar:x?}"
            );
        }
    }

    #[test]
    fn msm_matches_independent_scalar_multiplication() {
        let source_scalars = scalar_stream(96);
        let points: Vec<_> = source_scalars
            .iter()
            .map(|scalar| {
                G1Projective::generator()
                    .mul(Fr::from_raw(*scalar))
                    .to_affine()
            })
            .collect();
        let msm_scalars = scalar_stream(96).into_iter().rev().collect::<Vec<_>>();

        for n in [1, 2, 4, 8, 9, 16, 32, 64, 96] {
            let expected = reference(&points[..n], &msm_scalars[..n]).to_affine();
            let actual = msm_variable_time(&points[..n], &msm_scalars[..n]).to_affine();
            assert_eq!(actual, expected, "MSM n={n}");
        }
    }

    #[test]
    fn infinity_and_zero_terms_are_neutral() {
        let points = [G1Affine::identity(), G1Affine::generator()];
        let scalars = [[u64::MAX, 0, 0, 0], [0, 0, 0, 0]];
        assert!(msm_variable_time(&points, &scalars).is_identity());
    }

    /// Fermat oracle `a^{p-2}`, independent of both GCD implementations.
    fn invert_fp_fermat(value: Fp) -> Option<Fp> {
        if value.is_zero() {
            return None;
        }
        Some(value.pow_raw(&[
            0x3c208c16d87cfd45, // p - 2
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]))
    }

    fn base_field_stream(count: usize, seed: u64) -> Vec<[u64; 4]> {
        use rand::{RngCore, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(seed);
        (0..count)
            .map(|_| {
                let mut limbs = [0u64; 4];
                for limb in &mut limbs {
                    *limb = rng.next_u64();
                }
                limbs[3] &= (1 << 62) - 1;
                while cmp_limbs(&limbs, &BASE_MODULUS).is_ge() {
                    (limbs, _) = sub_wide(limbs, BASE_MODULUS);
                }
                limbs
            })
            .collect()
    }

    fn fp_inverse_edge_cases() -> Vec<[u64; 4]> {
        let mut cases = Vec::new();
        for small in 1u64..=64 {
            cases.push([small, 0, 0, 0]);
            let mut near_top = BASE_MODULUS;
            near_top[0] -= small;
            cases.push(near_top);
        }
        for bit in 0..254 {
            let mut power = [0u64; 4];
            power[bit / 64] = 1 << (bit % 64);
            cases.push(power);
            // Many trailing zeros with a non-trivial high part.
            if bit >= 64 {
                let mut shifted = power;
                shifted[3] |= 1 << 61;
                cases.push(shifted);
            }
        }
        cases.push([u64::MAX, u64::MAX, u64::MAX, (1 << 62) - 1]);
        cases.push([
            0xaaaa_aaaa_aaaa_aaaa,
            0xaaaa_aaaa_aaaa_aaaa,
            0xaaaa_aaaa_aaaa_aaaa,
            0x2aaa_aaaa_aaaa_aaaa,
        ]);
        cases.push([
            0x5555_5555_5555_5555,
            0x5555_5555_5555_5555,
            0x5555_5555_5555_5555,
            0x1555_5555_5555_5555,
        ]);
        cases
            .into_iter()
            .map(|mut limbs| {
                while cmp_limbs(&limbs, &BASE_MODULUS).is_ge() {
                    (limbs, _) = sub_wide(limbs, BASE_MODULUS);
                }
                limbs
            })
            .filter(|limbs| limbs.iter().any(|&limb| limb != 0))
            .collect()
    }

    #[test]
    fn variable_time_fp_inverse_matches_bit_serial_and_fermat_oracles() {
        assert_eq!(invert_fp_vartime(Fp::ZERO), None);
        assert_eq!(invert_fp_vartime_reference(Fp::ZERO), None);
        let mut values = vec![Fp::ONE, Fp::from_u64(2), Fp::from_u64(u64::MAX)];
        values.extend(fp_inverse_edge_cases().into_iter().map(Fp::from_raw));
        values.extend(
            scalar_stream(64)
                .into_iter()
                .map(Fp::from_raw)
                .filter(|value| !value.is_zero()),
        );
        for value in values {
            let inverse = invert_fp_vartime(value).expect("nonzero");
            assert_eq!(
                inverse,
                invert_fp_vartime_reference(value).expect("nonzero")
            );
            assert_eq!(inverse, invert_fp_fermat(value).expect("nonzero"));
            assert_eq!(value.invert_divsteps(), Some(inverse));
            assert_eq!(value.invert_kaliski(), Some(inverse));
            assert_eq!(value * inverse, Fp::ONE);
        }
    }

    #[test]
    fn variable_time_fp_inverse_matches_reference_on_random_stream() {
        let count = if cfg!(debug_assertions) {
            10_000
        } else {
            100_000
        };
        for limbs in base_field_stream(count, 0xf0f0_1234_5678_9abc) {
            let value = Fp::from_raw(limbs);
            if value.is_zero() {
                continue;
            }
            let inverse = invert_fp_vartime(value).expect("nonzero");
            assert_eq!(
                inverse,
                invert_fp_vartime_reference(value).expect("nonzero"),
                "limbs={limbs:x?}"
            );
            assert_eq!(value.invert_divsteps(), Some(inverse), "limbs={limbs:x?}");
            assert_eq!(value.invert_kaliski(), Some(inverse), "limbs={limbs:x?}");
        }
    }

    #[test]
    fn variable_time_fp_inverse_roundtrips_random_values() {
        for limbs in base_field_stream(10_000, 0x5eed_cafe_f00d_0001) {
            let value = Fp::from_raw(limbs);
            if value.is_zero() {
                continue;
            }
            let inverse = invert_fp_vartime(value).expect("nonzero");
            assert_eq!(value * inverse, Fp::ONE, "limbs={limbs:x?}");
        }
    }

    #[test]
    #[ignore = "manual latency microbenchmark: cargo test --release -- --ignored micro --nocapture"]
    fn invert_fp_micro_latency() {
        use std::hint::black_box;
        use std::time::Instant;

        let values: Vec<Fp> = scalar_stream(4096)
            .into_iter()
            .map(Fp::from_raw)
            .filter(|value| !value.is_zero())
            .collect();

        let rounds = 64usize;
        let measure = |name: &str, invert: &dyn Fn(Fp) -> Option<Fp>| {
            let mut acc = 0u64;
            for value in &values {
                acc ^= invert(black_box(*value)).unwrap().0[0];
            }
            let start = Instant::now();
            for _ in 0..rounds {
                for value in &values {
                    acc ^= invert(black_box(*value)).unwrap().0[0];
                }
            }
            let elapsed = start.elapsed();
            std::println!(
                "{name}: {:.1} ns/op (acc={acc})",
                elapsed.as_nanos() as f64 / (rounds * values.len()) as f64
            );
        };
        measure("fp invert divsteps (word-level gcd)", &|value: Fp| {
            value.invert_divsteps()
        });
        measure("fp invert kaliski (mont domain)", &|value: Fp| {
            value.invert_kaliski()
        });
        measure(
            "fp invert_fp_vartime_reference (bit-serial)",
            &invert_fp_vartime_reference,
        );
    }

    /// Small-n path without the shared-Z rescale: co-Z tables normalized by
    /// one batch inversion, endo tables copied, plus the final conversion's
    /// second inversion.  Interleaved A/B reference attributing the
    /// shared-Z gain.
    fn msm_joint_wnaf_prev<const CAP: usize, const CAP_TABLES: usize>(
        points: &[G1Affine],
        scalars: &[[u64; 4]],
    ) -> G1Projective {
        let n = points.len();
        assert!(n != 0 && n <= CAP);

        let mut decomposed = [(SignedScalar::ZERO, SignedScalar::ZERO); CAP];
        let mut tables_projective = [G1_PROJECTIVE_IDENTITY; CAP_TABLES];
        let mut dx_scratch = [Fp::ZERO; JOINT_TABLE];

        for (i, (point, scalar)) in points.iter().zip(scalars).enumerate() {
            decomposed[i] = decompose_scalar(*scalar);
            if point.infinity {
                continue;
            }
            fill_odd_multiples(
                *point,
                &mut tables_projective[i * JOINT_TABLE..(i + 1) * JOINT_TABLE],
                &mut dx_scratch[..JOINT_TABLE - 1],
            );
        }

        let used = n * JOINT_TABLE;
        let mut prefix = [Fp::ZERO; CAP_TABLES];
        let mut tables = [G1_AFFINE_IDENTITY; CAP_TABLES];
        batch_to_affine_into(
            &tables_projective[..used],
            &mut prefix[..used],
            &mut tables[..used],
        );
        let mut endomorphism_tables = tables;
        for entry in &mut endomorphism_tables[..used] {
            *entry = endomorphism_affine(*entry);
        }

        let mut digits = [(JointDigits::ZERO, JointDigits::ZERO); CAP];
        let mut max_len = 0usize;
        for (slot, (k1, k2)) in digits[..n].iter_mut().zip(&decomposed) {
            let (d1, n1) = recode_u128::<JOINT_WIDTH, 129>(k1.magnitude);
            let (d2, n2) = recode_u128::<JOINT_WIDTH, 129>(k2.magnitude);
            max_len = max_len.max(n1).max(n2);
            *slot = (d1, d2);
        }

        let mut acc = G1Projective::identity();
        for bit in (0..max_len).rev() {
            acc = acc.double();
            for i in 0..n {
                let table_offset = i * JOINT_TABLE;
                acc = add_wnaf_digit(
                    acc,
                    &tables[table_offset..table_offset + JOINT_TABLE],
                    digits[i].0.digit(bit),
                    decomposed[i].0.negative,
                );
                acc = add_wnaf_digit(
                    acc,
                    &endomorphism_tables[table_offset..table_offset + JOINT_TABLE],
                    digits[i].1.digit(bit),
                    decomposed[i].1.negative,
                );
            }
        }
        acc
    }

    fn msm_small_prev(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        match points.len() {
            1..=2 => msm_joint_wnaf_prev::<2, 16>(points, scalars),
            3..=4 => msm_joint_wnaf_prev::<4, 32>(points, scalars),
            5..=8 => msm_joint_wnaf_prev::<8, 64>(points, scalars),
            _ => unreachable!(),
        }
    }

    /// Experiment: n=1 GLV without affine tables (no batch inversion, full
    /// projective additions).  Measured against the affine-table path.
    fn msm_single_projective_tables(points: &[G1Affine], scalars: &[[u64; 4]]) -> G1Projective {
        assert_eq!(points.len(), 1);
        let point = points[0];
        if point.infinity {
            return G1Projective::identity();
        }
        let (k1, k2) = decompose_scalar(scalars[0]);

        let mut table = [G1_PROJECTIVE_IDENTITY; JOINT_TABLE];
        let mut odd = point.to_curve();
        let two = odd.double();
        table[0] = odd;
        for entry in &mut table[1..] {
            odd = odd.add(two);
            *entry = odd;
        }
        // Jacobian x = X/Z^2, so the endomorphism is X *= beta with Z fixed.
        let mut endo_table = table;
        for entry in &mut endo_table {
            entry.x *= BETA_MONT;
        }

        let (d1, n1) = recode_u128::<JOINT_WIDTH, 129>(k1.magnitude);
        let (d2, n2) = recode_u128::<JOINT_WIDTH, 129>(k2.magnitude);
        let max_len = n1.max(n2);

        let mut acc = G1Projective::identity();
        for bit in (0..max_len).rev() {
            acc = acc.double();
            for (digits, table, negative) in
                [(&d1, &table, k1.negative), (&d2, &endo_table, k2.negative)]
            {
                let digit = digits.digit(bit);
                if let Some(index) = digit.table_index() {
                    let mut point = table[index];
                    if digit.is_negative() ^ negative {
                        point = point.neg();
                    }
                    acc = acc.add(point);
                }
            }
        }
        acc
    }

    fn random_scalar(rng: &mut impl rand::RngCore) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        while cmp_limbs(&limbs, &SCALAR_MODULUS).is_ge() {
            (limbs, _) = sub_wide(limbs, SCALAR_MODULUS);
        }
        limbs
    }

    #[test]
    fn msm_matches_baseline_differentially() {
        use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x4d53_4d5f_4142_0001);

        let pool: Vec<G1Affine> = (0..64)
            .map(|_| {
                G1Projective::generator()
                    .mul(Fr::from_raw(random_scalar(&mut rng)))
                    .to_affine()
            })
            .collect();
        let r_minus_1 = {
            let mut limbs = SCALAR_MODULUS;
            limbs[0] -= 1;
            limbs
        };

        let small_sizes = [
            0usize, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 12, 15, 16, 16, 17, 24, 32, 33, 40,
            48, 49, 64, 65, 80, 81,
        ];
        let large_sizes = [96usize, 128, 256, 512, 1024, 2048];
        let cases = if cfg!(debug_assertions) { 700 } else { 10_000 };
        for case in 0..cases {
            let n = if case % 200 == 199 {
                large_sizes[(case / 200) % large_sizes.len()]
            } else {
                small_sizes[case % small_sizes.len()]
            };
            let all_same = rng.gen_ratio(1, 10);
            let mut points = Vec::with_capacity(n);
            let mut scalars = Vec::with_capacity(n);
            for i in 0..n {
                let point = if rng.gen_ratio(1, 20) {
                    G1Affine::identity()
                } else if i > 0 && (all_same || rng.gen_ratio(1, 10)) {
                    points[0]
                } else {
                    pool[rng.next_u32() as usize % pool.len()]
                };
                let scalar = if rng.gen_ratio(1, 20) {
                    [0u64; 4]
                } else if rng.gen_ratio(1, 20) {
                    r_minus_1
                } else {
                    random_scalar(&mut rng)
                };
                points.push(point);
                scalars.push(scalar);
            }
            let expected = baseline::msm_variable_time_old(&points, &scalars).to_affine();
            let actual = msm_variable_time(&points, &scalars).to_affine();
            assert_eq!(actual, expected, "case={case} n={n}");
            if n >= 9 {
                assert_eq!(
                    msm_signed_pippenger_batch_affine(&points, &scalars, pippenger_width(n))
                        .to_affine(),
                    expected,
                    "batch-affine case={case} n={n}"
                );
            }
            if (1..=8).contains(&n) {
                assert_eq!(
                    msm_small_prev(&points, &scalars).to_affine(),
                    expected,
                    "prev variant case={case} n={n}"
                );
            }
            if n == 1 {
                assert_eq!(
                    msm_single_projective_tables(&points, &scalars).to_affine(),
                    expected,
                    "projective variant case={case}"
                );
            }
        }
    }

    /// Constructed inputs that force every batch-affine special case: empty
    /// buckets, in-bucket doublings (same-x same-y), cancellations (same-x
    /// opposite-y), pending-bucket conflicts within one flush, and long
    /// deferred chains (every term hitting one bucket).  Narrow widths make
    /// buckets collide; wide widths exercise the flush-at-stream-end drain.
    #[test]
    fn batch_affine_pippenger_handles_constructed_special_cases() {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x6261_7463_685f_6166);
        let base: Vec<G1Affine> = (0..8)
            .map(|_| {
                G1Projective::generator()
                    .mul(Fr::from_raw(random_scalar(&mut rng)))
                    .to_affine()
            })
            .collect();
        let r_minus_1 = {
            let mut limbs = SCALAR_MODULUS;
            limbs[0] -= 1;
            limbs
        };

        let mut cases: Vec<(Vec<G1Affine>, Vec<[u64; 4]>)> = Vec::new();
        // Doubling then conflict chain: P repeated with one shared scalar.
        for repeats in [2usize, 3, 5, 17, 300] {
            let scalar = random_scalar(&mut rng);
            cases.push((vec![base[0]; repeats], vec![scalar; repeats]));
        }
        // Cancellation: P and -P with the same scalar, in both orders, plus a
        // survivor so buckets refill after emptying.
        cases.push((vec![base[1], base[1].neg(), base[2]], vec![[7, 0, 0, 0]; 3]));
        cases.push((vec![base[1].neg(), base[1], base[1]], vec![[9, 0, 0, 0]; 3]));
        // Cancellation arriving while the bucket has a pending double.
        cases.push((
            vec![base[3], base[3], base[3].neg(), base[3].neg()],
            vec![[5, 0, 0, 0]; 4],
        ));
        // r-1 scalars (negated digits) mixed with duplicates and identities.
        cases.push((
            vec![base[4], base[4], G1Affine::identity(), base[5]],
            vec![r_minus_1, r_minus_1, r_minus_1, [0, 0, 0, 0]],
        ));
        // Random mixture with heavy duplication.
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for i in 0..257 {
            points.push(base[(i * i) % 4]);
            scalars.push([1 + (i as u64 % 3), 0, 0, 0]);
        }
        cases.push((points, scalars));

        for (case, (points, scalars)) in cases.iter().enumerate() {
            let expected = reference(points, scalars).to_affine();
            for width in [3usize, 4, 5, 8, 10] {
                let actual = msm_signed_pippenger_batch_affine(points, scalars, width).to_affine();
                assert_eq!(actual, expected, "case={case} width={width}");
            }
        }
    }

    /// Encode one corpus, run it through the byte facade, and assert byte
    /// agreement with the typed reference.
    fn assert_facade_msm_matches(points: &[G1Affine], scalars: &[[u64; 4]], context: &str) {
        use crate::batch::{G1Bytes, ScalarBytes, g1_msm};
        let encoded_points: Vec<G1Bytes> = points.iter().map(G1Bytes::from_affine).collect();
        let encoded_scalars: Vec<ScalarBytes> = scalars
            .iter()
            .map(|limbs| ScalarBytes::from_fr(Fr::from_raw(*limbs)))
            .collect();
        let expected = G1Bytes::from_affine(&reference(points, scalars).to_affine());
        assert_eq!(
            g1_msm(&encoded_points, &encoded_scalars),
            Ok(expected),
            "{context}"
        );
    }

    /// Full validated path (bytes in through `g1_msm`, bytes out) over
    /// corpora shaped to zero an intermediate if anything could: bucket
    /// cancellations to infinity mid-MSM, in-bucket doubling chains with
    /// conflict overflow, identity and zero mixes, negated-digit (r-1)
    /// scalars, and dense duplication that crosses the 64-pending flush,
    /// across the joint-wNAF and Pippenger dispatch tiers. Byte-level
    /// agreement proves every internal inversion saw a nonzero argument.
    #[test]
    fn facade_msm_handles_adversarial_valid_corpora() {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(0x6661_6361_6465_5f31);
        let pool: Vec<G1Affine> = (0..48)
            .map(|_| {
                G1Projective::generator()
                    .mul(Fr::from_raw(random_scalar(&mut rng)))
                    .to_affine()
            })
            .collect();
        let r_minus_1 = {
            let mut limbs = SCALAR_MODULUS;
            limbs[0] -= 1;
            limbs
        };

        // Pairwise cancellation to infinity: P and -P share a scalar, so
        // every window sends them to the same bucket and the cancellation
        // branch empties it mid-MSM; the total is the identity encoding.
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for (i, point) in pool.iter().enumerate() {
            let scalar = [3 + i as u64, i as u64, 0, 0];
            points.push(*point);
            scalars.push(scalar);
            points.push(point.neg());
            scalars.push(scalar);
        }
        assert_facade_msm_matches(&points, &scalars, "pairwise cancellation n=96");

        // Doubling chains: one repeated point forces assign, pending double,
        // then overflow conflicts in every window; n=5 drives the joint-wNAF
        // co-Z rescaling tier instead.
        for repeats in [5usize, 96, 300] {
            let corpus = vec![pool[0]; repeats];
            let shared = vec![[0x1234_5678_9abc_def1u64, 42, 7, 0]; repeats];
            assert_facade_msm_matches(&corpus, &shared, &format!("doubling chain n={repeats}"));
        }

        // Identity mixes: encoded infinity points, zero scalars, and r-1
        // (negated-digit) scalars interleaved with live terms.
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for i in 0..120usize {
            let (point, scalar) = match i % 4 {
                0 => (G1Affine::identity(), random_scalar(&mut rng)),
                1 => (pool[i % pool.len()], [0, 0, 0, 0]),
                2 => (pool[i % pool.len()], r_minus_1),
                _ => (pool[i % pool.len()], random_scalar(&mut rng)),
            };
            points.push(point);
            scalars.push(scalar);
        }
        assert_facade_msm_matches(&points, &scalars, "identity mix n=120");

        // Dense duplication: enough distinct buckets fill per window to hit
        // the mid-stream 64-pending flush as well as the end-of-window drain.
        let mut points = Vec::new();
        let mut scalars = Vec::new();
        for i in 0..256usize {
            points.push(pool[(i * i) % pool.len()]);
            scalars.push(random_scalar(&mut rng));
        }
        assert_facade_msm_matches(&points, &scalars, "dense duplicates n=256");

        // Whole-sum cancellation at small n: [1]P + [r-1]P = O through the
        // joint-wNAF tier and the identity encoding on the way out.
        assert_facade_msm_matches(
            &[pool[1], pool[1]],
            &[[1, 0, 0, 0], r_minus_1],
            "small-n sum to infinity",
        );
    }

    /// No on-curve BN254 point has `y = 0`. This input can only bypass the byte
    /// facade. The internal MSM remains total when its batch denominator is
    /// zero.
    #[cfg(not(all(helius_avx512_ifma, not(feature = "force-portable"))))]
    #[test]
    fn msm_handles_off_curve_two_torsion_without_panicking() {
        let junk = G1Affine {
            x: Fp::from_u64(1),
            y: Fp::ZERO,
            infinity: false,
        };
        let points = vec![junk; BATCH_AFFINE_MIN_N];
        let scalars = vec![[1u64, 0, 0, 0]; BATCH_AFFINE_MIN_N];
        let _ = msm_variable_time(&points, &scalars);
    }

    #[test]
    #[ignore = "manual phase profile: cargo +1.97.1 test --release -p helius-bn254 -- --ignored msm_small_n_phase --nocapture"]
    fn msm_small_n_phase_profile() {
        use crate::batch::{G1Bytes, ScalarBytes};
        use std::hint::black_box;
        use std::time::Instant;

        let seeds = scalar_stream(16);
        let scalars_raw = scalar_stream(32).split_off(16);
        let point_bytes: Vec<G1Bytes> = seeds
            .iter()
            .map(|seed| {
                G1Bytes::from_affine(
                    &G1Projective::generator()
                        .mul(Fr::from_raw(*seed))
                        .to_affine(),
                )
            })
            .collect();
        let scalar_bytes: Vec<ScalarBytes> = scalars_raw
            .iter()
            .map(|limbs| {
                let mut out = [0u8; 32];
                for (i, limb) in limbs.iter().enumerate() {
                    out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
                }
                ScalarBytes(out)
            })
            .collect();

        const PHASES: usize = 7;
        let names = [
            "decode",
            "decompose",
            "tables",
            "rescale+endo",
            "recode",
            "loop",
            "final",
        ];
        for n in [1usize, 2, 4, 8] {
            let reps = 20_000usize / n;
            let mut totals = [0u64; PHASES];
            for _ in 0..reps {
                // decode + validate
                let t = Instant::now();
                let points: Vec<G1Affine> = point_bytes[..n]
                    .iter()
                    .map(|b| b.to_affine().unwrap())
                    .collect();
                let scalars: Vec<[u64; 4]> = scalar_bytes[..n]
                    .iter()
                    .map(|s| s.to_fr().map(|fr| fr.to_raw()).unwrap())
                    .collect();
                totals[0] += t.elapsed().as_nanos() as u64;

                const CAP: usize = 8;
                const CAP_TABLES: usize = 64;
                let t = Instant::now();
                let mut decomposed = [(SignedScalar::ZERO, SignedScalar::ZERO); CAP];
                for (slot, scalar) in decomposed[..n].iter_mut().zip(&scalars) {
                    *slot = decompose_scalar(*scalar);
                }
                totals[1] += t.elapsed().as_nanos() as u64;

                let t = Instant::now();
                let mut tables_projective = [G1_PROJECTIVE_IDENTITY; CAP_TABLES];
                let mut chain_dx = [[Fp::ZERO; JOINT_TABLE - 1]; CAP];
                let mut chain_z = [Fp::ONE; CAP];
                for (i, point) in points.iter().enumerate() {
                    let chain = &mut tables_projective[i * JOINT_TABLE..(i + 1) * JOINT_TABLE];
                    fill_odd_multiples(*point, chain, &mut chain_dx[i]);
                    chain_z[i] = chain[JOINT_TABLE - 1].z;
                }
                totals[2] += t.elapsed().as_nanos() as u64;

                let t = Instant::now();
                let mut outer = [Fp::ONE; CAP];
                let mut product = Fp::ONE;
                for i in 0..n {
                    outer[i] = product;
                    product *= chain_z[i];
                }
                let z_global = product;
                let mut suffix = Fp::ONE;
                for i in (0..n).rev() {
                    outer[i] *= suffix;
                    suffix *= chain_z[i];
                }
                let mut tables = [G1_AFFINE_IDENTITY; CAP_TABLES];
                let mut endomorphism_tables = [G1_AFFINE_IDENTITY; CAP_TABLES];
                for c in 0..n {
                    let base = c * JOINT_TABLE;
                    let mut scale = outer[c];
                    for i in (0..JOINT_TABLE).rev() {
                        let entry = tables_projective[base + i];
                        let (x, y) = if scale == Fp::ONE {
                            (entry.x, entry.y)
                        } else {
                            let scale_2 = scale.square();
                            (entry.x * scale_2, entry.y * (scale_2 * scale))
                        };
                        tables[base + i] = G1Affine {
                            x,
                            y,
                            infinity: false,
                        };
                        endomorphism_tables[base + i] = G1Affine {
                            x: x * BETA_MONT,
                            y,
                            infinity: false,
                        };
                        if i > 0 {
                            scale *= chain_dx[c][i - 1];
                        }
                    }
                }
                totals[3] += t.elapsed().as_nanos() as u64;

                let t = Instant::now();
                let mut digits = [(JointDigits::ZERO, JointDigits::ZERO); CAP];
                let mut max_len = 0usize;
                for (slot, (k1, k2)) in digits[..n].iter_mut().zip(&decomposed) {
                    let (d1, n1) = recode_u128::<JOINT_WIDTH, 129>(k1.magnitude);
                    let (d2, n2) = recode_u128::<JOINT_WIDTH, 129>(k2.magnitude);
                    max_len = max_len.max(n1).max(n2);
                    *slot = (d1, d2);
                }
                totals[4] += t.elapsed().as_nanos() as u64;

                let t = Instant::now();
                let mut acc = G1Projective::identity();
                for bit in (0..max_len).rev() {
                    acc = acc.double();
                    for i in 0..n {
                        let table_offset = i * JOINT_TABLE;
                        acc = add_wnaf_digit(
                            acc,
                            &tables[table_offset..table_offset + JOINT_TABLE],
                            digits[i].0.digit(bit),
                            decomposed[i].0.negative,
                        );
                        acc = add_wnaf_digit(
                            acc,
                            &endomorphism_tables[table_offset..table_offset + JOINT_TABLE],
                            digits[i].1.digit(bit),
                            decomposed[i].1.negative,
                        );
                    }
                }
                totals[5] += t.elapsed().as_nanos() as u64;

                let t = Instant::now();
                acc.z *= z_global;
                let affine = projective_to_affine_vartime(acc);
                black_box(G1Bytes::from_affine(&affine));
                totals[6] += t.elapsed().as_nanos() as u64;
            }
            let total: u64 = totals.iter().sum();
            let mut row = std::format!("n={n} total={:7.1}ns |", total as f64 / reps as f64);
            for (name, ns) in names.iter().zip(&totals) {
                row += &std::format!(
                    " {name}={:6.1} ({:4.1}%)",
                    *ns as f64 / reps as f64,
                    100.0 * *ns as f64 / total as f64
                );
            }
            std::println!("{row}");
        }
    }

    #[test]
    #[ignore = "manual MSM A/B microbenchmark: cargo +1.97.1 test --release -p helius-bn254 -- --ignored msm_ab --nocapture"]
    fn msm_ab_microbenchmark() {
        use std::hint::black_box;
        use std::time::Instant;

        type MsmFn = fn(&[G1Affine], &[[u64; 4]]) -> G1Projective;
        struct Variant {
            name: &'static str,
            func: MsmFn,
            min_n: usize,
            max_n: usize,
        }
        let variants = [
            Variant {
                name: "old",
                func: baseline::msm_variable_time_old,
                min_n: 1,
                max_n: 2048,
            },
            Variant {
                name: "new",
                func: msm_variable_time,
                min_n: 1,
                max_n: 2048,
            },
            Variant {
                name: "prev",
                func: msm_small_prev,
                min_n: 1,
                max_n: 8,
            },
            Variant {
                name: "1proj",
                func: msm_single_projective_tables,
                min_n: 1,
                max_n: 1,
            },
            Variant {
                name: "joint16",
                func: msm_joint_wnaf::<16, 128>,
                min_n: 9,
                max_n: 16,
            },
            Variant {
                name: "joint32",
                func: msm_joint_wnaf::<32, 256>,
                min_n: 17,
                max_n: 32,
            },
            Variant {
                name: "joint48",
                func: msm_joint_wnaf::<48, 384>,
                min_n: 33,
                max_n: 48,
            },
            Variant {
                name: "joint64",
                func: msm_joint_wnaf::<64, 512>,
                min_n: 33,
                max_n: 64,
            },
            Variant {
                name: "joint96",
                func: msm_joint_wnaf::<96, 768>,
                min_n: 65,
                max_n: 96,
            },
            Variant {
                name: "joint128",
                func: msm_joint_wnaf::<128, 1024>,
                min_n: 65,
                max_n: 128,
            },
            Variant {
                name: "pip-wm",
                func: msm_signed_pippenger,
                min_n: 9,
                max_n: 2048,
            },
            Variant {
                name: "pip-sc",
                func: msm_signed_pippenger_scalar,
                min_n: 9,
                max_n: 2048,
            },
            Variant {
                name: "pip-ba",
                func: |p, s| msm_signed_pippenger_batch_affine(p, s, batch_affine_width(p.len())),
                min_n: 9,
                max_n: 2048,
            },
            Variant {
                name: "pw8",
                func: |p, s| msm_signed_pippenger_with_width(p, s, 8),
                min_n: 512,
                max_n: 2048,
            },
            Variant {
                name: "pw9",
                func: |p, s| msm_signed_pippenger_with_width(p, s, 9),
                min_n: 512,
                max_n: 2048,
            },
            Variant {
                name: "pw10",
                func: |p, s| msm_signed_pippenger_with_width(p, s, 10),
                min_n: 512,
                max_n: 2048,
            },
            Variant {
                name: "pw11",
                func: |p, s| msm_signed_pippenger_with_width(p, s, 11),
                min_n: 512,
                max_n: 2048,
            },
            Variant {
                name: "pw12",
                func: |p, s| msm_signed_pippenger_with_width(p, s, 12),
                min_n: 512,
                max_n: 2048,
            },
        ];

        let max_n = 2048usize;
        let mut seeds = scalar_stream(max_n * 2);
        let scalars = seeds.split_off(max_n);
        let points: Vec<G1Affine> = seeds
            .iter()
            .map(|seed| {
                G1Projective::generator()
                    .mul(Fr::from_raw(*seed))
                    .to_affine()
            })
            .collect();

        for n in [
            1usize, 2, 4, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 256, 512, 1024, 2048,
        ] {
            let iters = (64 / n).max(1);
            let reps = 60usize;
            let active: Vec<&Variant> = variants
                .iter()
                .filter(|v| v.min_n <= n && n <= v.max_n)
                .collect();
            let mut samples = vec![Vec::with_capacity(reps); active.len()];
            for _ in 0..reps {
                for (variant, bucket) in active.iter().zip(&mut samples) {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box((variant.func)(
                            black_box(&points[..n]),
                            black_box(&scalars[..n]),
                        ));
                    }
                    bucket.push(start.elapsed().as_nanos() as f64 / iters as f64);
                }
            }
            let mut row = std::format!("n={n:5}");
            for (variant, bucket) in active.iter().zip(&mut samples) {
                bucket.sort_by(f64::total_cmp);
                let median = bucket[bucket.len() / 2];
                row += &std::format!("  {}={:9.1}ns", variant.name, median);
            }
            std::println!("{row}");
        }
    }

    #[test]
    fn signed_window_recode_consumes_top_carry_boundaries() {
        for width in [3usize, 4, 5, 6, 7, 8, 9, 10] {
            let windows = 127usize.div_ceil(width);
            let radix = 1u128 << width;
            let half = radix >> 1;
            let mask = radix - 1;
            for original in [
                1,
                half,
                (1u128 << 126) - 1,
                1u128 << 126,
                (1u128 << 127) - 1,
            ] {
                let mut scalar = original;
                let mut carry = 0;
                let mut positive = 0u128;
                let mut negative = 0u128;
                for window in 0..windows {
                    let digit =
                        next_signed_digit(&mut scalar, &mut carry, width, mask, half, radix);
                    let magnitude = (digit.unsigned_abs() as u128) << (window * width);
                    if digit < 0 {
                        negative += magnitude;
                    } else {
                        positive += magnitude;
                    }
                }
                assert_eq!(scalar, 0, "width={width} scalar={original:x}");
                assert_eq!(carry, 0, "width={width} scalar={original:x}");
                assert_eq!(positive - negative, original, "width={width}");
            }
        }
    }
}
