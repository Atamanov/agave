//! AVX-512 IFMA 8-way batched Montgomery arithmetic (radix-52).
//!
//! Eight independent `Fp` values ride the eight 64-bit lanes of ZMM
//! registers in structure-of-arrays form: five limbs of 52 bits each, in the
//! radix-52 Montgomery domain `v * 2^260 mod p`.  `vpmadd52{l,h}uq` performs
//! the 52x52-bit partial products.  Per-element conversion between the 4x64
//! `2^256` domain and the 5x52 `2^260` domain costs one batched Montgomery
//! multiplication by a fixed constant each way, so the tier only pays off
//! when several multiplications amortize one conversion pair (e.g. the MSM
//! bucket-accumulation phase).
//!
//! This module exists only when `build.rs` emitted `helius_avx512_ifma`,
//! i.e. the target has `avx512f` and `avx512ifma` in its compile-time
//! features (force/deny via `HELIUS_AVX512_IFMA`).  As with the ADX tier
//! there is no runtime dispatch: a binary built with this cfg requires an
//! IFMA-capable CPU, never a silent fallback.

use core::arch::x86_64::*;

use crate::consts::{MONT_ONE, P, P_INV};
use crate::fp::Fp;

const MASK52: u64 = (1 << 52) - 1;
/// `-p^{-1} mod 2^52`: the low 52 bits of the radix-64 constant, because the
/// inverse of `p` modulo `2^52` is the inverse modulo `2^64` truncated.
const P_INV_52: u64 = P_INV & MASK52;
const P52: [u64; 5] = to_radix52(P);

/// Repack canonical 4x64 little-endian limbs into 5x52. Pure bit slicing;
/// value-preserving for any 256-bit input.
const fn to_radix52(x: [u64; 4]) -> [u64; 5] {
    [
        x[0] & MASK52,
        ((x[0] >> 52) | (x[1] << 12)) & MASK52,
        ((x[1] >> 40) | (x[2] << 24)) & MASK52,
        ((x[2] >> 28) | (x[3] << 36)) & MASK52,
        x[3] >> 16,
    ]
}

/// Inverse of [`to_radix52`]; limbs must be normalized (below `2^52`).
#[inline(always)]
fn from_radix52(l: &[u64; 5]) -> [u64; 4] {
    debug_assert!(l.iter().all(|&limb| limb <= MASK52));
    [
        l[0] | (l[1] << 52),
        (l[1] >> 12) | (l[2] << 40),
        (l[2] >> 24) | (l[3] << 28),
        (l[3] >> 36) | (l[4] << 16),
    ]
}

const fn const_gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i = 3usize;
    loop {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
        if i == 0 {
            return true;
        }
        i -= 1;
    }
}

const fn const_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0usize;
    while i < 4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = (b1 as u64) | (b2 as u64);
        i += 1;
    }
    out
}

/// `2a mod p` for `a < p` (`2a < 2^255` never overflows four limbs).
const fn double_mod_p(a: [u64; 4]) -> [u64; 4] {
    let mut r = [
        a[0] << 1,
        (a[1] << 1) | (a[0] >> 63),
        (a[2] << 1) | (a[1] >> 63),
        (a[3] << 1) | (a[2] >> 63),
    ];
    if const_gte(&r, &P) {
        r = const_sub(&r, &P);
    }
    r
}

const fn pow2_shift_mod_p(mut v: [u64; 4], count: usize) -> [u64; 4] {
    let mut i = 0usize;
    while i < count {
        v = double_mod_p(v);
        i += 1;
    }
    v
}

/// Domain-entry constant `2^264 mod p`:
/// `mont52(x * 2^256, 2^264) = x * 2^260`, moving the 4x64 Montgomery domain
/// into the radix-52 one.
const C_IN_52: [u64; 5] = to_radix52(pow2_shift_mod_p(MONT_ONE, 8));
/// Domain-exit constant `2^256 mod p`:
/// `mont52(x * 2^260, 2^256) = x * 2^256`.
const C_OUT_52: [u64; 5] = to_radix52(MONT_ONE);

/// Eight `Fp` values in radix-52 Montgomery form (`v * 2^260 mod p`),
/// structure-of-arrays: `l[j]` holds limb `j` of all eight lanes. Invariant:
/// every lane is canonical (normalized 52-bit limbs, value below `p`).
#[derive(Clone, Copy)]
pub(crate) struct FpVec8 {
    l: [__m512i; 5],
}

// SAFETY of every intrinsic call in this module: `helius_avx512_ifma` is
// emitted only when `avx512f` and `avx512ifma` are compile-time target
// features, so the instructions are part of this binary's baseline ISA.
// All loads/stores go through 64-byte stack staging arrays via the
// unaligned-access intrinsics.

#[inline(always)]
fn splat(v: u64) -> __m512i {
    unsafe { _mm512_set1_epi64(v as i64) }
}

#[inline(always)]
fn splat5(v: &[u64; 5]) -> [__m512i; 5] {
    [
        splat(v[0]),
        splat(v[1]),
        splat(v[2]),
        splat(v[3]),
        splat(v[4]),
    ]
}

/// 8-way radix-52 CIOS Montgomery multiplication.
///
/// Contract: lanes of `a` and `b` are canonical radix-52 residues below `p`.
/// Returns canonical residues of `a * b * 2^-260 mod p` per lane.
///
/// Accumulator bound: each of the six 64-bit accumulators absorbs at most
/// four sub-`2^52` products per round plus one propagated carry, so after
/// five rounds every accumulator stays below `5 * 4 * 2^52 < 2^57` -- far
/// from wrapping.  The pre-reduction result is below `2p` (since
/// `p^2/2^260` is negligible next to `p`), so one masked subtraction
/// canonicalizes.
#[inline(always)]
fn mont_mul_8(a: &[__m512i; 5], b: &[__m512i; 5]) -> [__m512i; 5] {
    unsafe {
        let zero = _mm512_setzero_si512();
        let pinv = splat(P_INV_52);
        let p = splat5(&P52);
        let mut t = [zero; 6];
        for &bi in b {
            for j in 0..5 {
                t[j] = _mm512_madd52lo_epu64(t[j], a[j], bi);
                t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], a[j], bi);
            }
            // q only depends on the low 52 bits of t[0]; vpmadd52luq ignores
            // the accumulated high garbage in both multiplicands.
            let q = _mm512_madd52lo_epu64(zero, t[0], pinv);
            for j in 0..5 {
                t[j] = _mm512_madd52lo_epu64(t[j], p[j], q);
                t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], p[j], q);
            }
            // t[0] is now 0 mod 2^52; shift the window down one limb.
            let carry = _mm512_srli_epi64::<52>(t[0]);
            t[1] = _mm512_add_epi64(t[1], carry);
            for j in 0..5 {
                t[j] = t[j + 1];
            }
            t[5] = zero;
        }
        normalize_and_reduce(&mut t);
        [t[0], t[1], t[2], t[3], t[4]]
    }
}

/// 8-way radix-52 Montgomery squaring: the fifteen unique partial products
/// instead of the general kernel's twenty-five.  Cross terms are doubled in
/// the accumulator, never in an operand -- `vpmadd52` reads only the low 52
/// bits of its multiplicands, so a doubled operand at the 2^52 boundary would
/// silently truncate.  The full ten-column product is formed first, then five
/// reduction rounds walk the window down.
///
/// Contract: lanes of `a` are canonical radix-52 residues below `p`.  Returns
/// canonical residues of `a^2 * 2^-260 mod p` per lane.
///
/// Accumulator bound: a column takes at most two cross products plus two
/// cross highs before doubling (< 2^54), one diagonal low and high after
/// (< 2^55.5); each reduction round adds two sub-2^52 reduction rows and a
/// small carry, so no column ever nears 2^64.  The reduced value is
/// `(a^2 + m p) / 2^260 < p^2/2^260 + p < 2p`, so the shared single
/// conditional subtraction canonicalizes.
#[inline(always)]
fn mont_sqr_8(a: &[__m512i; 5]) -> [__m512i; 5] {
    unsafe {
        let zero = _mm512_setzero_si512();
        let pinv = splat(P_INV_52);
        let p = splat5(&P52);
        let mut t = [zero; 10];
        for i in 0..5 {
            for j in (i + 1)..5 {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[i], a[j]);
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[i], a[j]);
            }
        }
        for limb in &mut t {
            *limb = _mm512_add_epi64(*limb, *limb);
        }
        for i in 0..5 {
            t[2 * i] = _mm512_madd52lo_epu64(t[2 * i], a[i], a[i]);
            t[2 * i + 1] = _mm512_madd52hi_epu64(t[2 * i + 1], a[i], a[i]);
        }
        for _ in 0..5 {
            let q = _mm512_madd52lo_epu64(zero, t[0], pinv);
            for j in 0..5 {
                t[j] = _mm512_madd52lo_epu64(t[j], p[j], q);
                t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], p[j], q);
            }
            let carry = _mm512_srli_epi64::<52>(t[0]);
            t[1] = _mm512_add_epi64(t[1], carry);
            for j in 0..9 {
                t[j] = t[j + 1];
            }
            t[9] = zero;
        }
        let mut out = [t[0], t[1], t[2], t[3], t[4], zero];
        normalize_and_reduce(&mut out);
        [out[0], out[1], out[2], out[3], out[4]]
    }
}

/// Carry-normalize `t[0..5]` to 52-bit limbs, then subtract `p` in lanes
/// where the value is at least `p`.  Requires the pre-normalization value to
/// be below `2p` (top limb never carries out).
#[inline(always)]
unsafe fn normalize_and_reduce(t: &mut [__m512i; 6]) {
    unsafe {
        let zero = _mm512_setzero_si512();
        let mask = splat(MASK52);
        let p = splat5(&P52);
        let mut carry = zero;
        for limb in t.iter_mut().take(4) {
            let v = _mm512_add_epi64(*limb, carry);
            *limb = _mm512_and_si512(v, mask);
            carry = _mm512_srli_epi64::<52>(v);
        }
        // Value < 2p < 2^255, so limb 4 tops out below 2^48: no carry out.
        t[4] = _mm512_add_epi64(t[4], carry);

        // d = t - p with a borrow chain over 52-bit limbs; lanes whose final
        // borrow is clear (t >= p) take d.
        let mut d = [zero; 5];
        let mut borrow = zero;
        for j in 0..5 {
            let v = _mm512_sub_epi64(_mm512_sub_epi64(t[j], p[j]), borrow);
            d[j] = _mm512_and_si512(v, mask);
            borrow = _mm512_srli_epi64::<63>(v);
        }
        let ge = _mm512_cmpeq_epi64_mask(borrow, zero);
        for j in 0..5 {
            t[j] = _mm512_mask_blend_epi64(ge, t[j], d[j]);
        }
    }
}

/// Carry-normalize `t[0..5]` to 52-bit limbs, then subtract `p` in lanes still
/// at or above it, twice.  The sum-of-products accumulator can reach just under
/// `3p` (the scalar sos leaves show the same `(1 + c*n)p` bound for these pair
/// counts), so a single conditional subtraction is not enough.
#[inline(always)]
unsafe fn normalize_and_reduce_sos(t: &mut [__m512i; 6]) {
    unsafe {
        let zero = _mm512_setzero_si512();
        let mask = splat(MASK52);
        let p = splat5(&P52);
        let mut carry = zero;
        for limb in t.iter_mut().take(4) {
            let v = _mm512_add_epi64(*limb, carry);
            *limb = _mm512_and_si512(v, mask);
            carry = _mm512_srli_epi64::<52>(v);
        }
        // Value < 3p < 2^255, so limb 4 tops out below 2^49: no carry out.
        t[4] = _mm512_add_epi64(t[4], carry);
        for _ in 0..2 {
            let mut d = [zero; 5];
            let mut borrow = zero;
            for j in 0..5 {
                let v = _mm512_sub_epi64(_mm512_sub_epi64(t[j], p[j]), borrow);
                d[j] = _mm512_and_si512(v, mask);
                borrow = _mm512_srli_epi64::<63>(v);
            }
            let ge = _mm512_cmpeq_epi64_mask(borrow, zero);
            for j in 0..5 {
                t[j] = _mm512_mask_blend_epi64(ge, t[j], d[j]);
            }
        }
    }
}

/// 8-way radix-52 CIOS Montgomery sum-of-products.  Given `n` (`1..=8`) product
/// terms `a[i] * b[i]` per lane, returns `(sum_i a[i] b[i]) * 2^-260 mod p` per
/// lane with a SINGLE Montgomery reduction folded over the whole sum -- the
/// tower's lazy-reduction win, now lane-parallel across eight independent
/// components (e.g. the six sparse `mul_by_034` outputs).
///
/// Accumulator bound: per reduction round each 64-bit accumulator absorbs at
/// most `n` low and `n` high sub-`2^52` product halves, the reduction row's
/// two, and the shifted-in carry.  For `n <= 8` every accumulator stays below
/// `2 * 5 * (n + 1) * 2^52 < 2^60`, far from wrapping; the pre-normalization
/// result is below `3p`.  The all-`p-1` edge corpus with `n = 8` exercises the
/// tightest lane against both bounds.
#[inline]
fn mont_sos_mac_8(a: &[[__m512i; 5]], b: &[[__m512i; 5]]) -> [__m512i; 5] {
    debug_assert!(!a.is_empty() && a.len() == b.len() && a.len() <= 8);
    unsafe {
        let zero = _mm512_setzero_si512();
        let pinv = splat(P_INV_52);
        let p = splat5(&P52);
        let mut t = [zero; 6];
        for k in 0..5 {
            // Accumulate the k-th limb column of every product term, unreduced.
            for (av, bv) in a.iter().zip(b) {
                let bk = bv[k];
                for j in 0..5 {
                    t[j] = _mm512_madd52lo_epu64(t[j], av[j], bk);
                    t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], av[j], bk);
                }
            }
            // One Montgomery reduction step. q cancels t[0] mod 2^52;
            // vpmadd52luq reads only the low 52 bits of the accumulated t[0],
            // so its high garbage is irrelevant.
            let q = _mm512_madd52lo_epu64(zero, t[0], pinv);
            for j in 0..5 {
                t[j] = _mm512_madd52lo_epu64(t[j], p[j], q);
                t[j + 1] = _mm512_madd52hi_epu64(t[j + 1], p[j], q);
            }
            let carry = _mm512_srli_epi64::<52>(t[0]);
            t[1] = _mm512_add_epi64(t[1], carry);
            for j in 0..5 {
                t[j] = t[j + 1];
            }
            t[5] = zero;
        }
        normalize_and_reduce_sos(&mut t);
        [t[0], t[1], t[2], t[3], t[4]]
    }
}

impl FpVec8 {
    /// Load values already stored in the radix-52 Montgomery domain.
    pub(crate) fn load_radix52_montgomery(values: &[[u64; 5]; 8]) -> Self {
        let lanes: [[u64; 8]; 5] =
            core::array::from_fn(|limb| core::array::from_fn(|lane| values[lane][limb]));
        unsafe {
            Self {
                l: core::array::from_fn(|limb| _mm512_loadu_si512(lanes[limb].as_ptr().cast())),
            }
        }
    }

    /// Convert eight canonical `Fp` (4x64 Montgomery) into the batched
    /// radix-52 domain: repack, then one batched multiplication by
    /// `2^264 mod p`.
    pub(crate) fn load(values: &[Fp; 8]) -> Self {
        let mut lanes = [[0u64; 8]; 5];
        for (lane, fp) in values.iter().enumerate() {
            let r = to_radix52(fp.0);
            for j in 0..5 {
                lanes[j][lane] = r[j];
            }
        }
        unsafe {
            let raw = [
                _mm512_loadu_si512(lanes[0].as_ptr() as *const _),
                _mm512_loadu_si512(lanes[1].as_ptr() as *const _),
                _mm512_loadu_si512(lanes[2].as_ptr() as *const _),
                _mm512_loadu_si512(lanes[3].as_ptr() as *const _),
                _mm512_loadu_si512(lanes[4].as_ptr() as *const _),
            ];
            Self {
                l: mont_mul_8(&raw, &splat5(&C_IN_52)),
            }
        }
    }

    /// Convert back to eight canonical `Fp`: one batched multiplication by
    /// `2^256 mod p`, then repack.
    pub(crate) fn store(&self) -> [Fp; 8] {
        let out = mont_mul_8(&self.l, &splat5(&C_OUT_52));
        let mut lanes = [[0u64; 8]; 5];
        unsafe {
            for j in 0..5 {
                _mm512_storeu_si512(lanes[j].as_mut_ptr() as *mut _, out[j]);
            }
        }
        core::array::from_fn(|lane| {
            Fp(from_radix52(&[
                lanes[0][lane],
                lanes[1][lane],
                lanes[2][lane],
                lanes[3][lane],
                lanes[4][lane],
            ]))
        })
    }

    /// Select `other` for mask-set lanes and `self` for the remaining lanes.
    #[inline(always)]
    pub(crate) fn blend(&self, other: &Self, mask: u8) -> Self {
        unsafe {
            Self {
                l: core::array::from_fn(|index| {
                    _mm512_mask_blend_epi64(mask, self.l[index], other.l[index])
                }),
            }
        }
    }

    #[inline(always)]
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        Self {
            l: mont_mul_8(&self.l, &rhs.l),
        }
    }

    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        Self {
            l: mont_sqr_8(&self.l),
        }
    }

    /// Lane-parallel sum-of-products: `sum_i a[i] * b[i]` per lane with one
    /// folded Montgomery reduction (`a`, `b` same length, `1..=8` terms).
    /// Operands stay in the radix-52 domain, so a tower routine converts its
    /// inputs once, issues several of these across the eight independent
    /// components it produces, and converts back once.
    #[inline]
    pub(crate) fn sos_mac(a: &[FpVec8], b: &[FpVec8]) -> Self {
        debug_assert!(!a.is_empty() && a.len() == b.len() && a.len() <= 8);
        let mut al = [[unsafe { _mm512_setzero_si512() }; 5]; 8];
        let mut bl = [[unsafe { _mm512_setzero_si512() }; 5]; 8];
        for (i, (x, y)) in a.iter().zip(b).enumerate() {
            al[i] = x.l;
            bl[i] = y.l;
        }
        let n = a.len();
        Self {
            l: mont_sos_mac_8(&al[..n], &bl[..n]),
        }
    }

    // The mixed-addition formula is all-subtraction; add is kept as part of
    // the differential-gated op set for future batched formulas.
    #[inline(always)]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        unsafe {
            let mut t = [
                _mm512_add_epi64(self.l[0], rhs.l[0]),
                _mm512_add_epi64(self.l[1], rhs.l[1]),
                _mm512_add_epi64(self.l[2], rhs.l[2]),
                _mm512_add_epi64(self.l[3], rhs.l[3]),
                _mm512_add_epi64(self.l[4], rhs.l[4]),
                _mm512_setzero_si512(),
            ];
            // Sum < 2p; the shared normalize/reduce path canonicalizes.
            normalize_and_reduce(&mut t);
            Self {
                l: [t[0], t[1], t[2], t[3], t[4]],
            }
        }
    }

    #[inline(always)]
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        unsafe {
            let zero = _mm512_setzero_si512();
            let mask = splat(MASK52);
            let p = splat5(&P52);
            // d = a - b over 52-bit limbs; lanes that borrow add p back.
            let mut d = [zero; 5];
            let mut borrow = zero;
            for (j, slot) in d.iter_mut().enumerate() {
                let v = _mm512_sub_epi64(_mm512_sub_epi64(self.l[j], rhs.l[j]), borrow);
                *slot = _mm512_and_si512(v, mask);
                borrow = _mm512_srli_epi64::<63>(v);
            }
            let negative = _mm512_cmpneq_epi64_mask(borrow, zero);
            let mut carry = zero;
            let mut out = [zero; 5];
            for j in 0..5 {
                let addend = _mm512_maskz_mov_epi64(negative, p[j]);
                let v = _mm512_add_epi64(_mm512_add_epi64(d[j], addend), carry);
                out[j] = _mm512_and_si512(v, mask);
                carry = _mm512_srli_epi64::<52>(v);
            }
            // a - b + p < 2p < 2^255: limb 4 cannot carry out, so the final
            // mask is lossless.
            Self { l: out }
        }
    }

    /// The all-zero vector (value 0 in every lane; canonical radix-52).
    #[inline(always)]
    pub(crate) fn zero() -> Self {
        Self {
            l: [unsafe { _mm512_setzero_si512() }; 5],
        }
    }

    /// Per-lane additive inverse `p - self` (`0` maps to `0`).
    #[inline(always)]
    pub(crate) fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    /// Per-lane `2 * self`.
    #[inline(always)]
    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }

    /// Per-lane zero test (canonical representation makes this exact).
    #[inline(always)]
    pub(crate) fn is_zero_mask(&self) -> u8 {
        unsafe {
            let all = _mm512_or_si512(
                _mm512_or_si512(self.l[0], self.l[1]),
                _mm512_or_si512(_mm512_or_si512(self.l[2], self.l[3]), self.l[4]),
            );
            _mm512_cmpeq_epi64_mask(all, _mm512_setzero_si512())
        }
    }
}

/// Eight independent Jacobian mixed additions (general case of
/// madd-2007-bl, a = 0), batched over the IFMA lanes.
///
/// Inputs are eight buckets `(x1, y1, z1)` and eight affine points
/// `(x2, y2)` in ordinary 4x64 Montgomery form.  The kernel is total over
/// canonical residues: identity buckets (`z1 = 0`) and `h == 0` lanes
/// (shared x-coordinate: doubling or cancellation) produce garbage-but-
/// canonical outputs that the caller MUST mask and redo scalar-side. See
/// `flush_bucket_batch`, which passes such lanes deliberately.
/// Returns the eight sums plus the `h == 0` lane mask; masked lanes read the
/// original bucket.
///
/// 11 batched muls (3 of them squarings) + 7 batched subs + 8 domain
/// conversions, versus 8 x 11 scalar muls on the scalar path.
pub(crate) fn g1_madd_batch8(
    x1: &[Fp; 8],
    y1: &[Fp; 8],
    z1: &[Fp; 8],
    x2: &[Fp; 8],
    y2: &[Fp; 8],
) -> ([Fp; 8], [Fp; 8], [Fp; 8], u8) {
    let x1v = FpVec8::load(x1);
    let y1v = FpVec8::load(y1);
    let z1v = FpVec8::load(z1);
    let x2v = FpVec8::load(x2);
    let y2v = FpVec8::load(y2);

    let z1z1 = z1v.square();
    let h = x2v.mul(&z1z1).sub(&x1v);
    let r = z1z1.mul(&z1v).mul(&y2v).sub(&y1v);
    let h_zero = h.is_zero_mask();
    let z3 = z1v.mul(&h);
    let h2 = h.square();
    let mut ry = r.square();
    let u1h = x1v.mul(&h2);
    let h3 = h2.mul(&h);
    ry = ry.sub(&u1h).sub(&u1h);
    let x3 = ry.sub(&h3);
    let y3 = u1h.sub(&x3).mul(&r).sub(&h3.mul(&y1v));

    (x3.store(), y3.store(), z3.store(), h_zero)
}

#[cfg(test)]
mod tests {
    use core::ops::{Add, Mul, Neg};

    use super::*;
    use crate::consts::{MONT_ONE, MONT_R2, P};
    use crate::limb;

    fn next_residue(state: &mut u64) -> [u64; 4] {
        let mut value = [0u64; 4];
        for limb in &mut value {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *limb = *state;
        }
        while limb::gte(&value, &P) {
            value = limb::sub_noborrow(&value, &P);
        }
        value
    }

    fn reduced(mut value: [u64; 4]) -> [u64; 4] {
        while limb::gte(&value, &P) {
            value = limb::sub_noborrow(&value, &P);
        }
        value
    }

    /// Carry-edge corpus: canonical values whose radix-52 limbs sit at the
    /// 2^52-1 boundary, plus the usual field edges.
    fn edge_corpus() -> Vec<[u64; 4]> {
        let p_minus_one = limb::sub_noborrow(&P, &[1, 0, 0, 0]);
        let mut cases = vec![
            [0; 4],
            [1, 0, 0, 0],
            [MASK52, 0, 0, 0],
            [u64::MAX, MASK52, 0, 0],
            MONT_ONE,
            MONT_R2,
            p_minus_one,
            reduced([u64::MAX; 4]),
            reduced([u64::MAX, u64::MAX, u64::MAX, (1 << 62) - 1]),
            reduced([u64::MAX, 0, u64::MAX, 0]),
            reduced([0, u64::MAX, 0, 0x1000_0000_0000_0000]),
            // All radix-52 limbs saturated: (2^260 - 1) mod 2^256 pattern.
            reduced([u64::MAX, u64::MAX, u64::MAX, 0x000f_ffff_ffff_ffff]),
        ];
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..256 {
            cases.push(next_residue(&mut state));
        }
        cases
    }

    fn fp8(values: &[[u64; 4]]) -> [Fp; 8] {
        core::array::from_fn(|i| Fp(values[i % values.len()]))
    }

    #[test]
    fn radix52_repack_roundtrips() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..10_000 {
            let v = next_residue(&mut state);
            assert_eq!(from_radix52(&to_radix52(v)), v);
        }
        assert_eq!(from_radix52(&P52), P);
    }

    #[test]
    fn constants_are_consistent() {
        // p * (-p^{-1}) = -1 mod 2^52.
        let p0 = P[0] & MASK52;
        assert_eq!(p0.wrapping_mul(P_INV_52) & MASK52, MASK52);
        // C_IN = 2^264 mod p: check via Fp arithmetic.
        let two_pow_8 = Fp::from_u64(256);
        let expected = Fp::from_raw(MONT_ONE) * two_pow_8; // (2^256 mod p)*2^8
        assert_eq!(to_radix52(expected.to_raw()), C_IN_52);
    }

    #[test]
    fn load_store_roundtrips_on_edges() {
        for chunk in edge_corpus().chunks(8) {
            let input = fp8(chunk);
            assert_eq!(FpVec8::load(&input).store(), input);
        }
    }

    #[test]
    fn preconverted_radix52_load_matches_regular_load() {
        let values: [Fp; 8] = core::array::from_fn(|index| Fp::from_u64(11 + index as u64));
        let preconverted = core::array::from_fn(|index| values[index].to_ifma_montgomery_limbs52());
        assert_eq!(
            FpVec8::load_radix52_montgomery(&preconverted).store(),
            values
        );
    }

    #[test]
    fn batched_ops_match_scalar_on_edges_and_random() {
        let cases = edge_corpus();
        let mut state = 0x6a09_e667_f3bc_c909u64;
        let rounds = if cfg!(debug_assertions) {
            2_000
        } else {
            65_536
        };
        for round in 0..rounds {
            let a: [Fp; 8] = if round < cases.len() {
                fp8(&cases[round..(round + 8).min(cases.len())])
            } else {
                core::array::from_fn(|_| Fp(next_residue(&mut state)))
            };
            let b: [Fp; 8] = core::array::from_fn(|_| Fp(next_residue(&mut state)));
            let av = FpVec8::load(&a);
            let bv = FpVec8::load(&b);
            let mul = av.mul(&bv).store();
            let sqr = av.square().store();
            let add = av.add(&bv).store();
            let sub = av.sub(&bv).store();
            for lane in 0..8 {
                assert_eq!(
                    mul[lane],
                    a[lane] * b[lane],
                    "mul round {round} lane {lane}"
                );
                assert_eq!(sqr[lane], a[lane].square(), "sqr round {round} lane {lane}");
                assert_eq!(
                    add[lane],
                    a[lane] + b[lane],
                    "add round {round} lane {lane}"
                );
                assert_eq!(
                    sub[lane],
                    a[lane] - b[lane],
                    "sub round {round} lane {lane}"
                );
            }
            let zero_mask = av.is_zero_mask();
            for (lane, value) in a.iter().enumerate() {
                assert_eq!(zero_mask >> lane & 1 == 1, value.is_zero());
            }
        }
    }

    #[test]
    #[ignore = "million-case release stress gate; run explicitly before changing the IFMA kernel"]
    fn million_products_match_portable() {
        let mut state = 0xd1b5_4a32_d192_ed03u64;
        for case in 0..125_000u64 {
            let a: [Fp; 8] = core::array::from_fn(|_| Fp(next_residue(&mut state)));
            let b: [Fp; 8] = core::array::from_fn(|_| Fp(next_residue(&mut state)));
            let mul = FpVec8::load(&a).mul(&FpVec8::load(&b)).store();
            for lane in 0..8 {
                let expected = crate::fp::portable::mont_mul(&a[lane].0, &b[lane].0);
                assert_eq!(mul[lane], expected, "case {case} lane {lane}");
            }
        }
    }

    #[test]
    fn batched_madd_matches_scalar() {
        use crate::g1::G1Projective;
        use crate::{Fr, G1Affine};

        let mut state = 0x0123_4567_89ab_cdefu64;
        let random_point = |state: &mut u64| -> G1Affine {
            let scalar = next_residue(state);
            G1Projective::generator()
                .mul(Fr::from_raw(scalar))
                .to_affine()
        };

        for case in 0..64 {
            let points: [G1Affine; 8] = core::array::from_fn(|_| random_point(&mut state));
            let mut buckets: [G1Projective; 8] = core::array::from_fn(|_| {
                random_point(&mut state)
                    .to_curve()
                    .add(random_point(&mut state).to_curve())
            });
            // Lane 3: h == 0 doubling case (bucket is the point itself, z=1).
            // Lane 5: h == 0 cancellation case (bucket is the negation).
            buckets[3] = points[3].to_curve();
            buckets[5] = points[5].neg().to_curve();

            let x1 = core::array::from_fn(|i| buckets[i].x);
            let y1 = core::array::from_fn(|i| buckets[i].y);
            let z1 = core::array::from_fn(|i| buckets[i].z);
            let x2 = core::array::from_fn(|i| points[i].x);
            let y2 = core::array::from_fn(|i| points[i].y);
            let (x3, y3, z3, h_zero) = g1_madd_batch8(&x1, &y1, &z1, &x2, &y2);

            assert_eq!(h_zero, 0b0010_1000, "case {case}");
            for lane in 0..8 {
                if h_zero >> lane & 1 == 1 {
                    continue;
                }
                let expected = buckets[lane].add_mixed(points[lane]);
                let actual = G1Projective {
                    x: x3[lane],
                    y: y3[lane],
                    z: z3[lane],
                };
                assert_eq!(
                    actual.to_affine(),
                    expected.to_affine(),
                    "case {case} lane {lane}"
                );
            }
        }
    }

    #[test]
    fn sos_mac_matches_scalar_sum_of_products() {
        let mut state = 0x1234_5678_9abc_def0u64;
        let rounds = if cfg!(debug_assertions) { 300 } else { 6_144 };
        for n in 1..=8usize {
            for round in 0..rounds {
                let a_terms: Vec<[Fp; 8]> = (0..n)
                    .map(|_| core::array::from_fn(|_| Fp(next_residue(&mut state))))
                    .collect();
                let b_terms: Vec<[Fp; 8]> = (0..n)
                    .map(|_| core::array::from_fn(|_| Fp(next_residue(&mut state))))
                    .collect();
                let expected: [Fp; 8] = core::array::from_fn(|lane| {
                    let mut acc = Fp::ZERO;
                    for term in 0..n {
                        acc += a_terms[term][lane] * b_terms[term][lane];
                    }
                    acc
                });
                let av: Vec<FpVec8> = a_terms.iter().map(FpVec8::load).collect();
                let bv: Vec<FpVec8> = b_terms.iter().map(FpVec8::load).collect();
                let got = FpVec8::sos_mac(&av, &bv).store();
                for lane in 0..8 {
                    assert_eq!(got[lane], expected[lane], "n={n} round={round} lane={lane}");
                }
            }
        }
        // Tightest lane: all operands p-1, n = 8, against the 3p and accumulator
        // bounds at once.
        let pm1 = Fp(limb::sub_noborrow(&P, &[1, 0, 0, 0]));
        let terms: Vec<[Fp; 8]> = (0..8).map(|_| [pm1; 8]).collect();
        let v: Vec<FpVec8> = terms.iter().map(FpVec8::load).collect();
        let got = FpVec8::sos_mac(&v, &v).store();
        let mut acc = Fp::ZERO;
        for _ in 0..8 {
            acc += pm1 * pm1;
        }
        for (lane, value) in got.iter().enumerate() {
            assert_eq!(*value, acc, "edge lane {lane}");
        }
    }

    #[test]
    #[ignore = "manual IFMA sos-mac microbenchmark: cargo test --release --features std -- --ignored ifma_sos_mac --nocapture"]
    fn ifma_sos_mac_throughput() {
        use crate::fp::sos::{SosProduct, sos6};
        use std::hint::black_box;
        use std::time::Instant;

        let mut state = 0xabcd_1234_5678_9abcu64;
        // IFMA: eight lanes, each a sum of six products (the mul_by_034 shape).
        let a_terms: Vec<FpVec8> = (0..6)
            .map(|_| FpVec8::load(&core::array::from_fn(|_| Fp(next_residue(&mut state)))))
            .collect();
        let b_terms: Vec<FpVec8> = (0..6)
            .map(|_| FpVec8::load(&core::array::from_fn(|_| Fp(next_residue(&mut state)))))
            .collect();
        let reps = 200_000usize;
        let start = Instant::now();
        let mut acc = a_terms[0];
        for _ in 0..reps {
            acc = FpVec8::sos_mac(black_box(&a_terms), black_box(&b_terms));
        }
        black_box(acc.store());
        let ifma_ns = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!("ifma8 sos_mac (8 lanes x sum-of-6): {ifma_ns:.2} ns per 8 components");

        // Scalar baseline: eight independent sos6 of the same shape.
        let sa: [[[u64; 4]; 6]; 8] =
            core::array::from_fn(|_| core::array::from_fn(|_| next_residue(&mut state)));
        let sb: [[[u64; 4]; 6]; 8] =
            core::array::from_fn(|_| core::array::from_fn(|_| next_residue(&mut state)));
        let start = Instant::now();
        let mut sink = [0u64; 4];
        for _ in 0..reps {
            for l in 0..8 {
                let products =
                    core::array::from_fn(|index| SosProduct::new(&sa[l][index], &sb[l][index]));
                let r = sos6(products);
                sink[0] ^= r[0];
            }
            black_box(&sink);
        }
        black_box(sink);
        let scalar_ns = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!("scalar sos6 x8 (8 components): {scalar_ns:.2} ns per 8 components");
        std::println!("ifma sos_mac speedup: {:.2}x", scalar_ns / ifma_ns);
    }

    #[test]
    #[ignore = "manual: cargo test --release --features std -- --ignored ifma_mul034 --nocapture"]
    fn ifma_mul034_cost_probe() {
        use crate::{Fp2, Fp6, Fp12};
        use std::hint::black_box;
        use std::time::Instant;

        let mut state = 0x0f0f_1234_dead_c0deu64;
        let mut rfp = || Fp(next_residue(&mut state));
        let mut rfp2 = || Fp2::new(rfp(), rfp());
        let f0 = Fp12::new(
            Fp6::new(rfp2(), rfp2(), rfp2()),
            Fp6::new(rfp2(), rfp2(), rfp2()),
        );
        let (c0, c3, c4) = (rfp2(), rfp2(), rfp2());
        let reps = 500_000usize;

        // Scalar tower op (the real six-`sosd6` `mul_by_034`).
        let mut f = f0;
        let start = Instant::now();
        for _ in 0..reps {
            f.mul_by_034_assign(black_box(c0), black_box(c3), black_box(c4));
            black_box(&f);
        }
        black_box(f);
        let scalar_ns = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!("scalar mul_by_034_assign: {scalar_ns:.2} ns");

        // IFMA envelope any 12-component wiring pays: two 8-lane groups, each 6
        // A-loads + 6 B-loads (the radix-52 conversions) + one sos_mac(6) + one
        // store. Dummy operands; isolates the conversion+kernel cost from the
        // exact gather.
        let mk = |s: &mut u64| -> [Fp; 8] { core::array::from_fn(|_| Fp(next_residue(s))) };
        let a_src: Vec<[Fp; 8]> = (0..12).map(|_| mk(&mut state)).collect();
        let b_src: Vec<[Fp; 8]> = (0..12).map(|_| mk(&mut state)).collect();
        let mut sink = [Fp::ZERO; 8];
        let start = Instant::now();
        for _ in 0..reps {
            for g in 0..2 {
                let av: [FpVec8; 6] = core::array::from_fn(|i| FpVec8::load(&a_src[g * 6 + i]));
                let bv: [FpVec8; 6] = core::array::from_fn(|i| FpVec8::load(&b_src[g * 6 + i]));
                let r = FpVec8::sos_mac(black_box(&av), black_box(&bv)).store();
                sink[0] += r[0];
            }
            black_box(&sink);
        }
        black_box(sink);
        let ifma_ns = start.elapsed().as_nanos() as f64 / reps as f64;
        std::println!("ifma mul_by_034 envelope (24 loads + 2 sos_mac + 2 store): {ifma_ns:.2} ns");
        std::println!(
            "ifma/scalar: {:.2}x (< 1 means IFMA wins)",
            ifma_ns / scalar_ns
        );
    }

    #[test]
    #[ignore = "manual: cargo test --release --features std -- --ignored ifma_fp2_steady --nocapture"]
    fn ifma_fp2_steadystate() {
        use crate::Fp2;
        use std::hint::black_box;
        use std::time::Instant;

        // Steady-state cost of a tower Fp2 mul when operands are ALREADY in the
        // radix-52 domain (the multi-pairing case: convert 8 pairings in once,
        // run the whole Miller loop 8-wide, convert out once). Each lane is an
        // independent pairing, so there is no cross-lane gather and no per-op
        // conversion -- exactly the envelope a fully 8-wide loop pays.
        let mut state = 0x2222_3333_4444_5555u64;
        let n = 512usize;
        let load_n = |s: &mut u64| -> Vec<FpVec8> {
            (0..n)
                .map(|_| FpVec8::load(&core::array::from_fn(|_| Fp(next_residue(s)))))
                .collect()
        };
        let (va0, va1, vb0, vb1) = (
            load_n(&mut state),
            load_n(&mut state),
            load_n(&mut state),
            load_n(&mut state),
        );
        let zero = FpVec8::load(&[Fp::ZERO; 8]);
        let reps = 3_000usize;

        // 8-wide Fp2 mul: real = a0*b0 - a1*b1, imag = a0*b1 + a1*b0.
        let mut sink = zero;
        let start = Instant::now();
        for _ in 0..reps {
            for k in 0..n {
                let nb1 = zero.sub(&vb1[k]);
                let real = FpVec8::sos_mac(&[va0[k], va1[k]], &[vb0[k], nb1]);
                let imag = FpVec8::sos_mac(&[va0[k], va1[k]], &[vb1[k], vb0[k]]);
                sink = sink.add(&real).add(&imag);
            }
            black_box(&sink);
        }
        black_box(sink.store());
        let ifma_ns = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
        std::println!("ifma8 fp2 mul (radix-52 steady state): {ifma_ns:.2} ns per 8 Fp2 muls");

        // Scalar baseline: eight tower Fp2 muls over the same value stream.
        let mut s2 = 0x2222_3333_4444_5555u64;
        let fp2s = |s: &mut u64| -> Vec<Fp2> {
            (0..8 * n)
                .map(|_| Fp2::new(Fp(next_residue(s)), Fp(next_residue(s))))
                .collect()
        };
        let sa = fp2s(&mut s2);
        let sb = fp2s(&mut s2);
        let mut sout = sa.clone();
        let start = Instant::now();
        for _ in 0..reps {
            for k in 0..8 * n {
                sout[k] = black_box(sa[k]) * black_box(sb[k]);
            }
            black_box(&sout[0]);
        }
        black_box(sout[0]);
        let scalar_ns = start.elapsed().as_nanos() as f64 / (reps * n) as f64;
        std::println!("scalar fp2 mul x8: {scalar_ns:.2} ns per 8 Fp2 muls");
        std::println!(
            "ifma/scalar: {:.2}x (< 1 means IFMA wins)",
            ifma_ns / scalar_ns
        );
    }

    #[test]
    #[ignore = "manual IFMA microbenchmark: cargo test --release -- --ignored ifma_micro --nocapture"]
    fn ifma_micro_throughput() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut state = 0x5eed_1f3a_9c0f_fee1u64;
        let n = 1024usize;
        let scalar_a: Vec<Fp> = (0..8 * n).map(|_| Fp(next_residue(&mut state))).collect();
        let scalar_b: Vec<Fp> = (0..8 * n).map(|_| Fp(next_residue(&mut state))).collect();
        let vec_a: Vec<FpVec8> = (0..n)
            .map(|k| FpVec8::load(scalar_a[8 * k..8 * k + 8].try_into().unwrap()))
            .collect();
        let vec_b: Vec<FpVec8> = (0..n)
            .map(|k| FpVec8::load(scalar_b[8 * k..8 * k + 8].try_into().unwrap()))
            .collect();
        let reps = 2_000usize;

        let report = |name: &str, total_muls8: usize, elapsed_ns: f64| {
            std::println!(
                "{name}: {:.2} ns per 8 muls ({:.2} ns/mul)",
                elapsed_ns / total_muls8 as f64,
                elapsed_ns / (8 * total_muls8) as f64,
            );
        };

        // Kernel-only independent throughput: array sweep, no conversions.
        let mut out = vec_a.clone();
        let start = Instant::now();
        for _ in 0..reps {
            for k in 0..n {
                out[k] = black_box(&vec_a[k]).mul(black_box(&vec_b[k]));
            }
        }
        black_box(out[0].store());
        report(
            "ifma8 mul, independent sweep",
            reps * n,
            start.elapsed().as_nanos() as f64,
        );

        // Scalar backend independent throughput over the same value stream.
        let mut sout = scalar_a.clone();
        let start = Instant::now();
        for _ in 0..reps {
            for k in 0..8 * n {
                sout[k] = black_box(scalar_a[k]) * black_box(scalar_b[k]);
            }
        }
        black_box(sout[0]);
        report(
            "scalar mul, independent sweep",
            reps * n,
            start.elapsed().as_nanos() as f64,
        );

        // Dependent-chain latency.
        let chain = 200_000usize;
        let mut acc = vec_a[0];
        let start = Instant::now();
        for _ in 0..chain {
            acc = acc.mul(black_box(&vec_b[0]));
        }
        black_box(acc.store());
        std::println!(
            "ifma8 mul, dependent chain: {:.2} ns per 8 muls",
            start.elapsed().as_nanos() as f64 / chain as f64
        );
        let mut sacc = scalar_a[0];
        let start = Instant::now();
        for _ in 0..chain {
            sacc *= black_box(scalar_b[0]);
        }
        black_box(sacc);
        let per_mul = start.elapsed().as_nanos() as f64 / chain as f64;
        std::println!(
            "scalar mul, dependent chain: {per_mul:.2} ns per mul (x8 = {:.2})",
            8.0 * per_mul
        );

        // Realistic batch shape: conversions amortized over one batched
        // mixed addition (11 muls + 7 subs + 8 conversion muls + repack).
        let mut points_x = [Fp::ZERO; 8];
        let mut points_y = [Fp::ZERO; 8];
        let mut bx = [Fp::ZERO; 8];
        let mut by = [Fp::ZERO; 8];
        let mut bz = [Fp::ZERO; 8];
        bx.copy_from_slice(&scalar_a[..8]);
        by.copy_from_slice(&scalar_a[8..16]);
        bz.copy_from_slice(&scalar_a[16..24]);
        points_x.copy_from_slice(&scalar_b[..8]);
        points_y.copy_from_slice(&scalar_b[8..16]);
        let madd_reps = 100_000usize;
        let start = Instant::now();
        for _ in 0..madd_reps {
            let (x3, y3, z3, _) = g1_madd_batch8(
                black_box(&bx),
                black_box(&by),
                black_box(&bz),
                black_box(&points_x),
                black_box(&points_y),
            );
            bx = x3;
            by = y3;
            bz = z3;
        }
        black_box((bx[0], by[0], bz[0]));
        std::println!(
            "ifma8 g1 madd batch (incl. conversions): {:.2} ns per 8 mixed adds",
            start.elapsed().as_nanos() as f64 / madd_reps as f64
        );

        let start = Instant::now();
        let mut b8: [(crate::G1Projective, crate::G1Affine); 8] = core::array::from_fn(|lane| {
            (
                crate::G1Projective {
                    x: bx[lane],
                    y: by[lane],
                    z: bz[lane],
                },
                crate::G1Affine {
                    x: points_x[lane],
                    y: points_y[lane],
                    infinity: false,
                },
            )
        });
        for _ in 0..madd_reps {
            for pair in &mut b8 {
                pair.0 = black_box(pair.0).add_mixed(black_box(pair.1));
            }
        }
        black_box(b8[0].0);
        std::println!(
            "scalar g1 madd x8: {:.2} ns per 8 mixed adds",
            start.elapsed().as_nanos() as f64 / madd_reps as f64
        );
    }
}
