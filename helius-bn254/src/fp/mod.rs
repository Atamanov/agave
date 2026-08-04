//! Base field `Fp` of BN254 (Montgomery domain).
//!
//! Owns the canonicity invariant (limbs always `< p`; `from_raw_canonical`
//! const-asserts it) and the backend roster: which Montgomery leaf serves a
//! build is a compile-time property of the target, selected here once for
//! the whole crate, never a runtime dispatch.

use alloc::{string::String, vec::Vec};

#[cfg(all(
    target_arch = "aarch64",
    target_vendor = "apple",
    any(not(feature = "force-portable"), test)
))]
pub(crate) mod aarch64;
// Generated schedule-DSL leaf (ADR 0001); the cfg is emitted by build.rs
// exactly when it assembled the generated x86-64 kernel (Linux, bmi2+adx).
#[cfg(all(helius_mont4_x86_64_adx, any(not(feature = "force-portable"), test)))]
pub(crate) mod x86_64;
// AVX-512 IFMA 8-way batch kernels; cfg emitted by build.rs exactly when
// avx512f+avx512ifma are compile-time target features (HELIUS_AVX512_IFMA
// forces or denies the gate). Batch-phase tier, not a mont_backend.
#[cfg(helius_avx512_ifma)]
pub(crate) mod avx512ifma;
#[cfg(any(
    not(target_arch = "aarch64"),
    not(target_vendor = "apple"),
    feature = "force-portable",
    test,
))]
pub(crate) mod portable;
pub(crate) mod sos;

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::consts::{MONT_ONE, MONT_R2, P, derive};
use crate::limb::{self, is_zero};

/// Strict little-endian `a < b`, const-evaluable so [`Fp::from_raw_canonical`]
/// can assert canonicity at compile time for const callers.
#[inline(always)]
const fn lt4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false
}

/// `(p+1)/4 = (p >> 2) + 1` (exact: `p = 3 mod 4`, asserted): [`Fp::sqrt`]
/// exponent, since `a^((p+1)/4)` squares to `a^((p+1)/2) = +/-a`.
const SQRT_EXP: [u64; 4] = derive::add4_small(derive::shr4(P, 2), 1);
const _: () = assert!(P[0] & 3 == 3);
const _: () = assert!(derive::eq4(
    SQRT_EXP,
    [
        0x4f082305b61f3f52,
        0x65e05aa45a1c72a3,
        0x6e14116da0605617,
        0x0c19139cb84c680a,
    ]
));

// Keep `cfg(test)` structurally visible to the fail-closed source-surface audit;
// the timing harness must never inflate the production-Rust denominator.
#[cfg(test)]
#[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple"),
    helius_mont4_x86_64_adx,
))]
mod backend_compare_tests;

#[cfg(all(
    target_arch = "aarch64",
    target_vendor = "apple",
    not(feature = "force-portable"),
))]
use aarch64 as mont_backend;
#[cfg(all(helius_mont4_x86_64_adx, not(feature = "force-portable")))]
use x86_64 as mont_backend;
// Portable is the backend wherever no assembly tier exists, and always under
// the explicit force-portable benchmark/test tier. Never a silent fallback:
// the assembly tiers above are compile-time properties of the target.
#[cfg(any(
    feature = "force-portable",
    not(any(
        all(target_arch = "aarch64", target_vendor = "apple"),
        helius_mont4_x86_64_adx,
    )),
))]
use portable as mont_backend;

/// Element of `Fp` in Montgomery form: value represents `n * R mod p`.
// repr(C): the fp6 kernel ABI reads Fp6/Fp2/Fp as 24 contiguous limbs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Fp(pub(crate) [u64; 4]);

impl Fp {
    /// Additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    /// Multiplicative identity (`R mod p` in raw limbs).
    pub const ONE: Self = Self(MONT_ONE);
    /// Multiplicative inverse of two.
    pub const INV_TWO: Self = Self(crate::consts::half_mod(MONT_ONE, P));

    /// Wrap limbs already in canonical Montgomery form (`limbs < p`).
    ///
    /// Limbs `>= p` break representation equality (`PartialEq` compares raw
    /// limbs) and, if both operands of a product are non-canonical, the
    /// kernel output bound, so canonicity is asserted here: free for const
    /// callers (checked during const evaluation), one 4-limb compare at
    /// runtime.
    ///
    /// A non-canonical constant fails to compile:
    ///
    /// ```compile_fail
    /// // p itself is not canonical Montgomery form.
    /// const BAD: helius_bn254::Fp =
    ///     helius_bn254::Fp::from_raw_canonical(helius_bn254::consts::P);
    /// let _ = BAD;
    /// ```
    ///
    /// # Panics
    ///
    /// Panics when `limbs >= p`.
    #[inline]
    pub const fn from_raw_canonical(limbs: [u64; 4]) -> Self {
        assert!(
            lt4(&limbs, &P),
            "Fp::from_raw_canonical: limbs must be canonical (< p)"
        );
        Self(limbs)
    }

    /// Restore explicitly little-endian Montgomery limbs from authenticated
    /// backend state, rejecting representations outside the canonical bound.
    #[inline]
    pub const fn from_montgomery_limbs(limbs: [u64; 4]) -> Option<Self> {
        if lt4(&limbs, &P) {
            Some(Self(limbs))
        } else {
            None
        }
    }

    /// Return this element's canonical Montgomery limbs for backend state.
    #[inline]
    pub const fn to_montgomery_limbs(self) -> [u64; 4] {
        self.0
    }

    /// Return the same value in the IFMA backend's five-limb radix-52
    /// Montgomery domain (`value * 2^260 mod p`).
    #[inline]
    pub fn to_ifma_montgomery_limbs52(self) -> [u64; 5] {
        let shifted = self.double().double().double().double().0;
        const MASK52: u64 = (1u64 << 52) - 1;
        [
            shifted[0] & MASK52,
            ((shifted[0] >> 52) | (shifted[1] << 12)) & MASK52,
            ((shifted[1] >> 40) | (shifted[2] << 24)) & MASK52,
            ((shifted[2] >> 28) | (shifted[3] << 36)) & MASK52,
            shifted[3] >> 16,
        ]
    }

    /// Test-only escape hatch: wrap limbs with no canonicity check. Exists
    /// solely to drive kernels past their `< p` contract in controlled tests.
    #[cfg(test)]
    pub(crate) const fn from_raw_unchecked(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Integer -> Montgomery.
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        Self::from_raw([v, 0, 0, 0])
    }

    /// Little-endian raw limbs (non-Montgomery) -> Montgomery.
    ///
    /// Accepts any `limbs < 2^256` and returns the canonical Montgomery form
    /// of `limbs mod p`. Limbs reduce below p first (at most 5 subtractions,
    /// `2^256 < 6p`). The kernel contract requires both operands below p: the
    /// x86 dual-chain schedule miscomputes for larger `a` (interpreter-caught,
    /// hardware-confirmed), so kernels never see unreduced input.
    #[inline]
    pub fn from_raw(mut limbs: [u64; 4]) -> Self {
        while limb::gte(&limbs, &P) {
            limbs = limb::sub_noborrow(&limbs, &P);
        }
        mont_backend::mont_mul(&limbs, &MONT_R2)
    }

    /// Montgomery -> canonical little-endian limbs in `[0, p)`.
    #[inline]
    pub fn to_raw(self) -> [u64; 4] {
        mont_backend::mont_mul(&self.0, &[1, 0, 0, 0]).0
    }

    /// True iff the element is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }

    /// True iff the element is one.
    #[inline(always)]
    pub fn is_one(&self) -> bool {
        limb::ct_eq(&self.0, &MONT_ONE)
    }

    /// `2 * self`.
    #[inline(always)]
    pub fn double(self) -> Self {
        limb_add(self, self)
    }

    /// `self^2` via the dedicated squaring kernel.
    #[inline(always)]
    pub fn square(self) -> Self {
        mont_backend::mont_sqr(&self.0)
    }

    /// Variable-time modular inverse.
    ///
    /// Do not call it with secret values; this engine only handles public
    /// inputs. Kaliski measured faster than divsteps on both Zen 4 and Apple
    /// M4 (0.76-0.92x micro), so it is selected everywhere; the divsteps path
    /// stays compiled and differentially tested as the per-arch alternate.
    pub fn invert(self) -> Option<Self> {
        self.invert_kaliski()
    }

    /// Divsteps62 path of [`Self::invert`], via the canonical domain: the
    /// unselected per-arch alternate, kept compiled and differentially tested
    /// on every target, and the fallback of [`Self::invert_kaliski`].
    pub(crate) fn invert_divsteps(self) -> Option<Self> {
        let inverse = limb::invert_mod_vartime(&self.to_raw(), &P, crate::consts::P_INV)?;
        Some(Self::from_raw(inverse))
    }

    /// Kaliski path of [`Self::invert`], straight in the Montgomery domain:
    /// the table entry carries `C = 2^512`, so
    /// `(aR)^{-1}*2^k * 2^{768-k} * 2^{-256} = a^{-1}*R` in one multiply with no
    /// to_raw/from_raw round trip.
    pub(crate) fn invert_kaliski(self) -> Option<Self> {
        let (almost, k) = limb::kaliski_almost_inverse(&self.0, &P)?;
        // k in [253, 507] by the Kaliski bound; fall back to the divsteps path
        // (domain-correct on its own) rather than panic on a consensus path.
        let Some(correction) = k
            .checked_sub(limb::KALISKI_K_MIN)
            .and_then(|index| crate::consts::FP_KALISKI_TBL.get(index as usize))
        else {
            debug_assert!(false, "Kaliski k={k} out of table range");
            return self.invert_divsteps();
        };
        Some(Self(almost) * Self(*correction))
    }

    /// `a^{(p+1)/4}` square root for `p = 3 (mod 4)`.
    pub fn sqrt(self) -> Option<Self> {
        let s = self.pow_raw(&SQRT_EXP);
        if s.square() == self { Some(s) } else { None }
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

    /// Little-endian limb exponent (canonical).
    pub fn pow_raw(self, exp: &[u64; 4]) -> Self {
        let mut acc = Self::ONE;
        for i in (0..4).rev() {
            for j in (0..64).rev() {
                acc = acc.square();
                if (exp[i] >> j) & 1 == 1 {
                    acc *= self;
                }
            }
        }
        acc
    }

    /// Frobenius endomorphism `a -> a^p`; the identity on Fp.
    pub fn frobenius_map(self) -> Self {
        self
    }

    /// Canonical little-endian bytes to Montgomery form; `None` if `>= p`.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (bytes[i * 8 + j] as u64) << (8 * j);
            }
            limbs[i] = v;
        }
        if limb::gte(&limbs, &P) {
            return None;
        }
        Some(Self::from_raw(limbs))
    }

    /// Canonical alt_bn128 big-endian encoding to Montgomery form.
    #[inline]
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let limbs = limb::limbs_from_be_bytes(bytes);
        if limb::gte(&limbs, &P) {
            return None;
        }
        Some(Self::from_raw(limbs))
    }

    /// Montgomery form to canonical little-endian bytes.
    pub fn to_bytes_le(self) -> [u8; 32] {
        let raw = self.to_raw();
        let mut out = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                out[i * 8 + j] = (raw[i] >> (8 * j)) as u8;
            }
        }
        out
    }

    /// Montgomery form to canonical alt_bn128 big-endian encoding.
    #[inline]
    pub fn to_bytes_be(self) -> [u8; 32] {
        let raw = self.to_raw();
        let mut out = [0u8; 32];
        for (i, limb) in raw.iter().enumerate() {
            let start = 24 - 8 * i;
            out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Parse a canonical integer string in the given radix; `None` if `>= p`.
    pub fn from_str_radix(s: &str, radix: u32) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut acc = [0u64; 4];
        for ch in s.chars() {
            let d = ch.to_digit(radix)? as u64;
            acc = mul_u64_add(&acc, radix as u64, d, &P)?;
        }
        if limb::gte(&acc, &P) {
            return None;
        }
        Some(Self::from_raw(acc))
    }
}

fn mul_u64_add(a: &[u64; 4], k: u64, add: u64, modulus: &[u64; 4]) -> Option<[u64; 4]> {
    let mut carry = 0u128;
    let mut out = [0u64; 4];
    for i in 0..4 {
        let t = (a[i] as u128) * (k as u128) + carry;
        out[i] = t as u64;
        carry = t >> 64;
    }
    if carry != 0 {
        return None;
    }
    let (s0, c0) = limb::adc(out[0], add, 0);
    let (s1, c1) = limb::adc(out[1], 0, c0);
    let (s2, c2) = limb::adc(out[2], 0, c1);
    let (s3, c3) = limb::adc(out[3], 0, c2);
    if c3 != 0 {
        return None;
    }
    let mut s = [s0, s1, s2, s3];
    // a < modulus on entry, so s = a*k + add < (k+1)*modulus: at most k
    // subtractions.
    while limb::gte(&s, modulus) {
        s = limb::sub_noborrow(&s, modulus);
    }
    Some(s)
}

#[inline]
fn limb_add(a: Fp, b: Fp) -> Fp {
    Fp(limb::add_mod(&a.0, &b.0, &P))
}

#[inline]
fn limb_sub(a: Fp, b: Fp) -> Fp {
    Fp(limb::sub_mod(&a.0, &b.0, &P))
}

impl PartialEq for Fp {
    fn eq(&self, other: &Self) -> bool {
        limb::ct_eq(&self.0, &other.0)
    }
}
impl Eq for Fp {}

impl Add for Fp {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        limb_add(self, rhs)
    }
}
impl AddAssign for Fp {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Fp {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        limb_sub(self, rhs)
    }
}
impl SubAssign for Fp {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Fp {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        mont_backend::mont_mul(&self.0, &rhs.0)
    }
}
impl MulAssign for Fp {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Fp {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            Self(limb::sub_noborrow(&P, &self.0))
        }
    }
}

impl fmt::Display for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.to_raw();
        write!(f, "{}", limbs_to_dec(&raw))
    }
}

fn limbs_to_dec(limbs: &[u64; 4]) -> String {
    let mut n = limbs.to_vec();
    if n.iter().all(|&x| x == 0) {
        return "0".into();
    }
    let mut digits = Vec::new();
    while n.iter().any(|&x| x != 0) {
        let mut rem = 0u64;
        for x in n.iter_mut().rev() {
            let cur = (*x as u128) + ((rem as u128) << 64);
            *x = (cur / 10) as u64;
            rem = (cur % 10) as u64;
        }
        digits.push(b'0' + rem as u8);
    }
    digits.reverse();
    digits.into_iter().map(char::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_mul() {
        let a = Fp::from_u64(7);
        assert_eq!(a * Fp::ONE, a);
        assert_eq!(a + a, Fp::from_u64(14));
    }

    #[test]
    fn mul_inv() {
        let a = Fp::from_u64(123456789);
        let inv = a.invert().unwrap();
        assert_eq!(a * inv, Fp::ONE);
    }

    /// from_raw must reduce unreduced limbs before the kernel: the x86
    /// dual-chain schedule miscomputes for a >= p (found on Zen 4). Runs on
    /// every backend so any tier regression surfaces in its own CI.
    #[test]
    fn from_raw_reduces_unreduced_limbs_on_every_backend() {
        use rand::{RngCore, SeedableRng, rngs::StdRng};
        let reduce = |mut limbs: [u64; 4]| {
            while limb::gte(&limbs, &P) {
                limbs = limb::sub_noborrow(&limbs, &P);
            }
            limbs
        };
        let mut cases = alloc::vec![
            P,
            [P[0] + 1, P[1], P[2], P[3]],
            [u64::MAX; 4],
            // Zen 4 failing probe shape: high limb far above p.
            [
                0x57d8_57d8_57d8_57d8,
                u64::MAX,
                u64::MAX,
                0xff5f_576d_0000_0000
            ],
        ];
        let mut rng = StdRng::seed_from_u64(0x0f0f_5eed_2026_0718);
        for _ in 0..500 {
            cases.push(core::array::from_fn(|_| rng.next_u64()));
        }
        for limbs in cases {
            let via_unreduced = Fp::from_raw(limbs);
            let via_reduced = Fp::from_raw(reduce(limbs));
            assert_eq!(via_unreduced, via_reduced, "limbs={limbs:x?}");
            assert_eq!(via_unreduced.to_raw(), reduce(limbs), "limbs={limbs:x?}");
        }
    }

    #[test]
    fn invert_matches_fermat_oracle() {
        use rand::{RngCore, SeedableRng, rngs::StdRng};
        // p - 2 (no borrow: P[0] > 2).
        let mut fermat_exp = P;
        fermat_exp[0] -= 2;
        assert_eq!(Fp::ZERO.invert(), None);
        assert_eq!(Fp::ZERO.invert_divsteps(), None);
        assert_eq!(Fp::ZERO.invert_kaliski(), None);
        let mut rng = StdRng::seed_from_u64(0x0b57_ac1e_5eed_0002);
        for _ in 0..500 {
            let mut limbs = [0u64; 4];
            for limb in &mut limbs {
                *limb = rng.next_u64();
            }
            limbs[3] &= (1 << 62) - 1;
            while limb::gte(&limbs, &P) {
                limbs = limb::sub_noborrow(&limbs, &P);
            }
            let value = Fp::from_raw(limbs);
            if value.is_zero() {
                continue;
            }
            let inverse = value.invert().expect("nonzero");
            assert_eq!(inverse, value.pow_raw(&fermat_exp), "limbs={limbs:x?}");
            assert_eq!(value.invert_divsteps(), Some(inverse), "limbs={limbs:x?}");
            assert_eq!(value.invert_kaliski(), Some(inverse), "limbs={limbs:x?}");
            assert_eq!(value * inverse, Fp::ONE);
        }
    }

    #[test]
    fn from_str() {
        let s = "21888242871839275222246405745257275088696311157297823662689037894645226208582";
        let a = Fp::from_str_radix(s, 10).unwrap(); // p-1
        assert_eq!(a + Fp::ONE, Fp::ZERO);
    }

    #[test]
    fn sqrt_one() {
        assert_eq!(Fp::ONE.sqrt().unwrap(), Fp::ONE);
    }
}

#[cfg(test)]
mod mont_const_tests {
    use super::*;
    #[test]
    fn square_matches_mul() {
        let a = Fp::from_u64(0xdead_beef_cafe_babe);
        assert_eq!(a.square(), a * a);
        let b = Fp::from_raw([
            0x1234567890abcdef,
            0xfedcba0987654321,
            0x0f1e2d3c4b5a6978,
            0x1122334455667788,
        ]);
        assert_eq!(b.square(), b * b);
    }
    #[test]
    fn two_inv_mont() {
        let inv = Fp::from_raw_canonical([
            9781510331150239090,
            15059239858463337189,
            10331104244869713732,
            2249375503248834476,
        ]);
        let two = Fp::from_u64(2);
        assert_eq!(two * inv, Fp::ONE);
    }
    #[test]
    fn gamma1_mont_matches_from_raw() {
        let raw = [
            15423480562983756912u64,
            6652412619979170166,
            16769610461022161760,
            1334392721173227487,
        ];
        let via = Fp::from_raw(raw);
        let mont = Fp::from_raw_canonical([
            12653890742059813127,
            14585784200204367754,
            1278438861261381767,
            212598772761311868,
        ]);
        assert_eq!(via, mont);
    }

    #[test]
    fn from_raw_canonical_accepts_canonical_edges() {
        assert_eq!(Fp::from_raw_canonical(MONT_ONE), Fp::ONE);
        // p - 1: largest canonical limb pattern.
        let pm1 = limb::sub_noborrow(&P, &[1, 0, 0, 0]);
        assert_eq!(Fp::from_raw_canonical(pm1).0, pm1);
    }

    #[test]
    #[should_panic(expected = "canonical")]
    fn from_raw_canonical_rejects_p() {
        let _ = Fp::from_raw_canonical(P);
    }

    #[test]
    #[should_panic(expected = "canonical")]
    fn from_raw_canonical_rejects_above_p() {
        let _ = Fp::from_raw_canonical([u64::MAX; 4]);
    }
}
