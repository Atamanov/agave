//! Scalar field `Fr` of BN254 (Montgomery domain).
//!
//! Portable CIOS over the `limb` helpers on every target; limbs stay
//! canonical (`< r`). Inversion is variable-time (public inputs only), with
//! the Kaliski and divsteps engines cross-checked differentially.

use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::consts::{FR_MONT_ONE, FR_MONT_R2, R as MOD, R_INV};
use crate::limb::{self, adc, is_zero, mac, sbb};

/// Element of `Fr` in Montgomery form.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fr(pub(crate) [u64; 4]);

impl Fr {
    /// Additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    /// Multiplicative identity (`R mod r` in raw limbs).
    pub const ONE: Self = Self(FR_MONT_ONE);

    /// Integer -> Montgomery.
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        Self::from_raw([v, 0, 0, 0])
    }

    /// Little-endian raw limbs (non-Montgomery) -> Montgomery.
    #[inline]
    pub fn from_raw(limbs: [u64; 4]) -> Self {
        mont_mul(&limbs, &FR_MONT_R2)
    }

    /// Montgomery -> canonical little-endian limbs in `[0, r)`.
    #[inline]
    pub fn to_raw(self) -> [u64; 4] {
        mont_mul(&self.0, &[1, 0, 0, 0]).0
    }

    /// True iff the element is zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }

    /// `self^2`.
    #[inline]
    pub fn square(self) -> Self {
        mont_mul(&self.0, &self.0)
    }

    /// `2 * self`.
    #[inline]
    pub fn double(self) -> Self {
        Self(limb::add_mod(&self.0, &self.0, &MOD))
    }

    /// Additive inverse.
    #[inline]
    pub fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            Self(limb::sub_noborrow(&MOD, &self.0))
        }
    }

    /// Variable-time inversion for public inputs.
    ///
    /// This uses binary extended GCD. Do not call it with secret values.
    pub fn invert(self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        Some(Self::from_raw(invert_raw(self.to_raw())?))
    }

    /// `self^exp` for a little-endian limb exponent (variable-time).
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

    /// Canonical little-endian bytes to Montgomery form; `None` if `>= r`.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (bytes[i * 8 + j] as u64) << (8 * j);
            }
            limbs[i] = v;
        }
        if limb::gte(&limbs, &MOD) {
            return None;
        }
        Some(Self::from_raw(limbs))
    }

    /// Canonical big-endian scalar encoding to Montgomery form.
    #[inline]
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let limbs = [
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        ];
        if limb::gte(&limbs, &MOD) {
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

    /// Montgomery form to canonical big-endian scalar encoding.
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

    /// Parse a canonical integer string in the given radix; `None` if `>= r`.
    pub fn from_str_radix(s: &str, radix: u32) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let mut acc = [0u64; 4];
        for ch in s.chars() {
            let d = ch.to_digit(radix)? as u64;
            acc = mul_u64_add(&acc, radix as u64, d, &MOD)?;
        }
        if limb::gte(&acc, &MOD) {
            return None;
        }
        Some(Self::from_raw(acc))
    }

    /// Bits of canonical representation, LSB first.
    pub fn to_bits_le(self) -> [bool; 256] {
        let raw = self.to_raw();
        let mut bits = [false; 256];
        for i in 0..256 {
            bits[i] = ((raw[i / 64] >> (i % 64)) & 1) == 1;
        }
        bits
    }
}

/// Invert canonical limbs without entering or leaving Montgomery form.
///
/// Variable-time; intentional for this public-input verification engine.
/// Kaliski measured faster than divsteps on both Zen 4 (0.95x micro, and it
/// flipped the fr_batch_invert/1 e2e row vs MCL) and Apple M4 (0.77x micro),
/// so it is selected everywhere; the divsteps path stays compiled and
/// differentially tested as the per-arch alternate.
pub(crate) fn invert_raw(value: [u64; 4]) -> Option<[u64; 4]> {
    invert_raw_kaliski(value)
}

/// Bernstein-Yang divsteps62 path of [`invert_raw`]: the unselected per-arch
/// alternate, kept compiled and differentially tested on every target.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn invert_raw_divsteps(value: [u64; 4]) -> Option<[u64; 4]> {
    limb::invert_mod_vartime(&value, &MOD, R_INV)
}

/// Kaliski almost-inverse path of [`invert_raw`]: binary right-shift loop
/// producing `a^{-1}*2^k`, then one multiply by the precomputed `2^{256-k}`.
pub(crate) fn invert_raw_kaliski(value: [u64; 4]) -> Option<[u64; 4]> {
    limb::invert_mod_kaliski_vartime(&value, &MOD, R_INV, &crate::consts::FR_KALISKI_TBL)
}

/// Bit-serial binary extended GCD kept as the differential-test oracle for
/// [`invert_raw`].
#[cfg(test)]
fn invert_raw_reference(value: [u64; 4]) -> Option<[u64; 4]> {
    if is_zero(&value) {
        return None;
    }

    let mut u = value;
    let mut v = MOD;
    let mut x1 = [1, 0, 0, 0];
    let mut x2 = [0; 4];

    while !is_one_raw(&u) && !is_one_raw(&v) {
        while u[0] & 1 == 0 {
            shr1(&mut u);
            x1 = halve_mod(x1);
        }
        while v[0] & 1 == 0 {
            shr1(&mut v);
            x2 = halve_mod(x2);
        }
        if limb::gte(&u, &v) {
            u = limb::sub_noborrow(&u, &v);
            x1 = limb::sub_mod(&x1, &x2, &MOD);
        } else {
            v = limb::sub_noborrow(&v, &u);
            x2 = limb::sub_mod(&x2, &x1, &MOD);
        }
    }

    Some(if is_one_raw(&u) { x1 } else { x2 })
}

#[cfg(test)]
#[inline]
fn is_one_raw(value: &[u64; 4]) -> bool {
    value[0] == 1 && value[1] == 0 && value[2] == 0 && value[3] == 0
}

#[cfg(test)]
#[inline]
fn shr1(value: &mut [u64; 4]) {
    value[0] = (value[0] >> 1) | (value[1] << 63);
    value[1] = (value[1] >> 1) | (value[2] << 63);
    value[2] = (value[2] >> 1) | (value[3] << 63);
    value[3] >>= 1;
}

#[cfg(test)]
#[inline]
fn halve_mod(value: [u64; 4]) -> [u64; 4] {
    if value[0] & 1 == 0 {
        return [
            (value[0] >> 1) | (value[1] << 63),
            (value[1] >> 1) | (value[2] << 63),
            (value[2] >> 1) | (value[3] << 63),
            value[3] >> 1,
        ];
    }

    let (s0, c0) = adc(value[0], MOD[0], 0);
    let (s1, c1) = adc(value[1], MOD[1], c0);
    let (s2, c2) = adc(value[2], MOD[2], c1);
    let (s3, c3) = adc(value[3], MOD[3], c2);
    [
        (s0 >> 1) | (s1 << 63),
        (s1 >> 1) | (s2 << 63),
        (s2 >> 1) | (s3 << 63),
        (s3 >> 1) | (c3 << 63),
    ]
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
    let (s0, c0) = adc(out[0], add, 0);
    let (s1, c1) = adc(out[1], 0, c0);
    let (s2, c2) = adc(out[2], 0, c1);
    let (s3, c3) = adc(out[3], 0, c2);
    if c3 != 0 {
        return None;
    }
    let mut s = [s0, s1, s2, s3];
    while limb::gte(&s, modulus) {
        s = limb::sub_noborrow(&s, modulus);
    }
    Some(s)
}

#[inline]
pub(crate) fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> Fr {
    let mut t = [0u64; 5];
    for &b_limb in b {
        let mut carry = 0u64;
        for (j, &a_limb) in a.iter().enumerate() {
            let (lo, hi) = mac(a_limb, b_limb, t[j], carry);
            t[j] = lo;
            carry = hi;
        }
        let (lo, _) = adc(t[4], 0, carry);
        t[4] = lo;

        let m = t[0].wrapping_mul(R_INV);
        let (lo, mut carry) = mac(m, MOD[0], t[0], 0);
        debug_assert!(lo == 0);
        for j in 1..4 {
            let (lo, hi) = mac(m, MOD[j], t[j], carry);
            t[j - 1] = lo;
            carry = hi;
        }
        let (lo, hi) = adc(t[4], 0, carry);
        t[3] = lo;
        t[4] = hi;
    }
    let mut r = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || limb::gte(&r, &MOD) {
        let (d0, br0) = sbb(r[0], MOD[0], 0);
        let (d1, br1) = sbb(r[1], MOD[1], br0);
        let (d2, br2) = sbb(r[2], MOD[2], br1);
        let (d3, _) = sbb(r[3], MOD[3], br2);
        r = [d0, d1, d2, d3];
    }
    Fr(r)
}

impl PartialEq for Fr {
    fn eq(&self, other: &Self) -> bool {
        limb::ct_eq(&self.0, &other.0)
    }
}
impl Eq for Fr {}

impl Add for Fr {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(limb::add_mod(&self.0, &rhs.0, &MOD))
    }
}
impl AddAssign for Fr {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl Sub for Fr {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(limb::sub_mod(&self.0, &rhs.0, &MOD))
    }
}
impl SubAssign for Fr {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl Mul for Fr {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        mont_mul(&self.0, &rhs.0)
    }
}
impl MulAssign for Fr {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}
impl Neg for Fr {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Fr::neg(self)
    }
}

impl fmt::Display for Fr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_raw())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[test]
    fn inv() {
        let a = Fr::from_u64(42);
        assert_eq!(a * a.invert().unwrap(), Fr::ONE);
    }

    fn random_canonical(rng: &mut StdRng) -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        limbs[3] &= (1 << 62) - 1;
        while limb::gte(&limbs, &MOD) {
            limbs = limb::sub_noborrow(&limbs, &MOD);
        }
        limbs
    }

    fn inverse_edge_cases() -> alloc::vec::Vec<[u64; 4]> {
        let mut cases = alloc::vec::Vec::new();
        for small in 1u64..=64 {
            cases.push([small, 0, 0, 0]);
            let mut near_top = MOD;
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
                while limb::gte(&limbs, &MOD) {
                    limbs = limb::sub_noborrow(&limbs, &MOD);
                }
                limbs
            })
            .filter(|limbs| !is_zero(limbs))
            .collect()
    }

    #[test]
    fn invert_raw_matches_reference_on_edge_cases() {
        assert_eq!(invert_raw([0, 0, 0, 0]), None);
        assert_eq!(invert_raw_divsteps([0, 0, 0, 0]), None);
        assert_eq!(invert_raw_kaliski([0, 0, 0, 0]), None);
        assert_eq!(invert_raw([1, 0, 0, 0]), Some([1, 0, 0, 0]));
        assert_eq!(invert_raw_kaliski([1, 0, 0, 0]), Some([1, 0, 0, 0]));
        for limbs in inverse_edge_cases() {
            let inverse = invert_raw_divsteps(limbs).expect("nonzero");
            assert_eq!(
                inverse,
                invert_raw_reference(limbs).expect("nonzero"),
                "limbs={limbs:x?}"
            );
            assert_eq!(invert_raw_kaliski(limbs), Some(inverse), "limbs={limbs:x?}");
            assert_eq!(invert_raw(limbs), Some(inverse), "limbs={limbs:x?}");
            assert!(limb::gt(&MOD, &inverse), "limbs={limbs:x?}");
        }
    }

    #[test]
    fn invert_raw_matches_reference_on_random_stream() {
        let count = if cfg!(debug_assertions) {
            10_000
        } else {
            100_000
        };
        let mut rng = StdRng::seed_from_u64(0x1057_1e57_ba5e_f1e1);
        for _ in 0..count {
            let limbs = random_canonical(&mut rng);
            if is_zero(&limbs) {
                continue;
            }
            let inverse = invert_raw_divsteps(limbs).expect("nonzero");
            assert_eq!(
                inverse,
                invert_raw_reference(limbs).expect("nonzero"),
                "limbs={limbs:x?}"
            );
            assert_eq!(invert_raw_kaliski(limbs), Some(inverse), "limbs={limbs:x?}");
        }
    }

    #[test]
    fn invert_roundtrips_random_values() {
        let mut rng = StdRng::seed_from_u64(0xfeed_babe_0123_4567);
        for _ in 0..10_000 {
            let limbs = random_canonical(&mut rng);
            let value = Fr::from_raw(limbs);
            if value.is_zero() {
                continue;
            }
            assert_eq!(value * value.invert().expect("nonzero"), Fr::ONE);
            let raw = value.to_raw();
            let kaliski = invert_raw_kaliski(raw).expect("nonzero");
            assert_eq!(kaliski, invert_raw_divsteps(raw).expect("nonzero"));
            assert_eq!(value * Fr::from_raw(kaliski), Fr::ONE);
        }
    }

    #[test]
    #[ignore = "manual latency microbenchmark: cargo test --release -- --ignored micro --nocapture"]
    fn invert_raw_micro_latency() {
        use std::hint::black_box;
        use std::time::Instant;

        let mut state = 0x243f_6a88_85a3_08d3u64;
        let values: alloc::vec::Vec<[u64; 4]> = (0..4096)
            .map(|_| {
                let mut limbs = [0u64; 4];
                for limb in &mut limbs {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *limb = state;
                }
                limbs[3] &= (1 << 62) - 1;
                while limb::gte(&limbs, &MOD) {
                    limbs = limb::sub_noborrow(&limbs, &MOD);
                }
                limbs
            })
            .filter(|limbs| !is_zero(limbs))
            .collect();

        let rounds = 64usize;
        let measure = |name: &str, invert: &dyn Fn([u64; 4]) -> Option<[u64; 4]>| {
            let mut acc = 0u64;
            for value in &values {
                acc ^= invert(black_box(*value)).unwrap()[0];
            }
            let start = Instant::now();
            for _ in 0..rounds {
                for value in &values {
                    acc ^= invert(black_box(*value)).unwrap()[0];
                }
            }
            let elapsed = start.elapsed();
            std::println!(
                "{name}: {:.1} ns/op (acc={acc})",
                elapsed.as_nanos() as f64 / (rounds * values.len()) as f64
            );
        };
        measure(
            "fr invert_raw_divsteps (word-level gcd)",
            &invert_raw_divsteps,
        );
        measure(
            "fr invert_raw_kaliski (almost inverse)",
            &invert_raw_kaliski,
        );
        measure(
            "fr invert_raw_reference (bit-serial)",
            &invert_raw_reference,
        );
    }
}
