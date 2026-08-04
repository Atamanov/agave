//! Typed non-adjacent-form recoding for variable-time scalar multiplication.
//!
//! Digit validity is a type invariant: `WnafDigit`'s checked constructor
//! makes every nonzero digit odd and small enough for its width's
//! odd-multiple table, so table indexing cannot go out of bounds, and
//! width/table-size agreement is const-asserted. Serves the G1/G2 scalar
//! multiplications and the MSM recoders.

use crate::{fr::Fr, g1::G1Projective, g2::G2Projective};

mod sealed {
    pub trait Group {}
}

mod digit {
    use super::table_size;

    /// One width-`WIDTH` NAF digit.
    ///
    /// The field is private even from the parent recoder. Its checked
    /// constructor makes every nonzero value odd and small enough for the
    /// width's odd-multiple table.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(transparent)]
    pub(crate) struct WnafDigit<const WIDTH: usize>(i8);

    impl<const WIDTH: usize> WnafDigit<WIDTH> {
        pub(crate) const ZERO: Self = Self(0);

        #[inline(always)]
        pub(super) fn from_signed_odd(value: i16) -> Self {
            let largest = (1i16 << (WIDTH - 1)) - 1;
            assert!(
                value != 0 && value & 1 != 0 && (-largest..=largest).contains(&value),
                "invalid signed wNAF digit"
            );
            Self(value as i8)
        }

        #[inline(always)]
        pub(crate) const fn is_zero(self) -> bool {
            self.0 == 0
        }

        #[inline(always)]
        pub(crate) const fn is_negative(self) -> bool {
            self.0 < 0
        }

        #[inline(always)]
        pub(crate) fn table_index(self) -> Option<usize> {
            if self.is_zero() {
                return None;
            }
            let index = (self.0.unsigned_abs() as usize) >> 1;
            debug_assert!(index < table_size(WIDTH));
            Some(index)
        }

        #[cfg(test)]
        pub(super) const fn raw(self) -> i8 {
            self.0
        }
    }
}

pub(crate) use digit::WnafDigit;

/// Fixed-capacity LSB-first wNAF digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct WnafDigits<const WIDTH: usize, const CAPACITY: usize>(
    [WnafDigit<WIDTH>; CAPACITY],
);

impl<const WIDTH: usize, const CAPACITY: usize> WnafDigits<WIDTH, CAPACITY> {
    pub(crate) const ZERO: Self = Self([WnafDigit::ZERO; CAPACITY]);

    #[inline(always)]
    pub(crate) const fn digit(&self, bit: usize) -> WnafDigit<WIDTH> {
        self.0[bit]
    }
}

#[inline(always)]
const fn table_size(width: usize) -> usize {
    assert!(width >= 2 && width <= 8, "wNAF width must fit an i8 digit");
    1usize << (width - 2)
}

/// Compile-time relationship between digit width and odd-multiple table size.
#[inline(always)]
const fn assert_table_size<const WIDTH: usize, const TABLE: usize>() {
    assert!(
        TABLE == table_size(WIDTH),
        "wNAF table size disagrees with width"
    );
}

// These are deliberately const-evaluated: an invalid table declaration fails
// compilation rather than becoming a release-only out-of-bounds possibility.
const _: () = assert_table_size::<4, 4>();
const _: () = assert_table_size::<5, 8>();

#[derive(Clone, Copy)]
struct ScalarWords<const LIMBS: usize> {
    limbs: [u64; LIMBS],
    /// One carry bit above `limbs`; signed recoding can transiently turn an
    /// all-ones scalar into `2^(64*LIMBS)` before the mandatory right shift.
    high: u64,
}

impl<const LIMBS: usize> From<[u64; LIMBS]> for ScalarWords<LIMBS> {
    #[inline(always)]
    fn from(limbs: [u64; LIMBS]) -> Self {
        Self { limbs, high: 0 }
    }
}

impl<const LIMBS: usize> ScalarWords<LIMBS> {
    #[inline(always)]
    fn is_zero(self) -> bool {
        self.high == 0 && self.limbs.iter().all(|limb| *limb == 0)
    }

    #[inline(always)]
    fn is_odd(self) -> bool {
        self.limbs[0] & 1 == 1
    }

    #[inline(always)]
    fn low_window<const WIDTH: usize>(self) -> u16 {
        (self.limbs[0] & ((1u64 << WIDTH) - 1)) as u16
    }

    #[inline(always)]
    fn add_small(&mut self, value: u16) {
        let mut carry = value as u64;
        for limb in &mut self.limbs {
            let (sum, next) = limb.overflowing_add(carry);
            *limb = sum;
            carry = next as u64;
        }
        debug_assert!(self.high + carry <= 1);
        self.high += carry;
    }

    #[inline(always)]
    fn sub_small(&mut self, value: u16) {
        let mut borrow = value as u64;
        for limb in &mut self.limbs {
            let (difference, next) = limb.overflowing_sub(borrow);
            *limb = difference;
            borrow = next as u64;
        }
        debug_assert!(self.high >= borrow);
        self.high -= borrow;
    }

    #[inline(always)]
    fn shr1(&mut self) {
        let mut carry = self.high << 63;
        self.high = 0;
        for limb in self.limbs.iter_mut().rev() {
            let next = *limb << 63;
            *limb = (*limb >> 1) | carry;
            carry = next;
        }
    }
}

#[inline(always)]
fn recode<const LIMBS: usize, const WIDTH: usize, const CAPACITY: usize>(
    mut scalar: ScalarWords<LIMBS>,
) -> (WnafDigits<WIDTH, CAPACITY>, usize) {
    const {
        assert!(LIMBS != 0, "wNAF scalar must have at least one limb");
        assert!(WIDTH >= 2 && WIDTH <= 8, "wNAF width must fit an i8 digit");
        assert!(
            CAPACITY > LIMBS * 64,
            "wNAF storage needs one terminal carry digit"
        );
    }
    let radix = 1u16 << WIDTH;
    let half = radix >> 1;
    let mut output = [WnafDigit::ZERO; CAPACITY];
    let mut length = 0usize;

    for digit in &mut output {
        if scalar.is_zero() {
            break;
        }
        if scalar.is_odd() {
            let residue = scalar.low_window::<WIDTH>();
            let signed = if residue >= half {
                residue as i16 - radix as i16
            } else {
                residue as i16
            };
            if signed < 0 {
                scalar.add_small((-signed) as u16);
            } else {
                scalar.sub_small(signed as u16);
            }
            *digit = WnafDigit::from_signed_odd(signed);
        }
        scalar.shr1();
        length += 1;
    }
    assert!(scalar.is_zero(), "wNAF capacity did not consume scalar");
    (WnafDigits(output), length)
}

#[inline(always)]
pub(crate) fn recode_u128<const WIDTH: usize, const CAPACITY: usize>(
    scalar: u128,
) -> (WnafDigits<WIDTH, CAPACITY>, usize) {
    recode::<2, WIDTH, CAPACITY>([scalar as u64, (scalar >> 64) as u64].into())
}

pub(crate) trait WnafGroup: sealed::Group + Copy {
    fn identity() -> Self;
    fn double(self) -> Self;
    fn add(self, other: Self) -> Self;
    fn neg(self) -> Self;
}

macro_rules! impl_wnaf_group {
    ($group:ty) => {
        impl sealed::Group for $group {}

        impl WnafGroup for $group {
            #[inline(always)]
            fn identity() -> Self {
                <$group>::identity()
            }

            #[inline(always)]
            fn double(self) -> Self {
                <$group>::double(self)
            }

            #[inline(always)]
            fn add(self, other: Self) -> Self {
                core::ops::Add::add(self, other)
            }

            #[inline(always)]
            fn neg(self) -> Self {
                core::ops::Neg::neg(self)
            }
        }
    };
}

impl_wnaf_group!(G1Projective);
impl_wnaf_group!(G2Projective);

/// Generic evaluator monomorphized for G1/G2 and the selected window.
#[inline]
pub(crate) fn mul_group<
    G: WnafGroup,
    const WIDTH: usize,
    const TABLE: usize,
    const CAPACITY: usize,
>(
    base: G,
    scalar: Fr,
) -> G {
    const { assert_table_size::<WIDTH, TABLE>() };

    let mut table = [G::identity(); TABLE];
    table[0] = base;
    let double = base.double();
    for i in 1..TABLE {
        table[i] = table[i - 1].add(double);
    }

    let (digits, _) = recode::<4, WIDTH, CAPACITY>(scalar.to_raw().into());
    let mut accumulator = G::identity();
    for bit in (0..CAPACITY).rev() {
        accumulator = accumulator.double();
        let digit = digits.digit(bit);
        if let Some(index) = digit.table_index() {
            let point = if digit.is_negative() {
                table[index].neg()
            } else {
                table[index]
            };
            accumulator = accumulator.add(point);
        }
    }
    accumulator
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary_mul<G: WnafGroup>(base: G, mut scalar: u64) -> G {
        let mut accumulator = G::identity();
        let mut multiple = base;
        while scalar != 0 {
            if scalar & 1 == 1 {
                accumulator = accumulator.add(multiple);
            }
            multiple = multiple.double();
            scalar >>= 1;
        }
        accumulator
    }

    fn check_table_boundaries<const WIDTH: usize, const TABLE: usize>() {
        const { assert_table_size::<WIDTH, TABLE>() };
        let largest = (1i16 << (WIDTH - 1)) - 1;
        for raw in -largest..=largest {
            if raw != 0 && raw & 1 == 0 {
                continue;
            }
            let digit = if raw == 0 {
                WnafDigit::ZERO
            } else {
                WnafDigit::<WIDTH>::from_signed_odd(raw)
            };
            if raw == 0 {
                assert_eq!(digit.table_index(), None);
            } else {
                assert_eq!(
                    digit.table_index(),
                    Some((raw.unsigned_abs() as usize) >> 1)
                );
                assert!(digit.table_index().unwrap() < TABLE);
            }
        }
        assert_eq!(
            WnafDigit::<WIDTH>::from_signed_odd(largest).table_index(),
            Some(TABLE - 1)
        );
        assert_eq!(
            WnafDigit::<WIDTH>::from_signed_odd(-largest).table_index(),
            Some(TABLE - 1)
        );
    }

    fn check_full_width_terminal_carry<const WIDTH: usize>() {
        let (digits, length) = recode_u128::<WIDTH, 129>(u128::MAX);
        assert_eq!(length, 129);
        assert_eq!(digits.digit(0).raw(), -1);
        assert!((1..128).all(|bit| digits.digit(bit).is_zero()));
        assert_eq!(digits.digit(128).raw(), 1);
    }

    fn check_exhaustive_u16<const WIDTH: usize, const TABLE: usize>() {
        const { assert_table_size::<WIDTH, TABLE>() };
        for original in 0u128..=u16::MAX as u128 {
            let (digits, length) = recode_u128::<WIDTH, 129>(original);
            let mut positive = 0u128;
            let mut negative = 0u128;
            for bit in 0..length {
                let digit = digits.digit(bit);
                let raw = digit.raw();
                if raw == 0 {
                    continue;
                }
                assert_eq!(raw & 1, 1, "width={WIDTH} scalar={original}");
                assert!(digit.table_index().unwrap() < TABLE);
                let value = (raw.unsigned_abs() as u128) << bit;
                if raw < 0 {
                    negative += value;
                } else {
                    positive += value;
                }
            }
            assert_eq!(positive - negative, original, "width={WIDTH}");
        }
    }

    #[test]
    fn exhaustive_width_4_digits_and_table_boundaries() {
        check_table_boundaries::<4, 4>();
        check_exhaustive_u16::<4, 4>();
    }

    #[test]
    fn exhaustive_width_5_digits_and_table_boundaries() {
        check_table_boundaries::<5, 8>();
        check_exhaustive_u16::<5, 8>();
    }

    #[test]
    fn full_width_terminal_carry_is_preserved() {
        check_full_width_terminal_carry::<2>();
        check_full_width_terminal_carry::<3>();
        check_full_width_terminal_carry::<4>();
        check_full_width_terminal_carry::<5>();
        check_full_width_terminal_carry::<6>();
        check_full_width_terminal_carry::<7>();
        check_full_width_terminal_carry::<8>();
    }

    #[test]
    fn generic_group_evaluator_matches_binary_reference() {
        let g1 = G1Projective::generator();
        for scalar in 0..=255 {
            assert_eq!(
                mul_group::<G1Projective, 4, 4, 257>(g1, Fr::from_u64(scalar)).to_affine(),
                binary_mul(g1, scalar).to_affine()
            );
        }

        let g2 = crate::g2::G2Affine::arkworks_generator().to_curve();
        for scalar in [0, 1, 3, 7, 8, 15, 16, 31, 127, 255] {
            assert_eq!(
                mul_group::<G2Projective, 4, 4, 257>(g2, Fr::from_u64(scalar)).to_affine(),
                binary_mul(g2, scalar).to_affine()
            );
        }
    }
}
