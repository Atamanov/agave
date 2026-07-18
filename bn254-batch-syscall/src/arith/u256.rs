//! Fixed-width u64-limb helpers for the Barrett step of the GLV split.
//!
//! Every helper is exact integer arithmetic on little-endian limbs; the GLV
//! caller guarantees the bounds each function assumes. Unit tests compare
//! against independent u128-column and `BigInt` oracles.

/// Little-endian limbs 4..6 (bits 256..384) of `s * m`; the callers'
/// products are < 2^384 so nothing above limb 5 is ever set.
#[inline]
pub(crate) fn mul_hi_256(s: &[u64; 4], m: &[u64; 3]) -> u128 {
    let mut prod = [0u64; 8];
    for (i, &si) in s.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &mj) in m.iter().enumerate() {
            let t = prod[i + j] as u128 + si as u128 * mj as u128 + carry;
            prod[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut idx = i + 3;
        while carry != 0 {
            let t = prod[idx] as u128 + carry;
            prod[idx] = t as u64;
            carry = t >> 64;
            idx += 1;
        }
    }
    prod[4] as u128 | ((prod[5] as u128) << 64)
}

/// Full 256-bit product of two u128s as little-endian u64 limbs.
#[inline]
pub(crate) fn mul_u128(a: u128, b: u128) -> [u64; 4] {
    const MASK: u128 = (1 << 64) - 1;
    let (a0, a1) = (a & MASK, a >> 64);
    let (b0, b1) = (b & MASK, b >> 64);
    let ll = a0 * b0;
    let mid = (ll >> 64) + ((a0 * b1) & MASK) + ((a1 * b0) & MASK);
    let high = a1 * b1 + ((a0 * b1) >> 64) + ((a1 * b0) >> 64) + (mid >> 64);
    [ll as u64, mid as u64, high as u64, (high >> 64) as u64]
}

/// `acc += v`, discarding any carry out of limb 3 (the callers' sums stay
/// below 2^256).
#[inline]
pub(crate) fn add_u128_into(acc: &mut [u64; 4], v: u128) {
    let vl = [v as u64, (v >> 64) as u64, 0, 0];
    let mut carry = 0u128;
    for (a, &b) in acc.iter_mut().zip(vl.iter()) {
        let t = *a as u128 + b as u128 + carry;
        *a = t as u64;
        carry = t >> 64;
    }
}

/// `a - b` assuming `a >= b` (guaranteed by the decomposition bounds).
#[inline]
pub(crate) fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for ((o, &ai), &bi) in out.iter_mut().zip(a).zip(b) {
        let (t1, b1) = ai.overflowing_sub(bi);
        let (t2, b2) = t1.overflowing_sub(borrow);
        *o = t2;
        borrow = (b1 | b2) as u64;
    }
    out
}

#[inline]
pub(crate) fn geq_u256(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for (&ai, &bi) in a.iter().rev().zip(b.iter().rev()) {
        if ai != bi {
            return ai > bi;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_ff::{BigInt, BigInteger},
        ark_std::rand::Rng,
    };

    fn rng() -> impl Rng {
        crate::test_utils::rng()
    }

    /// Independent schoolbook oracle: full 7-limb product accumulated per
    /// output column, a different shape from the carry-chained implementation.
    fn mul_oracle(s: &[u64; 4], m: &[u64; 3]) -> [u64; 7] {
        let mut out = [0u64; 7];
        let mut carry_in = 0u128;
        for (k, limb) in out.iter_mut().enumerate() {
            // column sum fits u128 plus a small spill tracked separately
            let mut col = carry_in;
            let mut spill = 0u128;
            for (i, &si) in s.iter().enumerate() {
                for (j, &mj) in m.iter().enumerate() {
                    if i + j == k {
                        let (sum, overflow) = col.overflowing_add(si as u128 * mj as u128);
                        col = sum;
                        spill += u128::from(overflow);
                    }
                }
            }
            *limb = col as u64;
            carry_in = (col >> 64) | (spill << 64);
        }
        out
    }

    #[test]
    fn test_mul_hi_256_matches_column_oracle() {
        let mut rng = rng();
        let mut cases = vec![
            ([0u64; 4], [0u64; 3]),
            ([u64::MAX; 4], [u64::MAX; 3]),
            ([1, 0, 0, 0], [u64::MAX, u64::MAX, u64::MAX]),
        ];
        for _ in 0..512 {
            cases.push((
                core::array::from_fn(|_| rng.r#gen()),
                core::array::from_fn(|_| rng.r#gen()),
            ));
        }
        for (s, m) in cases {
            let oracle = mul_oracle(&s, &m);
            let expected = oracle[4] as u128 | ((oracle[5] as u128) << 64);
            assert_eq!(mul_hi_256(&s, &m), expected);
        }
    }

    #[test]
    fn test_mul_u128_matches_column_oracle() {
        let mut rng = rng();
        let mut cases = vec![(0u128, 0u128), (u128::MAX, u128::MAX), (1, u128::MAX)];
        for _ in 0..512 {
            cases.push((rng.r#gen(), rng.r#gen()));
        }
        for (a, b) in cases {
            let s = [a as u64, (a >> 64) as u64, 0, 0];
            let m = [b as u64, (b >> 64) as u64, 0];
            let oracle = mul_oracle(&s, &m);
            assert_eq!(&mul_u128(a, b)[..], &oracle[..4], "a = {a}, b = {b}");
        }
    }

    #[test]
    fn test_add_sub_geq_match_bigint() {
        let mut rng = rng();
        for _ in 0..512 {
            let a: [u64; 4] = core::array::from_fn(|_| rng.r#gen());
            let b: [u64; 4] = core::array::from_fn(|_| rng.r#gen());
            let (big_a, big_b) = (BigInt(a), BigInt(b));
            assert_eq!(geq_u256(&a, &b), big_a >= big_b);
            let (hi, lo) = if geq_u256(&a, &b) { (a, b) } else { (b, a) };
            let mut diff = BigInt(hi);
            assert!(!diff.sub_with_borrow(&BigInt(lo)));
            assert_eq!(sub_u256(&hi, &lo), diff.0);
            // add_u128_into vs BigInt add over a carry-free prefix
            let v: u128 = rng.r#gen::<u128>() >> 1;
            let mut base = a;
            base[3] >>= 2; // headroom so the discarded-carry contract holds
            let mut acc = base;
            add_u128_into(&mut acc, v);
            let mut big = BigInt(base);
            assert!(!big.add_with_carry(&BigInt([v as u64, (v >> 64) as u64, 0, 0])));
            assert_eq!(acc, big.0);
        }
        assert!(geq_u256(&[1, 2, 3, 4], &[1, 2, 3, 4]));
    }
}
