//! Fixed-width u64-limb helpers for the Barrett step of the GLV split.
//!
//! Every helper is exact integer arithmetic on little-endian limbs; the GLV
//! caller guarantees the bounds each function assumes. Unit tests compare
//! against independent u128-column and `BigInt` oracles.

/// Little-endian limbs 4..6 (bits 256..384) of `s * m`; the callers'
/// products are < 2^384 so nothing above limb 5 is ever set.
#[inline]
pub(crate) fn mul_hi_256(s: &[u64; 4], m: &[u64; 3]) -> Option<u128> {
    let mut prod = [0u64; 8];
    for (i, &si) in s.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &mj) in m.iter().enumerate() {
            let index = i.checked_add(j)?;
            let limb = prod.get_mut(index)?;
            let t = u128::from(*limb)
                .checked_add(u128::from(si).checked_mul(u128::from(mj))?)?
                .checked_add(carry)?;
            *limb = t as u64;
            carry = t >> 64;
        }
        let mut index = i.checked_add(m.len())?;
        while carry != 0 {
            let limb = prod.get_mut(index)?;
            let t = u128::from(*limb).checked_add(carry)?;
            *limb = t as u64;
            carry = t >> 64;
            index = index.checked_add(1)?;
        }
    }
    let high = u128::from(*prod.get(4)?) | (u128::from(*prod.get(5)?) << 64);
    Some(high)
}

/// Full 256-bit product of two u128s as little-endian u64 limbs.
#[inline]
pub(crate) fn mul_u128(a: u128, b: u128) -> Option<[u64; 4]> {
    const MASK: u128 = (1 << 64) - 1;
    let (a0, a1) = (a & MASK, a >> 64);
    let (b0, b1) = (b & MASK, b >> 64);
    let ll = a0.checked_mul(b0)?;
    let a0_b1 = a0.checked_mul(b1)?;
    let a1_b0 = a1.checked_mul(b0)?;
    let mid = (ll >> 64)
        .checked_add(a0_b1 & MASK)?
        .checked_add(a1_b0 & MASK)?;
    let high = a1
        .checked_mul(b1)?
        .checked_add(a0_b1 >> 64)?
        .checked_add(a1_b0 >> 64)?
        .checked_add(mid >> 64)?;
    Some([ll as u64, mid as u64, high as u64, (high >> 64) as u64])
}

/// Add `v` and reject a carry above bit 255.
#[inline]
pub(crate) fn add_u128_into(acc: &mut [u64; 4], v: u128) -> Option<()> {
    let vl = [v as u64, (v >> 64) as u64, 0, 0];
    let mut carry = 0u128;
    for (a, &b) in acc.iter_mut().zip(vl.iter()) {
        let t = u128::from(*a)
            .checked_add(u128::from(b))?
            .checked_add(carry)?;
        *a = t as u64;
        carry = t >> 64;
    }
    (carry == 0).then_some(())
}

/// Subtract `b` from `a` and reject an underflow.
#[inline]
pub(crate) fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 4]> {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for ((o, &ai), &bi) in out.iter_mut().zip(a).zip(b) {
        let (t1, b1) = ai.overflowing_sub(bi);
        let (t2, b2) = t1.overflowing_sub(borrow);
        *o = t2;
        borrow = u64::from(b1 | b2);
    }
    (borrow == 0).then_some(out)
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
                    if i.checked_add(j) == Some(k) {
                        let product = u128::from(si).checked_mul(u128::from(mj)).unwrap();
                        let (sum, overflow) = col.overflowing_add(product);
                        col = sum;
                        spill = spill.checked_add(u128::from(overflow)).unwrap();
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
            let [_, _, _, _, low, high, _] = oracle;
            let expected = u128::from(low) | (u128::from(high) << 64);
            assert_eq!(mul_hi_256(&s, &m), Some(expected));
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
            let [o0, o1, o2, o3, _, _, _] = oracle;
            assert_eq!(
                mul_u128(a, b).unwrap(),
                [o0, o1, o2, o3],
                "a = {a}, b = {b}"
            );
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
            assert_eq!(sub_u256(&hi, &lo), Some(diff.0));
            // add_u128_into vs BigInt add over a carry-free prefix
            let v: u128 = rng.r#gen::<u128>() >> 1;
            let mut base = a;
            let [_, _, _, top] = &mut base;
            *top >>= 2; // Keep enough headroom for the checked addition.
            let mut acc = base;
            add_u128_into(&mut acc, v).unwrap();
            let mut big = BigInt(base);
            assert!(!big.add_with_carry(&BigInt([v as u64, (v >> 64) as u64, 0, 0])));
            assert_eq!(acc, big.0);
        }
        assert!(geq_u256(&[1, 2, 3, 4], &[1, 2, 3, 4]));
        assert_eq!(sub_u256(&[0; 4], &[1, 0, 0, 0]), None);
    }
}
