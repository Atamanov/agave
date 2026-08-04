//! Four-limb little-endian arithmetic shared by `Fp` and `Fr`.
//!
//! Carry/borrow chains, modular add/sub, a generic CIOS product, and the two
//! variable-time inversion engines: Bernstein-Yang divsteps and the Kaliski
//! Montgomery inverse. Everything here is variable-time and admissible only
//! for public inputs; the no-overflow bound for each routine is documented
//! where it is relied on.

#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let (s1, c1) = a.overflowing_add(b);
    let (s2, c2) = s1.overflowing_add(carry);
    (s2, (c1 as u64) + (c2 as u64))
}

#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let (d1, b1) = a.overflowing_sub(b);
    let (d2, b2) = d1.overflowing_sub(borrow);
    (d2, (b1 as u64) + (b2 as u64))
}

/// `a * b + c + carry` -> (lo, hi) with full 128-bit product accumulated.
#[inline(always)]
pub fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    // `carrying_mul` exposes the independent low/high product to LLVM before
    // the serial carry chain. On AArch64 that lets instruction selection hoist
    // `mul`/`umulh` pairs instead of treating each row as one opaque `u128`
    // expression. The sum cannot overflow 128 bits by construction.
    let (lo, hi) = a.carrying_mul(b, 0);
    let (lo, c0) = lo.overflowing_add(c);
    let (lo, c1) = lo.overflowing_add(carry);
    (lo, hi + u64::from(c0) + u64::from(c1))
}

#[inline(always)]
pub fn gt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false
}

#[inline(always)]
pub fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    !gt(b, a)
}

// x86: bool-carry `carrying_add`/`borrowing_sub` chains lower to native
// adc/sbb runs; the u64-carry `adc`/`sbb` helpers rematerialize every carry
// through cmp/setb (~3x the code and instructions per reduction). aarch64
// lowers both forms identically (adcs/csel), verified neutral on M4.

/// x86: hide the modulus from const-prop. With P as immediates LLVM rewrites
/// `x - P` into `x + (2^256 - P)` limb-wise and loses the borrow chain
/// (cmp/setb/or per limb plus 10-byte movabs); a memory operand keeps sbb.
#[inline(always)]
fn opaque(m: &[u64; 4]) -> &[u64; 4] {
    #[cfg(target_arch = "x86_64")]
    {
        core::hint::black_box(m)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        m
    }
}

#[inline(always)]
pub fn sub_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let modulus = opaque(modulus);
    let (d0, br) = a[0].borrowing_sub(b[0], false);
    let (d1, br) = a[1].borrowing_sub(b[1], br);
    let (d2, br) = a[2].borrowing_sub(b[2], br);
    let (d3, br3) = a[3].borrowing_sub(b[3], br);
    // Branchless add-back (avoids mispredict on random field elements).
    let mask = 0u64.wrapping_sub(br3 as u64);
    let (s0, c) = d0.carrying_add(modulus[0] & mask, false);
    let (s1, c) = d1.carrying_add(modulus[1] & mask, c);
    let (s2, c) = d2.carrying_add(modulus[2] & mask, c);
    let (s3, _) = d3.carrying_add(modulus[3] & mask, c);
    [s0, s1, s2, s3]
}

#[inline(always)]
pub fn add_mod(a: &[u64; 4], b: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let modulus = opaque(modulus);
    let (s0, c) = a[0].carrying_add(b[0], false);
    let (s1, c) = a[1].carrying_add(b[1], c);
    let (s2, c) = a[2].carrying_add(b[2], c);
    let (s3, c3) = a[3].carrying_add(b[3], c);
    let (d0, br) = s0.borrowing_sub(modulus[0], false);
    let (d1, br) = s1.borrowing_sub(modulus[1], br);
    let (d2, br) = s2.borrowing_sub(modulus[2], br);
    let (d3, br3) = s3.borrowing_sub(modulus[3], br);
    // use reduced iff sum >= p (carry out or no borrow on s-p)
    let use_sub = c3 | !br3;
    let mask = 0u64.wrapping_sub(use_sub as u64);
    let nmask = !mask;
    [
        (d0 & mask) | (s0 & nmask),
        (d1 & mask) | (s1 & nmask),
        (d2 & mask) | (s2 & nmask),
        (d3 & mask) | (s3 & nmask),
    ]
}

#[inline(always)]
pub fn sub_noborrow(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (d0, br0) = sbb(a[0], b[0], 0);
    let (d1, br1) = sbb(a[1], b[1], br0);
    let (d2, br2) = sbb(a[2], b[2], br1);
    let (d3, _) = sbb(a[3], b[3], br2);
    [d0, d1, d2, d3]
}

#[inline(always)]
pub fn is_zero(a: &[u64; 4]) -> bool {
    (a[0] | a[1] | a[2] | a[3]) == 0
}

/// Limb-wise equality. Despite the `ct_` name this is variable-time by design
/// (the `&&` short-circuits): the crate is variable-time throughout and never
/// compares secrets.
#[inline(always)]
pub fn ct_eq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

const MASK62: u64 = (1 << 62) - 1;

/// Divstep transition matrix. Bounds: `|u| + |v| <= 2^62`, `|q| + |r| <= 2^62`,
/// `u*r - v*q = +/-2^62`.
struct Transition {
    u: i64,
    v: i64,
    q: i64,
    r: i64,
}

/// Variable-time modular inversion for odd `modulus` (public inputs only).
///
/// Bernstein-Yang divsteps ("safegcd", ePrint 2019/266) in the word-level
/// variable-time form (cf. libsecp256k1 `modinv64_var`): 62 exact divsteps per
/// round on the low limbs of `f`/`g`, with the accumulated 2x2 matrix applied
/// once per round to the full values and to the Bezout coefficients mod
/// `modulus`. `neg_mod_inv` is `-modulus^{-1} mod 2^64`. Returns the canonical
/// inverse in `[0, modulus)`, or `None` when `gcd(value, modulus) != 1`.
pub fn invert_mod_vartime(
    value: &[u64; 4],
    modulus: &[u64; 4],
    neg_mod_inv: u64,
) -> Option<[u64; 4]> {
    if is_zero(value) {
        return None;
    }
    debug_assert!(modulus[0].wrapping_mul(neg_mod_inv) == u64::MAX);

    // Invariants (mod modulus): f = value*d and g = value*e, with f, g signed
    // two's-complement `len`-limb values and d, e canonical in [0, modulus).
    let mut f = [modulus[0], modulus[1], modulus[2], modulus[3], 0];
    let mut g = [value[0], value[1], value[2], value[3], 0];
    let mut d = [0u64; 4];
    let mut e = [1u64, 0, 0, 0];
    // Top-bit-set inputs need a fifth limb to read as non-negative.
    let mut len: usize = if (modulus[3] | value[3]) >> 63 != 0 {
        5
    } else {
        4
    };
    let mut eta: i64 = -1; // eta = -delta of the divstep formulation
    let mut rounds = 0u32;

    loop {
        let t = divsteps62_var(&mut eta, f[0], g[0]);
        apply_shift62(&mut f, &mut g, &t, len);
        rounds += 1;
        // 254-bit inputs need at most ceil(741/62) = 12 rounds (safegcd bound).
        debug_assert!(rounds <= 16);
        if g == [0; 5] {
            // Only f survives past this round, so only the d row is needed.
            update_bezout_final(&mut d, &e, &t, modulus, neg_mod_inv);
            break;
        }
        update_bezout(&mut d, &mut e, &t, modulus, neg_mod_inv);
        // Magnitudes shrink by ~62 bits per round; drop redundant sign limbs.
        while len > 1
            && f[len - 1] == sign_extension(f[len - 2])
            && g[len - 1] == sign_extension(g[len - 2])
        {
            len -= 1;
        }
    }

    // g = 0, so f = +/-gcd(value, modulus) and value*d = f (mod modulus).
    if f == [1, 0, 0, 0, 0] {
        Some(d)
    } else if f == [u64::MAX; 5] {
        debug_assert!(!is_zero(&d));
        Some(sub_noborrow(modulus, &d))
    } else {
        None
    }
}

/// 62 divsteps on the low 64 bits of `f`/`g`; returns the transition matrix.
///
/// Coefficient bounds (no overflow): with `i` steps remaining the invariant
/// `|u| + |v| <= 2^(62-i)` and `|q| + |r| <= 2^(62-i)` holds at the top of the
/// loop, because a batched cancellation of `z` bits multiplies the row sums by
/// at most `2^z` while consuming `z` steps. All transients stay below 2^62.
fn divsteps62_var(eta: &mut i64, f0: u64, g0: u64) -> Transition {
    let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
    let (mut f, mut g) = (f0, g0);
    let mut i = 62u32;
    loop {
        // A sentinel bit caps the batched shift at the remaining step budget.
        let zeros = (g | (u64::MAX << i)).trailing_zeros();
        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        *eta -= i64::from(zeros);
        i -= zeros;
        if i == 0 {
            break;
        }
        debug_assert!(f & 1 == 1 && g & 1 == 1);
        if *eta < 0 {
            *eta = -*eta;
            let tmp = f;
            f = g;
            g = tmp.wrapping_neg();
            let tmp = u;
            u = q;
            q = tmp.wrapping_neg();
            let tmp = v;
            v = r;
            r = tmp.wrapping_neg();
        }
        // Cancel min(eta + 1, i, 6) low bits of g by adding w*f, with
        // w = -g/f mod 2^limit via the identity f*(f^2 - 2) = -f^{-1} (mod 64) for
        // odd f. The eta + 1 cap keeps this equivalent to plain divsteps; the
        // i cap keeps the step budget exact.
        let limit = (*eta + 1).min(i64::from(i)) as u32;
        debug_assert!((1..=62).contains(&limit));
        let mask = (u64::MAX >> (64 - limit)) & 63;
        let w = f
            .wrapping_mul(g)
            .wrapping_mul(f.wrapping_mul(f).wrapping_sub(2))
            & mask;
        g = g.wrapping_add(f.wrapping_mul(w));
        q = q.wrapping_add(u.wrapping_mul(w));
        r = r.wrapping_add(v.wrapping_mul(w));
        debug_assert!(g & mask == 0);
    }
    let t = Transition {
        u: u as i64,
        v: v as i64,
        q: q as i64,
        r: r as i64,
    };
    debug_assert!(t.u.unsigned_abs() + t.v.unsigned_abs() <= 1 << 62);
    debug_assert!(t.q.unsigned_abs() + t.r.unsigned_abs() <= 1 << 62);
    debug_assert!(
        (t.u as i128 * t.r as i128 - t.v as i128 * t.q as i128).unsigned_abs() == 1 << 62
    );
    t
}

#[inline(always)]
fn sign_extension(limb: u64) -> u64 {
    ((limb as i64) >> 63) as u64
}

/// `(f, g) <- ((u*f + v*g) >> 62, (q*f + r*g) >> 62)` over `len`-limb
/// two's-complement values, sign-extended to five limbs. The row bounds
/// `|u| + |v| <= 2^62` and `|q| + |r| <= 2^62` keep every per-limb
/// accumulation inside i128; both combinations are divisible by 2^62 (exact by
/// divstep theory).
///
/// Dispatching to a const-length body lets LLVM fully unroll each case and
/// resolve the sign-extension branch at compile time (measured ~30% faster on
/// Zen 4 and ~2x on M4 vs the variable-length loop).
fn apply_shift62(f: &mut [u64; 5], g: &mut [u64; 5], t: &Transition, len: usize) {
    debug_assert!(t.u.unsigned_abs() + t.v.unsigned_abs() <= 1 << 62);
    debug_assert!(t.q.unsigned_abs() + t.r.unsigned_abs() <= 1 << 62);
    match len {
        4 => apply_shift62_fixed::<4>(f, g, t),
        3 => apply_shift62_fixed::<3>(f, g, t),
        2 => apply_shift62_fixed::<2>(f, g, t),
        1 => apply_shift62_fixed::<1>(f, g, t),
        _ => apply_shift62_fixed::<5>(f, g, t),
    }
}

#[inline(always)]
fn apply_shift62_fixed<const LEN: usize>(f: &mut [u64; 5], g: &mut [u64; 5], t: &Transition) {
    let mut wide_f = [0u64; 6];
    let mut wide_g = [0u64; 6];
    let mut carry_f: i128 = 0;
    let mut carry_g: i128 = 0;
    for i in 0..LEN {
        let (fi, gi) = if i + 1 == LEN {
            (i128::from(f[i] as i64), i128::from(g[i] as i64))
        } else {
            (i128::from(f[i]), i128::from(g[i]))
        };
        let acc_f = i128::from(t.u) * fi + i128::from(t.v) * gi + carry_f;
        let acc_g = i128::from(t.q) * fi + i128::from(t.r) * gi + carry_g;
        wide_f[i] = acc_f as u64;
        wide_g[i] = acc_g as u64;
        carry_f = acc_f >> 64;
        carry_g = acc_g >> 64;
    }
    wide_f[LEN] = carry_f as u64;
    wide_g[LEN] = carry_g as u64;
    debug_assert!(wide_f[0] & MASK62 == 0 && wide_g[0] & MASK62 == 0);
    for i in 0..LEN {
        f[i] = (wide_f[i] >> 62) | (wide_f[i + 1] << 2);
        g[i] = (wide_g[i] >> 62) | (wide_g[i + 1] << 2);
    }
    let ext_f = sign_extension(f[LEN - 1]);
    let ext_g = sign_extension(g[LEN - 1]);
    for i in LEN..5 {
        f[i] = ext_f;
        g[i] = ext_g;
    }
}

/// `(d, e) <- ((u*d + v*e) / 2^62 mod modulus, (q*d + r*e) / 2^62 mod modulus)`
/// with both results canonical in `[0, modulus)`.
///
/// Each division is exact after adding `k*modulus` with
/// `k = (row)*(-modulus^{-1}) mod 2^62` (Montgomery-style reduction). Bounds: the
/// row sums are at most 2^62 and d, e < modulus, so pre-shift magnitudes stay
/// below `2^63*modulus` (fits five limbs signed) and post-shift values lie in
/// `(-modulus, 2*modulus)`, fixed by one conditional correction.
fn update_bezout(
    d: &mut [u64; 4],
    e: &mut [u64; 4],
    t: &Transition,
    modulus: &[u64; 4],
    neg_mod_inv: u64,
) {
    let mut wide_d = [0u64; 5];
    let mut wide_e = [0u64; 5];
    let mut carry_d: i128 = 0;
    let mut carry_e: i128 = 0;
    for i in 0..4 {
        let (di, ei) = (i128::from(d[i]), i128::from(e[i]));
        let acc_d = i128::from(t.u) * di + i128::from(t.v) * ei + carry_d;
        let acc_e = i128::from(t.q) * di + i128::from(t.r) * ei + carry_e;
        wide_d[i] = acc_d as u64;
        wide_e[i] = acc_e as u64;
        carry_d = acc_d >> 64;
        carry_e = acc_e >> 64;
    }
    wide_d[4] = carry_d as u64;
    wide_e[4] = carry_e as u64;
    *d = reduce_shift62(&mut wide_d, modulus, neg_mod_inv);
    *e = reduce_shift62(&mut wide_e, modulus, neg_mod_inv);
}

/// `d <- (u*d + v*e) / 2^62 mod modulus`: the d row of [`update_bezout`] for
/// the final round, where the e row is dead.
fn update_bezout_final(
    d: &mut [u64; 4],
    e: &[u64; 4],
    t: &Transition,
    modulus: &[u64; 4],
    neg_mod_inv: u64,
) {
    let mut wide_d = [0u64; 5];
    let mut carry_d: i128 = 0;
    for i in 0..4 {
        let acc_d =
            i128::from(t.u) * i128::from(d[i]) + i128::from(t.v) * i128::from(e[i]) + carry_d;
        wide_d[i] = acc_d as u64;
        carry_d = acc_d >> 64;
    }
    wide_d[4] = carry_d as u64;
    *d = reduce_shift62(&mut wide_d, modulus, neg_mod_inv);
}

/// Montgomery-style exact `wide / 2^62 mod modulus` for a signed five-limb
/// value of magnitude below `2^62*modulus`; canonical result in `[0, modulus)`.
fn reduce_shift62(wide: &mut [u64; 5], modulus: &[u64; 4], neg_mod_inv: u64) -> [u64; 4] {
    let k = wide[0].wrapping_mul(neg_mod_inv) & MASK62;
    let mut mul_carry = 0u64;
    for i in 0..4 {
        let (lo, hi) = mac(k, modulus[i], wide[i], mul_carry);
        wide[i] = lo;
        mul_carry = hi;
    }
    wide[4] = wide[4].wrapping_add(mul_carry);
    debug_assert!(wide[0] & MASK62 == 0);
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = (wide[i] >> 62) | (wide[i + 1] << 2);
    }
    let top = ((wide[4] as i64) >> 62) as u64;
    debug_assert!(top == 0 || top == u64::MAX);
    // Branchless: a masked modulus add wraps negative values into [0, 2*modulus)
    // and `sub_mod` folds the result into [0, modulus).
    let (s0, carry0) = adc(out[0], modulus[0] & top, 0);
    let (s1, carry1) = adc(out[1], modulus[1] & top, carry0);
    let (s2, carry2) = adc(out[2], modulus[2] & top, carry1);
    let (s3, _) = adc(out[3], modulus[3] & top, carry2);
    let out = sub_mod(&[s0, s1, s2, s3], modulus, modulus);
    debug_assert!(gt(modulus, &out));
    out
}

/// Smallest `k` [`kaliski_almost_inverse`] can produce for a 254-bit modulus.
///
/// Kaliski's bound is `k in [n, 2n]` for an n-bit modulus; this implementation
/// elides the final iteration's paired halve/double (which cancels in the
/// correction), shifting the range to `[n-1, 2n-1] = [253, 507]`.
pub(crate) const KALISKI_K_MIN: u32 = 253;
/// Correction-table length: one entry per attainable `k` in `[253, 507]`.
pub(crate) const KALISKI_TBL_LEN: usize = 255;

/// Kaliski almost-inverse (phase 1 of the Montgomery inverse; Kaliski 1995,
/// "The Montgomery inverse and its applications"). For odd `modulus` m and
/// `0 < value < m` with `gcd(value, m) = 1`, returns
/// `(value^{-1}*2^k mod m, k)`; `None` for zero or a non-trivial gcd.
///
/// State `(u, v, r, s, k)` maintains, with `a = value`:
///   `u*s + v*r = m`  (exact over the integers),
///   `a*r = -u*2^k` and `a*s = v*2^k`  (mod m).
/// Each round strips the factors of two from whichever of u/v is even
/// (batched via trailing zeros, doubling the paired coefficient), then
/// replaces the larger of the two odd values by half the difference. The
/// exact identity bounds `r <= m/v` and `s <= m/u`, so r and s never leave
/// four limbs and the batched doublings cannot overflow. At exit `v = 0`,
/// `u = gcd(a, m)`; for `u = 1` the result `m - r = a^{-1}*2^k` lies in
/// `(0, m)` and `k in [KALISKI_K_MIN, KALISKI_K_MIN + KALISKI_TBL_LEN - 1]`.
pub(crate) fn kaliski_almost_inverse(
    value: &[u64; 4],
    modulus: &[u64; 4],
) -> Option<([u64; 4], u32)> {
    if is_zero(value) {
        return None;
    }
    debug_assert!(modulus[0] & 1 == 1);
    debug_assert!(gt(modulus, value));

    let mut u = *modulus;
    let mut v = *value;
    let mut r = [0u64; 4];
    let mut s = [1u64, 0, 0, 0];
    let mut k = 0u32;
    // Establish the round invariant (v odd); r = 0 makes its paired shift a
    // no-op, but k must still count these halvings.
    while v[0] & 1 == 0 {
        let sh = v[0].trailing_zeros().min(63);
        shr_short::<4>(&mut v, sh);
        k += sh;
    }
    // u and v only shrink; each stage hands off to the next-shorter active
    // length once both top limbs are zero (r and s grow, staying full-width:
    // measured faster than length-tracking them, which defeats unrolling).
    let done = kaliski_rounds::<4>(&mut u, &mut v, &mut r, &mut s, &mut k)
        || kaliski_rounds::<3>(&mut u, &mut v, &mut r, &mut s, &mut k)
        || kaliski_rounds::<2>(&mut u, &mut v, &mut r, &mut s, &mut k)
        || kaliski_rounds::<1>(&mut u, &mut v, &mut r, &mut s, &mut k);
    debug_assert!(done);

    if u != [1, 0, 0, 0] {
        return None;
    }
    debug_assert!(!is_zero(&r) && gt(modulus, &r));
    Some((sub_noborrow(modulus, &r), k))
}

/// Kaliski rounds over `CN` active limbs of u and v; both odd on entry and at
/// the top of every round. Returns `true` when v reaches zero, `false` when
/// both top active limbs are zero (shrink).
///
/// Each round does one subtraction and then strips the difference's trailing
/// zeros inside the taken arm (the difference of odds is always even). The
/// strip target is thereby arm-determined instead of re-derived from a parity
/// test at the loop top. Such a test mirrors the unpredictable arm choice and
/// measurably doubles the mispredicted branches per round.
#[inline(always)]
fn kaliski_rounds<const CN: usize>(
    u: &mut [u64; 4],
    v: &mut [u64; 4],
    r: &mut [u64; 4],
    s: &mut [u64; 4],
    k: &mut u32,
) -> bool {
    loop {
        if CN > 1 && (u[CN - 1] | v[CN - 1]) == 0 {
            return false;
        }
        // The two difference chains run independently (ILP); the borrow of
        // v - u picks the arm.
        let (d, borrow) = sub_short::<CN>(v, u);
        let (e, _) = sub_short::<CN>(u, v);
        if borrow == 0 {
            if is_zero_short::<CN>(&d) {
                return true;
            }
            copy_short::<CN>(v, &d);
            add4_assign(s, r);
            // Batched even steps: v >>= t pairs with r <<= t, k += t. The
            // shift is capped at 63; a whole-limb-zero tail loops again.
            loop {
                let sh = v[0].trailing_zeros().min(63);
                shr_short::<CN>(v, sh);
                shl4(r, sh);
                *k += sh;
                if v[0] & 1 == 1 {
                    break;
                }
            }
        } else {
            copy_short::<CN>(u, &e);
            add4_assign(r, s);
            loop {
                let sh = u[0].trailing_zeros().min(63);
                shr_short::<CN>(u, sh);
                shl4(s, sh);
                *k += sh;
                if u[0] & 1 == 1 {
                    break;
                }
            }
        }
    }
}

#[inline(always)]
fn shr_short<const CN: usize>(a: &mut [u64; 4], sh: u32) {
    debug_assert!((1..64).contains(&sh));
    for i in 0..CN - 1 {
        a[i] = (a[i] >> sh) | (a[i + 1] << (64 - sh));
    }
    a[CN - 1] >>= sh;
}

/// `a <<= sh` over four limbs. The exact identity `u*s + v*r = m` bounds the
/// shifted value below `m < 2^254`, so no bits are lost.
#[inline(always)]
fn shl4(a: &mut [u64; 4], sh: u32) {
    debug_assert!((1..64).contains(&sh));
    a[3] = (a[3] << sh) | (a[2] >> (64 - sh));
    a[2] = (a[2] << sh) | (a[1] >> (64 - sh));
    a[1] = (a[1] << sh) | (a[0] >> (64 - sh));
    a[0] <<= sh;
}

/// `a += b`; `r + s` never exceeds `2*modulus < 2^255`, the carry out is dead.
#[inline(always)]
fn add4_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = 0u64;
    for i in 0..4 {
        let (sum, c) = adc(a[i], b[i], carry);
        a[i] = sum;
        carry = c;
    }
    debug_assert!(carry == 0);
}

#[inline(always)]
fn sub_short<const CN: usize>(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..CN {
        let (diff, br) = sbb(a[i], b[i], borrow);
        out[i] = diff;
        borrow = br;
    }
    (out, borrow)
}

#[inline(always)]
fn copy_short<const CN: usize>(a: &mut [u64; 4], b: &[u64; 4]) {
    a[..CN].copy_from_slice(&b[..CN]);
}

#[inline(always)]
fn is_zero_short<const CN: usize>(a: &[u64; 4]) -> bool {
    let mut acc = 0u64;
    for &limb in a.iter().take(CN) {
        acc |= limb;
    }
    acc == 0
}

/// CIOS Montgomery product `a*b*2^{-256} mod modulus`, canonical output.
pub(crate) fn mont_mul_limbs(
    a: &[u64; 4],
    b: &[u64; 4],
    modulus: &[u64; 4],
    neg_mod_inv: u64,
) -> [u64; 4] {
    debug_assert!(modulus[0].wrapping_mul(neg_mod_inv) == u64::MAX);
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

        let m = t[0].wrapping_mul(neg_mod_inv);
        let (lo, mut carry) = mac(m, modulus[0], t[0], 0);
        debug_assert!(lo == 0);
        for j in 1..4 {
            let (lo, hi) = mac(m, modulus[j], t[j], carry);
            t[j - 1] = lo;
            carry = hi;
        }
        let (lo, hi) = adc(t[4], 0, carry);
        t[3] = lo;
        t[4] = hi;
    }
    let mut out = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || gte(&out, modulus) {
        out = sub_noborrow(&out, modulus);
    }
    out
}

/// Variable-time Kaliski Montgomery inverse for odd `modulus` (public inputs
/// only): almost-inverse plus one table-driven Montgomery multiply.
///
/// `table[k - KALISKI_K_MIN]` must hold `C*2^{256-k} mod modulus` for the
/// caller's domain constant C; the result is then `value^{-1}*C mod modulus`
/// (C = 1 corrects a canonical-domain inversion, C = 2^512 keeps a
/// Montgomery-domain input in Montgomery form). Returns `None` when
/// `gcd(value, modulus) != 1`.
///
/// The out-of-range-`k` fallback returns the plain inverse, so it is only
/// domain-correct for `C = 1` callers; Montgomery-domain callers with their
/// own tables must guard the range themselves.
pub(crate) fn invert_mod_kaliski_vartime(
    value: &[u64; 4],
    modulus: &[u64; 4],
    neg_mod_inv: u64,
    table: &[[u64; 4]; KALISKI_TBL_LEN],
) -> Option<[u64; 4]> {
    let (almost, k) = kaliski_almost_inverse(value, modulus)?;
    // k in [253, 507] by the elided-final-iteration Kaliski bound; if a bug
    // ever broke it, fall back to divsteps rather than panicking on a
    // consensus path (one predictable never-taken branch).
    let Some(correction) = k
        .checked_sub(KALISKI_K_MIN)
        .and_then(|index| table.get(index as usize))
    else {
        debug_assert!(false, "Kaliski k={k} outside [{KALISKI_K_MIN}, ..)");
        return invert_mod_vartime(value, modulus, neg_mod_inv);
    };
    Some(mont_mul_limbs(&almost, correction, modulus, neg_mod_inv))
}

#[cfg(test)]
mod tests {
    use super::mac;

    // BN254 Fr modulus, little-endian limbs.
    const FR_MOD: [u64; 4] = [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];

    fn neg_inv64(m0: u64) -> u64 {
        // Newton iteration for -m^{-1} mod 2^64 (m odd).
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        }
        inv.wrapping_neg()
    }

    fn random_inputs(n: usize) -> alloc::vec::Vec<[u64; 4]> {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        (0..n)
            .map(|_| {
                let mut limbs = [0u64; 4];
                for limb in &mut limbs {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *limb = state;
                }
                limbs[3] &= (1 << 62) - 1;
                while super::gte(&limbs, &FR_MOD) {
                    limbs = super::sub_noborrow(&limbs, &FR_MOD);
                }
                limbs
            })
            .filter(|limbs| !super::is_zero(limbs))
            .collect()
    }

    /// Per-round state captured from real inversions so each component can be
    /// replayed and timed in isolation.
    struct Round {
        eta: i64,
        f0: u64,
        g0: u64,
        t: (i64, i64, i64, i64),
        f: [u64; 5],
        g: [u64; 5],
        len: usize,
        d: [u64; 4],
        e: [u64; 4],
    }

    fn capture_rounds(inputs: &[[u64; 4]], neg_mod_inv: u64) -> alloc::vec::Vec<Round> {
        let mut rounds = alloc::vec::Vec::new();
        for value in inputs {
            let modulus = &FR_MOD;
            let mut f = [modulus[0], modulus[1], modulus[2], modulus[3], 0];
            let mut g = [value[0], value[1], value[2], value[3], 0];
            let mut d = [0u64; 4];
            let mut e = [1u64, 0, 0, 0];
            let mut len: usize = 4;
            let mut eta: i64 = -1;
            loop {
                let eta_in = eta;
                let (f_in, g_in, d_in, e_in) = (f, g, d, e);
                let t = super::divsteps62_var(&mut eta, f[0], g[0]);
                super::update_bezout(&mut d, &mut e, &t, modulus, neg_mod_inv);
                super::apply_shift62(&mut f, &mut g, &t, len);
                rounds.push(Round {
                    eta: eta_in,
                    f0: f_in[0],
                    g0: g_in[0],
                    t: (t.u, t.v, t.q, t.r),
                    f: f_in,
                    g: g_in,
                    len,
                    d: d_in,
                    e: e_in,
                });
                if g == [0; 5] {
                    break;
                }
                while len > 1
                    && f[len - 1] == super::sign_extension(f[len - 2])
                    && g[len - 1] == super::sign_extension(g[len - 2])
                {
                    len -= 1;
                }
            }
        }
        rounds
    }

    // ---- candidate inner-loop variants (all must produce identical output) ----

    type DsFn = fn(&mut i64, u64, u64) -> (i64, i64, i64, i64);

    fn ds_base(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let t = super::divsteps62_var(eta, f0, g0);
        (t.u, t.v, t.q, t.r)
    }

    /// Hoisted -f^-1 mod 64, recomputed only at swaps; branchy swap.
    fn ds_hoist(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut f, mut g) = (f0, g0);
        let mut mfinv = f.wrapping_mul(f.wrapping_mul(f).wrapping_sub(2));
        let mut i = 62u32;
        loop {
            let zeros = (g | (u64::MAX << i)).trailing_zeros();
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            *eta -= i64::from(zeros);
            i -= zeros;
            if i == 0 {
                break;
            }
            if *eta < 0 {
                *eta = -*eta;
                let tmp = f;
                f = g;
                g = tmp.wrapping_neg();
                let tmp = u;
                u = q;
                q = tmp.wrapping_neg();
                let tmp = v;
                v = r;
                r = tmp.wrapping_neg();
                mfinv = f.wrapping_mul(f.wrapping_mul(f).wrapping_sub(2));
            }
            let limit = (*eta + 1).min(i64::from(i)) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 63;
            let w = mfinv.wrapping_mul(g) & mask;
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        (u as i64, v as i64, q as i64, r as i64)
    }

    /// libsecp256k1-style split: 6-bit cancel after swap, cheap 4-bit otherwise.
    fn ds_split4(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut f, mut g) = (f0, g0);
        let mut i = 62u32;
        loop {
            let zeros = (g | (u64::MAX << i)).trailing_zeros();
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            *eta -= i64::from(zeros);
            i -= zeros;
            if i == 0 {
                break;
            }
            let mask;
            let w;
            if *eta < 0 {
                *eta = -*eta;
                let tmp = f;
                f = g;
                g = tmp.wrapping_neg();
                let tmp = u;
                u = q;
                q = tmp.wrapping_neg();
                let tmp = v;
                v = r;
                r = tmp.wrapping_neg();
                let limit = (*eta + 1).min(i64::from(i)) as u32;
                mask = (u64::MAX >> (64 - limit)) & 63;
                w = f
                    .wrapping_mul(g)
                    .wrapping_mul(f.wrapping_mul(f).wrapping_sub(2))
                    & mask;
            } else {
                let limit = (*eta + 1).min(i64::from(i)) as u32;
                mask = (u64::MAX >> (64 - limit)) & 15;
                let inv16 = f.wrapping_add((f.wrapping_add(1) & 4) << 1);
                w = inv16.wrapping_neg().wrapping_mul(g) & mask;
            }
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        (u as i64, v as i64, q as i64, r as i64)
    }

    /// Branchless conditional swap-negate (mask selects, no eta branch).
    fn ds_brless(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut f, mut g) = (f0, g0);
        let mut e = *eta;
        let mut i = 62u32;
        loop {
            let zeros = (g | (u64::MAX << i)).trailing_zeros();
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            e -= i64::from(zeros);
            i -= zeros;
            if i == 0 {
                break;
            }
            let mi = e >> 63; // -1 if e < 0 else 0
            let m = mi as u64;
            e = (e ^ mi).wrapping_sub(mi);
            let tmp = f;
            f = (f & !m) | (g & m);
            g = (g & !m) | (tmp.wrapping_neg() & m);
            let tmp = u;
            u = (u & !m) | (q & m);
            q = (q & !m) | (tmp.wrapping_neg() & m);
            let tmp = v;
            v = (v & !m) | (r & m);
            r = (r & !m) | (tmp.wrapping_neg() & m);
            let limit = (e + 1).min(i64::from(i)) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 63;
            let w = f
                .wrapping_mul(g)
                .wrapping_mul(f.wrapping_mul(f).wrapping_sub(2))
                & mask;
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        *eta = e;
        (u as i64, v as i64, q as i64, r as i64)
    }

    /// Cap the cancel at 3 bits so w = -g*f^{-1} mod 8 = -(g*f) mod 8 (f odd is
    /// self-inverse mod 8): one narrow multiply on the g-critical path instead
    /// of two chained ones, at the cost of slightly more passes.
    fn ds_cap3(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut f, mut g) = (f0, g0);
        let mut i = 62u32;
        loop {
            let zeros = (g | (u64::MAX << i)).trailing_zeros();
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            *eta -= i64::from(zeros);
            i -= zeros;
            if i == 0 {
                break;
            }
            if *eta < 0 {
                *eta = -*eta;
                let tmp = f;
                f = g;
                g = tmp.wrapping_neg();
                let tmp = u;
                u = q;
                q = tmp.wrapping_neg();
                let tmp = v;
                v = r;
                r = tmp.wrapping_neg();
            }
            let limit = (*eta + 1).min(i64::from(i)) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 7;
            let w = f.wrapping_mul(g).wrapping_neg() & mask;
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        (u as i64, v as i64, q as i64, r as i64)
    }

    const NEG_INV64_TBL: [u64; 32] = {
        let mut t = [0u64; 32];
        let mut i = 0;
        while i < 32 {
            let x = (2 * i + 1) as u64;
            t[i as usize] = x.wrapping_mul(x.wrapping_mul(x).wrapping_sub(2)) & 63;
            i += 1;
        }
        t
    };

    /// Branchless swap + table lookup for -f^-1 mod 64 (one mul on g path).
    fn ds_brless_tbl(eta: &mut i64, f0: u64, g0: u64) -> (i64, i64, i64, i64) {
        let (mut u, mut v, mut q, mut r) = (1u64, 0u64, 0u64, 1u64);
        let (mut f, mut g) = (f0, g0);
        let mut e = *eta;
        let mut i = 62u32;
        loop {
            let zeros = (g | (u64::MAX << i)).trailing_zeros();
            g >>= zeros;
            u <<= zeros;
            v <<= zeros;
            e -= i64::from(zeros);
            i -= zeros;
            if i == 0 {
                break;
            }
            let mi = e >> 63;
            let m = mi as u64;
            e = (e ^ mi).wrapping_sub(mi);
            let tmp = f;
            f = (f & !m) | (g & m);
            g = (g & !m) | (tmp.wrapping_neg() & m);
            let tmp = u;
            u = (u & !m) | (q & m);
            q = (q & !m) | (tmp.wrapping_neg() & m);
            let tmp = v;
            v = (v & !m) | (r & m);
            r = (r & !m) | (tmp.wrapping_neg() & m);
            let limit = (e + 1).min(i64::from(i)) as u32;
            let mask = (u64::MAX >> (64 - limit)) & 63;
            let w = NEG_INV64_TBL[((f >> 1) & 31) as usize].wrapping_mul(g) & mask;
            g = g.wrapping_add(f.wrapping_mul(w));
            q = q.wrapping_add(u.wrapping_mul(w));
            r = r.wrapping_add(v.wrapping_mul(w));
        }
        *eta = e;
        (u as i64, v as i64, q as i64, r as i64)
    }

    // ---- candidate apply_shift62 variants ----

    type AsFn = fn(&mut [u64; 5], &mut [u64; 5], &(i64, i64, i64, i64), usize);

    /// Variable-length single-loop implementation: the A/B reference for the
    /// const-length dispatch.
    fn as_base(f: &mut [u64; 5], g: &mut [u64; 5], t: &(i64, i64, i64, i64), len: usize) {
        let mut wide_f = [0u64; 6];
        let mut wide_g = [0u64; 6];
        let mut carry_f: i128 = 0;
        let mut carry_g: i128 = 0;
        for i in 0..len {
            let (fi, gi) = if i + 1 == len {
                (i128::from(f[i] as i64), i128::from(g[i] as i64))
            } else {
                (i128::from(f[i]), i128::from(g[i]))
            };
            let acc_f = i128::from(t.0) * fi + i128::from(t.1) * gi + carry_f;
            let acc_g = i128::from(t.2) * fi + i128::from(t.3) * gi + carry_g;
            wide_f[i] = acc_f as u64;
            wide_g[i] = acc_g as u64;
            carry_f = acc_f >> 64;
            carry_g = acc_g >> 64;
        }
        wide_f[len] = carry_f as u64;
        wide_g[len] = carry_g as u64;
        for i in 0..len {
            f[i] = (wide_f[i] >> 62) | (wide_f[i + 1] << 2);
            g[i] = (wide_g[i] >> 62) | (wide_g[i + 1] << 2);
        }
        let ext_f = super::sign_extension(f[len - 1]);
        let ext_g = super::sign_extension(g[len - 1]);
        for i in len..5 {
            f[i] = ext_f;
            g[i] = ext_g;
        }
    }

    /// Production const-length dispatch ([`super::apply_shift62`]).
    fn as_disp(f: &mut [u64; 5], g: &mut [u64; 5], t: &(i64, i64, i64, i64), len: usize) {
        let t = super::Transition {
            u: t.0,
            v: t.1,
            q: t.2,
            r: t.3,
        };
        super::apply_shift62(f, g, &t, len);
    }

    // ---- candidate update_bezout variants ----

    type UbFn = fn(&mut [u64; 4], &mut [u64; 4], &(i64, i64, i64, i64), &[u64; 4], u64);

    fn ub_base(
        d: &mut [u64; 4],
        e: &mut [u64; 4],
        t: &(i64, i64, i64, i64),
        modulus: &[u64; 4],
        neg_mod_inv: u64,
    ) {
        let t = super::Transition {
            u: t.0,
            v: t.1,
            q: t.2,
            r: t.3,
        };
        super::update_bezout(d, e, &t, modulus, neg_mod_inv);
    }

    /// Montgomery factor chosen from the low limbs up front so the k*modulus
    /// addition folds into the single multiply-accumulate pass.
    fn ub_fused(
        d: &mut [u64; 4],
        e: &mut [u64; 4],
        t: &(i64, i64, i64, i64),
        modulus: &[u64; 4],
        neg_mod_inv: u64,
    ) {
        const MASK62: u64 = (1 << 62) - 1;
        let low_d = (t.0 as u64)
            .wrapping_mul(d[0])
            .wrapping_add((t.1 as u64).wrapping_mul(e[0]));
        let low_e = (t.2 as u64)
            .wrapping_mul(d[0])
            .wrapping_add((t.3 as u64).wrapping_mul(e[0]));
        let kd = low_d.wrapping_mul(neg_mod_inv) & MASK62;
        let ke = low_e.wrapping_mul(neg_mod_inv) & MASK62;
        let mut wide_d = [0u64; 5];
        let mut wide_e = [0u64; 5];
        let mut carry_d: i128 = 0;
        let mut carry_e: i128 = 0;
        for i in 0..4 {
            let (di, ei) = (i128::from(d[i]), i128::from(e[i]));
            let mi = i128::from(modulus[i]);
            let acc_d = i128::from(t.0) * di + i128::from(t.1) * ei + i128::from(kd) * mi + carry_d;
            let acc_e = i128::from(t.2) * di + i128::from(t.3) * ei + i128::from(ke) * mi + carry_e;
            wide_d[i] = acc_d as u64;
            wide_e[i] = acc_e as u64;
            carry_d = acc_d >> 64;
            carry_e = acc_e >> 64;
        }
        wide_d[4] = carry_d as u64;
        wide_e[4] = carry_e as u64;
        debug_assert!(wide_d[0] & MASK62 == 0 && wide_e[0] & MASK62 == 0);
        *d = ub_shift_out(&wide_d, modulus);
        *e = ub_shift_out(&wide_e, modulus);
    }

    fn ub_shift_out(wide: &[u64; 5], modulus: &[u64; 4]) -> [u64; 4] {
        let mut out = [0u64; 4];
        for i in 0..4 {
            out[i] = (wide[i] >> 62) | (wide[i + 1] << 2);
        }
        let top = ((wide[4] as i64) >> 62) as u64;
        let (s0, c0) = super::adc(out[0], modulus[0] & top, 0);
        let (s1, c1) = super::adc(out[1], modulus[1] & top, c0);
        let (s2, c2) = super::adc(out[2], modulus[2] & top, c1);
        let (s3, _) = super::adc(out[3], modulus[3] & top, c2);
        super::sub_mod(&[s0, s1, s2, s3], modulus, modulus)
    }

    #[test]
    #[ignore = "manual A/B: cargo test --release -p helios-bn254 --lib -- --ignored variants_bench --nocapture"]
    fn invert_variants_bench() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        let neg_mod_inv = neg_inv64(FR_MOD[0]);
        let inputs = random_inputs(4096);
        let rounds = capture_rounds(&inputs, neg_mod_inv);
        let n = inputs.len();

        let ds_variants: &[(&str, DsFn)] = &[
            ("ds_base", ds_base),
            ("ds_hoist", ds_hoist),
            ("ds_split4", ds_split4),
            ("ds_brless", ds_brless),
            ("ds_brless_tbl", ds_brless_tbl),
            ("ds_cap3", ds_cap3),
        ];
        let as_variants: &[(&str, AsFn)] = &[("as_base", as_base), ("as_disp", as_disp)];
        let ub_variants: &[(&str, UbFn)] = &[("ub_base", ub_base), ("ub_fused", ub_fused)];

        // Correctness: every variant must reproduce the baseline exactly.
        for r in &rounds {
            let mut eta0 = r.eta;
            let expect = ds_base(&mut eta0, r.f0, r.g0);
            for (name, ds) in ds_variants {
                let mut eta = r.eta;
                let got = ds(&mut eta, r.f0, r.g0);
                assert_eq!(
                    (got, eta),
                    (expect, eta0),
                    "{name} f0={:x} g0={:x}",
                    r.f0,
                    r.g0
                );
            }
            let (mut ef, mut eg) = (r.f, r.g);
            as_base(&mut ef, &mut eg, &r.t, r.len);
            for (name, asv) in as_variants {
                let (mut f, mut g) = (r.f, r.g);
                asv(&mut f, &mut g, &r.t, r.len);
                assert_eq!((f, g), (ef, eg), "{name}");
            }
            let (mut ed, mut ee) = (r.d, r.e);
            ub_base(&mut ed, &mut ee, &r.t, &FR_MOD, neg_mod_inv);
            for (name, ubv) in ub_variants {
                let (mut d, mut e) = (r.d, r.e);
                ubv(&mut d, &mut e, &r.t, &FR_MOD, neg_mod_inv);
                assert_eq!((d, e), (ed, ee), "{name}");
            }
        }
        std::println!(
            "correctness OK over {} rounds; timing (min of reps, interleaved):",
            rounds.len()
        );

        let reps = 15usize;
        let mut acc = 0u64;

        let mut best_ds = alloc::vec![Duration::MAX; ds_variants.len()];
        let mut best_as = alloc::vec![Duration::MAX; as_variants.len()];
        let mut best_ub = alloc::vec![Duration::MAX; ub_variants.len()];
        for _ in 0..reps {
            for (vi, (_, ds)) in ds_variants.iter().enumerate() {
                let start = Instant::now();
                for r in &rounds {
                    let mut eta = black_box(r.eta);
                    let t = ds(&mut eta, black_box(r.f0), black_box(r.g0));
                    acc ^= t.0 as u64 ^ eta as u64;
                }
                best_ds[vi] = best_ds[vi].min(start.elapsed());
            }
            for (vi, (_, asv)) in as_variants.iter().enumerate() {
                let start = Instant::now();
                for r in &rounds {
                    let mut f = black_box(r.f);
                    let mut g = black_box(r.g);
                    asv(&mut f, &mut g, &r.t, black_box(r.len));
                    acc ^= f[0] ^ g[0];
                }
                best_as[vi] = best_as[vi].min(start.elapsed());
            }
            for (vi, (_, ubv)) in ub_variants.iter().enumerate() {
                let start = Instant::now();
                for r in &rounds {
                    let mut d = black_box(r.d);
                    let mut e = black_box(r.e);
                    ubv(&mut d, &mut e, &r.t, &FR_MOD, neg_mod_inv);
                    acc ^= d[0] ^ e[0];
                }
                best_ub[vi] = best_ub[vi].min(start.elapsed());
            }
        }
        for (vi, (name, _)) in ds_variants.iter().enumerate() {
            std::println!(
                "{name:16} {:8.1} ns/inv",
                best_ds[vi].as_nanos() as f64 / n as f64
            );
        }
        for (vi, (name, _)) in as_variants.iter().enumerate() {
            std::println!(
                "{name:16} {:8.1} ns/inv",
                best_as[vi].as_nanos() as f64 / n as f64
            );
        }
        for (vi, (name, _)) in ub_variants.iter().enumerate() {
            std::println!(
                "{name:16} {:8.1} ns/inv",
                best_ub[vi].as_nanos() as f64 / n as f64
            );
        }
        std::println!("(acc={acc})");
    }

    #[test]
    #[ignore = "manual profiling: cargo test --release -p helios-bn254 --lib -- --ignored profile_split --nocapture"]
    fn invert_profile_split() {
        use std::hint::black_box;
        use std::time::Instant;

        let neg_mod_inv = neg_inv64(FR_MOD[0]);
        assert_eq!(FR_MOD[0].wrapping_mul(neg_mod_inv), u64::MAX);
        let inputs = random_inputs(4096);
        let rounds = capture_rounds(&inputs, neg_mod_inv);
        let reps = 64usize;
        std::println!(
            "captured {} rounds over {} inversions ({:.2} rounds/inv)",
            rounds.len(),
            inputs.len(),
            rounds.len() as f64 / inputs.len() as f64
        );

        // Full inversion latency.
        let mut acc = 0u64;
        let start = Instant::now();
        for _ in 0..reps {
            for value in &inputs {
                acc ^=
                    super::invert_mod_vartime(black_box(value), &FR_MOD, neg_mod_inv).unwrap()[0];
            }
        }
        let full = start.elapsed().as_nanos() as f64 / (reps * inputs.len()) as f64;
        std::println!("full invert:        {full:8.1} ns/op (acc={acc})");

        // divsteps62_var replay.
        let start = Instant::now();
        for _ in 0..reps {
            for r in &rounds {
                let mut eta = black_box(r.eta);
                let t = super::divsteps62_var(&mut eta, black_box(r.f0), black_box(r.g0));
                acc ^= t.u as u64 ^ eta as u64;
            }
        }
        let ds = start.elapsed().as_nanos() as f64 / (reps * inputs.len()) as f64;
        std::println!("divsteps62_var:     {ds:8.1} ns/op (acc={acc})");

        // apply_shift62 replay.
        let start = Instant::now();
        for _ in 0..reps {
            for r in &rounds {
                let t = super::Transition {
                    u: r.t.0,
                    v: r.t.1,
                    q: r.t.2,
                    r: r.t.3,
                };
                let mut f = black_box(r.f);
                let mut g = black_box(r.g);
                super::apply_shift62(&mut f, &mut g, &t, black_box(r.len));
                acc ^= f[0] ^ g[0];
            }
        }
        let shift = start.elapsed().as_nanos() as f64 / (reps * inputs.len()) as f64;
        std::println!("apply_shift62:      {shift:8.1} ns/op (acc={acc})");

        // update_bezout replay.
        let start = Instant::now();
        for _ in 0..reps {
            for r in &rounds {
                let t = super::Transition {
                    u: r.t.0,
                    v: r.t.1,
                    q: r.t.2,
                    r: r.t.3,
                };
                let mut d = black_box(r.d);
                let mut e = black_box(r.e);
                super::update_bezout(&mut d, &mut e, &t, &FR_MOD, neg_mod_inv);
                acc ^= d[0] ^ e[0];
            }
        }
        let bez = start.elapsed().as_nanos() as f64 / (reps * inputs.len()) as f64;
        std::println!("update_bezout:      {bez:8.1} ns/op (acc={acc})");
        std::println!(
            "sum of parts: {:.1} ns/op (overhead vs full: {:.1})",
            ds + shift + bez,
            full - (ds + shift + bez)
        );
    }

    fn random_mod(modulus: &[u64; 4], count: usize, mut state: u64) -> alloc::vec::Vec<[u64; 4]> {
        (0..count)
            .map(|_| {
                let mut limbs = [0u64; 4];
                for limb in &mut limbs {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *limb = state;
                }
                limbs[3] &= (1 << 62) - 1;
                while super::gte(&limbs, modulus) {
                    limbs = super::sub_noborrow(&limbs, modulus);
                }
                limbs
            })
            .filter(|limbs| !super::is_zero(limbs))
            .collect()
    }

    /// 1, m-1, small, m-small, single bits, trailing-zero-heavy, patterns.
    fn kaliski_edge_cases(modulus: &[u64; 4]) -> alloc::vec::Vec<[u64; 4]> {
        let mut cases = alloc::vec::Vec::new();
        for small in 1u64..=64 {
            cases.push([small, 0, 0, 0]);
            let mut near_top = *modulus;
            near_top[0] -= small;
            cases.push(near_top);
        }
        for bit in 0..254 {
            let mut power = [0u64; 4];
            power[bit / 64] = 1 << (bit % 64);
            cases.push(power);
            if bit >= 64 {
                let mut shifted = power;
                shifted[3] |= 1 << 61;
                cases.push(shifted);
            }
        }
        cases.push([u64::MAX, u64::MAX, u64::MAX, (1 << 62) - 1]);
        cases.push([0xaaaa_aaaa_aaaa_aaaa; 4].map(|limb: u64| limb >> 2));
        cases.push([0x5555_5555_5555_5555; 4].map(|limb: u64| limb >> 2));
        cases
            .into_iter()
            .map(|mut limbs| {
                while super::gte(&limbs, modulus) {
                    limbs = super::sub_noborrow(&limbs, modulus);
                }
                limbs
            })
            .filter(|limbs| !super::is_zero(limbs))
            .collect()
    }

    fn kaliski_domain_inputs(modulus: &[u64; 4], seed: u64) -> alloc::vec::Vec<[u64; 4]> {
        let count = if cfg!(debug_assertions) {
            10_000
        } else {
            100_000
        };
        let mut inputs = kaliski_edge_cases(modulus);
        inputs.extend(random_mod(modulus, count, seed));
        inputs
    }

    /// Differential gate: Kaliski (canonical correction) against divsteps for
    /// both field moduli over edges plus the full random stream.
    #[test]
    fn kaliski_matches_divsteps_for_both_moduli() {
        let fp_canonical_tbl: alloc::vec::Vec<[u64; 4]> = {
            let mut entries = alloc::vec::Vec::with_capacity(super::KALISKI_TBL_LEN);
            let mut entry = [8u64, 0, 0, 0];
            for _ in 0..super::KALISKI_TBL_LEN {
                entries.push(entry);
                entry = crate::consts::half_mod(entry, crate::consts::P);
            }
            entries
        };
        let fp_tbl: &[[u64; 4]; super::KALISKI_TBL_LEN] =
            fp_canonical_tbl.as_slice().try_into().unwrap();
        type Case<'a> = (
            &'a [u64; 4],
            u64,
            &'a [[u64; 4]; super::KALISKI_TBL_LEN],
            u64,
        );
        let cases: &[Case] = &[
            (
                &FR_MOD,
                crate::consts::R_INV,
                &crate::consts::FR_KALISKI_TBL,
                0x6b79_c355_1e5f_0001,
            ),
            (
                &crate::consts::P,
                crate::consts::P_INV,
                fp_tbl,
                0x0dd0_5ea5_e1ba_5e01,
            ),
        ];
        for &(modulus, neg_inv, table, seed) in cases {
            assert_eq!(
                super::invert_mod_kaliski_vartime(&[0, 0, 0, 0], modulus, neg_inv, table),
                None
            );
            for limbs in kaliski_domain_inputs(modulus, seed) {
                let expected = super::invert_mod_vartime(&limbs, modulus, neg_inv);
                let got = super::invert_mod_kaliski_vartime(&limbs, modulus, neg_inv, table);
                assert_eq!(got, expected, "limbs={limbs:x?}");
            }
        }
    }

    /// Verified phase-1 invariant: `value*almost = 2^k (mod m)` with
    /// `k in [KALISKI_K_MIN, KALISKI_K_MIN + KALISKI_TBL_LEN - 1]`.
    #[test]
    fn kaliski_almost_inverse_invariant_and_k_range() {
        let cases: &[(&[u64; 4], u64, &[u64; 4], u64)] = &[
            (
                &FR_MOD,
                crate::consts::R_INV,
                &crate::consts::FR_MONT_R2,
                0x9e37_79b9_7f4a_7c15,
            ),
            (
                &crate::consts::P,
                crate::consts::P_INV,
                &crate::consts::MONT_R2,
                0xc2b2_ae3d_27d4_eb4f,
            ),
        ];
        for &(modulus, neg_inv, r2, seed) in cases {
            // pow2[k] = 2^k mod m for every attainable k.
            let mut pow2 = alloc::vec::Vec::with_capacity(super::KALISKI_TBL_LEN);
            let mut acc = [1u64, 0, 0, 0];
            for _ in 0..super::KALISKI_K_MIN {
                acc = crate::consts::double_mod(acc, *modulus);
            }
            for _ in 0..super::KALISKI_TBL_LEN {
                pow2.push(acc);
                acc = crate::consts::double_mod(acc, *modulus);
            }
            let mut seen_min = u32::MAX;
            let mut seen_max = 0u32;
            for limbs in kaliski_domain_inputs(modulus, seed) {
                let (almost, k) =
                    super::kaliski_almost_inverse(&limbs, modulus).expect("nonzero coprime");
                assert!(
                    (super::KALISKI_K_MIN..super::KALISKI_K_MIN + super::KALISKI_TBL_LEN as u32)
                        .contains(&k),
                    "k={k} limbs={limbs:x?}"
                );
                seen_min = seen_min.min(k);
                seen_max = seen_max.max(k);
                // value*almost mod m via two Montgomery multiplies.
                let product = super::mont_mul_limbs(&limbs, &almost, modulus, neg_inv);
                let product = super::mont_mul_limbs(&product, r2, modulus, neg_inv);
                assert_eq!(
                    product,
                    pow2[(k - super::KALISKI_K_MIN) as usize],
                    "limbs={limbs:x?} k={k}"
                );
            }
            // The streams must exercise a wide slice of the k range.
            assert!(
                seen_max - seen_min > 50,
                "k range too narrow: [{seen_min}, {seen_max}]"
            );
        }
    }

    // ---- candidate Kaliski phase-1 variants (all must produce identical output) ----

    type KaFn = fn(&[u64; 4], &[u64; 4]) -> Option<([u64; 4], u32)>;

    fn ka_prod(value: &[u64; 4], modulus: &[u64; 4]) -> Option<([u64; 4], u32)> {
        super::kaliski_almost_inverse(value, modulus)
    }

    /// Single-bit steps, MCL gen_preInv shape (no trailing-zero batching),
    /// with the final halve/double elided to match the production contract.
    fn ka_bit(value: &[u64; 4], modulus: &[u64; 4]) -> Option<([u64; 4], u32)> {
        if super::is_zero(value) {
            return None;
        }
        let mut u = *modulus;
        let mut v = *value;
        let mut r = [0u64; 4];
        let mut s = [1u64, 0, 0, 0];
        let mut k = 0u32;
        loop {
            if v[0] & 1 == 0 {
                shr1(&mut v);
                super::shl4(&mut r, 1);
                k += 1;
            } else if u[0] & 1 == 0 {
                shr1(&mut u);
                super::shl4(&mut s, 1);
                k += 1;
            } else if super::gte(&v, &u) {
                v = super::sub_noborrow(&v, &u);
                super::add4_assign(&mut s, &r);
                if super::is_zero(&v) {
                    break;
                }
            } else {
                u = super::sub_noborrow(&u, &v);
                super::add4_assign(&mut r, &s);
            }
        }
        if u != [1, 0, 0, 0] {
            return None;
        }
        Some((super::sub_noborrow(modulus, &r), k))
    }

    fn shr1(a: &mut [u64; 4]) {
        a[0] = (a[0] >> 1) | (a[1] << 63);
        a[1] = (a[1] >> 1) | (a[2] << 63);
        a[2] = (a[2] >> 1) | (a[3] << 63);
        a[3] >>= 1;
    }

    #[test]
    #[ignore = "manual A/B: cargo test --release -p helios-bn254 --lib -- --ignored kaliski_variants --nocapture"]
    fn kaliski_variants_bench() {
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        let inputs = random_mod(&FR_MOD, 4096, 0x243f_6a88_85a3_08d3);
        let n = inputs.len();
        let variants: &[(&str, KaFn)] = &[("ka_prod", ka_prod), ("ka_bit", ka_bit)];

        for value in &inputs {
            let expect = ka_prod(value, &FR_MOD);
            for (name, ka) in variants {
                assert_eq!(ka(value, &FR_MOD), expect, "{name} value={value:x?}");
            }
        }

        // Iteration statistics for the production shape.
        let (mut subs, mut strips, mut k_sum) = (0u64, 0u64, 0u64);
        for value in &inputs {
            let mut u = FR_MOD;
            let mut v = *value;
            let mut r = [0u64; 4];
            let mut s = [1u64, 0, 0, 0];
            loop {
                while v[0] & 1 == 0 {
                    let sh = v[0].trailing_zeros().min(63);
                    super::shr_short::<4>(&mut v, sh);
                    super::shl4(&mut r, sh);
                    k_sum += u64::from(sh);
                    strips += 1;
                }
                while u[0] & 1 == 0 {
                    let sh = u[0].trailing_zeros().min(63);
                    super::shr_short::<4>(&mut u, sh);
                    super::shl4(&mut s, sh);
                    k_sum += u64::from(sh);
                    strips += 1;
                }
                subs += 1;
                let (d, borrow) = super::sub_short::<4>(&v, &u);
                if borrow == 0 {
                    if super::is_zero(&d) {
                        break;
                    }
                    v = d;
                    super::add4_assign(&mut s, &r);
                } else {
                    let (e, _) = super::sub_short::<4>(&u, &v);
                    u = e;
                    super::add4_assign(&mut r, &s);
                }
            }
        }
        std::println!(
            "stats: {:.1} subtracts, {:.1} strip passes, k avg {:.1}",
            subs as f64 / n as f64,
            strips as f64 / n as f64,
            k_sum as f64 / n as f64
        );

        let reps = 15usize;
        let mut acc = 0u64;
        let mut best = alloc::vec![Duration::MAX; variants.len()];
        for _ in 0..reps {
            for (vi, (_, ka)) in variants.iter().enumerate() {
                let start = Instant::now();
                for value in &inputs {
                    let (almost, k) = ka(black_box(value), &FR_MOD).unwrap();
                    acc ^= almost[0] ^ u64::from(k);
                }
                best[vi] = best[vi].min(start.elapsed());
            }
        }
        for (vi, (name, _)) in variants.iter().enumerate() {
            std::println!(
                "{name:12} {:8.1} ns/inv",
                best[vi].as_nanos() as f64 / n as f64
            );
        }
        std::println!("(acc={acc})");
    }

    #[test]
    fn mac_matches_u128_at_carry_boundaries() {
        const CASES: [u64; 8] = [
            0,
            1,
            2,
            u32::MAX as u64,
            1 << 63,
            u64::MAX - 2,
            u64::MAX - 1,
            u64::MAX,
        ];

        for a in CASES {
            for b in CASES {
                for c in CASES {
                    for carry in CASES {
                        let expected = (a as u128) * (b as u128) + (c as u128) + (carry as u128);
                        let (lo, hi) = mac(a, b, c, carry);
                        assert_eq!((lo, hi), (expected as u64, (expected >> 64) as u64));
                    }
                }
            }
        }
    }
}
