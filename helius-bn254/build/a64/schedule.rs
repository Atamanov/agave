//! The AArch64 Montgomery kernel schedule for 4x64 moduli (BN254's p).
//!
//! An instruction-for-instruction port of the measured hand-scheduled Apple
//! leaf (ADR 0001, build-time amendment); the emitted text is pinned
//! byte-for-byte by `tests/golden/mont4_aarch64.s`, so the M4 performance is
//! a property of the pin. The counted loop is the algorithm: one iteration
//! is one radix-2^64 CIOS round (product row, then reduction row).
//!
//! # Carry discipline
//!
//! MUL/UMULH preserve NZCV, so products are interleaved through a single
//! ADDS/ADCS chain: only one adjacent product pair is live at a time instead
//! of eight half-products. Each row closes its chain before the next opens
//! one (CINC or CSET consumes the final carry), and the loop counter's SUBS
//! clobbers flags on the back edge, so no flag crosses a row boundary.
//!
//! # Bounds
//!
//! With `b < p` and `a < 2^256` the CIOS accumulator obeys `t < 2p` at every
//! round boundary (see the contract in `src/fp/aarch64.rs`), so the fifth
//! accumulator word absorbs every carry: the closing `adc` of the product
//! row discards a provably zero carry-out, which the interpreter asserts.

use super::machine::Reg::{
    Sp, X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X19, X20,
    X21, X22, X23, Xzr,
};
use super::machine::{MachineA64, Reg};

/// Register roles for `helius_mont4`.
pub const MONT4_REGISTER_MAP: &[(Reg, &str)] = &[
    (X0, "z: result pointer (live throughout)"),
    (
        X1,
        "x pointer on entry; then per-round scratch: b_i, then m",
    ),
    (X2, "y pointer, walked one limb per round by post-index"),
    (
        X3,
        "consts pointer on entry; then (as w3) the round counter",
    ),
    (
        X4,
        "accumulator t0 (shifts down one word per reduction row)",
    ),
    (X5, "accumulator t1"),
    (X6, "accumulator t2"),
    (X7, "accumulator t3"),
    (X8, "accumulator t4 (carry word)"),
    (
        X9,
        "a0 (x limb 0, loaded once); result scratch in the epilogue",
    ),
    (X10, "a1; result scratch"),
    (X11, "a2; result scratch"),
    (X12, "a3; result scratch"),
    (X13, "p0"),
    (X14, "p1"),
    (X15, "p2"),
    (X16, "p3"),
    (X17, "-p^-1 mod 2^64; borrow scratch in the epilogue"),
    (
        X19,
        "column word 0 of the current row (callee-saved, spilled)",
    ),
    (X20, "column word 1"),
    (X21, "column word 2"),
    (X22, "column word 3"),
    (X23, "column word 4"),
];

/// `x` limbs, loaded once, immutable across the loop.
const A: [Reg; 4] = [X9, X10, X11, X12];
/// `p` limbs, loaded once.
const P: [Reg; 4] = [X13, X14, X15, X16];
/// Five-word accumulator t0..t4.
const T: [Reg; 5] = [X4, X5, X6, X7, X8];
/// Column words of the current row: S[k] collects word k of `v * limbs`.
const S: [Reg; 5] = [X19, X20, X21, X22, X23];
/// Per-round scratch: the loaded `b_i`, then the Montgomery factor `m`.
const V: Reg = X1;

/// Column sums of `v * limbs` into S: `S0 = lo0`, `S1 = hi0 + lo1`, ...,
/// `S4 = hi3 + chain carry`. Opens and closes its own carry chain; the CINC
/// cannot wrap because UMULH high halves are at most `2^64 - 2`.
fn column_products<M: MachineA64>(m: &mut M, v: Reg, limbs: [Reg; 4], limb: &str, factor: &str) {
    m.mul(S[0], limbs[0], v, &format!("lo({limb}0*{factor})"));
    m.umulh(S[1], limbs[0], v, &format!("hi({limb}0*{factor})"));
    m.mul(S[2], limbs[1], v, &format!("lo({limb}1*{factor})"));
    m.adds(S[1], S[1], S[2], "S1 += lo1 (opens the chain)");
    m.umulh(S[2], limbs[1], v, &format!("hi({limb}1*{factor})"));
    m.mul(S[3], limbs[2], v, &format!("lo({limb}2*{factor})"));
    m.adcs(S[2], S[2], S[3], "S2 = hi1 + lo2");
    m.umulh(S[3], limbs[2], v, &format!("hi({limb}2*{factor})"));
    m.mul(S[4], limbs[3], v, &format!("lo({limb}3*{factor})"));
    m.adcs(S[3], S[3], S[4], "S3 = hi2 + lo3");
    m.umulh(S[4], limbs[3], v, &format!("hi({limb}3*{factor})"));
    m.cinc_hs(S[4], S[4], "S4 = hi3 + chain carry (cannot wrap)");
}

/// `helius_mont4`: four-word CIOS Montgomery multiplication, counted loop.
pub fn mont4<M: MachineA64>(m: &mut M) {
    m.stp_pre(X19, X20, -48);
    m.stp(X21, X22, Sp, 16, "");
    m.str_off(X23, Sp, 32, "");

    m.comment("");
    m.ldp(A[0], A[1], X1, 0, "a0, a1");
    m.ldp(A[2], A[3], X1, 16, "a2, a3");
    m.ldp(P[0], P[1], X3, 0, "p0, p1");
    m.ldp(P[2], P[3], X3, 16, "p2, p3");
    m.ldr(X17, X3, 32, "-p^-1 mod 2^64");
    for (k, t) in T.into_iter().enumerate() {
        m.mov_zero(t, &format!("t{k} = 0"));
    }

    m.comment("");
    m.counted_loop(X3, 4, "L_round", &mut |m| {
        m.comment("product row: t += a * b_i, one column chain via S");
        m.ldr_post(V, X2, 8, "b_i (y walks one limb per round)");
        column_products(m, V, A, "a", "b_i");
        m.adds(T[0], T[0], S[0], "t0 += S0 (opens the accumulate chain)");
        m.adcs(T[1], T[1], S[1], "t1 += S1");
        m.adcs(T[2], T[2], S[2], "t2 += S2");
        m.adcs(T[3], T[3], S[3], "t3 += S3");
        m.adc(T[4], T[4], S[4], "t4 += S4; t < 2^64 * 2^256, no carry out");

        m.comment("reduction row: m cancels t0; dropping that zero word");
        m.comment("and shifting down one word is the division by 2^64");
        m.mul(V, X17, T[0], "m = t0 * -p^-1 mod 2^64");
        column_products(m, V, P, "p", "m");
        m.cmn(T[0], S[0], "t0 + S0 = 0 mod 2^64; keep only its carry");
        m.adcs(T[0], T[1], S[1], "t0 = t1 + S1 (shift down)");
        m.adcs(T[1], T[2], S[2], "t1 = t2 + S2");
        m.adcs(T[2], T[3], S[3], "t2 = t3 + S3");
        m.adcs(T[3], T[4], S[4], "t3 = t4 + S4");
        m.cset_hs(T[4], "t4 = chain carry");
    });

    m.comment("");
    m.comment("four CIOS rounds leave t < 2p: one branch-free conditional");
    m.comment("subtraction produces the unique canonical residue");
    m.subs(X9, T[0], P[0], "word 0 of t - p");
    m.sbcs(X10, T[1], P[1], "word 1");
    m.sbcs(X11, T[2], P[2], "word 2");
    m.sbcs(X12, T[3], P[3], "word 3");
    m.sbcs(X17, T[4], Xzr, "consume t4; C = (t >= p)");
    m.csel_hs(T[0], X9, T[0], "no borrow: keep t - p");
    m.csel_hs(T[1], X10, T[1], "");
    m.csel_hs(T[2], X11, T[2], "");
    m.csel_hs(T[3], X12, T[3], "");
    m.stp(T[0], T[1], X0, 0, "z0, z1");
    m.stp(T[2], T[3], X0, 16, "z2, z3");

    m.comment("");
    m.ldr(X23, Sp, 32, "");
    m.ldp(X21, X22, Sp, 16, "");
    m.ldp_post(X19, X20, Sp, 48);
    m.ret();
}
