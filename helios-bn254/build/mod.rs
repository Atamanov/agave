//! Schedule DSL for the helios-bn254 assembly kernels (ADR 0001).
//!
//! A kernel is an ordinary Rust function over an abstract machine trait; the
//! same schedule text is emitted as assembly and executed with exact flag
//! semantics, so its algebra is verified on any host. These modules have two
//! consumers, each `#[path]`-including this file, so there is one source of
//! truth: the crate build script, which renders the assembly text at build
//! time (no `.s` file is checked in), and `tests/kernelgen_verify.rs`, which
//! interprets and verifies the same schedules. Never part of the production
//! dependency graph.

// Each consumer uses only half of the modules: the build script emits, the
// test harness interprets. The other half is dead code in that consumer.
#![allow(dead_code)]

pub mod a64;
pub mod emit;
pub mod interp;
pub mod layout;
pub mod machine;
pub mod render;
pub mod schedule;

/// BN254 base-field modulus, little-endian limbs. Kept here only for the
/// schedule tests; the kernels read the modulus from their constants table.
pub const BN254_P: [u64; 4] = [
    0x3c208c16d87cfd47,
    0x97816a916871ca8d,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// `-p^-1 mod 2^64` for BN254.
pub const BN254_P_INV: u64 = 0x87d20782e4866389;

/// `floor(2^310 / p)` for BN254: the fp6 kernel's xi-scaling quotient
/// estimate (`q = floor(E*mu/2^58)` for `E = floor(value/2^252)`). Pinned
/// against the production `consts::P_MU_310` by the constants test.
pub const BN254_MU: u64 = 0x015291d18988e812;

/// Execute the x86-64 mul schedule in the interpreter for one input pair.
pub fn interpret_mont4_mul(x: [u64; 4], y: [u64; 4], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut machine = interp::Interp::call_frame(x, y, p, p_inv);
    schedule::mont4_mul(&mut machine);
    machine.output()
}

/// Execute the x86-64 sqr schedule in the interpreter. `y` is unused by the
/// kernel; pass the same synthetic frame to keep the ABI identical.
pub fn interpret_mont4_sqr(x: [u64; 4], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut machine = interp::Interp::call_frame(x, x, p, p_inv);
    schedule::mont4_sqr(&mut machine);
    machine.output()
}

/// Execute the AArch64 mul schedule in the interpreter for one input pair.
pub fn interpret_mont4_a64(x: [u64; 4], y: [u64; 4], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut machine = a64::interp::InterpA64::call_frame(x, y, p, p_inv);
    a64::schedule::mont4(&mut machine);
    machine.output()
}

/// Execute the rolled x86-64 SoS schedule in the interpreter for one
/// `(a_i, b_i)` pair list (`1..=10` pairs, operands at most p).
pub fn interpret_sos(pairs: &[([u64; 4], [u64; 4])], p: [u64; 4], p_inv: u64) -> [u64; 4] {
    let mut machine = interp::Interp::sos_frame(pairs, p, p_inv);
    schedule::sos_rolled(&mut machine);
    machine.output()
}

/// Execute the dual-lane x86-64 sosd6 schedule in the interpreter: both
/// lanes of `sum_{i<3} x_i * y_i` over Fp2 (operands at most p), exactly
/// the portable `sosd6`. `xs` is (x00, x01, x10, x11, x20, x21), `ys`
/// likewise.
pub fn interpret_sosd6(
    xs: &[[u64; 4]; 6],
    ys: &[[u64; 4]; 6],
    p: [u64; 4],
    p_inv: u64,
) -> ([u64; 4], [u64; 4]) {
    let mut machine = interp::Interp::sosd6_frame(xs, ys, p, p_inv);
    schedule::sosd6_x86(&mut machine);
    machine.output_lanes()
}

/// Execute the whole-Fp6 multiply schedule in the interpreter: `a * b` in
/// `Fp6 = Fp2[v]/(v^3 - (9+u))`, operands and result as six canonical Fp
/// values in `repr(C)` order (c0.re, c0.im, c1.re, c1.im, c2.re, c2.im).
pub fn interpret_fp6_mul(
    a: &[[u64; 4]; 6],
    b: &[[u64; 4]; 6],
    p: [u64; 4],
    p_inv: u64,
    mu: u64,
) -> [[u64; 4]; 6] {
    let mut machine = interp::Interp::fp6_frame(a, b, p, p_inv, mu);
    schedule::fp6_mul_x86(&mut machine);
    machine.output_fp6()
}

/// Execute the sparse Fp12 034 schedule in the interpreter:
/// `f * (c0 + c3*w + c4*v*w)` in `Fp12 = Fp6[w]/(w^2 - v)`, operands and
/// result as twelve canonical Fp values in `repr(C)` Fp12 order; `c` is the
/// three sparse coefficients c0, c3, c4 as (re, im) pairs. With `alias` the
/// kernel runs in place (`z == f`), the production shape.
pub fn interpret_fp12_034(
    f: &[[u64; 4]; 12],
    c: &[[u64; 4]; 6],
    p: [u64; 4],
    p_inv: u64,
    mu: u64,
    alias: bool,
) -> [[u64; 4]; 12] {
    let mut machine = interp::Interp::fp12_034_frame(f, c, p, p_inv, mu, alias);
    schedule::fp12_034_x86(&mut machine);
    machine.output_fp12(alias)
}

/// Execute the whole-Fp12 square schedule in the interpreter: `f^2` in
/// `Fp12 = Fp6[w]/(w^2 - v)`, operand and result as twelve canonical Fp
/// values in `repr(C)` Fp12 order. With `alias` the kernel runs in place
/// (`z == f`).
pub fn interpret_fp12_sqr(
    f: &[[u64; 4]; 12],
    p: [u64; 4],
    p_inv: u64,
    mu: u64,
    alias: bool,
) -> [[u64; 4]; 12] {
    let mut machine = interp::Interp::fp12_sqr_frame(f, p, p_inv, mu, alias);
    schedule::fp12_sqr_x86(&mut machine);
    machine.output_fp12(alias)
}

/// Execute the cyclotomic-square schedule in the interpreter: the
/// Granger-Scott square of `f` in `Fp12 = Fp6[w]/(w^2 - v)`, operand and
/// result as twelve canonical Fp values in `repr(C)` Fp12 order. With
/// `alias` the kernel runs in place (`z == f`), the production pow_x shape.
pub fn interpret_cyc_sqr(
    f: &[[u64; 4]; 12],
    p: [u64; 4],
    p_inv: u64,
    mu: u64,
    alias: bool,
) -> [[u64; 4]; 12] {
    let mut machine = interp::Interp::fp12_sqr_frame(f, p, p_inv, mu, alias);
    schedule::cyc_sqr_x86(&mut machine);
    machine.output_fp12(alias)
}

/// Execute the whole-Fp12 multiply schedule in the interpreter: `a * b` in
/// `Fp12 = Fp6[w]/(w^2 - v)`, operands and result as twelve canonical Fp
/// values in `repr(C)` Fp12 order. `alias` selects the output pointer:
/// 0 = distinct z, 1 = `z == a` (the production shape), 2 = `z == b`.
pub fn interpret_fp12_mul(
    a: &[[u64; 4]; 12],
    b: &[[u64; 4]; 12],
    p: [u64; 4],
    p_inv: u64,
    mu: u64,
    alias: usize,
) -> [[u64; 4]; 12] {
    let mut machine = interp::Interp::fp12_mul_frame(a, b, p, p_inv, mu, alias);
    schedule::fp12_mul_x86(&mut machine);
    machine.output_fp12_at(match alias {
        0 => interp::OUT_ADDR,
        1 => interp::X_ADDR,
        2 => interp::Y_ADDR,
        other => panic!("unknown alias mode {other}"),
    })
}

/// Execute the rolled dual-lane sosd2 schedule in the interpreter: returns
/// `((x0*y0 + x1*(p - y1))/R, (x0*y1 + x1*y0)/R) mod p` (operands at most p).
pub fn interpret_sosd2_small(
    x0: [u64; 4],
    x1: [u64; 4],
    y0: [u64; 4],
    y1: [u64; 4],
    p: [u64; 4],
    p_inv: u64,
) -> ([u64; 4], [u64; 4]) {
    let mut machine = interp::Interp::sosd2_frame(x0, x1, y0, y1, p, p_inv);
    schedule::sosd2_small_x86(&mut machine);
    machine.output_lanes()
}
