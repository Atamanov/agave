//! The Montgomery kernel schedules for 4x64 moduli (BN254's p).
//!
//! These functions are the audited artifact: each call names the semantic
//! value it computes, and the emitted assembly is this text, one instruction
//! per call, in this order. Both kernels receive `(z, x, y, consts)` in the
//! System V argument registers, with `consts = { p[4], -p^-1 mod 2^64 }`
//! owned by Rust (same contract as the AArch64 leaf).
//!
//! # Dual carry chains
//!
//! Products are accumulated with two independent carry chains so consecutive
//! `mulx` results never serialize on one flag:
//!
//! * the **value chain** (`adox`, OF) adds each product's low half into
//!   accumulator word `j`;
//! * the **carry chain** (`adcx`, CF) adds each product's high half into
//!   accumulator word `j + 1`.
//!
//! The chains cannot collide: within a row, word `j` receives exactly one
//! `adox` and one `adcx`, and `mulx`/`mov` between them touch no flags.
//!
//! # Carry bounds (why the chains close without a sixth word)
//!
//! Requires `p < 2^62 * 2^192` (four-limb modulus with two spare top bits;
//! BN254's top limb is `0x3064...` ~ 2^61.6). With `a, b < p` the CIOS
//! accumulator obeys `t < 2p` at every round boundary, so:
//!
//! * after a product row:    `t + a*b_i  < 2p + 2^64*p        < 2^64 * 2^255`
//! * after the cancel row:   `... + m*p  < 2^64*p + 2^64*p    < 2^65 * 2^255`
//!
//! Both stay below `2^320`, so the fifth word absorbs every carry and both
//! chains provably close with CF = OF = 0 -- the `claim_flags_clear` calls
//! make the interpreter check exactly that, and each round relies on it
//! instead of re-clearing flags.

use super::layout::{FrameLayout, FrameSlot, TableLayout, TableSegment};
use super::machine::Reg::{
    R8, R9, R10, R11, R12, R13, R14, R15, Rax, Rbp, Rbx, Rcx, Rdi, Rdx, Rsi,
};
use super::machine::{LoopEnd, Machine, Mem, Reg};

/// The consts mirror every table-addressing frame shares as its prefix:
/// p at +0 and -p^-1 at +32 reproduce the consts-table shape (so cancel
/// rows and reductions address rsp exactly like a consts pointer), mu at
/// +40 where the kernel needs the xi quotient estimate.
struct ConstsMirror {
    p: FrameSlot,
    pinv: FrameSlot,
    mu: FrameSlot,
}

const CONSTS_MIRROR: ConstsMirror = {
    let l = FrameLayout::new();
    let (l, p) = l.slot(32);
    let (l, pinv) = l.slot(8);
    let (_, mu) = l.slot(8);
    ConstsMirror { p, pinv, mu }
};

/// Register roles for `helius_mont4_mul_x86`. All fifteen usable GPRs are
/// live; there are no spills.
pub const MUL_REGISTER_MAP: &[(Reg, &str)] = &[
    (Rdi, "z: result pointer (argument 1, live throughout)"),
    (
        Rsi,
        "x pointer on entry; repointed at y after the operand load",
    ),
    (
        Rdx,
        "y pointer on entry; then the implicit mulx multiplicand",
    ),
    (Rcx, "consts pointer: p at +0..+24, -p^-1 at +32"),
    (R8, "a0 (x limb 0, loaded once)"),
    (R9, "a1"),
    (R10, "a2"),
    (R11, "a3"),
    (
        R12,
        "CIOS accumulator (rotates: t_k of round r is ACC[(r+k) % 5])",
    ),
    (R13, "CIOS accumulator"),
    (R14, "CIOS accumulator"),
    (R15, "CIOS accumulator"),
    (Rbp, "CIOS accumulator"),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (Rbx, "high half of the current product"),
];

/// Register roles for `helius_mont4_sqr_x86`.
pub const SQR_REGISTER_MAP: &[(Reg, &str)] = &[
    (Rdi, "z: result pointer (argument 1, live throughout)"),
    (Rsi, "x pointer on entry; then cross-product word C6 / T6"),
    (
        Rdx,
        "unused argument on entry; the implicit mulx multiplicand",
    ),
    (Rcx, "consts pointer: p at +0..+24, -p^-1 at +32"),
    (R8, "x0; then T0 (dies as round 0 cancels it)"),
    (R9, "x1; then high-half scratch of the reduction rows"),
    (R10, "x2; freed by the diagonal row"),
    (R11, "x3; freed by the diagonal row"),
    (R12, "cross-product word C1; then T1"),
    (R13, "cross-product word C2; then T2"),
    (R14, "cross-product word C3; then T3"),
    (R15, "cross-product word C4; then T4"),
    (Rbp, "cross-product word C5; then T5"),
    (Rbx, "doubling carry H; then T7"),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
];

const OUT_PTR: Reg = Rdi;
const CONSTS: Reg = Rcx;
/// The implicit `mulx` multiplicand.
const MULTIPLIER: Reg = Rdx;
/// `x` limbs for mul, `x` limbs for sqr; loaded once, immutable.
const A: [Reg; 4] = [R8, R9, R10, R11];
/// Rotating five-word CIOS accumulator (mul kernel).
const ACC: [Reg; 5] = [R12, R13, R14, R15, Rbp];
/// Product low half / zero source for chain closes.
const LO: Reg = Rax;

const CALLEE_SAVED: [Reg; 6] = [Rbx, Rbp, R12, R13, R14, R15];

/// Frame-kernel skeleton shared by every spill-frame leaf: push the
/// callee-saved set, open the frame, run the body, close the frame, pop in
/// reverse, ret.
fn frame<M: Machine>(m: &mut M, size: i32, body: impl FnOnce(&mut M)) {
    for reg in CALLEE_SAVED {
        m.push(reg);
    }
    m.alloc_stack(size);
    body(m);
    m.free_stack(size);
    for reg in CALLEE_SAVED.iter().rev() {
        m.pop(*reg);
    }
    m.ret();
}

fn p_limb(j: usize) -> Mem {
    Mem::new(CONSTS, 8 * j as i32)
}

fn p_inv() -> Mem {
    Mem::new(CONSTS, 32)
}

/// Accumulator register of round `round`, logical word `k`. Rounds shift the
/// accumulator down one word by renaming registers instead of moving data.
fn acc(round: usize, k: usize) -> Reg {
    ACC[(round + k) % 5]
}

/// `t[j] += lo(product)` on the value chain, `t[j+1] += hi(product)` on the
/// carry chain. `hi` is the per-kernel high-half scratch register.
fn mul_into_columns<M: Machine>(
    m: &mut M,
    hi: Reg,
    src: Reg,
    t_lo: Reg,
    t_hi: Reg,
    product: &str,
    j: usize,
) {
    m.mulx(hi, LO, src, &format!("{product} -> (lo, hi)"));
    m.adox(t_lo, LO, &format!("t{j} += lo({product})   [value chain]"));
    m.adcx(
        t_hi,
        hi,
        &format!("t{} += hi({product})   [carry chain]", j + 1),
    );
}

/// Same column step with the multiplicand taken from the constant table.
fn mul_mem_into_columns<M: Machine>(
    m: &mut M,
    hi: Reg,
    src: Mem,
    t_lo: Reg,
    t_hi: Reg,
    product: &str,
    j: usize,
) {
    m.mulx_mem(hi, LO, src, &format!("{product} -> (lo, hi)"));
    m.adox(t_lo, LO, &format!("t{j} += lo({product})   [value chain]"));
    m.adcx(
        t_hi,
        hi,
        &format!("t{} += hi({product})   [carry chain]", j + 1),
    );
}

/// The verbatim chain-close opener of every dual-chain row: a
/// flag-preserving zero, then the value-chain close into `word`.
fn close_value_chain<M: Machine>(m: &mut M, word: Reg, what: &str) {
    m.mov_zero(LO, "zero for the chain closes (flags preserved)");
    m.adox(word, LO, what);
}

/// Full double close of a six-word accumulator row: value chain into t4,
/// ripple into t5, carry chain into t5. Verbatim in every T-bank row.
fn close_chains_t5<M: Machine>(m: &mut M) {
    close_value_chain(m, T[4], "close the value chain into t4");
    m.adox(T[5], LO, "ripple the t4 close into t5");
    m.adcx(T[5], LO, "close the carry chain into t5");
}

/// Montgomery cancel row: `m = t0 * (-p^-1) mod 2^64`, then `t += m*p`, which
/// forces `t0` to exactly zero. Shared verbatim by both kernels; `t` is the
/// five-word window, `hi` the high-half scratch.
///
/// Entry and exit invariant: CF = OF = 0 (see the module bound argument; for
/// the squaring kernel the caller ripples the window carries out instead).
fn cancel_low_word<M: Machine>(m: &mut M, t: [Reg; 5], hi: Reg, round: usize) {
    cancel_low_word_at(m, t, hi, CONSTS, &round.to_string());
}

/// Same cancel row with the constants table at `consts`: the rolled sosd2
/// kernel keeps rcx as its round cursor and reloads the table pointer.
fn cancel_low_word_at<M: Machine>(m: &mut M, t: [Reg; 5], hi: Reg, consts: Reg, tag: &str) {
    m.mov(MULTIPLIER, t[0], &format!("m{tag} multiplicand <- t0"));
    m.mulx_mem(
        hi,
        MULTIPLIER,
        Mem::new(consts, 32),
        &format!("m{tag} = t0 * -p^-1 mod 2^64 (hi half discarded)"),
    );
    for j in 0..4 {
        let product = format!("m{tag}*p{j}");
        mul_mem_into_columns(
            m,
            hi,
            Mem::new(consts, 8 * j as i32),
            t[j],
            t[j + 1],
            &product,
            j,
        );
    }
    close_value_chain(m, t[4], "close the value chain into t4");
}

/// Push callee-saved registers and load the four `x` limbs into registers.
fn enter<M: Machine>(m: &mut M, operand: &str) {
    for reg in CALLEE_SAVED {
        m.push(reg);
    }
    for (j, reg) in A.iter().enumerate() {
        m.load(*reg, Mem::new(Rsi, 8 * j as i32), &format!("{operand}{j}"));
    }
}

/// One conditional-subtraction pass, the reduction idiom of every epilogue:
/// keep-copies into `keep`, a borrowing subtraction of p (`p_at` addresses
/// limb k), then the borrow-driven restore. The note closures carry each
/// site's exact emitted comment text.
fn csub_pass<M: Machine>(
    m: &mut M,
    value: [Reg; 4],
    keep: [Reg; 4],
    p_at: impl Fn(usize) -> Mem,
    keep_note: impl Fn(usize) -> String,
    sub_note: impl Fn(usize) -> String,
    cmov_note: impl Fn(usize) -> String,
) {
    for (k, (v, s)) in value.iter().zip(keep).enumerate() {
        m.mov(s, *v, &keep_note(k));
    }
    for (k, v) in value.iter().enumerate() {
        let what = sub_note(k);
        if k == 0 {
            m.sub_mem(*v, p_at(k), &what);
        } else {
            m.sbb_mem(*v, p_at(k), &what);
        }
    }
    for (k, (v, s)) in value.iter().zip(keep).enumerate() {
        m.cmov_carry(*v, s, &cmov_note(k));
    }
}

/// Conditionally subtract p and store. `value < 2p` fits four words, so a
/// four-word borrow decides: borrow means `value < p`, keep the original.
fn reduce_and_store<M: Machine>(m: &mut M, value: [Reg; 4], keep: [Reg; 4]) {
    m.comment("final reduction: value < 2p, subtract p once if value >= p");
    csub_pass(
        m,
        value,
        keep,
        p_limb,
        |j| format!("keep-copy of word {j}"),
        |j| format!("word {j} -= p{j}"),
        |j| format!("borrow: value < p, keep word {j}"),
    );
    for (j, v) in value.iter().enumerate() {
        m.store(Mem::new(OUT_PTR, 8 * j as i32), *v, &format!("z{j}"));
    }
    for reg in CALLEE_SAVED.iter().rev() {
        m.pop(*reg);
    }
    m.ret();
}

/// `helius_mont4_mul_x86`: fully unrolled CIOS Montgomery multiplication.
///
/// Round r: `t += a * b_r` (product row), then one [`cancel_low_word`]
/// (cancel row), then the shift-by-renaming. Round 0 builds `t` directly from
/// the products (single adc chain) instead of adding into zeros.
pub fn mont4_mul<M: Machine>(m: &mut M) {
    let hi = Rbx;
    enter(m, "a");
    m.mov(
        Rsi,
        Rdx,
        "y pointer moves; rdx becomes the mulx multiplicand",
    );

    m.comment("");
    m.comment("round 0: t = a*b0, then cancel t0");
    let (t0, t1, t2, t3, t4) = (acc(0, 0), acc(0, 1), acc(0, 2), acc(0, 3), acc(0, 4));
    m.load(MULTIPLIER, Mem::new(Rsi, 0), "b0");
    m.mulx(t1, t0, A[0], "a0*b0 -> (t0, t1)");
    m.mulx(t2, LO, A[1], "a1*b0 -> (lo, t2)");
    m.add(t1, LO, "t1 += lo(a1*b0)");
    m.mulx(t3, LO, A[2], "a2*b0 -> (lo, t3)");
    m.adc(t2, LO, "t2 += lo(a2*b0)");
    m.mulx(t4, LO, A[3], "a3*b0 -> (lo, t4)");
    m.adc(t3, LO, "t3 += lo(a3*b0)");
    m.adc_zero(t4, "t4 += chain carry; hi(a3*b0) <= 2^64-2 so CF = 0");
    m.xor_clear(
        LO,
        "clear OF (adc left it undefined) before the dual chains",
    );
    cancel_low_word(m, [t0, t1, t2, t3, t4], hi, 0);

    for round in 1..4 {
        m.comment("");
        m.comment(&format!("round {round}: t += a*b{round}, then cancel t0"));
        m.claim_flags_clear("previous round closed both chains under the 2^320 bound");
        let t: [Reg; 5] = core::array::from_fn(|k| acc(round, k));
        m.load(
            MULTIPLIER,
            Mem::new(Rsi, 8 * round as i32),
            &format!("b{round}"),
        );
        for j in 0..4 {
            let product = format!("a{j}*b{round}");
            mul_into_columns(m, hi, A[j], t[j], t[j + 1], &product, j);
        }
        close_value_chain(m, t[4], "close the value chain into t4");
        cancel_low_word(m, t, hi, round);
    }
    m.claim_flags_clear("final round closed both chains under the 2^320 bound");

    m.comment("");
    // Round 3's canceled word 0 drops; its words 1..4 are the result, which
    // in the round-4 renaming frame are exactly acc(4, 0..3).
    let result: [Reg; 4] = core::array::from_fn(|k| acc(4, k));
    reduce_and_store(m, result, A);
}

/// `helius_mont4_sqr_x86`: dedicated Montgomery squaring.
///
/// Ten products instead of sixteen: six cross products summed once and
/// doubled by an add-to-self chain, then four diagonal squares folded in.
/// The full 512-bit square lives in eight registers; reduction then runs
/// four [`cancel_low_word`] rows in exactly the mul kernel's style, with the
/// window carries rippled out to the top through both chains.
///
/// Trade-off vs. `mont4_mul`: fewer multiplier uops (port pressure win on
/// wide cores), but the reduction's `m_i` values depend serially on finished
/// words T_i, so the dependent-chain latency win is smaller than the
/// product-count saving suggests.
///
/// Bound: the running value stays below `p^2 + p*2^256 < 2^511`, so no carry
/// ever leaves T7 and every round re-enters with CF = OF = 0.
pub fn mont4_sqr<M: Machine>(m: &mut M) {
    let x = A; // x0..x3, same physical registers as the mul kernel's a.
    let (c1, c2, c3, c4, c5, c6) = (R12, R13, R14, R15, Rbp, Rsi);
    let h = Rbx;
    enter(m, "x");

    m.comment("");
    m.comment("cross products: C = sum of x_i*x_j (i < j), words C1..C6");
    m.mov(MULTIPLIER, x[0], "multiplicand <- x0");
    m.mulx(c4, c3, x[3], "x0*x3 -> (C3, C4)");
    m.mulx(LO, c2, x[2], "x0*x2 -> (C2, hi)");
    m.add(c3, LO, "C3 += hi(x0*x2)");
    m.mov(MULTIPLIER, x[1], "multiplicand <- x1");
    m.mulx(c5, LO, x[3], "x1*x3 -> (lo, C5)");
    m.adc(c4, LO, "C4 += lo(x1*x3)");
    m.adc_zero(c5, "C5 += chain carry; hi(x1*x3) <= 2^64-2 so CF = 0");
    m.mulx(LO, c1, x[0], "x0*x1 -> (C1, hi)");
    m.add(c2, LO, "C2 += hi(x0*x1)   [new chain]");
    m.mulx(h, LO, x[2], "x1*x2 -> (lo, hi)");
    m.adc(c3, LO, "C3 += lo(x1*x2)");
    m.adc(c4, h, "C4 += hi(x1*x2)");
    m.mov(MULTIPLIER, x[3], "multiplicand <- x3");
    m.mulx(c6, LO, x[2], "x2*x3 -> (lo, C6)");
    m.adc(c5, LO, "C5 += lo(x2*x3)");
    m.adc_zero(c6, "C6 += chain carry; hi(x2*x3) <= 2^64-2 so CF = 0");

    m.comment("");
    m.comment("double the cross words: T channel = 2C, carry bit lands in H");
    m.xor_clear(h, "H = 0; also clears CF for the doubling chain");
    for (word, c) in [c1, c2, c3, c4, c5, c6].into_iter().enumerate() {
        let what = format!("C{} *= 2", word + 1);
        if word == 0 {
            m.add(c, c, &what);
        } else {
            m.adc(c, c, &what);
        }
    }
    m.adc(h, h, "H = carry shifted out of 2*C6");

    m.comment("");
    m.comment("fold the diagonal squares: T = 2C + sum of x_i^2 * 2^(128i)");
    let t_of_c = [c1, c2, c3, c4, c5, c6];
    // Diagonal x_j^2 covers words 2j and 2j+1. Word 0 (T0) has no cross term;
    // each x_j frees its own register the moment it becomes the multiplicand.
    m.mov(MULTIPLIER, x[0], "multiplicand <- x0 (r8 freed for T0)");
    m.mulx(LO, x[0], MULTIPLIER, "x0^2 -> (T0, hi)");
    m.add(t_of_c[0], LO, "T1 = 2C1 + hi(x0^2)");
    for j in 1..4 {
        m.mov(
            MULTIPLIER,
            x[j],
            &format!("multiplicand <- x{j} (register freed)"),
        );
        m.mulx(x[j], LO, MULTIPLIER, &format!("x{j}^2 -> (lo, hi)"));
        m.adc(t_of_c[2 * j - 1], LO, &format!("T{} += lo(x{j}^2)", 2 * j));
        if j < 3 {
            m.adc(
                t_of_c[2 * j],
                x[j],
                &format!("T{} += hi(x{j}^2)", 2 * j + 1),
            );
        } else {
            m.adc(h, x[j], "T7 = H + hi(x3^2); x^2 < 2^512 so CF = 0");
        }
    }

    // T0..T7; R9..R11 (former x1..x3) are now scratch.
    let t = [x[0], c1, c2, c3, c4, c5, c6, h];
    let hi = R9;
    m.comment("");
    m.comment("Montgomery reduction: four cancel rows over the 8-word square");
    m.xor_clear(
        LO,
        "clear OF (adc left it undefined) before the dual chains",
    );
    for round in 0..4 {
        if round > 0 {
            m.comment("");
            m.claim_flags_clear("previous row rippled both chains out under the 2^511 bound");
        }
        let window: [Reg; 5] = core::array::from_fn(|k| t[round + k]);
        cancel_low_word(m, window, hi, round);
        for (k, &word) in t.iter().enumerate().skip(round + 5) {
            m.adcx(word, LO, &format!("T{k} += carry-chain ripple"));
            m.adox(word, LO, &format!("T{k} += value-chain ripple"));
        }
    }
    m.claim_flags_clear("last row closed at T7 under the 2^511 bound");

    m.comment("");
    let result: [Reg; 4] = core::array::from_fn(|k| t[4 + k]);
    reduce_and_store(m, result, [x[0], R9, R10, R11]);
}

/// Register roles for `helius_sos_x86`.
pub const SOS_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); then the current b_i pointer inside a row",
    ),
    (Rsi, "pair-table base (argument 2, live throughout)"),
    (
        Rdx,
        "T (pair count) on entry; then the implicit mulx multiplicand",
    ),
    (Rcx, "consts pointer: p at +0..+24, -p^-1 at +32"),
    (R8, "accumulator t0"),
    (R9, "accumulator t1"),
    (R10, "accumulator t2"),
    (R11, "accumulator t3"),
    (R12, "accumulator t4"),
    (R13, "accumulator t5 (top carry word)"),
    (
        R14,
        "byte offset 8j of the round's source limb; epilogue scratch",
    ),
    (R15, "pair-table cursor; epilogue scratch"),
    (Rbp, "pair-table end (rsi + 16T)"),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (Rbx, "high half of the current product"),
];

/// Six-word SoS accumulator t0..t5.
const T: [Reg; 6] = [R8, R9, R10, R11, R12, R13];
/// Byte offset `8j` of the current CIOS round's source limb.
const JOFF: Reg = R14;
/// Pair-table cursor of the inner product walk.
const CURSOR: Reg = R15;
/// Pair-table end bound (`rsi + 16T`).
const TABLE_END: Reg = Rbp;

/// One dual-chain product row into the six-word accumulator: for the value
/// already in `rdx`, `t[k] += lo_k` on the value chain and `t[k+1] += hi_k`
/// on the carry chain, source limbs from `[b + off + 8k]`. Both chains are
/// then closed into the top words, so the row leaves CF = OF = 0 and nothing
/// crosses the following back edge or row boundary.
fn sos_row_at<M: Machine>(m: &mut M, b: Reg, off: i32, product: &str) {
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            Mem::new(b, off + 8 * k as i32),
            T[k],
            T[k + 1],
            &format!("{product}[{k}]"),
            k,
        );
    }
    close_chains_t5(m);
    m.claim_flags_clear("in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping");
}

fn sos_row<M: Machine>(m: &mut M, b: Reg, product: &str) {
    sos_row_at(m, b, 0, product);
}

/// Five-word accumulator of sosd2 lane 0 (real part).
const L0: [Reg; 5] = [R8, R9, R10, R11, R12];
/// Five-word accumulator of sosd2 lane 1 (imaginary part).
const L1: [Reg; 5] = [R13, R14, R15, Rbp, Rdi];

/// The four result words of a five-word lane accumulator (word 4 is the
/// provably-zero top word by the time the epilogue runs).
const fn lane_result(lane: [Reg; 5]) -> [Reg; 4] {
    [lane[0], lane[1], lane[2], lane[3]]
}

/// sosd2 frame, all rsp + disp8. Limb values first (ny1 and the y0 copy
/// feed `mulx` memory operands directly), spilled pointers after; the
/// consts pointer is spilled so rcx can serve as the round cursor.
struct Sosd2Frame {
    ny1: FrameSlot,
    y0_copy: FrameSlot,
    x0_ptr: FrameSlot,
    x1_ptr: FrameSlot,
    y1_ptr: FrameSlot,
    z_ptr: FrameSlot,
    consts_ptr: FrameSlot,
    size: i32,
}

const SOSD2F: Sosd2Frame = {
    let l = FrameLayout::new();
    let (l, ny1) = l.slot(32);
    let (l, y0_copy) = l.slot(32);
    let (l, x0_ptr) = l.slot(8);
    let (l, x1_ptr) = l.slot(8);
    let (l, y1_ptr) = l.slot(8);
    let (l, z_ptr) = l.slot(8);
    let (l, consts_ptr) = l.slot(8);
    Sosd2Frame {
        ny1,
        y0_copy,
        x0_ptr,
        x1_ptr,
        y1_ptr,
        z_ptr,
        consts_ptr,
        size: l.size(),
    }
};

/// One dual-chain accumulate row of a lane window: `t[k] += lo_k` on the
/// value chain, `t[k+1] += hi_k` on the carry chain, source limbs from
/// `[base + off + 8k]`. Entry and exit invariant: CF = OF = 0.
fn sosd2_acc_row<M: Machine>(m: &mut M, t: [Reg; 5], base: Reg, off: i32, product: &str) {
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            Mem::new(base, off + 8 * k as i32),
            t[k],
            t[k + 1],
            &format!("{product}[{k}]"),
            k,
        );
    }
    close_value_chain(m, t[4], "close the value chain into the top word");
    m.claim_flags_clear("in-round peak < 3p*2^64 < 2^320 keeps the top word from wrapping");
}

/// Register roles for `helius_sosd2_small_x86`.
pub const SOSD2_SMALL_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); lane1 top accumulator; z again at the end",
    ),
    (Rsi, "x0 pointer on entry; then reloaded pointer scratch"),
    (
        Rdx,
        "x1 pointer on entry (spilled); the implicit mulx multiplicand",
    ),
    (
        Rcx,
        "y0 pointer on entry; then the round cursor (byte offset 8j)",
    ),
    (
        R8,
        "y1 pointer on entry (spilled); then lane0 accumulator t0",
    ),
    (
        R9,
        "consts pointer on entry (spilled); then lane0 accumulator t1",
    ),
    (R10, "lane0 accumulator t2"),
    (R11, "lane0 accumulator t3"),
    (R12, "lane0 accumulator t4 (top word)"),
    (R13, "lane1 accumulator u0"),
    (R14, "lane1 accumulator u1"),
    (R15, "lane1 accumulator u2"),
    (Rbp, "lane1 accumulator u3"),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (Rbx, "high half of the current product; prologue scratch"),
];

/// `helius_sosd2_small_x86`: dedicated dual-lane sum of products, fixed
/// T = 2 per lane -- the whole Fp2 product `(x0 + x1*u) * (y0 + y1*u)` in
/// one rolled leaf:
///
/// * lane0 = `(x0*y0 + x1*(p - y1)) * R^-1 mod p` (real part; the
///   subtraction enters as the negp image, exactly the portable `sosd2`),
/// * lane1 = `(x0*y1 + x1*y0) * R^-1 mod p` (imaginary part),
///
/// operands at most p, both lanes canonical on return. Arguments:
/// `(z: *mut u64x8 (lane0 then lane1), x0, x1, y0, y1: *const u64x4,
/// consts)` in `rdi, rsi, rdx, rcx, r8, r9`.
///
/// # Register budget and spill plan
///
/// T = 2 admits five-word lane accumulators (the portable round5 bound:
/// in-round peak < 3p*2^64 < 2^320), so the two lanes take ten GPRs; rdx
/// (mulx multiplicand), rax (product low), rbx (product high) and rcx (the
/// round cursor, byte offset 8j) take four more -- not enough left for the
/// five pointers (z, x0, x1, y0, y1), the consts table and the derived ny1
/// operand. No accumulator word ever spills: every word is touched by every
/// row of its lane, so an accumulator slot would sit inside the carry
/// chains and serialize them. Instead the operands whose consumers are
/// memory-source `mulx` anyway live in the frame: ny1 and a copy of y0 as
/// limb values read straight off rsp, x0/x1/y1/z/consts as spilled pointers
/// reloaded into rsi at most a few times per round.
///
/// # Shape and interleaving
///
/// The four reduction rounds share one loop body, so the text stays
/// op-cache friendly inside the combined pairing loop (the retired unrolled
/// twin's 2.4 KiB measurably pressured the frontend there). Per source limb
/// j, four product rows alternate lanes (`x0[j]*y0 -> t`, `x0[j]*y1 -> u`,
/// `x1[j]*ny1 -> t`, `x1[j]*y0 -> u`; the lane pairs share the multiplicand
/// load), then one Montgomery cancel row per lane. Every row closes both
/// flag chains, so the alternating rows are architecturally serial but
/// data-independent: flag renaming keeps both lanes' chains in flight,
/// which is the cross-lane ILP that two serial `helius_sos_x86` calls
/// measurably lose (g2 -13%). The back edge forces iteration-invariant
/// register names (the shift is four movs plus a flag-safe xor per lane),
/// zeroed accumulators up front, and a flag-cutting xor re-seed per
/// iteration.
///
/// # Bounds (operands <= p, T = 2)
///
/// Between rounds each lane holds `u_j < 3p < 2^258`; the in-round peak
/// before the shift stays below `3p*2^64 < 2^320`, so five words absorb
/// every carry. The final value is `< (1 + 0.1891*2)p < 1.379p < 2p`: the
/// top word ends exactly zero and one conditional subtraction per lane
/// reaches the canonical range.
pub fn sosd2_small_x86<M: Machine>(m: &mut M) {
    let cursor = Rcx;
    frame(m, SOSD2F.size, |m| {
        m.comment("frame: ny1 +0..24, y0 copy +32..56, x0/x1/y1/z/consts pointers +64..96");
        m.store(SOSD2F.z_ptr.mem(), Rdi, "spill z");
        m.store(SOSD2F.x1_ptr.mem(), Rdx, "spill the x1 pointer");
        m.store(SOSD2F.y1_ptr.mem(), R8, "spill the y1 pointer");
        m.store(SOSD2F.x0_ptr.mem(), Rsi, "spill the x0 pointer");
        m.store(SOSD2F.consts_ptr.mem(), R9, "spill the consts pointer");

        let scratch = [Rax, Rbx, R10, R11];
        m.comment("copy y0 into the frame: two rows per round read it via rsp");
        for (k, s) in scratch.into_iter().enumerate() {
            m.load(s, Mem::new(Rcx, 8 * k as i32), &format!("y0[{k}]"));
        }
        for (k, s) in scratch.into_iter().enumerate() {
            m.store(SOSD2F.y0_copy.limb(k), s, &format!("y0[{k}]"));
        }
        m.comment("ny1 = p - y1: lane0's subtracted term enters as the negp image");
        for (k, s) in scratch.into_iter().enumerate() {
            m.load(s, Mem::new(R9, 8 * k as i32), &format!("p{k}"));
        }
        for (k, s) in scratch.into_iter().enumerate() {
            let what = format!("p{k} - y1[{k}]");
            if k == 0 {
                m.sub_mem(s, Mem::new(R8, 0), &what);
            } else {
                m.sbb_mem(s, Mem::new(R8, 8 * k as i32), &what);
            }
        }
        for (k, s) in scratch.into_iter().enumerate() {
            m.store(SOSD2F.ny1.limb(k), s, &format!("ny1[{k}]"));
        }
        for (k, t) in L0.into_iter().enumerate() {
            m.xor_clear(t, &format!("t{k} = 0"));
        }
        for (k, u) in L1.into_iter().enumerate() {
            m.xor_clear(u, &format!("u{k} = 0"));
        }
        m.xor_clear(cursor, "byte offset of the round's source limb: 8j = 0");

        m.comment("");
        m.stride_loop(cursor, 8, LoopEnd::Imm(32), ".Lsosd2_round", &mut |m| {
            m.comment("product rows: both lanes, sharing each multiplicand load");
            m.load(Rsi, SOSD2F.x0_ptr.mem(), "x0 pointer");
            m.load_indexed(MULTIPLIER, Rsi, cursor, "x0[j], the row multiplicand");
            m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
            sosd2_acc_row(m, L0, Reg::Rsp, SOSD2F.y0_copy.off(), "x0[j]*y0");
            m.load(Rsi, SOSD2F.y1_ptr.mem(), "y1 pointer");
            sosd2_acc_row(m, L1, Rsi, 0, "x0[j]*y1");
            m.load(Rsi, SOSD2F.x1_ptr.mem(), "x1 pointer");
            m.load_indexed(MULTIPLIER, Rsi, cursor, "x1[j]");
            sosd2_acc_row(m, L0, Reg::Rsp, SOSD2F.ny1.off(), "x1[j]*ny1");
            sosd2_acc_row(m, L1, Reg::Rsp, SOSD2F.y0_copy.off(), "x1[j]*y0");
            m.load(Rsi, SOSD2F.consts_ptr.mem(), "consts pointer");
            m.comment("lane0 cancel row");
            cancel_low_word_at(m, L0, Rbx, Rsi, "");
            m.claim_flags_clear("cancel row closed both chains under the 2^320 bound");
            m.comment("lane1 cancel row");
            cancel_low_word_at(m, L1, Rbx, Rsi, "");
            m.claim_flags_clear("cancel row closed both chains under the 2^320 bound");
            m.claim_zero(L0[0], "the Montgomery factor cancels lane0's low word");
            m.claim_zero(L1[0], "the Montgomery factor cancels lane1's low word");
            m.comment("shift both lanes down one word: the canceled zero drops");
            for k in 0..4 {
                m.mov(L0[k], L0[k + 1], &format!("t{k} = t{}", k + 1));
            }
            m.xor_clear(L0[4], "t4 = 0 (CF/OF stay clear)");
            for k in 0..4 {
                m.mov(L1[k], L1[k + 1], &format!("u{k} = u{}", k + 1));
            }
            m.xor_clear(L1[4], "u4 = 0 (CF/OF stay clear)");
        });

        m.comment("");
        m.load(Rcx, SOSD2F.consts_ptr.mem(), "consts pointer back in rcx");
        m.load(
            Rdi,
            SOSD2F.z_ptr.mem(),
            "reload z (lane1's zeroed top word)",
        );
        m.comment("final reduction per lane: value < 2p, subtract p once if >= p");
        let keep = [Rax, Rbx, Rsi, MULTIPLIER];
        let lanes = [(lane_result(L0), 0), (lane_result(L1), 32)];
        for (lane, (value, out_off)) in lanes.into_iter().enumerate() {
            csub_pass(
                m,
                value,
                keep,
                p_limb,
                |k| format!("lane{lane}: keep-copy of word {k}"),
                |k| format!("lane{lane}: word {k} -= p{k}"),
                |k| format!("borrow: lane{lane} < p, keep word {k}"),
            );
            for (k, v) in value.iter().enumerate() {
                m.store(
                    Mem::new(Rdi, out_off + 8 * k as i32),
                    *v,
                    &format!("z[{}]", lane * 4 + k),
                );
            }
        }
    });
}

/// Register roles for `helius_fp6_mul_x86`.
pub const FP6_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled as a z+128 cursor); row-base cursor PY in the main loops; z again per component",
    ),
    (
        Rsi,
        "a pointer on entry (spilled); prologue pointer scratch; then PA, the multiplicand cursor a + 8j + 64i",
    ),
    (
        Rdx,
        "b pointer on entry (prologue cursor); the implicit mulx multiplicand",
    ),
    (
        Rcx,
        "consts pointer on entry (prologue only); then the product-walk bound PY + 288",
    ),
    (R8, "active-lane accumulator t0 (xi prologue: value limb 0)"),
    (R9, "active-lane accumulator t1"),
    (R10, "active-lane accumulator t2"),
    (R11, "active-lane accumulator t3"),
    (
        R12,
        "active-lane accumulator t4 (xi prologue: value top limb)",
    ),
    (
        R13,
        "shared top word t5: only the active lane's in-round carries live there",
    ),
    (
        R14,
        "xi outer cursor; then round cursor (byte offset 8j of the source limb)",
    ),
    (
        R15,
        "xi inner cursor; then component cursor (y-window byte offset 0/96/192)",
    ),
    (
        Rbp,
        "lane cursor: y-row byte offset 0 (real lane) / 32 (imag lane)",
    ),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (Rbx, "high half of the current product; prologue scratch"),
];

/// fp6 frame, all rsp-relative: the consts mirror, then the kernel slots.
struct Fp6Frame {
    a_ptr: FrameSlot,
    z_cur: FrameSlot,
    /// Dormant lane t0..t4 (t5 is provably zero between lane blocks).
    dorm: FrameSlot,
    /// Five 96-byte Fp2 blocks `[p - im, re, im]` in the order B2 B1 B0 X2 X1.
    yb: FrameSlot,
    size: i32,
}

const FP6F: Fp6Frame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv)
        .alias(CONSTS_MIRROR.mu);
    let (l, a_ptr) = l.slot(8);
    let (l, z_cur) = l.slot(8);
    let (l, dorm) = l.slot(40);
    let (l, yb) = l.slot(480);
    Fp6Frame {
        a_ptr,
        z_cur,
        dorm,
        yb,
        size: l.size(),
    }
};

/// Two conditional subtractions of p (final value < 2.135p) on t0..t3, then
/// store four limbs at `[rdi + out_off]`. Scratch: rax, rbx, rcx, rdx.
fn fp6_reduce_store<M: Machine>(m: &mut M, out_off: i32, lane: &str) {
    reduce_store(
        m,
        out_off,
        lane,
        2,
        "value < 2.135p, subtract p at most twice",
    );
}

/// `passes` conditional subtractions of p on t0..t3, then store four limbs at
/// `[rdi + out_off]`. `bound` documents the pre-reduction range. Scratch:
/// rax, rbx, rcx, rdx.
fn reduce_store<M: Machine>(m: &mut M, out_off: i32, lane: &str, passes: usize, bound: &str) {
    let value = [T[0], T[1], T[2], T[3]];
    let keep = [Rax, Rbx, Rcx, MULTIPLIER];
    m.comment(&format!("final reduction: {bound}"));
    for pass in 0..passes {
        csub_pass(
            m,
            value,
            keep,
            |k| CONSTS_MIRROR.p.limb(k),
            |k| format!("{lane} pass {pass}: keep-copy of word {k}"),
            |k| format!("{lane}: word {k} -= p{k}"),
            |k| format!("borrow: value < p, keep word {k}"),
        );
    }
    for (k, v) in value.iter().enumerate() {
        m.store(
            Mem::new(Rdi, out_off + 8 * k as i32),
            *v,
            &format!("z component {lane} limb {k}"),
        );
    }
}

/// Stage one Fp2 operand into the 96-byte frame block `[p - im, re, im]`
/// (the y-side shape every dual-lane row consumes). Entry: rdx = source Fp2,
/// rdi = destination block, A = p limbs (kept intact), rax/rbx/r12/r13
/// scratch.
fn stage_fp2_block<M: Machine>(m: &mut M, tag: &str) {
    let scratch = [Rax, Rbx, R12, R13];
    for (k, s) in scratch.into_iter().enumerate() {
        m.load(s, Mem::new(Rdx, 8 * k as i32), &format!("{tag}.re[{k}]"));
    }
    for (k, s) in scratch.into_iter().enumerate() {
        m.store(
            Mem::new(Rdi, 32 + 8 * k as i32),
            s,
            &format!("block re[{k}]"),
        );
    }
    for (k, s) in scratch.into_iter().enumerate() {
        m.load(
            s,
            Mem::new(Rdx, 32 + 8 * k as i32),
            &format!("{tag}.im[{k}]"),
        );
    }
    for (k, s) in scratch.into_iter().enumerate() {
        m.store(
            Mem::new(Rdi, 64 + 8 * k as i32),
            s,
            &format!("block im[{k}]"),
        );
    }
    m.comment("negp row: the subtracted imag term enters as p - im");
    for (k, s) in scratch.into_iter().enumerate() {
        m.mov(s, A[k], &format!("p{k}"));
    }
    for (k, s) in scratch.into_iter().enumerate() {
        let what = format!("p{k} - {tag}.im[{k}]");
        if k == 0 {
            m.sub_mem(s, Mem::new(Rdx, 32), &what);
        } else {
            m.sbb_mem(s, Mem::new(Rdx, 32 + 8 * k as i32), &what);
        }
    }
    for (k, s) in scratch.into_iter().enumerate() {
        m.store(Mem::new(Rdi, 8 * k as i32), s, &format!("block negp[{k}]"));
    }
}

/// Stage three Fp2 operands into consecutive 96-byte frame blocks
/// `[p - im, re, im]`. Entry: rdx = first source Fp2 (three contiguous,
/// 192 bytes), A = p limbs (kept intact), rax/rbx/r12/r13 scratch; rsi/rdi
/// consumed. The destination cursor starts at `rsp + dest_start` and steps
/// `dest_step` per block.
fn fp2_block_stage<M: Machine>(m: &mut M, dest_start: i32, dest_step: i32, label: &str, tag: &str) {
    let rsp = Reg::Rsp;
    m.mov(Rsi, Rdx, "");
    m.add_imm(Rsi, 192, "source end (three Fp2 components)");
    m.mov(Rdi, rsp, "");
    m.add_imm(Rdi, dest_start, "first destination block");
    m.stride_loop(Rdx, 64, LoopEnd::Reg(Rsi), label, &mut |m| {
        stage_fp2_block(m, tag);
        m.add_imm(Rdi, dest_step, "next block");
    });
}

/// xi = 9 + u scaling of two staged Fp2 blocks (`rsp + src_base` and
/// `+ 96`) into their X blocks `block_delta` bytes above: re' = 9re +
/// (p - im), im' = 9im + re, each reduced to canonical via the mu quotient
/// estimate, then the X block's negp row. Consumes r8..r13, rax, rbx, rcx,
/// rbp, rdx, rsi, rdi, r14, r15; frame table at +0 (p), +32 (-p^-1),
/// +40 (mu).
fn xi_scale_pass<M: Machine>(
    m: &mut M,
    src_base: i32,
    block_delta: i32,
    outer_label: &str,
    inner_label: &str,
) {
    let rsp = Reg::Rsp;
    let v = W5;
    m.xor_clear(
        R14,
        "outer cursor: first source block (+0) then second (+96)",
    );
    m.stride_loop(R14, 96, LoopEnd::Imm(192), outer_label, &mut |m| {
        m.xor_clear(R15, "inner cursor: real output (+0) then imag (+32)");
        m.stride_loop(R15, 32, LoopEnd::Imm(64), inner_label, &mut |m| {
            m.comment(
                "C row = [PC]: negp(im) for re = 9re - im, re for im = 9im + re; A row = [PC + 32]",
            );
            m.mov(Rsi, rsp, "");
            m.add(Rsi, R14, "+ source block");
            m.add(Rsi, R15, "+ pass");
            m.add_imm(Rsi, src_base, "PC");
            m.mov(Rdi, Rsi, "");
            m.add_imm(
                Rdi,
                block_delta + 32,
                &format!(
                    "output row: each X row sits {} bytes above its C row",
                    block_delta + 32
                ),
            );
            for (k, reg) in v[..4].iter().enumerate() {
                m.load(*reg, Mem::new(Rsi, 32 + 8 * k as i32), &format!("A[{k}]"));
            }
            m.xor_clear(v[4], "top limb; also clears CF/OF for the doubling chains");
            for doubled in ["2A", "4A", "8A"] {
                for (k, reg) in v.iter().enumerate() {
                    let what = format!("{doubled}[{k}]");
                    if k == 0 {
                        m.add(*reg, *reg, &what);
                    } else {
                        m.adc(*reg, *reg, &what);
                    }
                }
            }
            m.comment("9A = 8A + A, then + C: value = 9A + C < 10p < 2^257");
            for (k, reg) in v[..4].iter().enumerate() {
                let what = format!("+= A[{k}]");
                if k == 0 {
                    m.add_mem(*reg, Mem::new(Rsi, 32), &what);
                } else {
                    m.adc_mem(*reg, Mem::new(Rsi, 32 + 8 * k as i32), &what);
                }
            }
            m.adc_zero(v[4], "9A < 9p keeps the top limb below 2^61");
            for (k, reg) in v[..4].iter().enumerate() {
                let what = format!("+= C[{k}]");
                if k == 0 {
                    m.add_mem(*reg, Mem::new(Rsi, 0), &what);
                } else {
                    m.adc_mem(*reg, Mem::new(Rsi, 8 * k as i32), &what);
                }
            }
            m.adc_zero(v[4], "value < 10p < 2^257: top limb is 0 or 1");
            m.comment("estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10");
            m.mov(Rbx, v[4], "E builds from the top limbs");
            m.shld_imm(Rbx, v[3], 4, "E = top five bits of the value");
            m.load(MULTIPLIER, CONSTS_MIRROR.mu.mem(), "mu");
            m.mulx(Rcx, Rax, Rbx, "E*mu (high half zero: E < 2^5, mu < 2^57)");
            m.shr_imm(Rax, 58, "q");
            m.mov(MULTIPLIER, Rax, "q is the multiplicand");
            m.mulx_mem(Rbx, Rax, CONSTS_MIRROR.p.mem(), "q*p0 -> (l0, h0)");
            m.mulx_mem(R13, Rcx, CONSTS_MIRROR.p.at(8), "q*p1 -> (l1, h1)");
            m.add(Rcx, Rbx, "l1 += h0");
            m.mulx_mem(Rbx, Rbp, CONSTS_MIRROR.p.at(16), "q*p2 -> (l2, h2)");
            m.adc(Rbp, R13, "l2 += h1");
            m.mulx_mem(
                R13,
                MULTIPLIER,
                CONSTS_MIRROR.p.at(24),
                "q*p3 -> (l3, h3); rdx freed",
            );
            m.adc(MULTIPLIER, Rbx, "l3 += h2");
            m.adc_zero(R13, "h3 += carry; q*p < 11p < 2^260");
            m.sub_rr(v[0], Rax, "value -= q*p, limb 0");
            m.sbb_rr(v[1], Rcx, "limb 1");
            m.sbb_rr(v[2], Rbp, "limb 2");
            m.sbb_rr(v[3], MULTIPLIER, "limb 3");
            m.sbb_rr(v[4], R13, "limb 4");
            m.claim_zero(v[4], "value - q*p < 1.33p < 2^255 fits four limbs");
            m.comment("one conditional subtraction reaches canonical (< 1.33p < 2p)");
            let keep = [Rax, Rbx, Rcx, Rbp];
            csub_pass(
                m,
                [v[0], v[1], v[2], v[3]],
                keep,
                |k| CONSTS_MIRROR.p.limb(k),
                |k| format!("keep-copy of limb {k}"),
                |k| format!("limb {k} -= p{k}"),
                |k| format!("borrow: value < p, keep limb {k}"),
            );
            for (k, reg) in v[..4].iter().enumerate() {
                m.store(
                    Mem::new(Rdi, 8 * k as i32),
                    *reg,
                    &format!("X row limb {k}"),
                );
            }
        });
        m.comment("negp row of the X block just written: p - x.im (x canonical)");
        m.mov(Rsi, rsp, "");
        m.add(Rsi, R14, "+ source block offset");
        m.add_imm(Rsi, src_base + block_delta, "X block of this pass's source");
        for (k, reg) in v[..4].iter().enumerate() {
            m.load(*reg, CONSTS_MIRROR.p.limb(k), &format!("p{k}"));
        }
        for (k, reg) in v[..4].iter().enumerate() {
            let what = format!("p{k} - x.im[{k}]");
            if k == 0 {
                m.sub_mem(*reg, Mem::new(Rsi, 64), &what);
            } else {
                m.sbb_mem(*reg, Mem::new(Rsi, 64 + 8 * k as i32), &what);
            }
        }
        for (k, reg) in v[..4].iter().enumerate() {
            m.store(Mem::new(Rsi, 8 * k as i32), *reg, &format!("X negp[{k}]"));
        }
    });
}

/// Zero both dual-lane accumulators: the six T registers and the five
/// dormant frame words at `rsp + dorm`.
fn zero_lanes<M: Machine>(m: &mut M, dorm: FrameSlot) {
    m.comment("both lanes start at zero: registers (imag) and dormant frame (real)");
    for (k, t) in T.into_iter().enumerate() {
        m.xor_clear(t, &format!("t{k} = 0"));
    }
    for (k, t) in T[..5].iter().enumerate() {
        m.store(dorm.limb(k), *t, &format!("dormant word {k} = 0"));
    }
}

/// Swap the active and dormant lane accumulators through rbx. The shared
/// top word (t5) stays in place: it is provably zero between lane blocks.
fn lane_swap<M: Machine>(m: &mut M, dorm: FrameSlot) {
    m.claim_zero(T[5], "the shared top word is clear between lane blocks");
    m.comment("swap the active and dormant lanes through rbx");
    for (k, t) in T[..5].iter().enumerate() {
        let slot = dorm.limb(k);
        m.load(Rbx, slot, "dormant word");
        m.store(slot, *t, "spill the active word");
        m.mov(*t, Rbx, "activate");
    }
}

/// Montgomery cancel row plus the one-word shift for the six-word T
/// accumulator, reading `-p^-1` and p from the frame table (+32, +0).
/// Register names are loop-iteration-invariant, so the shift is five moves.
fn t6_cancel_shift<M: Machine>(m: &mut M) {
    m.comment("cancel row: m = t0 * -p^-1, then t += m*p zeroes t0");
    m.mov(MULTIPLIER, T[0], "m multiplicand <- t0");
    m.mulx_mem(
        Rbx,
        MULTIPLIER,
        CONSTS_MIRROR.pinv.mem(),
        "m = t0 * -p^-1 mod 2^64 (hi half discarded)",
    );
    m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
    sos_row_at(m, Reg::Rsp, CONSTS_MIRROR.p.off(), "m*p");
    m.claim_zero(T[0], "the Montgomery factor cancels the low word");
    m.comment("shift down one word: the canceled zero word drops");
    for k in 0..5 {
        m.mov(T[k], T[k + 1], &format!("t{k} = t{}", k + 1));
    }
    m.xor_clear(T[5], "t5 = 0 (CF/OF stay clear)");
}

/// `helius_fp6_mul_x86`: one whole Fp6 = Fp2[v]/(v^3 - xi) product,
/// `z = a * b` with `xi = 9 + u`, in a single leaf call.
///
/// Semantics (exactly `Fp6::mul`'s SoS schoolbook, Longa 2022/367 Eq. 9,
/// with x1 = xi*b1, x2 = xi*b2):
///
/// * c0 = a0*b0 + a1*x2 + a2*x1
/// * c1 = a0*b1 + a1*b0 + a2*x2
/// * c2 = a0*b2 + a1*b1 + a2*b0
///
/// Each output component is one dual-lane sum of three Fp2 products: per
/// lane a T = 6 sum of products with a single interleaved Montgomery
/// reduction (the portable sosd6), subtracted imag terms entering as
/// `p - y` rows. Arguments: `(z, a, b: *mut/const u64x24 in repr(C) Fp6
/// order c0.re, c0.im, .., c2.im; consts: *const { p[4], -p^-1, mu })` in
/// rdi, rsi, rdx, rcx. `a`, `b` fully canonical (every Fp < p); outputs
/// canonical. `mu = floor(2^310/p)` drives the xi-scaling reduction.
///
/// # Layout: one cursor for all three components
///
/// The frame holds five Fp2 operand blocks `[p - im, re, im]` (96 bytes
/// each) in the order B2 B1 B0 X2 X1. The three components' operand lists
/// are consecutive windows of that sequence -- c2 = (B2, B1, B0),
/// c1 = (B1, B0, X2), c0 = (B0, X2, X1) -- so a single window cursor
/// (r15 = 0, 96, 192) selects the component and one 96-byte-stride pointer
/// walks its three products. The a side is the same a0, a1, a2 for every
/// component, addressed as a + 8j + 64i. Output components are produced
/// c2, c1, c0; a z cursor in the frame walks down from z + 128.
///
/// # xi scaling in-kernel
///
/// x = xi*w computed once per b component into the X blocks:
/// re = 9*w.re + (p - w.im), im = 9*w.im + w.re, both < 10p over five limbs
/// (9t built as three add-doublings plus t). Reduction to canonical in
/// constant shape: E = floor(value/2^252) (a shld), q = floor(E*mu/2^58)
/// (one mulx by mu), value -= q*p, which lands below 1.33p (worst case over
/// all E buckets), then one conditional subtraction. The interpreter checks
/// the fifth limb dies; the negp rows p - x.im then need x.im < p, which
/// canonical guarantees.
///
/// # Register budget and spill plan
///
/// A dual-lane T = 6 needs two six-word accumulators -- twelve registers,
/// which with rdx/rax/rbx leaves nothing for cursors. Instead the lanes run
/// as blocks (all real rows, cancel, then all imag rows, cancel) and only
/// the active lane keeps registers: the dormant lane's five words live in
/// the frame and swap through rbx at each lane switch. The sixth word (r13)
/// is shared: a lane's in-round overflow dies into t4 at its own cancel
/// shift, so between blocks t5 is provably zero (the interpreter asserts
/// it). That prices the second lane at ten memory ops per round and frees
/// the round, window, and lane cursors plus the two walking pointers --
/// exactly fifteen registers. Cross-lane ILP inside one dual-lane pair is
/// coarser than the row-interleaved sosd2 leaf, but adjacent blocks are
/// data-independent and fit one OoO window together; the point of this leaf
/// is killing per-mul call/marshal overhead (6 calls, 72 pointer stores,
/// 9 negp temps, 2 Rust xi scalings), which is frontend mass, not ILP.
///
/// # Bounds (operands < p after the xi reduction, T = 6)
///
/// Exactly the portable sosd6 bounds: between rounds each lane holds
/// u < 7p < 2^260; the in-round peak before the shift stays below
/// 7p*2^64 < 2^322, so the six-word window absorbs every carry and each
/// row's chain closes are carry-free at t5. The final value is
/// < (1 + 0.1891*6)p < 2.135p: t4 ends exactly zero and two conditional
/// subtractions reach the canonical range.
pub fn fp6_mul_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    frame(m, FP6F.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, mu +40, a +48, z cursor +56, dormant lane +64, y window +104",
        );
        m.store(FP6F.a_ptr.mem(), Rsi, "spill the a pointer");
        m.mov(Rax, Rdi, "z");
        m.add_imm(
            Rax,
            128,
            "z + 128: components are produced c2 first, cursor walks down",
        );
        m.store(FP6F.z_cur.mem(), Rax, "z component cursor");
        for (k, reg) in A.iter().enumerate() {
            m.load(
                *reg,
                Mem::new(Rcx, 8 * k as i32),
                &format!("p{k} (kept live through the b copy)"),
            );
        }
        for (k, reg) in A.iter().enumerate() {
            m.store(
                CONSTS_MIRROR.p.limb(k),
                *reg,
                &format!("p{k}: cancel rows address the frame as a consts table"),
            );
        }
        m.load(Rax, Mem::new(Rcx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");
        m.load(Rax, Mem::new(Rcx, 40), "mu = floor(2^310/p)");
        m.store(CONSTS_MIRROR.mu.mem(), Rax, "mu");

        m.comment("");
        m.comment("copy b into the y window: source walks b0 b1 b2, blocks walk B0 B1 B2 down");
        fp2_block_stage(m, FP6F.yb.off() + 192, -96, ".Lfp6_bcopy", "b_i");

        m.comment("");
        m.comment("xi scaling: X2 = xi*b2 from B2, then X1 = xi*b1 from B1");
        xi_scale_pass(m, FP6F.yb.off(), 288, ".Lfp6_xi", ".Lfp6_xi_val");

        m.comment("");
        m.comment("components c2, c1, c0 = consecutive 3-block windows of [B2, B1, B0, X2, X1]");
        m.xor_clear(R15, "component cursor: window byte offset");
        m.stride_loop(R15, 96, LoopEnd::Imm(288), ".Lfp6_comp", &mut |m| {
            zero_lanes(m, FP6F.dorm);
            m.xor_clear(R14, "round cursor: byte offset 8j of the source limb");
            m.stride_loop(R14, 8, LoopEnd::Imm(32), ".Lfp6_round", &mut |m| {
                m.xor_clear(Rbp, "lane cursor: real rows (+0) first, then imag (+32)");
                m.stride_loop(Rbp, 32, LoopEnd::Imm(64), ".Lfp6_lane", &mut |m| {
                    lane_swap(m, FP6F.dorm);
                    m.load(Rsi, FP6F.a_ptr.mem(), "a");
                    m.add(Rsi, R14, "PA = a + 8j");
                    m.mov(Rdi, rsp, "");
                    m.add(Rdi, R15, "+ window");
                    m.add(Rdi, Rbp, "+ lane row offset");
                    m.add_imm(
                        Rdi,
                        FP6F.yb.off(),
                        "PY: the first product's block, lane-adjusted",
                    );
                    m.mov(Rcx, Rdi, "");
                    m.add_imm(Rcx, 288, "window end: three products");
                    m.stride_loop(Rdi, 96, LoopEnd::Reg(Rcx), ".Lfp6_prod", &mut |m| {
                        m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
                        m.load(MULTIPLIER, Mem::new(Rsi, 0), "a_i.re[j]");
                        sos_row_at(m, Rdi, 32, "a_i.re[j]*row0");
                        m.load(MULTIPLIER, Mem::new(Rsi, 32), "a_i.im[j]");
                        sos_row_at(m, Rdi, 0, "a_i.im[j]*row1");
                        m.add_imm(Rsi, 64, "next a component");
                    });
                    t6_cancel_shift(m);
                });
            });
            m.comment("component epilogue: imag lane in registers, real lane dormant");
            m.load(Rdi, FP6F.z_cur.mem(), "z component cursor");
            m.claim_zero(T[4], "imag final value < 2.135p < 2^256 fits four words");
            fp6_reduce_store(m, 32, "imag");
            for (k, t) in T[..5].iter().enumerate() {
                m.load(*t, FP6F.dorm.limb(k), &format!("real lane word {k}"));
            }
            m.claim_zero(T[4], "real final value < 2.135p < 2^256 fits four words");
            fp6_reduce_store(m, 0, "real");
            m.add_imm(Rdi, -64, "");
            m.store(
                FP6F.z_cur.mem(),
                Rdi,
                "z cursor steps down to the next component",
            );
        });
    });
}

/// Register roles for `helius_fp12_034_x86`.
pub const FP12_034_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); staging cursor; PY per product; z component pointer in the epilogue",
    ),
    (
        Rsi,
        "f pointer on entry (g staging cursor); then PA, the g multiplicand base rsp + G + 8*limb",
    ),
    (
        Rdx,
        "coefficient pointer on entry (staging cursor); the implicit mulx multiplicand",
    ),
    (
        Rcx,
        "consts pointer on entry (prologue only); then the product-walk cursor over the table",
    ),
    (R8, "active-lane accumulator t0 (xi prologue: value limb 0)"),
    (R9, "active-lane accumulator t1"),
    (R10, "active-lane accumulator t2"),
    (R11, "active-lane accumulator t3"),
    (
        R12,
        "active-lane accumulator t4 (xi prologue: value top limb)",
    ),
    (
        R13,
        "shared top word t5: only the active lane's in-round carries live there",
    ),
    (
        R14,
        "xi outer cursor; then round cursor (byte offset 8j of the source limb)",
    ),
    (R15, "component cursor 64*j over the six W-power outputs"),
    (
        Rbp,
        "duplicate-slot cursor in the prologue; then lane cursor: 0 (real) / 32 (imag)",
    ),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (
        Rbx,
        "high half of the current product; g-offset and prologue scratch",
    ),
];

/// fp12_034 frame. p/-p^-1/mu and the dormant lane sit at the fp6 kernel's
/// offsets (declared as aliases) so the shared cancel, swap and xi helpers
/// address both frames identically.
struct F034Frame {
    z_ptr: FrameSlot,
    /// Product-walk bound: the absolute address of the table end (the walk
    /// cursor is an absolute pointer, so the back edge compares against
    /// memory).
    walk_end: FrameSlot,
    /// Product-walk table: three 16-byte entries (y block offset, g offset).
    tab: FrameSlot,
    /// Five 96-byte y blocks `[p - im, re, im]`: C0, C3, C4, X3, X4.
    yb: FrameSlot,
    /// Twelve 64-byte g slots: f in W-power order, then slots 0..5 again.
    g: FrameSlot,
    size: i32,
}

const F034F: F034Frame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv)
        .alias(CONSTS_MIRROR.mu);
    let (l, z_ptr) = l.slot(8);
    let (l, walk_end) = l.slot(8);
    let l = l.alias(FP6F.dorm);
    let (l, tab) = l.slot(48);
    let (l, yb) = l.slot(480);
    let (l, g) = l.slot(768);
    F034Frame {
        z_ptr,
        walk_end,
        tab,
        yb,
        g,
        size: l.size(),
    }
};

/// `helius_fp12_034_x86`: the whole sparse Fp12 product of the Miller loop,
/// `z = f * (c0 + c3*w + c4*v*w)` with `w^2 = v`, `v^3 = xi = 9 + u`, in a
/// single leaf call (arkworks `mul_by_034`, D-type lines).
///
/// # Semantics (exactly `Fp12::mul_by_034_assign`'s SoS schoolbook)
///
/// In the W-power basis `W = w` (`W^6 = xi`) the element is
/// `sum g_k W^k` with `g = (a0, b0, a1, b1, a2, b2)` for `f = a + b*w`, and
/// the sparse multiplier is `c0 + c3 W + c4 W^3`, so every output is one
/// dual-lane T = 6 sum of three Fp2 products with a single interleaved
/// Montgomery reduction per lane (the portable sosd6):
///
/// * `h_j = g_j*c0 + g_{(j+5) mod 6}*C3' + g_{(j+3) mod 6}*C4'`,
/// * `C3' = xi*c3` exactly at j = 0, `C4' = xi*c4` exactly for j < 3
///   (the wrap terms), both xi values computed in-kernel via the mu
///   quotient-estimate reduction; subtracted imag terms enter as `p - im`
///   rows staged once per y block.
///
/// Arguments: `(z: *mut u64x48, f: *const u64x48, c: *const u64x24,
/// consts: *const { p[4], -p^-1, mu })` in rdi, rsi, rdx, rcx. `f` is
/// `repr(C)` Fp12 (48 limbs, c0 then c1, each Fp6 as in the fp6 leaf); `c`
/// is the three sparse coefficients c0, c3, c4 as contiguous Fp2s (the
/// caller stages them; they are freshly built per line evaluation, so the
/// staging is free). All inputs canonical (< p); outputs canonical.
///
/// # In-place update
///
/// `z == f` is the production shape (the Miller accumulator updates in
/// place) and is safe by construction: the prologue stages all of `f` into
/// the frame's g array and `f` is never read again, so output stores cannot
/// alias a live operand and the wrapper needs no copy.
///
/// # Layout: one walk table for all six components
///
/// The g array holds `f` in W-power order with slots 0..5 duplicated to
/// 6..11, so the wrap operands `g_{j+3}`, `g_{j+5}` are plain offsets
/// +192/+320 from slot j -- no modular indexing. The three products of a
/// component are walked through a 3-entry frame table of (y block, g
/// offset) pairs; only the two wrap y fields change per component (one
/// cmov each: X4-vs-C4 at j < 3, X3-vs-C3 at j = 0). Outputs are produced
/// h_0..h_5; the epilogue maps W order back to `repr(C)` as
/// `z + 192*(j&1) + 64*(j>>1)`.
///
/// # Register budget, spill plan, bounds
///
/// Exactly the fp6 leaf's design: lanes run as blocks sharing one six-word
/// accumulator set (dormant lane in the frame, shared top word provably
/// zero between blocks), the walk cursor is rcx with its bound in the frame
/// (all fifteen GPRs are otherwise live), and the sosd6 bounds apply
/// unchanged -- operands at most p, in-round peak < 7p*2^64 < 2^322, final
/// value < 2.135p, two conditional subtractions per lane.
pub fn fp12_034_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    frame(m, F034F.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, mu +40, z +48, walk bound +56, dormant lane +64, product table +104, y blocks +152, g array +632",
        );
        m.store(F034F.z_ptr.mem(), Rdi, "spill z");
        for (k, reg) in A.iter().enumerate() {
            m.load(
                *reg,
                Mem::new(Rcx, 8 * k as i32),
                &format!("p{k} (kept live through the coefficient copy)"),
            );
        }
        for (k, reg) in A.iter().enumerate() {
            m.store(
                CONSTS_MIRROR.p.limb(k),
                *reg,
                &format!("p{k}: cancel rows address the frame as a consts table"),
            );
        }
        m.load(Rax, Mem::new(Rcx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");
        m.load(Rax, Mem::new(Rcx, 40), "mu = floor(2^310/p)");
        m.store(CONSTS_MIRROR.mu.mem(), Rax, "mu");

        m.comment("");
        m.comment("product-walk table: g fields and the C0 entry are fixed, the");
        m.comment("two wrap y fields (e1, e2) are rewritten per component");
        m.xor_clear(Rax, "");
        m.store(F034F.tab.mem(), Rax, "e0.y: the C0 block (+0)");
        m.store(F034F.tab.at(8), Rax, "e0.g: g_j (+0)");
        m.add_imm(Rax, 192, "");
        m.store(F034F.tab.at(24), Rax, "e1.g: g_{j+3} (+192)");
        m.add_imm(Rax, 128, "");
        m.store(F034F.tab.at(40), Rax, "e2.g: g_{j+5} (+320)");
        m.mov(Rax, rsp, "");
        m.add_imm(Rax, F034F.tab.off() + 48, "");
        m.store(
            F034F.walk_end.mem(),
            Rax,
            "product-walk bound: the table end address",
        );

        m.comment("");
        m.comment("g array: f in W-power order g = a0, b0, a1, b1, a2, b2, slots");
        m.comment("duplicated so the wrap products index without mod; f is fully");
        m.comment("staged before any z store, which is what makes z == f safe");
        m.mov(Rax, Rsi, "");
        m.add_imm(Rax, 192, "a-half end");
        m.mov(R14, Rsi, "");
        m.add_imm(R14, 192, "b-half source cursor");
        m.mov(Rdi, rsp, "");
        m.add_imm(
            Rdi,
            F034F.g.off(),
            "g slot cursor (one a/b slot pair per iteration)",
        );
        m.mov(Rbp, Rdi, "");
        m.add_imm(Rbp, 384, "duplicate cursor: slot k + 6");
        let scratch = [Rbx, Rcx, R12, R13];
        m.stride_loop(Rsi, 64, LoopEnd::Reg(Rax), ".Lf034_g", &mut |m| {
            for (name, src, dst) in [("a_t", Rsi, 0), ("b_t", R14, 64)] {
                for half in 0..2i32 {
                    for (k, s) in scratch.into_iter().enumerate() {
                        m.load(
                            s,
                            Mem::new(src, 32 * half + 8 * k as i32),
                            &format!("{name}[{}]", 4 * half + k as i32),
                        );
                    }
                    for (k, s) in scratch.into_iter().enumerate() {
                        m.store(
                            Mem::new(Rdi, dst + 32 * half + 8 * k as i32),
                            s,
                            &format!("g slot limb {}", 4 * half + k as i32),
                        );
                    }
                    for (k, s) in scratch.into_iter().enumerate() {
                        m.store(
                            Mem::new(Rbp, dst + 32 * half + 8 * k as i32),
                            s,
                            "duplicate slot",
                        );
                    }
                }
            }
            m.add_imm(R14, 64, "");
            m.add_imm(Rdi, 128, "next slot pair");
            m.add_imm(Rbp, 128, "");
        });

        m.comment("");
        m.comment("stage the coefficient blocks: c0 -> C0, c3 -> C3, c4 -> C4");
        fp2_block_stage(m, F034F.yb.off(), 96, ".Lf034_c", "c_i");

        m.comment("");
        m.comment("xi scaling: X3 = xi*c3 from C3, then X4 = xi*c4 from C4");
        xi_scale_pass(m, F034F.yb.off() + 96, 192, ".Lf034_xi", ".Lf034_xi_val");

        m.comment("");
        m.comment("components h_j, j = 0..5 in the W-power basis:");
        m.comment("h_j = g_j*C0 + g_{j+5}*C3' + g_{j+3}*C4' (wrap xi via X blocks)");
        m.xor_clear(R15, "component cursor: 64*j");
        m.stride_loop(R15, 64, LoopEnd::Imm(384), ".Lf034_comp", &mut |m| {
            m.comment("wrap selection: e1.y = X4 exactly for j < 3, e2.y = X3 exactly at j = 0");
            m.xor_clear(Rax, "");
            m.add_imm(Rax, 192, "the C4 block offset, also the C -> X block delta");
            m.mov(Rbx, Rax, "");
            m.add(Rbx, Rax, "X4 block offset (+384)");
            m.mov(Rcx, R15, "");
            m.add_imm(Rcx, -192, "CF set exactly when 64j >= 192, i.e. j >= 3");
            m.cmov_carry(Rbx, Rax, "j >= 3: plain C4");
            m.store(F034F.tab.at(16), Rbx, "e1.y");
            m.xor_clear(Rbx, "");
            m.add_imm(Rbx, 96, "C3 block offset");
            m.mov(Rcx, Rbx, "");
            m.add(Rcx, Rax, "X3 block offset (+288)");
            m.xor_clear(Rax, "");
            m.sub_rr(Rax, R15, "CF set exactly when j > 0");
            m.cmov_carry(Rcx, Rbx, "j > 0: plain C3");
            m.store(F034F.tab.at(32), Rcx, "e2.y");
            zero_lanes(m, FP6F.dorm);
            m.xor_clear(R14, "round cursor: byte offset 8j of the source limb");
            m.stride_loop(R14, 8, LoopEnd::Imm(32), ".Lf034_round", &mut |m| {
                m.xor_clear(Rbp, "lane cursor: real rows (+0) first, then imag (+32)");
                m.stride_loop(Rbp, 32, LoopEnd::Imm(64), ".Lf034_lane", &mut |m| {
                    lane_swap(m, FP6F.dorm);
                    m.mov(Rsi, rsp, "");
                    m.add(Rsi, R15, "+ 64j: the g_j slot");
                    m.add(Rsi, R14, "+ 8*limb");
                    m.add_imm(Rsi, F034F.g.off(), "PA: the g multiplicand base");
                    m.mov(Rcx, rsp, "");
                    m.add_imm(Rcx, F034F.tab.off(), "product-walk cursor");
                    m.stride_loop(
                        Rcx,
                        16,
                        LoopEnd::Mem(F034F.walk_end.mem()),
                        ".Lf034_prod",
                        &mut |m| {
                            m.mov(Rdi, rsp, "");
                            m.add(Rdi, Rbp, "+ lane row offset");
                            m.add_imm(Rdi, F034F.yb.off(), "");
                            m.add_mem(Rdi, Mem::new(Rcx, 0), "PY: this product's y block");
                            m.load(Rbx, Mem::new(Rcx, 8), "g offset of this product");
                            m.load_indexed(MULTIPLIER, Rsi, Rbx, "g.re[limb]");
                            m.xor_clear(LO, "re-seed CF = OF = 0 (pointer math clobbered flags)");
                            sos_row_at(m, Rdi, 32, "g.re*row0");
                            m.load(
                                Rbx,
                                Mem::new(Rcx, 8),
                                "g offset again (rbx was the row's hi scratch)",
                            );
                            m.add_imm(Rbx, 32, "the imag limbs sit 32 bytes up");
                            m.load_indexed(MULTIPLIER, Rsi, Rbx, "g.im[limb]");
                            m.xor_clear(LO, "re-seed CF = OF = 0 (add clobbered flags)");
                            sos_row_at(m, Rdi, 0, "g.im*row1");
                        },
                    );
                    t6_cancel_shift(m);
                });
            });
            m.comment("component epilogue: W order back to repr(C), z + 192*(j&1) + 64*(j>>1)");
            m.xor_clear(Rcx, "zero source for the shift");
            m.mov(Rax, R15, "");
            m.shr_imm(Rax, 7, "j >> 1");
            m.shld_imm(Rax, Rcx, 6, "A = 64*(j >> 1)");
            m.mov(Rbx, R15, "");
            m.sub_rr(Rbx, Rax, "");
            m.sub_rr(Rbx, Rax, "64j - 128*(j >> 1) = 64*(j&1)");
            m.mov(Rcx, Rbx, "");
            m.add(Rbx, Rbx, "");
            m.add(Rbx, Rcx, "192*(j&1)");
            m.add(Rbx, Rax, "the component's z offset");
            m.load(Rdi, F034F.z_ptr.mem(), "z");
            m.add(Rdi, Rbx, "z component pointer");
            m.add_imm(Rdi, 32, "imag half first: the store cursor walks down");
            m.comment("imag lane from the registers, then the dormant real lane");
            m.xor_clear(Rbp, "output-lane counter");
            m.stride_loop(Rbp, 32, LoopEnd::Imm(64), ".Lf034_out", &mut |m| {
                m.claim_zero(T[4], "final value < 2.135p < 2^256 fits four words");
                fp6_reduce_store(m, 0, "lane");
                m.comment("reload the dormant (real) lane; the last pass reloads dead words");
                for (k, t) in T[..5].iter().enumerate() {
                    m.load(*t, FP6F.dorm.limb(k), &format!("real lane word {k}"));
                }
                m.add_imm(Rdi, -32, "step down to the real half");
            });
        });
    });
}

/// fsq-family value bank: the walk bodies' full eight-word 512-bit value
/// (the register map's "accumulator/value word k"). Shared by the fp12_sqr,
/// fp12_mul and cyc_sqr walk bodies.
const W8: [Reg; 8] = [R8, R9, R10, R11, R12, R13, R14, R15];
/// Low and high quads of [`W8`]: four-limb rows, staging and copy loops,
/// and the halves of a double-width value.
const W4L: [Reg; 4] = [R8, R9, R10, R11];
const W4H: [Reg; 4] = [R12, R13, R14, R15];
/// Five-word value of the mu quotient-estimate reductions (the fp6/f034 xi
/// scale and the fsq muxi pass share the shape).
const W5: [Reg; 5] = [R8, R9, R10, R11, R12];

/// Register roles for `helius_fp12_sqr_x86`.
pub const FP12_SQR_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); walk destination pointer in every table-driven pass",
    ),
    (
        Rsi,
        "f pointer on entry (staging source); walk source-1 pointer; mask scratch",
    ),
    (
        Rdx,
        "consts pointer on entry; the implicit mulx multiplicand; walk scratch",
    ),
    (
        Rcx,
        "walk source-2 pointer; product m-walk cursor; staging cursor",
    ),
    (R8, "accumulator/value word 0"),
    (R9, "accumulator/value word 1"),
    (R10, "accumulator/value word 2"),
    (R11, "accumulator/value word 3"),
    (R12, "accumulator/value word 4"),
    (R13, "accumulator/value word 5; mu-reduction scratch"),
    (
        R14,
        "product round cursor (byte offset 8j); 8-limb value word 6",
    ),
    (R15, "product block cursor 96k; 8-limb value word 7"),
    (
        Rbp,
        "outer iteration cursor (ctx row address, spilled per phase); every walk's row cursor",
    ),
    (
        Rax,
        "low half of the current product; zero for chain closes; borrow mask",
    ),
    (
        Rbx,
        "high half of the current product; walk bound and half cursors",
    ),
];

/// fp12_sqr frame. p/-p^-1/mu sit at the fp6 kernel's offsets (the consts
/// mirror) so the shared cancel-row helper addresses this frame as a consts
/// table.
struct FsqFrame {
    z: FrameSlot,
    /// Outer two-iteration loop bound (ctx table end address).
    outer_end: FrameSlot,
    /// Current walk bound (one walk at a time), plus a second slot for the
    /// sums walk nested inside the side loop.
    walk_end: FrameSlot,
    walk_end2: FrameSlot,
    /// Outer cursor spill: every phase uses all fifteen GPRs.
    ctx_spill: FrameSlot,
    /// The rodata table base (lea once, reloaded per walk).
    tbl: FrameSlot,
    /// Product m-walk bound (constant address, set once).
    mend: FrameSlot,
    // Per-iteration ctx fields, unpacked from the ctx row into frame slots.
    muxi_src: FrameSlot,
    muxi_dst: FrameSlot,
    stage_x: FrameSlot,
    stage_y: FrameSlot,
    mod_dst: FrameSlot,
    add_seg: FrameSlot,
    /// p - src.im of the current xi site.
    negim: FrameSlot,
    /// Staging destination cursor (XSTG then YSTG).
    stage_cur: FrameSlot,
    /// An 8-limb zero: source of the double-width negation rows.
    zero8: FrameSlot,
    /// Per-iteration xi output (one Fp2): xi*b.c2, then xi*V.c2.
    xi: FrameSlot,
    /// t0 = a + b and t1 = b*v + a (canonical Fp6 each).
    t0: FrameSlot,
    t1: FrameSlot,
    /// V = a*b mod p and U = t0*t1 mod p (canonical Fp6 each).
    v: FrameSlot,
    u: FrameSlot,
    /// W = t1*v + t1 built here, then y.a = U - W in place; y.b = 2V follows
    /// contiguously so one loop copies both halves out to z.
    ya: FrameSlot,
    yb: FrameSlot,
    /// f staged once (48 limbs): all later reads are frame-relative, and
    /// z == f becomes trivially safe (no f read after any z store).
    fst: FrameSlot,
    /// Karatsuba operand sides: 6 blocks x 96 bytes `[re, im, re+im]` in the
    /// order c0, c1, c2, c1+c2, c0+c1, c0+c2.
    xstg: FrameSlot,
    ystg: FrameSlot,
    /// Product regions: 6 x 192 bytes (d0 +0, d1 +64, d2 +128).
    prod: FrameSlot,
    /// Four 8-limb xi outputs S1, S2, S3, S4 of the nine-fold walk.
    scr: FrameSlot,
    /// Two negated .b lanes (p*2^256 - x) feeding the nine-fold walk.
    nb: FrameSlot,
    size: i32,
}

const FSQF: FsqFrame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv)
        .alias(CONSTS_MIRROR.mu);
    let (l, z) = l.slot(8);
    let (l, outer_end) = l.slot(8);
    let (l, walk_end) = l.slot(8);
    let (l, walk_end2) = l.slot(8);
    let (l, ctx_spill) = l.slot(8);
    let (l, tbl) = l.slot(8);
    let (l, mend) = l.slot(8);
    let (l, muxi_src) = l.slot(8);
    let (l, muxi_dst) = l.slot(8);
    let (l, stage_x) = l.slot(8);
    let (l, stage_y) = l.slot(8);
    let (l, mod_dst) = l.slot(8);
    let (l, add_seg) = l.slot(8);
    let (l, negim) = l.slot(32);
    let (l, stage_cur) = l.slot(8);
    let (l, zero8) = l.slot(64);
    let (l, xi) = l.slot(64);
    let (l, t0) = l.slot(192);
    let (l, t1) = l.slot(192);
    let (l, v) = l.slot(192);
    let (l, u) = l.slot(192);
    let (l, ya) = l.slot(192);
    let (l, yb) = l.slot(192);
    let (l, fst) = l.slot(384);
    let (l, xstg) = l.slot(576);
    let (l, ystg) = l.slot(576);
    let (l, prod) = l.slot(1152);
    let (l, scr) = l.slot(256);
    let (l, nb) = l.slot(128);
    FsqFrame {
        z,
        outer_end,
        walk_end,
        walk_end2,
        ctx_spill,
        tbl,
        mend,
        muxi_src,
        muxi_dst,
        stage_x,
        stage_y,
        mod_dst,
        add_seg,
        negim,
        stage_cur,
        zero8,
        xi,
        t0,
        t1,
        v,
        u,
        ya,
        yb,
        fst,
        xstg,
        ystg,
        prod,
        scr,
        nb,
        size: l.size(),
    }
};

/// The fp12_sqr walk-table regions, in blob order.
struct FsqTab {
    ctx: TableSegment,
    add: TableSegment,
    subs: TableSegment,
    gsub: TableSegment,
    nine: TableSegment,
    gadd: TableSegment,
    mod_red: TableSegment,
    msub: TableSegment,
    sums: TableSegment,
    bytes: i32,
}

const FSQ_TB: FsqTab = {
    let l = TableLayout::new();
    let (l, ctx) = l.seg(2, 8); // per-iteration ctx rows
    let (l, add) = l.seg(24, 3); // modular single-width adds (12/iteration)
    let (l, subs) = l.seg(6, 3); // epilogue modular subs
    let (l, gsub) = l.seg(32, 3); // guarded double-width subs
    let (l, nine) = l.seg(4, 3); // nine-fold xi rows
    let (l, gadd) = l.seg(6, 3); // guarded double-width adds
    let (l, mod_red) = l.seg(6, 2); // Montgomery reduction rows
    let (l, msub) = l.seg(3, 2); // product sub-rows
    let (l, sums) = l.seg(3, 3); // staging sum rows
    FsqTab {
        ctx,
        add,
        subs,
        gsub,
        nine,
        gadd,
        mod_red,
        msub,
        sums,
        bytes: l.bytes(),
    }
};

const FSQ_TAB_LABEL: &str = ".Lfsq_tab";

/// The read-only walk tables. Offsets are rsp-relative (operands) or
/// blob-relative (the ctx rows' modadd segment field).
fn fp12_sqr_tables() -> Vec<u64> {
    let mut t: Vec<u64> = Vec::new();
    let row3 = |t: &mut Vec<u64>, dst: i32, s1: i32, s2: i32| {
        t.extend([dst as u64, s1 as u64, s2 as u64]);
    };
    // Product regions and their lanes: .a = d0 (+0), .b = d1 (+64).
    let pk = |k: i32| FSQF.prod.off() + 192 * k;
    let (ad, be, cf, za, zb, zc) = (pk(0), pk(1), pk(2), pk(3), pk(4), pk(5));

    // ctx rows: muxi src/dst, stage x/y, mod dst, modadd segment.
    // Iteration 0 computes V = a*b and prebuilds t0/t1 (t1 needs xi*b.c2);
    // iteration 1 computes U = t0*t1 and prebuilds W and y.b from V.
    t.extend([
        (FSQF.fst.off() + 320) as u64, // b.c2
        FSQF.xi.off() as u64,
        FSQF.fst.off() as u64,
        (FSQF.fst.off() + 192) as u64,
        FSQF.v.off() as u64,
        FSQ_TB.add.off() as u64,
        0,
        0,
    ]);
    t.extend([
        (FSQF.v.off() + 128) as u64, // V.c2
        FSQF.xi.off() as u64,
        FSQF.t0.off() as u64,
        FSQF.t1.off() as u64,
        FSQF.u.off() as u64,
        FSQ_TB.add.row(12) as u64,
        0,
        0,
    ]);

    // Modular single-width adds, iteration 0: t0 = a + b, then
    // t1 = b*v + a = (xi*b.c2 + a.c0, b.c0 + a.c1, b.c1 + a.c2).
    assert_eq!(t.len() * 8, FSQ_TB.add.off() as usize);
    for j in 0..6 {
        row3(
            &mut t,
            FSQF.t0.off() + 32 * j,
            FSQF.fst.off() + 32 * j,
            FSQF.fst.off() + 192 + 32 * j,
        );
    }
    for half in 0..2 {
        row3(
            &mut t,
            FSQF.t1.off() + 32 * half,
            FSQF.xi.off() + 32 * half,
            FSQF.fst.off() + 32 * half,
        );
    }
    for j in 0..4 {
        row3(
            &mut t,
            FSQF.t1.off() + 64 + 32 * j,
            FSQF.fst.off() + 192 + 32 * j,
            FSQF.fst.off() + 64 + 32 * j,
        );
    }
    // Iteration 1: W = V*v + V = (xi*V.c2 + V.c0, V.c0 + V.c1, V.c1 + V.c2)
    // into YA, and y.b = 2V into YB.
    for half in 0..2 {
        row3(
            &mut t,
            FSQF.ya.off() + 32 * half,
            FSQF.xi.off() + 32 * half,
            FSQF.v.off() + 32 * half,
        );
    }
    for j in 0..4 {
        row3(
            &mut t,
            FSQF.ya.off() + 64 + 32 * j,
            FSQF.v.off() + 32 * j,
            FSQF.v.off() + 64 + 32 * j,
        );
    }
    for j in 0..6 {
        row3(
            &mut t,
            FSQF.yb.off() + 32 * j,
            FSQF.v.off() + 32 * j,
            FSQF.v.off() + 32 * j,
        );
    }

    // Modular single-width subs (epilogue): y.a = U - W, in place over YA.
    assert_eq!(t.len() * 8, FSQ_TB.subs.off() as usize);
    for j in 0..6 {
        row3(
            &mut t,
            FSQF.ya.off() + 32 * j,
            FSQF.u.off() + 32 * j,
            FSQF.ya.off() + 32 * j,
        );
    }

    // Double-width subs. First the per-product Karatsuba assembly
    // (d1 -= d0, d1 -= d2 exact; d0 -= d2 guarded), then the cross-term
    // subtractions (a-lane guarded, b-lane exact), then the two negations
    // feeding the nine-fold walk.
    assert_eq!(t.len() * 8, FSQ_TB.gsub.off() as usize);
    for k in 0..6 {
        let p = pk(k);
        row3(&mut t, p + 64, p + 64, p);
        row3(&mut t, p + 64, p + 64, p + 128);
        row3(&mut t, p, p, p + 128);
    }
    for (dst, src) in [(za, be), (za, cf), (zb, ad), (zb, be), (zc, ad), (zc, cf)] {
        row3(&mut t, dst, dst, src);
        row3(&mut t, dst + 64, dst + 64, src + 64);
    }
    row3(&mut t, FSQF.nb.off(), FSQF.zero8.off(), za + 64);
    row3(&mut t, FSQF.nb.off() + 64, FSQF.zero8.off(), cf + 64);

    // Nine-fold rows (dst, x, y): dst = 9x + y mod p*2^256, canonical high.
    // S1, S2 = xi*ZA; S3, S4 = xi*CF.
    assert_eq!(t.len() * 8, FSQ_TB.nine.off() as usize);
    row3(&mut t, FSQF.scr.off(), za, FSQF.nb.off());
    row3(&mut t, FSQF.scr.off() + 64, za + 64, za);
    row3(&mut t, FSQF.scr.off() + 128, cf, FSQF.nb.off() + 64);
    row3(&mut t, FSQF.scr.off() + 192, cf + 64, cf);

    // Double-width adds: z.a = xi(ZA) + AD (into S1/S2), z.b = ZB + xi(CF),
    // z.c = ZC + BE.
    assert_eq!(t.len() * 8, FSQ_TB.gadd.off() as usize);
    row3(&mut t, FSQF.scr.off(), FSQF.scr.off(), ad);
    row3(&mut t, FSQF.scr.off() + 64, FSQF.scr.off() + 64, ad + 64);
    row3(&mut t, zb, zb, FSQF.scr.off() + 128);
    row3(&mut t, zb + 64, zb + 64, FSQF.scr.off() + 192);
    row3(&mut t, zc, zc, be);
    row3(&mut t, zc + 64, zc + 64, be + 64);

    // Montgomery reduction rows (src, dst offset relative to the ctx dst).
    assert_eq!(t.len() * 8, FSQ_TB.mod_red.off() as usize);
    for (row, src) in [
        FSQF.scr.off(),
        FSQF.scr.off() + 64,
        zb,
        zb + 64,
        zc,
        zc + 64,
    ]
    .into_iter()
    .enumerate()
    {
        t.extend([src as u64, 32 * row as u64]);
    }

    // Product sub-rows (operand sub-offset, destination sub-offset):
    // d1 = s*s first, then d0 = re*re, then d2 = im*im.
    assert_eq!(t.len() * 8, FSQ_TB.msub.off() as usize);
    t.extend([64, 64, 0, 0, 32, 128]);

    // Staging sum rows relative to the side base: block3 = c1 + c2,
    // block4 = c0 + c1, block5 = c0 + c2 (all 12 limbs, s-lanes add).
    assert_eq!(t.len() * 8, FSQ_TB.sums.off() as usize);
    row3(&mut t, 288, 96, 192);
    row3(&mut t, 384, 0, 96);
    row3(&mut t, 480, 0, 192);
    assert_eq!(t.len() * 8, FSQ_TB.bytes as usize);
    t
}

/// Load the walk table base and set a walk's cursor and bound:
/// cursor (returned in `cursor`) = table base + `offset`, bound slot
/// `end_slot` = cursor + `bytes`.
fn fsq_walk_setup<M: Machine>(m: &mut M, cursor: Reg, seg: TableSegment, end_slot: FrameSlot) {
    m.load(cursor, FSQF.tbl.mem(), "table base");
    m.add_imm(cursor, seg.off(), "walk start");
    m.mov(Rax, cursor, "");
    m.add_imm(Rax, seg.bytes(), "walk end");
    m.store(end_slot.mem(), Rax, "walk bound");
}

/// Run one table walk whose cursor (rbp) and walk-end slot are already set:
/// one `row` call per `seg`-shaped row (the fmu ctx-end and cyc chained
/// setups position the cursor themselves).
fn walk_rows<M: Machine>(m: &mut M, seg: TableSegment, label: &str, row: &mut dyn FnMut(&mut M)) {
    m.stride_loop(
        Rbp,
        seg.row_bytes(),
        LoopEnd::Mem(FSQF.walk_end.mem()),
        label,
        row,
    );
}

/// One whole fixed-segment table walk: cursor to the segment start, bound to
/// its end, then the rows.
fn walk<M: Machine>(m: &mut M, seg: TableSegment, label: &str, row: &mut dyn FnMut(&mut M)) {
    fsq_walk_setup(m, Rbp, seg, FSQF.walk_end);
    walk_rows(m, seg, label, row);
}

/// Decode a 3-slot walk row at `[rbp]` into rsp-relative pointers:
/// rdi = dst, rsi = source 1, rcx = source 2.
fn fsq_decode3<M: Machine>(m: &mut M) {
    fsq_decode3_at(m, None);
}

/// [`fsq_decode3`] with an optional extra destination base: with
/// `dst_ctx = Some(slot)` the row's dst field is relative to the frame
/// offset held in that ctx slot (the fp12_mul park decode); sources stay
/// rsp-relative.
fn fsq_decode3_at<M: Machine>(m: &mut M, dst_ctx: Option<FrameSlot>) {
    let rsp = Reg::Rsp;
    m.mov(Rdi, rsp, "");
    if let Some(slot) = dst_ctx {
        m.add_mem(Rdi, slot.mem(), "+ ctx destination base");
    }
    m.add_mem(Rdi, Mem::new(Rbp, 0), "dst = rsp + row.dst");
    m.mov(Rsi, rsp, "");
    m.add_mem(Rsi, Mem::new(Rbp, 8), "s1 = rsp + row.s1");
    m.mov(Rcx, rsp, "");
    m.add_mem(Rcx, Mem::new(Rbp, 16), "s2 = rsp + row.s2");
}

/// Load p & mask into `dst` (borrow-mask route of the guarded subtraction);
/// `mask` holds 0 or all-ones.
fn fsq_masked_p<M: Machine>(m: &mut M, dst: Reg, mask: Reg, limb: usize) {
    if dst != mask {
        m.mov(dst, mask, "");
    }
    m.and_mem(
        dst,
        CONSTS_MIRROR.p.limb(limb),
        &format!("p{limb} & borrow mask"),
    );
}

/// One dual-chain product row of the 4x4 mulpre: `t[k] += lo_k` on the value
/// chain, `t[k+1] += hi_k` on the carry chain, source limbs from `[y + 8k]`,
/// both chains closed into the top words. Entry/exit: CF = OF = 0.
fn fsq_mulpre_row<M: Machine>(m: &mut M, y: Reg) {
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            Mem::new(y, 8 * k as i32),
            T[k],
            T[k + 1],
            &format!("x[j]*y[{k}]"),
            k,
        );
    }
    close_chains_t5(m);
    m.claim_flags_clear(
        "row peak < 2^257 window + 2^320 product < 2^321, far below the six-word 2^384",
    );
}

/// Copy-subtract-cmov canonicalization of the four-limb value in `v`,
/// through `scratch`, then store at `[base + off .. off+24]`. The mirror
/// image of [`csub_pass`] -- here the subtraction runs on the scratch
/// copies and `v` stays intact until the cmov -- so the two idioms emit
/// different text and stay separate.
fn fsq_csub_store<M: Machine>(m: &mut M, v: [Reg; 4], scratch: [Reg; 4], base: Reg, off: i32) {
    for (k, (val, s)) in v.iter().zip(scratch).enumerate() {
        m.mov(s, *val, &format!("keep-copy of limb {k}"));
    }
    for (k, s) in scratch.into_iter().enumerate() {
        let what = format!("limb {k} -= p{k}");
        if k == 0 {
            m.sub_mem(s, CONSTS_MIRROR.p.mem(), &what);
        } else {
            m.sbb_mem(s, CONSTS_MIRROR.p.limb(k), &what);
        }
    }
    for (k, (val, s)) in v.iter().zip(scratch).enumerate() {
        m.cmov_carry(s, *val, &format!("borrow: value < p, keep limb {k}"));
    }
    for (k, s) in scratch.into_iter().enumerate() {
        m.store(
            Mem::new(base, off + 8 * k as i32),
            s,
            &format!("out limb {k}"),
        );
    }
}

/// mu quotient-estimate reduction of the five-limb value `v` (< 10p) to a
/// canonical residue in `v[0..4]`: E = floor(value/2^252), q = floor(E*mu/
/// 2^58) <= 10, value -= q*p lands below 1.33p, one conditional subtraction.
/// Exactly the fp6 xi bound argument. Clobbers rax, rbx?, no: clobbers
/// `s` (four scratch) plus rdx; asserts the fifth limb dies.
fn fsq_mu_reduce5<M: Machine>(m: &mut M, v: [Reg; 5], s: [Reg; 5]) {
    m.comment("estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10");
    m.mov(s[0], v[4], "E builds from the top limbs");
    m.shld_imm(s[0], v[3], 4, "E = top five bits of the value");
    m.load(MULTIPLIER, CONSTS_MIRROR.mu.mem(), "mu");
    m.mulx(s[1], Rax, s[0], "E*mu (high half zero: E < 2^5, mu < 2^57)");
    m.shr_imm(Rax, 58, "q");
    m.mov(MULTIPLIER, Rax, "q is the multiplicand");
    m.mulx_mem(s[0], Rax, CONSTS_MIRROR.p.mem(), "q*p0 -> (l0, h0)");
    m.mulx_mem(s[2], s[1], CONSTS_MIRROR.p.at(8), "q*p1 -> (l1, h1)");
    m.add(s[1], s[0], "l1 += h0");
    m.mulx_mem(s[0], s[3], CONSTS_MIRROR.p.at(16), "q*p2 -> (l2, h2)");
    m.adc(s[3], s[2], "l2 += h1");
    m.mulx_mem(
        s[2],
        s[4],
        CONSTS_MIRROR.p.at(24),
        "q*p3 -> (l3, h3); rdx freed",
    );
    m.adc(s[4], s[0], "l3 += h2");
    m.adc_zero(s[2], "h3 += carry; q*p < 11p < 2^260");
    m.sub_rr(v[0], Rax, "value -= q*p, limb 0");
    m.sbb_rr(v[1], s[1], "limb 1");
    m.sbb_rr(v[2], s[3], "limb 2");
    m.sbb_rr(v[3], s[4], "limb 3");
    m.sbb_rr(v[4], s[2], "limb 4");
    m.claim_zero(v[4], "value - q*p < 1.33p < 2^255 fits four limbs");
}

/// `helius_fp12_sqr_x86`: the whole Fp12 square in mcl's lazy double-width
/// shape -- 36 raw 4x4 products and 12 Montgomery reductions where the
/// composed SoS path pays 84 products and 12 interleaved reductions.
///
/// # Semantics (mcl `Fp12::sqr`, fp_tower.hpp)
///
/// For `f = a + b*w` (`w^2 = v`, `v^3 = xi = 9 + u`):
///
/// * `t0 = a + b`, `t1 = b*v + a = (xi*b.c2 + a.c0, b.c0 + a.c1, b.c1 +
///   a.c2)`, both canonical Fp6;
/// * `V = a*b`, `U = t0*t1`, each one lazy Fp6 product: Karatsuba at both
///   tower levels (6 Fp2Dbl products of 3 raw 4x4 mulpre each = 18 products),
///   all cross-terms held as 512-bit values, ONE Montgomery reduction per
///   output Fp (6 per product);
/// * `z.c1 = 2V`, `z.c0 = U - (V*v + V)`, single-width modular ops.
///
/// # Laziness and the p*2^256 guard
///
/// Unreduced 512-bit values are exact where provably nonnegative (Karatsuba
/// middle terms, the imaginary cross-term lanes) and otherwise guarded
/// mod `p*2^256`: a subtraction that borrows adds p to the HIGH four limbs
/// (one masked add), an addition whose high half reaches p subtracts it
/// (one conditional subtraction). `T = T' mod p*2^256` keeps Montgomery
/// congruence: `T/2^256 = T'/2^256 mod p`.
///
/// # Bounds (BN254: p < 2^253.61, so 4p < 2^256 and K = 2^256, pK < 2^510)
///
/// * staged sums: Fp6-level `b+c` < 2p, in-block `re+im` < 4p < 2^256 --
///   four limbs, no reduction;
/// * raw products: <= (4p)^2 = 16p^2 < 2^512 (needs p < 2^254: two
///   headroom bits, mcl's isLtQuad argument);
/// * Karatsuba middle `d1 - d0 - d2 = ad+bc` <= 8p^2, exact and nonnegative;
///   real lanes `d0 - d2` guarded < pK (valid: subtrahend <= 4p^2 < pK);
/// * cross-term a-lanes stay guarded < pK; b-lanes stay exact <= 4p^2 < pK
///   after their subtractions (the intermediate 8p^2 > pK only ever passes
///   through exact subtractions);
/// * xi on doubles: `9x + y mod pK` splits at the limb-4 boundary; the high
///   part `9*xH + yH + carry < 10p` reduces by the mu quotient estimate
///   (q <= 10, remainder < 1.33p, one conditional subtraction) so the
///   result's high half is canonical -- strictly below every guard bound;
/// * z.c additions peak at 6p^2 < 1.14*pK: one high-half conditional
///   subtraction returns below pK;
/// * every reduced value satisfies T < pK, the Montgomery precondition:
///   `(T + m*p*2^256)/2^256 < 2p`, one conditional subtraction, canonical.
///
/// The interpreter asserts the flag claims on every path; the u512 reference
/// in `kernelgen_verify` asserts each stage bound on random and adversarial
/// inputs.
///
/// # In-place update
///
/// `z == f` is allowed and is the production shape: the prologue stages all
/// of `f` into the frame and `f` is never read again, so no output store can
/// alias a live operand.
///
/// # Structure
///
/// One outer two-iteration loop (iteration 0: V = a*b plus the t0/t1
/// prebuild; iteration 1: U = t0*t1 plus the W/2V prebuild from V) whose
/// per-iteration pointers come from a ctx row. All linear double-width work
/// runs as table-driven walks over rodata (dst, src1, src2) rows -- guarded
/// sub, nine-fold xi, guarded add, Montgomery reduction, modular single-width
/// add/sub -- so each op kind is emitted once. The same walks are the
/// building blocks for the planned Fp12 full mul (3 Fp6Dbl products),
/// mul_by_034 lazy variant, and the lazy cyclotomic square.
///
/// Arguments: `(z: *mut u64x48, f: *const u64x48, consts: *const { p[4],
/// -p^-1, mu })` in rdi, rsi, rdx. `f` is repr(C) Fp12, canonical; outputs
/// canonical.
pub fn fp12_sqr_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    let tables = fp12_sqr_tables();
    m.rodata(FSQ_TAB_LABEL, &tables);
    frame(m, FSQF.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, mu +40, z +48, loop bounds +56..96, ctx slots +104..152, xi scratch +152..320, t0/t1/V/U/y +320..1472, staged f +1472, operand sides +1856, products +3008, xi/neg scratch +4160",
        );
        m.store(FSQF.z.mem(), Rdi, "spill z");
        for k in 0..4 {
            m.load(Rax, Mem::new(Rdx, 8 * k), &format!("p{k}"));
            m.store(
                CONSTS_MIRROR.p.at(8 * k),
                Rax,
                "cancel rows address the frame as a consts table",
            );
        }
        m.load(Rax, Mem::new(Rdx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");
        m.load(Rax, Mem::new(Rdx, 40), "mu = floor(2^310/p)");
        m.store(CONSTS_MIRROR.mu.mem(), Rax, "mu");
        m.lea_rodata(Rax, FSQ_TAB_LABEL, "walk tables");
        m.store(FSQF.tbl.mem(), Rax, "table base");
        m.mov(Rbx, Rax, "");
        m.add_imm(Rbx, FSQ_TB.msub.end(), "product m-walk end");
        m.store(FSQF.mend.mem(), Rbx, "");
        m.mov(Rbx, Rax, "");
        m.add_imm(Rbx, FSQ_TB.ctx.end(), "ctx table end (two 64-byte rows)");
        m.store(FSQF.outer_end.mem(), Rbx, "");
        m.xor_clear(Rax, "");
        for k in 0..8 {
            m.store(
                FSQF.zero8.at(8 * k),
                Rax,
                "zero word (negation rows subtract from it)",
            );
        }

        m.comment("");
        m.comment("stage f: all later reads are frame-relative, which is what");
        m.comment("makes z == f safe (no f read after any z store)");
        m.mov(Rdi, rsp, "");
        m.add_imm(Rdi, FSQF.fst.off(), "staging cursor");
        m.xor_clear(Rcx, "48 limbs, 4 per iteration");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lfsq_fst", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("f limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "staged");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });

        m.comment("");
        m.comment("outer loop: iteration 0 computes V = a*b (and prebuilds t0, t1),");
        m.comment("iteration 1 computes U = t0*t1 (and prebuilds W = V*v + V, 2V)");
        m.load(Rbp, FSQF.tbl.mem(), "ctx cursor = first ctx row");
        m.stride_loop(
            Rbp,
            64,
            LoopEnd::Mem(FSQF.outer_end.mem()),
            ".Lfsq_iter",
            &mut |m| {
                m.store(FSQF.ctx_spill.mem(), Rbp, "spill the outer cursor");
                for (field, slot, what) in [
                    (0, FSQF.muxi_src, "ctx: xi site source"),
                    (8, FSQF.muxi_dst, "ctx: xi site destination"),
                    (16, FSQF.stage_x, "ctx: x-side source"),
                    (24, FSQF.stage_y, "ctx: y-side source"),
                    (32, FSQF.mod_dst, "ctx: reduction destination"),
                    (40, FSQF.add_seg, "ctx: modadd segment"),
                ] {
                    m.load(Rax, Mem::new(Rbp, field), what);
                    m.store(slot.mem(), Rax, "");
                }
                fsq_muxi(m);
                m.comment("modular add walk: t0/t1 build (iteration 0), W and 2V (iteration 1)");
                m.load(Rbp, FSQF.tbl.mem(), "table base");
                m.add_mem(Rbp, FSQF.add_seg.mem(), "+ this iteration's segment");
                m.mov(Rbx, Rbp, "");
                m.add_imm(Rbx, 12 * FSQ_TB.add.row_bytes(), "segment end");
                m.store(FSQF.walk_end.mem(), Rbx, "walk bound");
                walk_rows(m, FSQ_TB.add, ".Lfsq_madd", &mut |m| dbl_modadd_row(m));
                stage_sides_walk(m, "fsq", FSQ_TB.sums);
                products_walk(m, "fsq", FSQ_TB.msub);
                m.comment("double-width sub walk: Karatsuba assembly, cross terms, negations");
                walk(m, FSQ_TB.gsub, ".Lfsq_gsub", &mut |m| dbl_gsub_row(m));
                m.comment("nine-fold walk: xi = 9 + u on 512-bit values, mu-canonical high");
                walk(m, FSQ_TB.nine, ".Lfsq_nine", &mut |m| dbl_nine_row(m));
                m.comment("double-width add walk: xi'd cross terms into the output lanes");
                walk(m, FSQ_TB.gadd, ".Lfsq_gadd", &mut |m| dbl_gadd_row(m, None));
                m.comment("Montgomery reduction walk: 6 coefficients, 4 cancel rows each");
                walk(m, FSQ_TB.mod_red, ".Lfsq_mod", &mut |m| dbl_mod_row(m));
                m.load(Rbp, FSQF.ctx_spill.mem(), "reload the outer cursor");
            },
        );

        m.comment("");
        m.comment("epilogue: y.a = U - W (modular, in place over the W area)");
        walk(m, FSQ_TB.subs, ".Lfsq_msub", &mut |m| {
            dbl_msub_row(m, "y.a")
        });

        m.comment("");
        m.comment("copy out: y.a then y.b are contiguous, 48 limbs to z");
        m.load(Rdi, FSQF.z.mem(), "z");
        m.mov(Rsi, rsp, "");
        m.add_imm(Rsi, FSQF.ya.off(), "y.a base");
        m.xor_clear(Rcx, "");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lfsq_out", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("y limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "z");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });
    });
}

/// Single-width xi = 9 + u of the ctx site: dst = (9*re + (p - im),
/// 9*im + re), both halves canonicalized by the mu estimate. The negp
/// subtraction's clean flags also assert the site is canonical.
fn fsq_muxi<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    m.comment("xi site: (9*re - im, 9*im + re), subtraction via p - im");
    m.mov(Rsi, rsp, "");
    m.add_mem(Rsi, FSQF.muxi_src.mem(), "site source Fp2");
    m.mov(Rdi, rsp, "");
    m.add_mem(Rdi, FSQF.muxi_dst.mem(), "site destination Fp2");
    for (k, reg) in W4L.into_iter().enumerate() {
        m.load(reg, CONSTS_MIRROR.p.limb(k), &format!("p{k}"));
    }
    for (k, reg) in W4L.into_iter().enumerate() {
        let what = format!("p{k} - im[{k}]");
        if k == 0 {
            m.sub_mem(reg, Mem::new(Rsi, 32), &what);
        } else {
            m.sbb_mem(reg, Mem::new(Rsi, 32 + 8 * k as i32), &what);
        }
    }
    m.claim_flags_clear("im < p (canonical site): p - im cannot borrow");
    for (k, reg) in W4L.into_iter().enumerate() {
        m.store(FSQF.negim.limb(k), reg, "negp(im)");
    }
    m.xor_clear(Rbx, "half cursor: re output (+0) then im (+32)");
    m.stride_loop(Rbx, 32, LoopEnd::Imm(64), ".Lfsq_muxi", &mut |m| {
        m.comment("value = 9*X + Y: X = site half, Y = negp(im) for re, re for im");
        m.mov(Rcx, Rsi, "");
        m.add(Rcx, Rbx, "X = site + half");
        m.mov(Rbp, rsp, "");
        m.add_imm(Rbp, FSQF.negim.off(), "Y candidate: negp(im)");
        m.xor_clear(Rax, "");
        m.sub_rr(Rax, Rbx, "CF set exactly on the im half");
        m.cmov_carry(Rbp, Rsi, "im half: Y = site.re");
        m.xor_clear(MULTIPLIER, "");
        m.add_imm(MULTIPLIER, 9, "xi = 9 + u: the scale is one mulx row");
        let v = W5;
        m.mulx_mem(R13, v[0], Mem::new(Rcx, 0), "9*X[0] -> (v0, hi)");
        m.mulx_mem(R14, v[1], Mem::new(Rcx, 8), "9*X[1] -> (v1, hi)");
        m.add(v[1], R13, "v1 += hi(9*X[0])");
        m.mulx_mem(R13, v[2], Mem::new(Rcx, 16), "9*X[2] -> (v2, hi)");
        m.adc(v[2], R14, "v2 += hi(9*X[1])");
        m.mulx_mem(v[4], v[3], Mem::new(Rcx, 24), "9*X[3] -> (v3, v4)");
        m.adc(v[3], R13, "v3 += hi(9*X[2])");
        m.adc_zero(v[4], "9X < 9p: the chain closes into the top limb");
        for k in 0..4 {
            let what = format!("+= Y[{k}]");
            if k == 0 {
                m.add_mem(v[0], Mem::new(Rbp, 0), &what);
            } else {
                m.adc_mem(v[k], Mem::new(Rbp, 8 * k as i32), &what);
            }
        }
        m.adc_zero(v[4], "value < 10p < 2^257: top limb is at most 2");
        fsq_mu_reduce5(m, v, [R13, R14, R15, Rbp, Rcx]);
        m.comment("one conditional subtraction reaches canonical (< 1.33p)");
        m.mov(R13, Rdi, "");
        m.add(R13, Rbx, "output half");
        fsq_csub_store(
            m,
            [v[0], v[1], v[2], v[3]],
            [Rax, Rcx, Rbp, MULTIPLIER],
            R13,
            0,
        );
    });
}

/// One modular single-width add row: dst = s1 + s2 mod p (all three
/// canonical). Shared by the fp12_sqr and fp12_mul walks.
fn dbl_modadd_row<M: Machine>(m: &mut M) {
    fsq_decode3(m);
    for (k, reg) in W4L.into_iter().enumerate() {
        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("s1 limb {k}"));
    }
    for (k, reg) in W4L.into_iter().enumerate() {
        let what = format!("+= s2 limb {k}");
        if k == 0 {
            m.add_mem(reg, Mem::new(Rcx, 0), &what);
        } else {
            m.adc_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
        }
    }
    m.claim_flags_clear("s1 + s2 < 2p < 2^256: no carry out");
    fsq_csub_store(m, W4L, W4H, Rdi, 0);
}

/// One modular single-width subtraction row: dst = s1 - s2 mod p (operands
/// canonical; p returns on borrow). Shared by the fp12_sqr epilogue and the
/// cyc_sqr z-combines; `out` names the destination in the store comments.
fn dbl_msub_row<M: Machine>(m: &mut M, out: &str) {
    fsq_decode3(m);
    for (k, reg) in W4L.into_iter().enumerate() {
        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("s1 limb {k}"));
    }
    m.xor_clear(Rax, "mask seed; also clears flags for the chain");
    for (k, reg) in W4L.into_iter().enumerate() {
        let what = format!("limb {k} -= s2");
        if k == 0 {
            m.sub_mem(reg, Mem::new(Rcx, 0), &what);
        } else {
            m.sbb_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
        }
    }
    m.sbb_rr(Rax, Rax, "mask = -borrow");
    fsq_masked_p(m, Rbx, Rax, 0);
    fsq_masked_p(m, Rdx, Rax, 1);
    fsq_masked_p(m, Rsi, Rax, 2);
    fsq_masked_p(m, Rax, Rax, 3);
    m.add(R8, Rbx, "borrow: += p, limb 0");
    m.adc(R9, Rdx, "limb 1");
    m.adc(R10, Rsi, "limb 2");
    m.adc(R11, Rax, "limb 3");
    // The fix-up carries out exactly when it fired (it cancels the borrow);
    // the next row re-seeds its flags, so nothing relies on CF here.
    for (k, reg) in W4L.into_iter().enumerate() {
        m.store(Mem::new(Rdi, 8 * k as i32), reg, &format!("{out} limb {k}"));
    }
}

/// [`fsq_stage_sides`] body, shared by the fp12_sqr and fp12_mul kernels:
/// `tag` names the loop labels, `tb_sums` locates the kernel's staging sum
/// rows in its own rodata blob. Frame contract: side sources in the adjacent
/// STAGE_X/STAGE_Y ctx slots, destinations at XSTG then YSTG.
fn stage_sides_walk<M: Machine>(m: &mut M, tag: &str, tb_sums: TableSegment) {
    let rsp = Reg::Rsp;
    m.comment("stage the two operand sides (six blocks each: singles + sums)");
    m.xor_clear(Rax, "");
    m.add_imm(Rax, FSQF.xstg.off(), "");
    m.store(FSQF.stage_cur.mem(), Rax, "destination: x side first");
    m.mov(Rbx, rsp, "");
    m.add_imm(
        Rbx,
        FSQF.stage_x.off(),
        "side cursor walks the two source slots",
    );
    m.mov(Rax, Rbx, "");
    m.add_imm(Rax, 16, "");
    m.store(FSQF.walk_end.mem(), Rax, "side bound");
    m.stride_loop(
        Rbx,
        8,
        LoopEnd::Mem(FSQF.walk_end.mem()),
        &format!(".L{tag}_side"),
        &mut |m| {
            m.mov(Rsi, rsp, "");
            m.add_mem(Rsi, Mem::new(Rbx, 0), "side source (one Fp6)");
            m.mov(Rdi, rsp, "");
            m.add_mem(Rdi, FSQF.stage_cur.mem(), "side destination");
            m.comment("singles: copy each Fp2 and add its in-block s = re + im");
            m.xor_clear(Rcx, "");
            m.stride_loop(
                Rcx,
                64,
                LoopEnd::Imm(192),
                &format!(".L{tag}_single"),
                &mut |m| {
                    for (k, reg) in W4L.into_iter().enumerate() {
                        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("re[{k}]"));
                    }
                    for (k, reg) in W4H.into_iter().enumerate() {
                        m.load(reg, Mem::new(Rsi, 32 + 8 * k as i32), &format!("im[{k}]"));
                    }
                    for (k, reg) in W4L.into_iter().enumerate() {
                        m.store(Mem::new(Rdi, 8 * k as i32), reg, &format!("block re[{k}]"));
                    }
                    for (k, reg) in W4H.into_iter().enumerate() {
                        m.store(
                            Mem::new(Rdi, 32 + 8 * k as i32),
                            reg,
                            &format!("block im[{k}]"),
                        );
                    }
                    m.add(R8, R12, "s = re + im, limb 0");
                    m.adc(R9, R13, "limb 1");
                    m.adc(R10, R14, "limb 2");
                    m.adc(R11, R15, "limb 3");
                    m.claim_flags_clear("re + im < 2p < 2^256: s fits four limbs");
                    for (k, reg) in W4L.into_iter().enumerate() {
                        m.store(
                            Mem::new(Rdi, 64 + 8 * k as i32),
                            reg,
                            &format!("block s[{k}]"),
                        );
                    }
                    m.add_imm(Rsi, 64, "next source Fp2");
                    m.add_imm(Rdi, 96, "next block");
                },
            );
            m.comment("sums: whole-block adds (s-lanes add to the sums' s)");
            fsq_walk_setup(m, MULTIPLIER, tb_sums, FSQF.walk_end2);
            m.stride_loop(
                MULTIPLIER,
                24,
                LoopEnd::Mem(FSQF.walk_end2.mem()),
                &format!(".L{tag}_sums"),
                &mut |m| {
                    m.mov(Rbp, rsp, "");
                    m.add_mem(Rbp, FSQF.stage_cur.mem(), "side base");
                    m.mov(Rdi, Rbp, "");
                    m.add_mem(Rdi, Mem::new(MULTIPLIER, 0), "sum block");
                    m.mov(Rsi, Rbp, "");
                    m.add_mem(Rsi, Mem::new(MULTIPLIER, 8), "addend block A");
                    m.mov(Rcx, Rbp, "");
                    m.add_mem(Rcx, Mem::new(MULTIPLIER, 16), "addend block B");
                    m.xor_clear(Rbp, "row cursor: re, im, s");
                    m.stride_loop(
                        Rbp,
                        32,
                        LoopEnd::Imm(96),
                        &format!(".L{tag}_sumrow"),
                        &mut |m| {
                            for (k, reg) in W4L.into_iter().enumerate() {
                                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("A limb {k}"));
                            }
                            for (k, reg) in W4L.into_iter().enumerate() {
                                let what = format!("+= B limb {k}");
                                if k == 0 {
                                    m.add_mem(reg, Mem::new(Rcx, 0), &what);
                                } else {
                                    m.adc_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
                                }
                            }
                            // No flags claim: s-lane sums reach 4p, whose top
                            // limb crosses the sign bit (OF may set legally);
                            // CF stays clear since 4p < 2^256, and the u512
                            // reference asserts the value bound.
                            for (k, reg) in W4L.into_iter().enumerate() {
                                m.store(Mem::new(Rdi, 8 * k as i32), reg, "sum limb");
                            }
                            m.add_imm(Rsi, 32, "");
                            m.add_imm(Rcx, 32, "");
                            m.add_imm(Rdi, 32, "");
                        },
                    );
                },
            );
            m.load(Rax, FSQF.stage_cur.mem(), "");
            m.add_imm(Rax, 576, "");
            m.store(FSQF.stage_cur.mem(), Rax, "destination: y side next");
        },
    );
}

/// [`fsq_products`] body, shared by the fp12_sqr and fp12_mul kernels:
/// `tag` names the loop labels, `tb_msub` locates the kernel's sub-product
/// rows in its own rodata blob (the mend slot must hold their end).
fn products_walk<M: Machine>(m: &mut M, tag: &str, tb_msub: TableSegment) {
    let rsp = Reg::Rsp;
    m.comment("products: 6 blocks x 3 sub-products, rolled 4x4 mulpre rounds");
    m.xor_clear(R15, "block cursor 96k");
    m.stride_loop(
        R15,
        96,
        LoopEnd::Imm(576),
        &format!(".L{tag}_prod_k"),
        &mut |m| {
            m.load(Rcx, FSQF.tbl.mem(), "");
            m.add_imm(Rcx, tb_msub.off(), "sub-product walk");
            m.stride_loop(
                Rcx,
                16,
                LoopEnd::Mem(FSQF.mend.mem()),
                &format!(".L{tag}_prod_m"),
                &mut |m| {
                    m.load(Rax, Mem::new(Rcx, 0), "operand sub-offset");
                    m.load(Rbx, Mem::new(Rcx, 8), "destination sub-offset");
                    m.mov(Rsi, rsp, "");
                    m.add(Rsi, R15, "");
                    m.add(Rsi, Rax, "");
                    m.add_imm(Rsi, FSQF.xstg.off(), "PA: x sub-row (the multiplicand)");
                    m.mov(Rdi, rsp, "");
                    m.add(Rdi, R15, "");
                    m.add(Rdi, Rax, "");
                    m.add_imm(Rdi, FSQF.ystg.off(), "PY: y sub-row");
                    m.mov(Rbp, rsp, "");
                    m.add(Rbp, R15, "");
                    m.add(Rbp, R15, "product regions stride 192 = 2*96k");
                    m.add(Rbp, Rbx, "");
                    m.add_imm(Rbp, FSQF.prod.off(), "PZ");
                    for (k, t) in T.into_iter().enumerate() {
                        m.xor_clear(t, &format!("t{k} = 0"));
                    }
                    m.xor_clear(R14, "round cursor: byte offset 8j of the x limb");
                    m.stride_loop(
                        R14,
                        8,
                        LoopEnd::Imm(32),
                        &format!(".L{tag}_prod_j"),
                        &mut |m| {
                            m.load_indexed(MULTIPLIER, Rsi, R14, "x[j], the row multiplicand");
                            m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
                            fsq_mulpre_row(m, Rdi);
                            m.store(Mem::new(Rbp, 0), T[0], "product limb j is final");
                            m.add_imm(Rbp, 8, "next output limb");
                            m.comment("shift down one word");
                            for k in 0..5 {
                                m.mov(T[k], T[k + 1], &format!("t{k} = t{}", k + 1));
                            }
                            m.xor_clear(T[5], "t5 = 0 (CF/OF stay clear)");
                        },
                    );
                    for (k, t) in T[..4].iter().enumerate() {
                        m.store(
                            Mem::new(Rbp, 8 * k as i32),
                            *t,
                            &format!("product limb {}", k + 4),
                        );
                    }
                },
            );
        },
    );
}

/// One guarded double-width subtraction row: dst = s1 - s2, plus p on the
/// HIGH four limbs when the subtraction borrows (mod p*2^256; a no-op mask
/// for the provably nonnegative rows). Shared by fp12_sqr and fp12_mul.
fn dbl_gsub_row<M: Machine>(m: &mut M) {
    fsq_decode3(m);
    let v = W8;
    for (k, reg) in v.into_iter().enumerate() {
        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("s1 word {k}"));
    }
    m.xor_clear(Rax, "mask seed; also clears flags for the chain");
    for (k, reg) in v.into_iter().enumerate() {
        let what = format!("word {k} -= s2");
        if k == 0 {
            m.sub_mem(reg, Mem::new(Rcx, 0), &what);
        } else {
            m.sbb_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
        }
    }
    m.sbb_rr(Rax, Rax, "mask = -borrow");
    fsq_masked_p(m, Rbx, Rax, 0);
    fsq_masked_p(m, MULTIPLIER, Rax, 1);
    fsq_masked_p(m, Rsi, Rax, 2);
    fsq_masked_p(m, Rax, Rax, 3);
    m.add(R12, Rbx, "borrow: high half += p, word 4");
    m.adc(R13, MULTIPLIER, "word 5");
    m.adc(R14, Rsi, "word 6");
    m.adc(R15, Rax, "word 7");
    // The fix-up carries out exactly when it fired (it cancels the
    // borrow); the next row re-seeds its flags. Result: s1 - s2, or
    // s1 - s2 + p*2^256 on borrow, both below 2^512.
    for (k, reg) in v.into_iter().enumerate() {
        m.store(Mem::new(Rdi, 8 * k as i32), reg, &format!("dst word {k}"));
    }
}

/// One nine-fold xi row: dst = 9*x + y mod p*2^256 for 512-bit x, y. Splits
/// at the limb-4 boundary: the low half is exact (its carry joins the high),
/// the high half 9*xH + yH + carry < 10p reduces by the mu estimate, so the
/// stored high half is canonical. Shared by fp12_sqr and fp12_mul.
fn dbl_nine_row<M: Machine>(m: &mut M) {
    fsq_decode3(m);
    m.xor_clear(MULTIPLIER, "");
    m.add_imm(MULTIPLIER, 9, "9 is the mulx multiplicand");
    m.comment("low half: l = 9*xL + yL, carry limb l4 <= 10");
    m.mulx_mem(R13, R8, Mem::new(Rsi, 0), "9*x0 -> (l0, hi)");
    m.mulx_mem(R14, R9, Mem::new(Rsi, 8), "9*x1 -> (l1, hi)");
    m.add(R9, R13, "l1 += hi(9*x0)");
    m.mulx_mem(R13, R10, Mem::new(Rsi, 16), "9*x2 -> (l2, hi)");
    m.adc(R10, R14, "l2 += hi(9*x1)");
    m.mulx_mem(R12, R11, Mem::new(Rsi, 24), "9*x3 -> (l3, l4)");
    m.adc(R11, R13, "l3 += hi(9*x2)");
    m.adc_zero(R12, "9*xL < 9*2^256: l4 closes the chain");
    for (k, reg) in W4L.into_iter().enumerate() {
        let what = format!("+= y{k}");
        if k == 0 {
            m.add_mem(reg, Mem::new(Rcx, 0), &what);
        } else {
            m.adc_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
        }
    }
    m.adc_zero(R12, "l4 <= 10");
    for (k, reg) in W4L.into_iter().enumerate() {
        m.store(Mem::new(Rdi, 8 * k as i32), reg, &format!("dst word {k}"));
    }
    m.comment("high half: v = 9*xH + yH + l4 < 10p (xH, yH < p)");
    m.mulx_mem(R13, R8, Mem::new(Rsi, 32), "9*x4 -> (v0, hi)");
    m.mulx_mem(R14, R9, Mem::new(Rsi, 40), "9*x5 -> (v1, hi)");
    m.add(R9, R13, "v1 += hi(9*x4)");
    m.mulx_mem(R13, R10, Mem::new(Rsi, 48), "9*x6 -> (v2, hi)");
    m.adc(R10, R14, "v2 += hi(9*x5)");
    m.mulx_mem(R15, R11, Mem::new(Rsi, 56), "9*x7 -> (v3, v4)");
    m.adc(R11, R13, "v3 += hi(9*x6)");
    m.adc_zero(R15, "9*xH < 9p closes into v4");
    m.add(R8, R12, "+= l4");
    for reg in [R9, R10, R11, R15] {
        m.adc_zero(reg, "ripple the l4 carry");
    }
    for (k, reg) in W4L.into_iter().enumerate() {
        let what = format!("+= y{}", k + 4);
        if k == 0 {
            m.add_mem(reg, Mem::new(Rcx, 32), &what);
        } else {
            m.adc_mem(reg, Mem::new(Rcx, 32 + 8 * k as i32), &what);
        }
    }
    m.adc_zero(R15, "v < 10p < 2^257");
    fsq_mu_reduce5(m, [R8, R9, R10, R11, R15], [R13, R14, R12, Rbx, Rsi]);
    m.comment("one conditional subtraction: the stored high half is canonical");
    fsq_csub_store(m, W4L, [Rax, Rbx, Rcx, Rsi], Rdi, 32);
}

/// One guarded double-width addition row: dst = s1 + s2, minus p on the
/// HIGH four limbs when they reach p (mod p*2^256). Shared by fp12_sqr and
/// fp12_mul; `dst_ctx` is the fp12_mul park decode (see
/// [`fsq_decode3_at`]).
fn dbl_gadd_row<M: Machine>(m: &mut M, dst_ctx: Option<FrameSlot>) {
    fsq_decode3_at(m, dst_ctx);
    let v = W8;
    for (k, reg) in v.into_iter().enumerate() {
        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("s1 word {k}"));
    }
    for (k, reg) in v.into_iter().enumerate() {
        let what = format!("word {k} += s2");
        if k == 0 {
            m.add_mem(reg, Mem::new(Rcx, 0), &what);
        } else {
            m.adc_mem(reg, Mem::new(Rcx, 8 * k as i32), &what);
        }
    }
    m.claim_flags_clear("sum of two sub-2^510 values < 2^511: no carry out");
    m.comment("high half >= p: subtract p once (sum < 2p*2^256)");
    m.mov(Rax, R12, "");
    m.mov(Rbx, R13, "");
    m.mov(MULTIPLIER, R14, "");
    m.mov(Rcx, R15, "");
    m.sub_mem(Rax, CONSTS_MIRROR.p.mem(), "high word 0 - p0");
    m.sbb_mem(Rbx, CONSTS_MIRROR.p.at(8), "high word 1 - p1");
    m.sbb_mem(MULTIPLIER, CONSTS_MIRROR.p.at(16), "high word 2 - p2");
    m.sbb_mem(Rcx, CONSTS_MIRROR.p.at(24), "high word 3 - p3");
    m.cmov_carry(Rax, R12, "borrow: high < p, keep");
    m.cmov_carry(Rbx, R13, "");
    m.cmov_carry(MULTIPLIER, R14, "");
    m.cmov_carry(Rcx, R15, "");
    for (k, reg) in W4L.into_iter().enumerate() {
        m.store(Mem::new(Rdi, 8 * k as i32), reg, &format!("dst word {k}"));
    }
    for (k, reg) in [Rax, Rbx, MULTIPLIER, Rcx].into_iter().enumerate() {
        m.store(
            Mem::new(Rdi, 32 + 8 * k as i32),
            reg,
            &format!("dst word {}", k + 4),
        );
    }
}

/// One Montgomery reduction row: reduces one 512-bit value T < p*2^256 to
/// the canonical residue T/2^256 mod p at [MOD_DST ctx slot] + row offset.
/// Shared by fp12_sqr and fp12_mul.
fn dbl_mod_row<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    m.mov(Rsi, rsp, "");
    m.add_mem(Rsi, Mem::new(Rbp, 0), "source T");
    m.mov(Rdi, rsp, "");
    m.add_mem(Rdi, FSQF.mod_dst.mem(), "V or U base");
    m.add_mem(Rdi, Mem::new(Rbp, 8), "+ coefficient offset");
    let t = W8;
    for (k, reg) in t.into_iter().enumerate() {
        m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("T{k}"));
    }
    m.xor_clear(LO, "clear CF = OF before the dual chains");
    for round in 0..4 {
        if round > 0 {
            m.claim_flags_clear("previous row rippled both chains out under the 2pK bound");
        }
        let window: [Reg; 5] = core::array::from_fn(|k| t[round + k]);
        cancel_low_word_at(m, window, Rbx, rsp, &round.to_string());
        for (k, &word) in t.iter().enumerate().skip(round + 5) {
            m.adcx(word, LO, &format!("T{k} += carry-chain ripple"));
            m.adox(word, LO, &format!("T{k} += value-chain ripple"));
        }
    }
    m.claim_flags_clear("T < p*2^256 keeps the total below 2p*2^256: no word beyond T7");
    m.comment("result T4..T7 < 2p: one conditional subtraction");
    fsq_csub_store(m, W4H, [Rax, Rbx, MULTIPLIER, Rsi], Rdi, 0);
}

/// Register roles for `helius_fp12_mul_x86` (the fp12_sqr roles verbatim:
/// every phase is a shared walk body).
pub const FP12_MUL_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); walk destination pointer in every table-driven pass",
    ),
    (
        Rsi,
        "a pointer on entry (staging source); walk source-1 pointer; mask scratch",
    ),
    (
        Rdx,
        "b pointer on entry (staging source); the implicit mulx multiplicand; walk scratch",
    ),
    (
        Rcx,
        "consts pointer on entry; walk source-2 pointer; product m-walk cursor; staging cursor",
    ),
    (R8, "accumulator/value word 0"),
    (R9, "accumulator/value word 1"),
    (R10, "accumulator/value word 2"),
    (R11, "accumulator/value word 3"),
    (R12, "accumulator/value word 4"),
    (R13, "accumulator/value word 5; mu-reduction scratch"),
    (
        R14,
        "product round cursor (byte offset 8j); 8-limb value word 6",
    ),
    (R15, "product block cursor 96k; 8-limb value word 7"),
    (
        Rbp,
        "outer iteration cursor (ctx row address, spilled per phase); every walk's row cursor",
    ),
    (
        Rax,
        "low half of the current product; zero for chain closes; borrow mask",
    ),
    (
        Rbx,
        "high half of the current product; walk bound and half cursors",
    ),
];

/// fp12_mul frame. Every slot and region a shared walk body addresses
/// (p/-p^-1/mu, z, loop bounds, ctx spill, table base, product m-walk end,
/// stage_x/stage_y, mod_dst, stage_cur, zero8, xstg/ystg, prod, scr, nb)
/// is declared as an alias of its fp12_sqr slot, so the bodies emit
/// unchanged; only the mul-specific slots differ.
struct FmuFrame {
    /// Ctx: the iteration's Fp6Dbl park base (frame offset).
    park: FrameSlot,
    /// Ctx: per-iteration gsub/nine/gadd walk end offsets (table-relative).
    gsub_end: FrameSlot,
    nine_end: FrameSlot,
    gadd_end: FrameSlot,
    /// p*2^256 - BD.c.im, the negation feeding the mulVadd xi rows.
    nb2: FrameSlot,
    /// a staged (48 limbs) then b staged (48 limbs), contiguous.
    ast: FrameSlot,
    bst: FrameSlot,
    /// t1 = a0 + a1 and t2 = b0 + b1 (canonical Fp6 each).
    t1: FrameSlot,
    t2: FrameSlot,
    /// The twelve reduced output coefficients (z.a then z.b), copied last.
    yout: FrameSlot,
    /// Fp6Dbl parks: AC = a0*b0, BD = a1*b1, CR = t1*t2, TA = the assembled
    /// z.a; each six 64-byte lanes in order a.re, a.im, b.re, b.im, c.re,
    /// c.im.
    ac: FrameSlot,
    bd: FrameSlot,
    cr: FrameSlot,
    ta: FrameSlot,
    size: i32,
}

const FMUF: FmuFrame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv)
        .alias(CONSTS_MIRROR.mu)
        .alias(FSQF.z)
        .alias(FSQF.outer_end)
        .alias(FSQF.walk_end)
        .alias(FSQF.walk_end2)
        .alias(FSQF.ctx_spill)
        .alias(FSQF.tbl)
        .alias(FSQF.mend);
    let (l, park) = l.slot(8);
    let (l, gsub_end) = l.slot(8);
    let l = l
        .alias(FSQF.stage_x)
        .alias(FSQF.stage_y)
        .alias(FSQF.mod_dst);
    let (l, nine_end) = l.slot(8);
    let (l, gadd_end) = l.slot(8);
    let l = l.gap(24).alias(FSQF.stage_cur).alias(FSQF.zero8);
    let (l, nb2) = l.slot(64);
    let (l, ast) = l.slot(384);
    let (l, bst) = l.slot(384);
    let (l, t1) = l.slot(192);
    let (l, t2) = l.slot(192);
    let (l, yout) = l.slot(384);
    let l = l.alias(FSQF.xstg).alias(FSQF.ystg).alias(FSQF.prod);
    let l = l.alias(FSQF.scr).alias(FSQF.nb);
    let (l, ac) = l.slot(384);
    let (l, bd) = l.slot(384);
    let (l, cr) = l.slot(384);
    let (l, ta) = l.slot(384);
    FmuFrame {
        park,
        gsub_end,
        nine_end,
        gadd_end,
        nb2,
        ast,
        bst,
        t1,
        t2,
        yout,
        ac,
        bd,
        cr,
        ta,
        size: l.size(),
    }
};

/// The fp12_mul walk-table regions, in blob order.
struct FmuTab {
    ctx: TableSegment,
    madd: TableSegment,
    /// Row 32: iteration 2 only.
    gsub: TableSegment,
    /// Rows 4..6: iteration 2 only.
    nine: TableSegment,
    /// Rows 6..12: iteration 2 only.
    gadd: TableSegment,
    gsub2: TableSegment,
    mod_red: TableSegment,
    msub: TableSegment,
    sums: TableSegment,
    bytes: i32,
}

const FMU_TB: FmuTab = {
    let l = TableLayout::new();
    let (l, ctx) = l.seg(3, 6); // per-iteration ctx rows
    let (l, madd) = l.seg(12, 3); // modular single-width adds
    let (l, gsub) = l.seg(33, 3); // guarded double-width subs
    let (l, nine) = l.seg(6, 3); // nine-fold xi rows
    let (l, gadd) = l.seg(12, 3); // guarded double-width adds
    let (l, gsub2) = l.seg(12, 3); // epilogue z.b subs
    let (l, mod_red) = l.seg(12, 2); // Montgomery reduction rows
    let (l, msub) = l.seg(3, 2); // product sub-rows
    let (l, sums) = l.seg(3, 3); // staging sum rows
    FmuTab {
        ctx,
        madd,
        gsub,
        nine,
        gadd,
        gsub2,
        mod_red,
        msub,
        sums,
        bytes: l.bytes(),
    }
};

const FMU_TAB_LABEL: &str = ".Lfmu_tab";

/// The fp12_mul read-only walk tables. Offsets are rsp-relative (operands),
/// blob-relative (the ctx rows' walk ends), or PARK-relative (the gadd
/// destinations, decoded through the ctx park slot).
fn fp12_mul_tables() -> Vec<u64> {
    let mut t: Vec<u64> = Vec::new();
    let row3 = |t: &mut Vec<u64>, dst: i32, s1: i32, s2: i32| {
        t.extend([dst as u64, s1 as u64, s2 as u64]);
    };
    let pk = |k: i32| FSQF.prod.off() + 192 * k;
    let (ad, be, cf, za, zb, zc) = (pk(0), pk(1), pk(2), pk(3), pk(4), pk(5));

    // Ctx rows: stage x/y sources, Fp6Dbl park, then the gsub/nine/gadd walk
    // end offsets. Iteration 2 extends each walk with the z.a = mulVadd(BD,
    // AC) rows -- exactly the rows whose operands (AC, BD) are parked by
    // then; z.b needs CR too and runs in the epilogue.
    let ends = |t: &mut Vec<u64>, last: bool| {
        let (g, n, a) = if last { (33, 6, 12) } else { (32, 4, 6) };
        t.extend([
            FMU_TB.gsub.row(g) as u64,
            FMU_TB.nine.row(n) as u64,
            FMU_TB.gadd.row(a) as u64,
        ]);
    };
    t.extend([
        FMUF.ast.off() as u64,
        FMUF.bst.off() as u64,
        FMUF.ac.off() as u64,
    ]);
    ends(&mut t, false);
    t.extend([
        (FMUF.ast.off() + 192) as u64,
        (FMUF.bst.off() + 192) as u64,
        FMUF.bd.off() as u64,
    ]);
    ends(&mut t, false);
    t.extend([
        FMUF.t1.off() as u64,
        FMUF.t2.off() as u64,
        FMUF.cr.off() as u64,
    ]);
    ends(&mut t, true);

    // Modular single-width adds: t1 = a0 + a1, t2 = b0 + b1.
    assert_eq!(t.len() * 8, FMU_TB.madd.off() as usize);
    for j in 0..6 {
        row3(
            &mut t,
            FMUF.t1.off() + 32 * j,
            FMUF.ast.off() + 32 * j,
            FMUF.ast.off() + 192 + 32 * j,
        );
    }
    for j in 0..6 {
        row3(
            &mut t,
            FMUF.t2.off() + 32 * j,
            FMUF.bst.off() + 32 * j,
            FMUF.bst.off() + 192 + 32 * j,
        );
    }

    // Double-width subs: the fp12_sqr mulPre rows verbatim (Karatsuba
    // assembly, cross terms, NB negations), plus the iteration-2-only
    // negation of the parked BD.c.im feeding the mulVadd xi.
    assert_eq!(t.len() * 8, FMU_TB.gsub.off() as usize);
    for k in 0..6 {
        let p = pk(k);
        row3(&mut t, p + 64, p + 64, p);
        row3(&mut t, p + 64, p + 64, p + 128);
        row3(&mut t, p, p, p + 128);
    }
    for (dst, src) in [(za, be), (za, cf), (zb, ad), (zb, be), (zc, ad), (zc, cf)] {
        row3(&mut t, dst, dst, src);
        row3(&mut t, dst + 64, dst + 64, src + 64);
    }
    row3(&mut t, FSQF.nb.off(), FSQF.zero8.off(), za + 64);
    row3(&mut t, FSQF.nb.off() + 64, FSQF.zero8.off(), cf + 64);
    row3(
        &mut t,
        FMUF.nb2.off(),
        FSQF.zero8.off(),
        FMUF.bd.off() + 320,
    );

    // Nine-fold rows: S1..S4 as in fp12_sqr, then (iteration 2 only) the
    // mulVadd xi of the parked BD.c into TA's first lane pair.
    assert_eq!(t.len() * 8, FMU_TB.nine.off() as usize);
    row3(&mut t, FSQF.scr.off(), za, FSQF.nb.off());
    row3(&mut t, FSQF.scr.off() + 64, za + 64, za);
    row3(&mut t, FSQF.scr.off() + 128, cf, FSQF.nb.off() + 64);
    row3(&mut t, FSQF.scr.off() + 192, cf + 64, cf);
    row3(&mut t, FMUF.ta.off(), FMUF.bd.off() + 256, FMUF.nb2.off());
    row3(
        &mut t,
        FMUF.ta.off() + 64,
        FMUF.bd.off() + 320,
        FMUF.bd.off() + 256,
    );

    // Double-width adds, destinations PARK-relative (ctx dst decode).
    // Rows 0..6: assemble and park the Fp6Dbl product (fp12_sqr's adds, but
    // parked instead of in place). Rows 6..12 (iteration 2, PARK = CR):
    // z.a = mulVadd(BD, AC) into TA -- xi(BD.c) + AC.a in place over the
    // nine outputs, BD.a + AC.b and BD.b + AC.c into TA's b/c lanes (BD
    // itself stays intact for the epilogue z.b subtractions).
    assert_eq!(t.len() * 8, FMU_TB.gadd.off() as usize);
    row3(&mut t, 0, FSQF.scr.off(), ad);
    row3(&mut t, 64, FSQF.scr.off() + 64, ad + 64);
    row3(&mut t, 128, zb, FSQF.scr.off() + 128);
    row3(&mut t, 192, zb + 64, FSQF.scr.off() + 192);
    row3(&mut t, 256, zc, be);
    row3(&mut t, 320, zc + 64, be + 64);
    for (i, (s1, s2)) in [
        (FMUF.ta.off(), FMUF.ac.off()),
        (FMUF.ta.off() + 64, FMUF.ac.off() + 64),
        (FMUF.bd.off(), FMUF.ac.off() + 128),
        (FMUF.bd.off() + 64, FMUF.ac.off() + 192),
        (FMUF.bd.off() + 128, FMUF.ac.off() + 256),
        (FMUF.bd.off() + 192, FMUF.ac.off() + 320),
    ]
    .into_iter()
    .enumerate()
    {
        row3(
            &mut t,
            FMUF.ta.off() - FMUF.cr.off() + 64 * i as i32,
            s1,
            s2,
        );
    }

    // Epilogue double-width subs: z.b = CR - AC - BD, every lane guarded
    // (the parked lanes are congruences mod p*2^256, not exact values).
    assert_eq!(t.len() * 8, FMU_TB.gsub2.off() as usize);
    for lane in 0..6 {
        let off = 64 * lane;
        row3(
            &mut t,
            FMUF.cr.off() + off,
            FMUF.cr.off() + off,
            FMUF.ac.off() + off,
        );
        row3(
            &mut t,
            FMUF.cr.off() + off,
            FMUF.cr.off() + off,
            FMUF.bd.off() + off,
        );
    }

    // Montgomery reduction rows (src, dst offset; the MOD_DST slot holds
    // zero, so the offsets are absolute): z.a from TA, z.b from CR.
    assert_eq!(t.len() * 8, FMU_TB.mod_red.off() as usize);
    for i in 0..6 {
        t.extend([
            (FMUF.ta.off() + 64 * i) as u64,
            (FMUF.yout.off() + 32 * i) as u64,
        ]);
    }
    for i in 0..6 {
        t.extend([
            (FMUF.cr.off() + 64 * i) as u64,
            (FMUF.yout.off() + 192 + 32 * i) as u64,
        ]);
    }

    // Product sub-rows and staging sum rows: identical to fp12_sqr's.
    assert_eq!(t.len() * 8, FMU_TB.msub.off() as usize);
    t.extend([64, 64, 0, 0, 32, 128]);
    assert_eq!(t.len() * 8, FMU_TB.sums.off() as usize);
    row3(&mut t, 288, 96, 192);
    row3(&mut t, 384, 0, 96);
    row3(&mut t, 480, 0, 192);
    assert_eq!(t.len() * 8, FMU_TB.bytes as usize);
    t
}

/// Walk setup whose end offset (table-relative) comes from a ctx slot:
/// cursor = table base + `start`, bound slot `end_slot` = base + [ctx_end].
fn fmu_walk_setup_ctx<M: Machine>(
    m: &mut M,
    cursor: Reg,
    seg: TableSegment,
    ctx_end: FrameSlot,
    end_slot: FrameSlot,
) {
    m.load(cursor, FSQF.tbl.mem(), "table base");
    m.mov(Rax, cursor, "");
    m.add_mem(Rax, ctx_end.mem(), "+ ctx walk end offset");
    m.store(end_slot.mem(), Rax, "walk bound");
    m.add_imm(cursor, seg.off(), "walk start");
}

/// `helius_fp12_mul_x86`: the whole Fp12 product in mcl's lazy double-width
/// shape -- 54 raw 4x4 products and 12 Montgomery reductions where the
/// composed path (Karatsuba over three Fp6 products) pays 108 products and
/// 18 reductions.
///
/// # Semantics (mcl `Fp12::mul`, fp_tower.hpp)
///
/// For `x = a0 + a1*w`, `y = b0 + b1*w` (`w^2 = v`, `v^3 = xi = 9 + u`):
///
/// * `t1 = a0 + a1`, `t2 = b0 + b1`, canonical Fp6 (modular adds);
/// * `AC = a0*b0`, `BD = a1*b1`, `CR = t1*t2`: three Fp6Dbl::mulPre, each
///   the fp12_sqr iteration verbatim (Karatsuba at both tower levels, 18 raw
///   products, cross terms held as 512-bit values) but WITHOUT the per-
///   iteration reduction -- the six coefficient lanes park as 512-bit
///   values < p*2^256 with canonical high halves;
/// * `z.a = mod(mulVadd(BD, AC))`: `(xi*BD.c + AC.a, BD.a + AC.b,
///   BD.b + AC.c)` on doubles (one xi via the nine walk, six guarded adds),
///   then six reductions;
/// * `z.b = mod(CR - AC - BD)`: twelve guarded subtractions, six reductions.
///
/// # Bounds (BN254: p < 2^253.61, K = 2^256, pK < 2^510)
///
/// Inside each mulPre iteration the fp12_sqr bounds hold verbatim (staged
/// sums < 4p < 2^256, raw products <= 16p^2 < 2^512, Karatsuba middles
/// exact <= 8p^2, guarded lanes < pK, nine-walk highs < 10p reduced
/// canonical). The mul-specific stages:
///
/// * parked lanes: every gadd output is < pK with a canonical (< p) high
///   half -- the guard subtracts p from the high half exactly when it
///   reaches p;
/// * `NB2 = 0 - BD.c.im mod pK < pK`, high half < p, so both mulVadd nine
///   rows meet the nine-walk precondition (operand highs < p);
/// * mulVadd adds: two sub-pK addends < 2pK < 2^511; the high-half guard
///   returns below pK;
/// * z.b subtractions: minuend and subtrahend < pK, guarded difference
///   < pK;
/// * every reduced value satisfies T < pK, the Montgomery precondition:
///   `(T + m*p*2^256)/2^256 < 2p`, one conditional subtraction, canonical.
///
/// The interpreter asserts the flag claims on every path; the u512 reference
/// in `kernelgen_verify` asserts each stage bound on random and adversarial
/// inputs.
///
/// # Aliasing
///
/// `z == a`, `z == b` and `a == b` are all allowed (`z == a` is the
/// production MulAssign shape): the prologue stages both operands into the
/// frame and neither is read again, so no output store can alias a live
/// operand.
///
/// # Structure
///
/// One outer three-iteration loop (AC, BD, CR) whose per-iteration pointers
/// and walk bounds come from a ctx row; every phase is a walk body shared
/// with fp12_sqr (stage sides, products, guarded sub, nine-fold xi, guarded
/// add with the park destination decode, Montgomery reduction, modular
/// add). Iteration 2's gsub/nine/gadd segments are extended with the
/// mulVadd rows for z.a (their operands AC and BD are parked by then), so
/// the epilogue needs only the z.b subtractions, the twelve reductions and
/// the copy-out -- no walk body is emitted twice except gsub.
///
/// Arguments: `(z: *mut u64x48, a: *const u64x48, b: *const u64x48,
/// consts: *const { p[4], -p^-1, mu })` in rdi, rsi, rdx, rcx. `a` and `b`
/// are repr(C) Fp12, canonical; outputs canonical.
pub fn fp12_mul_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    let tables = fp12_mul_tables();
    m.rodata(FMU_TAB_LABEL, &tables);
    frame(m, FMUF.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, mu +40, z +48, loop bounds +56..96, ctx slots +104..160, NB2 +256, staged a/b +320..1088, t1/t2 +1088..1472, outputs +1472, operand sides +1856, products +3008, xi/neg scratch +4160, AC/BD/CR/TA parks +4544..6080",
        );
        m.store(FSQF.z.mem(), Rdi, "spill z");
        for k in 0..4 {
            m.load(Rax, Mem::new(Rcx, 8 * k), &format!("p{k}"));
            m.store(
                CONSTS_MIRROR.p.at(8 * k),
                Rax,
                "cancel rows address the frame as a consts table",
            );
        }
        m.load(Rax, Mem::new(Rcx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");
        m.load(Rax, Mem::new(Rcx, 40), "mu = floor(2^310/p)");
        m.store(CONSTS_MIRROR.mu.mem(), Rax, "mu");
        m.lea_rodata(Rax, FMU_TAB_LABEL, "walk tables");
        m.store(FSQF.tbl.mem(), Rax, "table base");
        m.mov(Rbx, Rax, "");
        m.add_imm(Rbx, FMU_TB.msub.end(), "product m-walk end");
        m.store(FSQF.mend.mem(), Rbx, "");
        m.mov(Rbx, Rax, "");
        m.add_imm(Rbx, FMU_TB.ctx.end(), "ctx table end (three 48-byte rows)");
        m.store(FSQF.outer_end.mem(), Rbx, "");
        m.xor_clear(Rax, "");
        for k in 0..8 {
            m.store(
                FSQF.zero8.at(8 * k),
                Rax,
                "zero word (negation rows subtract from it)",
            );
        }
        m.store(
            FSQF.mod_dst.mem(),
            Rax,
            "mod rows carry absolute destination offsets",
        );

        m.comment("");
        m.comment("stage a then b: all later reads are frame-relative, which is");
        m.comment("what makes z == a, z == b and a == b safe (no operand read");
        m.comment("after any z store)");
        m.mov(Rdi, rsp, "");
        m.add_imm(Rdi, FMUF.ast.off(), "staging cursor (b's area follows a's)");
        m.xor_clear(Rcx, "48 limbs, 4 per iteration");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lfmu_sta", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("a limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "staged");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });
        m.mov(Rsi, MULTIPLIER, "b pointer (rdi has walked to b's area)");
        m.xor_clear(Rcx, "");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lfmu_stb", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("b limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "staged");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });

        m.comment("");
        m.comment("t1 = a0 + a1, t2 = b0 + b1 (modular, canonical)");
        walk(m, FMU_TB.madd, ".Lfmu_madd", &mut |m| dbl_modadd_row(m));

        m.comment("");
        m.comment("outer loop: iteration 0 parks AC = a0*b0, 1 parks BD = a1*b1,");
        m.comment("2 parks CR = t1*t2 and rides the mulVadd rows for z.a");
        m.load(Rbp, FSQF.tbl.mem(), "ctx cursor = first ctx row");
        m.stride_loop(
            Rbp,
            48,
            LoopEnd::Mem(FSQF.outer_end.mem()),
            ".Lfmu_iter",
            &mut |m| {
                m.store(FSQF.ctx_spill.mem(), Rbp, "spill the outer cursor");
                for (field, slot, what) in [
                    (0, FSQF.stage_x, "ctx: x-side source"),
                    (8, FSQF.stage_y, "ctx: y-side source"),
                    (16, FMUF.park, "ctx: Fp6Dbl park base"),
                    (24, FMUF.gsub_end, "ctx: gsub walk end"),
                    (32, FMUF.nine_end, "ctx: nine walk end"),
                    (40, FMUF.gadd_end, "ctx: gadd walk end"),
                ] {
                    m.load(Rax, Mem::new(Rbp, field), what);
                    m.store(slot.mem(), Rax, "");
                }
                stage_sides_walk(m, "fmu", FMU_TB.sums);
                products_walk(m, "fmu", FMU_TB.msub);
                m.comment("double-width sub walk: Karatsuba assembly, cross terms, negations");
                fmu_walk_setup_ctx(m, Rbp, FMU_TB.gsub, FMUF.gsub_end, FSQF.walk_end);
                walk_rows(m, FMU_TB.gsub, ".Lfmu_gsub", &mut |m| dbl_gsub_row(m));
                m.comment("nine-fold walk: xi = 9 + u on 512-bit values, mu-canonical high");
                fmu_walk_setup_ctx(m, Rbp, FMU_TB.nine, FMUF.nine_end, FSQF.walk_end);
                walk_rows(m, FMU_TB.nine, ".Lfmu_nine", &mut |m| dbl_nine_row(m));
                m.comment("double-width add walk: assemble and park the Fp6Dbl (+ z.a rows)");
                fmu_walk_setup_ctx(m, Rbp, FMU_TB.gadd, FMUF.gadd_end, FSQF.walk_end);
                walk_rows(m, FMU_TB.gadd, ".Lfmu_gadd", &mut |m| {
                    dbl_gadd_row(m, Some(FMUF.park))
                });
                m.load(Rbp, FSQF.ctx_spill.mem(), "reload the outer cursor");
            },
        );

        m.comment("");
        m.comment("z.b assembly: CR -= AC, CR -= BD (all lanes guarded mod p*2^256)");
        walk(m, FMU_TB.gsub2, ".Lfmu_gsub2", &mut |m| dbl_gsub_row(m));
        m.comment("Montgomery reduction walk: 12 output coefficients into YOUT");
        walk(m, FMU_TB.mod_red, ".Lfmu_mod", &mut |m| dbl_mod_row(m));

        m.comment("");
        m.comment("copy out: z.a then z.b are contiguous, 48 limbs to z");
        m.load(Rdi, FSQF.z.mem(), "z");
        m.mov(Rsi, rsp, "");
        m.add_imm(Rsi, FMUF.yout.off(), "output base");
        m.xor_clear(Rcx, "");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lfmu_out", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("z limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "z");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });
    });
}

/// Register roles for `helius_cyc_sqr_x86` (walk bodies shared with
/// fp12_sqr/fp12_mul, so the roles mirror theirs).
pub const CYC_SQR_REGISTER_MAP: &[(Reg, &str)] = &[
    (
        Rdi,
        "z on entry (spilled); walk destination pointer in every table-driven pass",
    ),
    (
        Rsi,
        "f pointer on entry (staging source); walk source-1 pointer; mask scratch",
    ),
    (
        Rdx,
        "consts pointer on entry; the implicit mulx multiplicand; walk scratch",
    ),
    (
        Rcx,
        "walk source-2 pointer; staging cursor; the product output cursor",
    ),
    (R8, "accumulator/value word 0"),
    (R9, "accumulator/value word 1"),
    (R10, "accumulator/value word 2"),
    (R11, "accumulator/value word 3"),
    (R12, "accumulator/value word 4"),
    (R13, "accumulator/value word 5; mu-reduction scratch"),
    (
        R14,
        "product round cursor (byte offset 8j); 8-limb value word 6",
    ),
    (
        R15,
        "product cursor (64-byte operand-pair steps); 8-limb value word 7",
    ),
    (
        Rbp,
        "the walk row cursor, marching once through the whole table",
    ),
    (
        Rax,
        "low half of the current product; zero for chain closes; borrow mask",
    ),
    (Rbx, "high half of the current product; prologue scratch"),
];

/// cyc_sqr frame. Every slot a shared walk body addresses (p/-p^-1/mu, z,
/// walk bound, table base, mod_dst) is declared as an alias of its fp12_sqr
/// slot, so the bodies emit unchanged.
struct CycFrame {
    /// An 8-limb zero window: negation rows subtract from it, copy rows add
    /// its low half. Deliberately spans the shared mod_dst slot, whose
    /// required value here is exactly zero (mod rows carry absolute
    /// destination offsets), so one store pass initializes both -- the
    /// containment assert below declares the overlap.
    zero8: FrameSlot,
    /// f staged once (48 limbs): all later reads are frame-relative, and
    /// z == f becomes trivially safe (no f read after any z store).
    fst: FrameSlot,
    /// The three Fp4 cross operands s_k = x0_k + x1_k (canonical Fp2 each).
    ssum: FrameSlot,
    /// negp images p - r of the subtractive z-combine operands r0, r4, r3:
    /// the three subtraction openers run as modular adds of these.
    np: FrameSlot,
    /// Nine 128-byte square-operand blocks `[a - b, a + b, 2b, a]`, all four
    /// rows canonical, three blocks per Fp4 (sqrPre of x0, x1, s).
    sqb: FrameSlot,
    /// Eighteen 8-limb raw products: block q's a-lane at 128q, b-lane at
    /// 128q + 64 (the 64-byte operand-pair stride maps 1:1 onto output
    /// lanes).
    prod: FrameSlot,
    /// Negations: nbb_k = -sqr(x0_k).b for the three yb rows, then -U_2.b
    /// for the xi*t5 fold.
    nb: FrameSlot,
    /// The nine-fold y operands: ya_k = T0.a - T1.b, yb_k = T1.a + T0.b.
    y: FrameSlot,
    /// Nine-fold outputs: the complete T2_k = xi*T1_k + T0_k (three
    /// Fp2Dbl), then XT = xi*U_2.
    scr: FrameSlot,
    /// The six reduced Fp4 outputs t0, t1, t2, t3, t4, xi*t5 (canonical
    /// Fp2s).
    tt: FrameSlot,
    /// The z-combine area, laid out as the final repr(C) Fp12:
    /// z0, z4, z3, z2, z1, z5 at +0, +64, +128, +192, +256, +320.
    out: FrameSlot,
    size: i32,
}

const CYCF: CycFrame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv)
        .alias(CONSTS_MIRROR.mu)
        .alias(FSQF.z)
        .gap(8)
        .alias(FSQF.walk_end)
        .gap(16)
        .alias(FSQF.tbl);
    let (l, zero8) = l.slot(64);
    let l = l.gap(48);
    let (l, fst) = l.slot(384);
    let (l, ssum) = l.slot(192);
    let (l, np) = l.slot(192);
    let (l, sqb) = l.slot(1152);
    let (l, prod) = l.slot(1152);
    let (l, nb) = l.slot(256);
    let (l, y) = l.slot(384);
    let (l, scr) = l.slot(512);
    let (l, tt) = l.slot(384);
    let (l, out) = l.slot(384);
    CycFrame {
        zero8,
        fst,
        ssum,
        np,
        sqb,
        prod,
        nb,
        y,
        scr,
        tt,
        out,
        size: l.size(),
    }
};

// The declared overlap: the zero window spans the shared mod_dst slot.
const _: () = assert!(CYCF.zero8.contains(FSQF.mod_dst));

/// The cyc_sqr walk-table regions, in blob order. The regions are
/// contiguous in walk order: one cursor marches through the whole table,
/// each phase only storing the next bound.
struct CycTab {
    madd1: TableSegment,
    msub1: TableSegment,
    gsub: TableSegment,
    nine: TableSegment,
    mod_red: TableSegment,
    madd2: TableSegment,
    bytes: i32,
}

const CYC_TB: CycTab = {
    let l = TableLayout::new();
    let (l, madd1) = l.seg(33, 3); // modular add walk 1
    let (l, msub1) = l.seg(15, 3); // modular sub walk
    let (l, gsub) = l.seg(22, 3); // guarded double-width subs
    let (l, nine) = l.seg(8, 3); // nine-fold xi rows
    let (l, mod_red) = l.seg(12, 2); // Montgomery reduction rows
    let (l, madd2) = l.seg(36, 3); // modular add walk 2 (z-combines)
    CycTab {
        madd1,
        msub1,
        gsub,
        nine,
        mod_red,
        madd2,
        bytes: l.bytes(),
    }
};

const CYC_TAB_LABEL: &str = ".Lcyc_tab";

/// The cyc_sqr read-only walk tables (rsp-relative offsets).
fn cyc_sqr_tables() -> Vec<u64> {
    let mut t: Vec<u64> = Vec::new();
    let row3 = |t: &mut Vec<u64>, dst: i32, s1: i32, s2: i32| {
        t.extend([dst as u64, s1 as u64, s2 as u64]);
    };
    // The Granger-Scott operand pairs in repr(C) f order (r0 = c0.c0,
    // r4 = c0.c1, r3 = c0.c2, r2 = c1.c0, r1 = c1.c1, r5 = c1.c2):
    // Fp4 #0 squares (r0, r1), #1 (r2, r3), #2 (r4, r5).
    let (r0, r4, r3, r2, r1, r5) = (
        CYCF.fst.off(),
        CYCF.fst.off() + 64,
        CYCF.fst.off() + 128,
        CYCF.fst.off() + 192,
        CYCF.fst.off() + 256,
        CYCF.fst.off() + 320,
    );
    let pairs = [(r0, r1), (r2, r3), (r4, r5)];
    // Square q's staged block and raw product lanes. Squares 3k, 3k+1,
    // 3k+2 are Fp4 k's x0, x1, s; per square, T.a = (a-b)(a+b) and
    // T.b = 2b*a (all four operand rows canonical, so both lanes < p^2).
    let blk = |q: i32| CYCF.sqb.off() + 128 * q;
    let pa = |q: i32| CYCF.prod.off() + 128 * q;
    let pb = |q: i32| CYCF.prod.off() + 128 * q + 64;
    // Square q's source Fp2.
    let src = |q: i32| {
        let (x0, x1) = pairs[(q / 3) as usize];
        [x0, x1, CYCF.ssum.off() + 64 * (q / 3)][(q % 3) as usize]
    };

    // Modular add walk 1. First the three cross operands s_k = x0_k + x1_k
    // (per Fp half), then per square the additive block rows: a + b, 2b,
    // and the a copy (a + 0), every output canonical.
    for (k, (x0, x1)) in pairs.into_iter().enumerate() {
        for half in 0..2 {
            row3(
                &mut t,
                CYCF.ssum.off() + 64 * k as i32 + 32 * half,
                x0 + 32 * half,
                x1 + 32 * half,
            );
        }
    }
    for q in 0..9 {
        row3(&mut t, blk(q) + 32, src(q), src(q) + 32);
        row3(&mut t, blk(q) + 64, src(q) + 32, src(q) + 32);
        row3(&mut t, blk(q) + 96, src(q), CYCF.zero8.off());
    }

    // Modular sub walk: the a - b block rows, then the negp images
    // p - r = 0 - r mod p of the subtractive z-combine operands.
    assert_eq!(t.len() * 8, CYC_TB.msub1.off() as usize);
    for q in 0..9 {
        row3(&mut t, blk(q), src(q), src(q) + 32);
    }
    for (j, r) in [r0, r4, r3].into_iter().enumerate() {
        for half in 0..2 {
            row3(
                &mut t,
                CYCF.np.off() + 64 * j as i32 + 32 * half,
                CYCF.zero8.off(),
                r + 32 * half,
            );
        }
    }

    // Double-width subs. Per Fp4 the nine-fold y operands
    // (ya = T0.a - T1.b, yb = T1.a + T0.b, the addition via the negated
    // nbb = 0 - T0.b), then the twelve U_k = TS_k - T0_k - T1_k rows (in
    // place over the s-square lanes), then NB = 0 - U_2.b feeding the
    // xi*t5 fold (its operand is final only after the U rows).
    assert_eq!(t.len() * 8, CYC_TB.gsub.off() as usize);
    for k in 0..3 {
        row3(&mut t, CYCF.y.off() + 128 * k, pa(3 * k), pb(3 * k + 1));
        row3(&mut t, CYCF.nb.off() + 64 * k, CYCF.zero8.off(), pb(3 * k));
        row3(
            &mut t,
            CYCF.y.off() + 128 * k + 64,
            pa(3 * k + 1),
            CYCF.nb.off() + 64 * k,
        );
    }
    for k in 0..3 {
        let u = 3 * k + 2;
        row3(&mut t, pa(u), pa(u), pa(3 * k));
        row3(&mut t, pa(u), pa(u), pa(3 * k + 1));
        row3(&mut t, pb(u), pb(u), pb(3 * k));
        row3(&mut t, pb(u), pb(u), pb(3 * k + 1));
    }
    row3(&mut t, CYCF.nb.off() + 192, CYCF.zero8.off(), pb(8));

    // Nine-fold rows completing each T2 = xi*T1 + T0 in one step
    // (dst = 9x + y with the T0 term folded into y), then XT = xi*U_2
    // (t5 is consumed only as xi*t5, so the xi folds into the double-width
    // value and t5 itself never materializes).
    assert_eq!(t.len() * 8, CYC_TB.nine.off() as usize);
    for k in 0..3 {
        row3(
            &mut t,
            CYCF.scr.off() + 128 * k,
            pa(3 * k + 1),
            CYCF.y.off() + 128 * k,
        );
        row3(
            &mut t,
            CYCF.scr.off() + 128 * k + 64,
            pb(3 * k + 1),
            CYCF.y.off() + 128 * k + 64,
        );
    }
    row3(&mut t, CYCF.scr.off() + 384, pa(8), CYCF.nb.off() + 192);
    row3(&mut t, CYCF.scr.off() + 448, pb(8), pa(8));

    // Montgomery reduction rows (src, absolute dst offset; the MOD_DST slot
    // holds zero): t0 = mod(T2_0), t1 = mod(U_0), t2 = mod(T2_1),
    // t3 = mod(U_1), t4 = mod(T2_2), xt5 = mod(XT).
    assert_eq!(t.len() * 8, CYC_TB.mod_red.off() as usize);
    let tt = |i: i32| CYCF.tt.off() + 64 * i;
    for (i, s) in [
        (0, CYCF.scr.off()),
        (1, pa(2)),
        (2, CYCF.scr.off() + 128),
        (3, pa(5)),
        (4, CYCF.scr.off() + 256),
        (5, CYCF.scr.off() + 384),
    ] {
        t.extend([s as u64, tt(i) as u64]);
        t.extend([(s + 64) as u64, (tt(i) + 32) as u64]);
    }

    // Modular add walk 2: the z-combines, in dependency order. Openers
    // (the subtractive ones as adds of the negp images), then all six
    // in-place doublings, then the final += t of every z -- exactly the
    // composed 3t +- 2r shape (z = 2*(t -+ r) + t).
    assert_eq!(t.len() * 8, CYC_TB.madd2.off() as usize);
    let (z0, z4, z3, z2, z1, z5) = (
        CYCF.out.off(),
        CYCF.out.off() + 64,
        CYCF.out.off() + 128,
        CYCF.out.off() + 192,
        CYCF.out.off() + 256,
        CYCF.out.off() + 320,
    );
    let openers = [
        (z0, tt(0), CYCF.np.off()),
        (z4, tt(2), CYCF.np.off() + 64),
        (z3, tt(4), CYCF.np.off() + 128),
        (z2, tt(5), r2),
        (z1, tt(1), r1),
        (z5, r5, tt(3)),
    ];
    for (dst, s1, s2) in openers {
        for half in 0..2 {
            row3(&mut t, dst + 32 * half, s1 + 32 * half, s2 + 32 * half);
        }
    }
    for j in 0..12 {
        row3(
            &mut t,
            CYCF.out.off() + 32 * j,
            CYCF.out.off() + 32 * j,
            CYCF.out.off() + 32 * j,
        );
    }
    for (dst, t_src) in [
        (z0, tt(0)),
        (z4, tt(2)),
        (z3, tt(4)),
        (z2, tt(5)),
        (z1, tt(1)),
        (z5, tt(3)),
    ] {
        for half in 0..2 {
            row3(&mut t, dst + 32 * half, dst + 32 * half, t_src + 32 * half);
        }
    }
    assert_eq!(t.len() * 8, CYC_TB.bytes as usize);
    t
}

/// Advance the walk chain: the row cursor already sits at this region's
/// start (the previous walk's exact exit value), so only the new bound is
/// stored.
fn cyc_walk_bound<M: Machine>(m: &mut M, seg: TableSegment) {
    m.load(Rax, FSQF.tbl.mem(), "table base");
    m.add_imm(Rax, seg.end(), "next walk's bound");
    m.store(FSQF.walk_end.mem(), Rax, "walk bound");
}

/// `helius_cyc_sqr_x86`: the Granger-Scott cyclotomic square in mcl's lazy
/// double-width shape -- 18 raw 4x4 products and 12 Montgomery reductions
/// where the composed SoS path pays 36 products and 12 interleaved
/// reductions. The single hottest final-exponentiation shape: 192 calls per
/// final exp, all on the latency-critical pow_x dependent chain.
///
/// # Semantics (exactly `Fp12::cyclotomic_square`'s composed path; mcl
/// `fasterSqr`/`sqrFp4`, pairing_impl.hpp)
///
/// With the arkworks mapping r0 = c0.c0, r4 = c0.c1, r3 = c0.c2,
/// r2 = c1.c0, r1 = c1.c1, r5 = c1.c2 and three Fp4 squares
/// `(t0, t1) = (r0 + r1*y)^2` etc. (`y^2 = xi = 9 + u`):
///
/// * each Fp4 square is three lazy Fp2Dbl::sqrPre products
///   (`T0 = sqr(x0)`, `T1 = sqr(x1)`, `TS = sqr(x0 + x1)`), each TWO raw
///   4x4 products by the complex method (`(a - b)*(a + b)` and `2b*a`, all
///   four operand rows staged canonical), with `t0 = mod(xi*T1 + T0)` and
///   `t1 = mod(TS - T0 - T1)` -- one Montgomery reduction per output Fp
///   instead of the composed path's interleaved sos4/sos2 dispatches;
/// * the T0 addition folds into the nine-fold's y operand
///   (`T2.a = 9*T1.a + (T0.a - T1.b)`, `T2.b = 9*T1.b + (T1.a + T0.b)`),
///   so each T2 finishes inside the nine walk and no double-width add walk
///   exists;
/// * t5 is consumed only as xi*t5 (the z2 combine), so its xi folds into
///   the double-width value: `xt5 = mod(xi*(TS_2 - T0_2 - T1_2))` -- same
///   reduction count, one single-width xi saved;
/// * z-combines on the REDUCED values, single-width modular (mcl's
///   fasterSqr shape, bit-identical to the composed path):
///   z0 = 2(t0 - r0) + t0, z1 = 2(t1 + r1) + t1, z2 = 2(xt5 + r2) + xt5,
///   z3 = 2(t4 - r3) + t4, z4 = 2(t2 - r4) + t2, z5 = 2(r5 + t3) + t3,
///   the three subtractions entering as adds of staged negp images
///   (t - r = t + (p - r) mod p, canonical either way), output
///   (z0, z4, z3, z2, z1, z5) in repr(C) order.
///
/// # Bounds (BN254: p < 2^253.61, K = 2^256, pK < 2^510)
///
/// * staged rows all canonical: a - b, a + b, 2b, a, s = x0 + x1 and the
///   negp images are modular single-width outputs < p;
/// * raw products < p^2 < pK: every sqrPre lane is nonnegative and already
///   below the guard modulus;
/// * nine-fold y operands: ya = T0.a - T1.b and yb = T1.a + T0.b (via
///   nbb = 0 - T0.b) guarded mod pK, high halves < p; U = TS - T0 - T1
///   guarded mod pK (subtrahends < p^2 < pK);
/// * nine rows: operand highs < p (lanes < p^2 or guarded < pK), output
///   < pK with a mu-canonical high half;
/// * every reduced value satisfies T < pK, the Montgomery precondition:
///   result < 2p, one conditional subtraction, canonical;
/// * z-combines: canonical single-width adds (sums < 2p; the opener adds
///   of negp images are exact because t < p and p - r <= p).
///
/// The interpreter asserts the flag claims on every path; the u512
/// reference in `kernelgen_verify` asserts each stage bound on random and
/// adversarial inputs.
///
/// # In-place update
///
/// `z == f` is allowed and is the production shape (pow_x squares its
/// accumulator in place): the prologue stages all of `f` into the frame and
/// `f` is never read again, so no output store can alias a live operand.
///
/// # Structure and latency
///
/// No outer loop: the three Fp4 squares are fully independent, so every
/// phase runs once as a flat walk over all three -- maximal cross-Fp4 ILP
/// for the OoO window. All staging and z-combine work runs as rows of the
/// two single-width bodies (modular add, modular sub), so besides them the
/// kernel emits only the product loop and the three shared double-width
/// bodies (guarded sub, nine-fold, reduction), each exactly once. One row
/// cursor marches through the whole rodata table; phase boundaries store
/// the next bound. The critical path per call is one product (4 rolled
/// rounds) + one guarded sub + nine + one reduction + three single-width
/// combine rows; the composed path has the same reduction depth but 2x the
/// product mass.
///
/// Arguments: `(z: *mut u64x48, f: *const u64x48, consts: *const { p[4],
/// -p^-1, mu })` in rdi, rsi, rdx. `f` is repr(C) Fp12, canonical; outputs
/// canonical. The Granger-Scott identity requires a cyclotomic-subgroup
/// input for z to equal f^2, but the leaf computes the composed formula
/// bit-identically on ANY canonical input.
pub fn cyc_sqr_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    let tables = cyc_sqr_tables();
    m.rodata(CYC_TAB_LABEL, &tables);
    frame(m, CYCF.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, mu +40, z +48, walk bound +64, table base +88, zero8 +96 (spans mod dst +136), staged f +208, s sums +592, negp images +784, square blocks +976, products +2128, negations +3280, nine-fold y +3536, xi scratch +3920, t values +4432, z combines +4816",
        );
        m.store(FSQF.z.mem(), Rdi, "spill z");
        for k in 0..4 {
            m.load(Rax, Mem::new(Rdx, 8 * k), &format!("p{k}"));
            m.store(
                CONSTS_MIRROR.p.at(8 * k),
                Rax,
                "cancel rows address the frame as a consts table",
            );
        }
        m.load(Rax, Mem::new(Rdx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");
        m.load(Rax, Mem::new(Rdx, 40), "mu = floor(2^310/p)");
        m.store(CONSTS_MIRROR.mu.mem(), Rax, "mu");
        m.lea_rodata(Rax, CYC_TAB_LABEL, "walk tables");
        m.store(FSQF.tbl.mem(), Rax, "table base");
        m.xor_clear(Rax, "");
        for k in 0..8 {
            m.store(
                CYCF.zero8.at(8 * k),
                Rax,
                "zero word (negation/copy rows and the spanned MOD_DST slot)",
            );
        }

        m.comment("");
        m.comment("stage f: all later reads are frame-relative, which is what");
        m.comment("makes z == f safe (no f read after any z store)");
        m.mov(Rdi, rsp, "");
        m.add_imm(Rdi, CYCF.fst.off(), "staging cursor");
        m.xor_clear(Rcx, "48 limbs, 4 per iteration");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lcyc_fst", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("f limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "staged");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });

        m.comment("");
        m.comment("modular add walk 1: the s_k = x0_k + x1_k cross operands, then");
        m.comment("the additive block rows a + b, 2b and the a copy, all canonical");
        walk(m, CYC_TB.madd1, ".Lcyc_madd1", &mut |m| dbl_modadd_row(m));

        m.comment("");
        m.comment("modular sub walk: the a - b block rows, then the negp images");
        m.comment("p - r of the subtractive z-combine operands");
        cyc_walk_bound(m, CYC_TB.msub1);
        walk_rows(m, CYC_TB.msub1, ".Lcyc_msub", &mut |m| {
            dbl_msub_row(m, "dst")
        });

        m.comment("");
        m.comment("products: 18 raw 4x4 mulpre, two per square (the complex method:");
        m.comment("a-lane (a-b)(a+b), b-lane 2b*a); the 64-byte operand-pair stride");
        m.comment("maps 1:1 onto the 64-byte output lanes");
        m.xor_clear(R15, "product cursor: 64-byte operand-pair steps");
        m.stride_loop(R15, 64, LoopEnd::Imm(18 * 64), ".Lcyc_prod", &mut |m| {
            m.mov(Rsi, rsp, "");
            m.add(Rsi, R15, "");
            m.add_imm(Rsi, CYCF.sqb.off(), "PA: the multiplicand row");
            m.mov(Rdi, Rsi, "");
            m.add_imm(Rdi, 32, "PY: the y row");
            m.mov(Rcx, Rsi, "");
            m.add_imm(
                Rcx,
                CYCF.prod.off() - CYCF.sqb.off(),
                "PZ: the 512-bit product lane",
            );
            for (k, t) in T.into_iter().enumerate() {
                m.xor_clear(t, &format!("t{k} = 0"));
            }
            m.xor_clear(R14, "round cursor: byte offset 8j of the multiplicand limb");
            m.stride_loop(R14, 8, LoopEnd::Imm(32), ".Lcyc_prod_j", &mut |m| {
                m.load_indexed(MULTIPLIER, Rsi, R14, "x[j], the row multiplicand");
                m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
                fsq_mulpre_row(m, Rdi);
                m.store(Mem::new(Rcx, 0), T[0], "product limb j is final");
                m.add_imm(Rcx, 8, "next output limb");
                m.comment("shift down one word");
                for k in 0..5 {
                    m.mov(T[k], T[k + 1], &format!("t{k} = t{}", k + 1));
                }
                m.xor_clear(T[5], "t5 = 0 (CF/OF stay clear)");
            });
            for (k, t) in T[..4].iter().enumerate() {
                m.store(
                    Mem::new(Rcx, 8 * k as i32),
                    *t,
                    &format!("product limb {}", k + 4),
                );
            }
        });

        m.comment("");
        m.comment("double-width sub walk: the nine-fold y operands ya = T0.a - T1.b");
        m.comment("and yb = T1.a + T0.b (via nbb = 0 - T0.b), U = TS - T0 - T1, then");
        m.comment("the xi*t5 negation (its operand U_2.b is final only after the U rows)");
        cyc_walk_bound(m, CYC_TB.gsub);
        walk_rows(m, CYC_TB.gsub, ".Lcyc_gsub", &mut |m| dbl_gsub_row(m));

        m.comment("");
        m.comment("nine-fold walk: each T2 = xi*T1 + T0 completes as 9x + y, then");
        m.comment("XT = xi*U_2 (the t5 site), mu-canonical high halves");
        cyc_walk_bound(m, CYC_TB.nine);
        walk_rows(m, CYC_TB.nine, ".Lcyc_nine", &mut |m| dbl_nine_row(m));

        m.comment("");
        m.comment("Montgomery reduction walk: t0, t1, t2, t3, t4, xi*t5");
        cyc_walk_bound(m, CYC_TB.mod_red);
        walk_rows(m, CYC_TB.mod_red, ".Lcyc_mod", &mut |m| dbl_mod_row(m));

        m.comment("");
        m.comment("modular add walk 2: the z-combines -- openers (subtractions as");
        m.comment("adds of the negp images), six in-place doublings, final += t");
        cyc_walk_bound(m, CYC_TB.madd2);
        walk_rows(m, CYC_TB.madd2, ".Lcyc_madd2", &mut |m| dbl_modadd_row(m));

        m.comment("");
        m.comment("copy out: the z area is already repr(C) Fp12, 48 limbs to z");
        m.load(Rdi, FSQF.z.mem(), "z");
        m.mov(Rsi, rsp, "");
        m.add_imm(Rsi, CYCF.out.off(), "z-combine base");
        m.xor_clear(Rcx, "");
        m.stride_loop(Rcx, 32, LoopEnd::Imm(384), ".Lcyc_out", &mut |m| {
            for (k, reg) in W4L.into_iter().enumerate() {
                m.load(reg, Mem::new(Rsi, 8 * k as i32), &format!("z limb {k}"));
            }
            for (k, reg) in W4L.into_iter().enumerate() {
                m.store(Mem::new(Rdi, 8 * k as i32), reg, "z");
            }
            m.add_imm(Rsi, 32, "");
            m.add_imm(Rdi, 32, "");
        });
    });
}

/// `helius_sos_x86`: rolled sum-of-products Montgomery reduction
/// (Longa, ePrint 2022/367, Alg. 2, B = 1) with runtime product count.
///
/// Computes `(sum_{i<T} a_i * b_i) * R^{-1} mod p` for `T` operand pairs
/// (`T` even, production shapes 2/4/6/8) passed as a table of `2T` pointers;
/// every Fp2/Fp6/Fp12 tower product routes through this one loop body, so
/// the whole tower's hot code is a few hundred bytes and stays op-cache
/// resident (the unrolled portable bodies miss L1I on every pairing round).
///
/// # Shape
///
/// Outer counted round: `j` walks the four source limbs (cursor = byte
/// offset `8j`). Inner counted walk: the pair table, one dual-chain product
/// row per pair, two pairs per iteration (the walk stride is 32 bytes, which
/// is also what forces `T` even: the trip proof rejects odd counts), then
/// one Montgomery cancel row and the one-word shift. The back edges'
/// `add`/`cmp` clobber CF/OF, so every row closes both chains and the first
/// row of each iteration re-seeds with a flag-cutting `xor` -- exactly the
/// discipline the dual-chain serialization finding demands.
///
/// # Bounds (operands <= p, T <= 10)
///
/// Between rounds the accumulator is `u_j < (T+1)p < 11p < 2^260`; the
/// in-round peak before the shift stays below `(T+1)*p*2^64 < 2^325`, so a
/// six-word accumulator absorbs every carry and each row's chain closes are
/// provably carry-free at t5 (the interpreter asserts the claims). The final
/// value is `< (1 + 0.1891*T)p < 3p < 2^256`: t4 ends exactly zero and two
/// conditional subtractions reach the canonical range.
pub fn sos_rolled<M: Machine>(m: &mut M) {
    for reg in CALLEE_SAVED {
        m.push(reg);
    }
    m.push(Rdi);
    m.comment("table end = pairs + 16T; T arrives in rdx (2 pointers/pair)");
    m.mov(TABLE_END, Rdx, "T");
    for doubled in [2, 4, 8, 16] {
        m.add(TABLE_END, TABLE_END, &format!("{doubled}T"));
    }
    m.add(TABLE_END, Rsi, "pair-table end");
    for (k, t) in T.into_iter().enumerate() {
        m.xor_clear(t, &format!("t{k} = 0"));
    }
    m.xor_clear(JOFF, "byte offset of the round's source limb: 8j = 0");

    m.comment("");
    m.stride_loop(JOFF, 8, LoopEnd::Imm(32), ".Lsos_round", &mut |m| {
        m.comment("product rows: t += a_i[j] * b_i, two pairs per iteration");
        m.mov(CURSOR, Rsi, "rewind the pair-table cursor");
        m.stride_loop(
            CURSOR,
            32,
            LoopEnd::Reg(TABLE_END),
            ".Lsos_pair",
            &mut |m| {
                m.load(Rdi, Mem::new(CURSOR, 0), "a_i pointer");
                m.load_indexed(MULTIPLIER, Rdi, JOFF, "a_i[j], the row multiplicand");
                m.load(Rdi, Mem::new(CURSOR, 8), "b_i pointer");
                m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
                sos_row(m, Rdi, "a_i[j]*b_i");
                m.comment("second pair of the iteration");
                m.load(Rdi, Mem::new(CURSOR, 16), "a_{i+1} pointer");
                m.load_indexed(MULTIPLIER, Rdi, JOFF, "a_{i+1}[j]");
                m.load(Rdi, Mem::new(CURSOR, 24), "b_{i+1} pointer");
                m.xor_clear(
                    LO,
                    "flag-cutting re-seed: without it the row serializes on the previous row's closes",
                );
                sos_row(m, Rdi, "a_{i+1}[j]*b_{i+1}");
            },
        );
        m.comment("cancel row: m = t0 * -p^-1, then t += m*p zeroes t0");
        m.mov(MULTIPLIER, T[0], "m multiplicand <- t0");
        m.mulx_mem(
            Rbx,
            MULTIPLIER,
            p_inv(),
            "m = t0 * -p^-1 mod 2^64 (hi half discarded)",
        );
        m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
        sos_row(m, Rcx, "m*p");
        m.claim_zero(T[0], "the Montgomery factor cancels the low word");
        m.comment("shift down one word: the canceled zero word drops");
        for k in 0..5 {
            m.mov(T[k], T[k + 1], &format!("t{k} = t{}", k + 1));
        }
        m.xor_clear(T[5], "t5 = 0 (CF/OF stay clear)");
    });

    m.comment("");
    m.claim_zero(T[4], "final value < 3p < 2^256 fits four words");
    m.pop(Rdi);
    m.comment("final reduction: value < 3p, subtract p at most twice");
    let value: [Reg; 4] = [T[0], T[1], T[2], T[3]];
    let keep: [Reg; 4] = [Rdx, Rbx, R14, R15];
    for pass in 0..2 {
        csub_pass(
            m,
            value,
            keep,
            p_limb,
            |k| format!("pass {pass}: keep-copy of word {k}"),
            |k| format!("word {k} -= p{k}"),
            |k| format!("borrow: value < p, keep word {k}"),
        );
    }
    for (k, v) in value.iter().enumerate() {
        m.store(Mem::new(OUT_PTR, 8 * k as i32), *v, &format!("z{k}"));
    }
    for reg in CALLEE_SAVED.iter().rev() {
        m.pop(*reg);
    }
    m.ret();
}

/// Register roles for `helius_sosd6_x86`.
pub const SOSD6_REGISTER_MAP: &[(Reg, &str)] = &[
    (Rdi, "z on entry (spilled at once); then lane1 word 4"),
    (
        Rsi,
        "stage pointer: walks the 24 transposed x limbs linearly, 8 bytes per pair (also the round cursor)",
    ),
    (
        Rdx,
        "consts pointer on entry (copied to the frame); the implicit mulx multiplicand",
    ),
    (
        Rcx,
        "y pair-block cursor over the five rolled pairs; the shared top word in the round tail",
    ),
    (R8, "lane0 word 0 (prologue: p limb 0 for the negp rows)"),
    (R9, "lane0 word 1 (prologue: p limb 1)"),
    (R10, "lane0 word 2 (prologue: p limb 2)"),
    (R11, "lane0 word 3 (prologue: p limb 3)"),
    (R12, "lane0 word 4 (prologue: negp scratch)"),
    (R13, "lane1 word 0 (prologue: negp scratch)"),
    (R14, "lane1 word 1"),
    (R15, "lane1 word 2"),
    (Rbp, "lane1 word 3"),
    (
        Rax,
        "low half of the current product; zero for chain closes",
    ),
    (Rbx, "high half of the current product; prologue scratch"),
];

/// Lane0 accumulator words 0..4 (loop-invariant names; the sixth word is the
/// shared [`SOSD6_TOP`]).
const SOSD6_L0: [Reg; 5] = [R8, R9, R10, R11, R12];
/// Lane1 accumulator words 0..4.
const SOSD6_L1: [Reg; 5] = [R13, R14, R15, Rbp, Rdi];
/// The shared sixth accumulator word. At T = 6 a lane's word 4 can only
/// overflow on its sixth product row and its cancel row (five rows peak
/// below 2^320), and each lane's overflow dies at its own shift, so one
/// register serves both lanes back to back inside the round tail. Doubles
/// as the y pair-block cursor while the five rolled pairs run.
const SOSD6_TOP: Reg = Rcx;

/// sosd6 frame, all rsp + disp8: the consts mirror (p, -p^-1; no mu -- ny21
/// takes its place), then the round tail's row sources and the walk bounds.
struct Sosd6Frame {
    ny21: FrameSlot,
    y20: FrameSlot,
    z_ptr: FrameSlot,
    yb: FrameSlot,
    yend: FrameSlot,
    size: i32,
}

const SOSD6F: Sosd6Frame = {
    let l = FrameLayout::new()
        .alias(CONSTS_MIRROR.p)
        .alias(CONSTS_MIRROR.pinv);
    let (l, ny21) = l.slot(32);
    let (l, y20) = l.slot(32);
    let (l, z_ptr) = l.slot(8);
    let (l, yb) = l.slot(8);
    let (l, yend) = l.slot(8);
    Sosd6Frame {
        ny21,
        y20,
        z_ptr,
        yb,
        yend,
        size: l.size(),
    }
};

// Stage-block byte offsets (see the `sosd6_x86` ABI): the transposed x limbs
// at +0, then five 64-byte y pair blocks. Blocks 1 and 3 arrive holding
// [y01, y00] and [y11, y10]; the prologue negates their low vectors in
// place. Pair 5's sources (ny21, a y20 copy) live in the frame instead: the
// tail has no free base register for the stage.
const SOSD6_STAGE_Y: i32 = 192;
const SOSD6_STAGE_NY01: i32 = 256;
const SOSD6_STAGE_NY11: i32 = 384;
const SOSD6_STAGE_Y20: i32 = 448;
const SOSD6_STAGE_Y21: i32 = 480;

/// Full double close through the sosd6 shared top word: value chain into
/// the lane's word 4, ripple and carry chain into [`SOSD6_TOP`].
fn sosd6_close_chains<M: Machine>(m: &mut M, word4: Reg) {
    close_value_chain(m, word4, "close the value chain into word 4");
    m.adox(
        SOSD6_TOP,
        LO,
        "ripple the word-4 close into the shared top word",
    );
    m.adcx(
        SOSD6_TOP,
        LO,
        "close the carry chain into the shared top word",
    );
}

/// Five-word dual-chain product row: `t[k] += lo_k` on the value chain,
/// `t[k+1] += hi_k` on the carry chain, sources at `[base + off + 8k]`.
/// Valid for each lane's first five rows of a round, where the running
/// value stays below 2^320 and word 4 absorbs both closes. Entry and exit
/// invariant: CF = OF = 0.
fn sosd6_row5<M: Machine>(m: &mut M, t: [Reg; 5], base: Reg, off: i32, product: &str) {
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            Mem::new(base, off + 8 * k as i32),
            t[k],
            t[k + 1],
            &format!("{product}[{k}]"),
            k,
        );
    }
    close_value_chain(m, t[4], "close the value chain into word 4");
    m.claim_flags_clear("value through five rows < (5*2^64 + 7)p < 2^320: word 4 cannot wrap");
}

/// Sixth-row variant: the running value may pass 2^320, so both chain
/// closes ripple into the shared top word. Sources in `src` (the
/// frame-held ny21 or y20 copy). Entry invariant: CF = OF = 0 and
/// [`SOSD6_TOP`] = 0 for the first of the two tail rows, or the other
/// lane's freed zero for the second.
fn sosd6_row6<M: Machine>(m: &mut M, t: [Reg; 5], src: FrameSlot, product: &str) {
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            src.limb(k),
            t[k],
            t[k + 1],
            &format!("{product}[{k}]"),
            k,
        );
    }
    sosd6_close_chains(m, t[4]);
    m.claim_flags_clear("row-6 peak < 7p + 6p*2^64 < 2^321: the top word cannot wrap");
}

/// Montgomery cancel row over the six-word window `[t, SOSD6_TOP]`, then the
/// one-word shift that drops the canceled zero and frees the top word for
/// the other lane. Register names are loop-iteration-invariant, so the
/// shift is five moves plus a flag-safe xor.
fn sosd6_cancel_shift<M: Machine>(m: &mut M, t: [Reg; 5], lane: &str) {
    m.comment(&format!(
        "{lane} cancel row: m = w0 * -p^-1, then += m*p zeroes w0"
    ));
    m.mov(MULTIPLIER, t[0], "m multiplicand <- w0");
    m.mulx_mem(
        Rbx,
        MULTIPLIER,
        CONSTS_MIRROR.pinv.mem(),
        "m = w0 * -p^-1 mod 2^64 (hi half discarded)",
    );
    for k in 0..4 {
        mul_mem_into_columns(
            m,
            Rbx,
            CONSTS_MIRROR.p.limb(k),
            t[k],
            t[k + 1],
            &format!("m*p{k}"),
            k,
        );
    }
    sosd6_close_chains(m, t[4]);
    m.claim_flags_clear("cancel row closed both chains under the 2^321 bound");
    m.claim_zero(t[0], "the Montgomery factor cancels the low word");
    m.comment(&format!(
        "{lane} shift down one word: the canceled zero drops, the top word empties"
    ));
    for k in 0..4 {
        m.mov(t[k], t[k + 1], &format!("w{k} = w{}", k + 1));
    }
    m.mov(t[4], SOSD6_TOP, "word 4 <- the shared top word");
    m.xor_clear(
        SOSD6_TOP,
        "top word frees for the other lane (CF/OF stay clear)",
    );
}

/// `helius_sosd6_x86`: dedicated dual-lane sum of products, fixed T = 6 per
/// lane -- both Fp components of `sum_{i<3} x_i * y_i` over Fp2 in one leaf:
///
/// * lane0 = `(sum x_i0*y_i0 + x_i1*(p - y_i1)) * R^-1 mod p`,
/// * lane1 = `(sum x_i0*y_i1 + x_i1*y_i0) * R^-1 mod p`,
///
/// operands at most p, both lanes canonical on return -- exactly the
/// portable `sosd6`, with the three `p - y_i1` images computed in-kernel.
/// This is the tower's hottest dual-lane shape (each composed Fp12 square
/// dispatches it six times, each mul_by_034 six, each Fp6 mul three), and
/// the composed route pays it as two serial `helius_sos_x86` calls whose
/// ~700-instruction single-lane carry chains cannot overlap.
///
/// # ABI: one caller-staged block
///
/// Arguments: `(z: *mut u64x8 (lane0 then lane1), stage: *mut u64x64,
/// consts: *const { p[4], -p^-1 })` in rdi, rsi, rdx. The stage block is
/// caller-built scratch, 512 bytes:
///
/// * +0..191: the 24 x limbs transposed -- `x_i[j]` at byte `8*(6j + i)`,
///   operand order x00 x01 x10 x11 x20 x21 -- so one pointer (rsi, already
///   the argument register) walks all four rounds' multiplicands linearly;
/// * +192..511: five 64-byte y pair blocks, `[y00, y01] [y01, y00]
///   [y10, y11] [y11, y10] [y20, y21]`: block i holds pair i's lane0 row
///   source, then its lane1 row source. The kernel overwrites the low
///   vectors of blocks 1 and 3 with `p - y01`, `p - y11` in place (`stage`
///   is therefore `*mut`); `p - y21` and the pair-5 y20 copy go to the
///   kernel frame instead.
///
/// Twelve SysV pointer arguments do not exist, so the ABI choice is between
/// a 12-pointer table (the `helius_sos_x86` shape) and this staged block.
/// The block wins on total overhead: a table costs the kernel twelve
/// pointer loads plus 48 double-indirected limb loads and ~60 stores of
/// prologue staging on every call (the rounds must read y via rsp and the
/// multiplicands via one linear pointer regardless -- fifteen registers are
/// spoken for, see below), while the caller builds the block with plain
/// vector copies the compiler schedules freely, replacing the pointer-table
/// stores plus three `negp` temporaries the composed route already paid.
///
/// # Register budget and spill plan
///
/// Two six-word lane accumulators would take twelve registers, and with
/// rdx/rax/rbx there would be none left for any cursor. The T = 6 bound
/// rescues one word: from a round-boundary value below 7p, five product
/// rows peak below `(5*2^64 + 7)p < 2^320`, so each lane's first five rows
/// close inside a five-word window, and only the sixth row and the cancel
/// row can spill into a sixth word. Those run in the round tail, one lane
/// at a time, so a single shared top word (rcx) serves both lanes -- eleven
/// accumulator registers, and rcx doubles as the y pair-block cursor while
/// the five rolled pairs run. rsi walks the transposed x limbs (multiplicand
/// pointer and round cursor at once: five inner steps of 8 plus the back
/// edge's 8 = 48 bytes per round, and the y blocks begin exactly where the
/// x limbs end, so one frame slot is both the outer loop bound and the y
/// rewind value). No accumulator word ever touches memory; the frame holds
/// only the consts copy, the two pair-5 row sources, z, and the two walk
/// bounds.
///
/// # Shape and interleaving
///
/// Per source limb j, the five rolled pairs each load one multiplicand
/// `x_i[j]` and run a lane0 row then a lane1 row against the pair block --
/// the sosd2 alternation at T = 6, so both lanes' dual carry chains stay in
/// flight across the whole round body. The tail keeps the alternation as
/// far as the shared top word allows: lane0's sixth row, cancel and shift
/// (freeing the top word at zero), then lane1's sixth row, cancel and
/// shift. The tail's lane1 rows depend on the top word only through the
/// flag-cutting xor that frees it, so out-of-order execution overlaps them
/// with lane0's cancel; program order alone is serial there.
///
/// # Bounds (operands <= p, T = 6)
///
/// Exactly the portable sosd6 bounds: between rounds each lane holds
/// `u < 7p < 2^260`; five product rows peak below 2^320 (five-word rows),
/// the sixth row below `7p + 6p*2^64 < 2^321` and the cancel row below
/// `7p(1 + 2^64) < 2^321` (six-word rows; the interpreter checks every
/// close). After the shift the value is again below 7p, so the top word is
/// zero and hands over cleanly. The final value is `< (1 + 0.1891*6)p <
/// 2.135p < 2^256`: word 4 ends exactly zero and two conditional
/// subtractions per lane reach the canonical range.
pub fn sosd6_x86<M: Machine>(m: &mut M) {
    let rsp = Reg::Rsp;
    frame(m, SOSD6F.size, |m| {
        m.comment(
            "frame: p +0, -p^-1 +32, ny21 +40, y20 copy +72, z +104, y base +112, y end +120",
        );
        m.store(SOSD6F.z_ptr.mem(), Rdi, "spill z");
        m.comment("consts into the frame: cancel rows and reductions address rsp as a table");
        for (k, reg) in A.iter().enumerate() {
            m.load(
                *reg,
                Mem::new(Rdx, 8 * k as i32),
                &format!("p{k} (kept live for the negp rows)"),
            );
        }
        for (k, reg) in A.iter().enumerate() {
            m.store(CONSTS_MIRROR.p.limb(k), *reg, &format!("p{k}"));
        }
        m.load(Rax, Mem::new(Rdx, 32), "-p^-1");
        m.store(CONSTS_MIRROR.pinv.mem(), Rax, "-p^-1");

        let scratch = [Rax, Rbx, R12, R13];
        for (name, src, dst_base, dst) in [
            ("ny01", SOSD6_STAGE_NY01, Rsi, SOSD6_STAGE_NY01),
            ("ny11", SOSD6_STAGE_NY11, Rsi, SOSD6_STAGE_NY11),
            ("ny21", SOSD6_STAGE_Y21, rsp, SOSD6F.ny21.off()),
        ] {
            m.comment(&format!(
                "{name} = p - {}: lane0's subtracted term enters as the negp image",
                &name[1..]
            ));
            for (k, s) in scratch.into_iter().enumerate() {
                m.mov(s, A[k], &format!("p{k}"));
            }
            for (k, s) in scratch.into_iter().enumerate() {
                let what = format!("p{k} - {}[{k}]", &name[1..]);
                if k == 0 {
                    m.sub_mem(s, Mem::new(Rsi, src), &what);
                } else {
                    m.sbb_mem(s, Mem::new(Rsi, src + 8 * k as i32), &what);
                }
            }
            for (k, s) in scratch.into_iter().enumerate() {
                m.store(
                    Mem::new(dst_base, dst + 8 * k as i32),
                    s,
                    &format!("{name}[{k}]"),
                );
            }
        }
        m.comment("copy y20 beside ny21: the tail's lane1 row reads pair 5 off rsp");
        for (k, s) in scratch.into_iter().enumerate() {
            m.load(
                s,
                Mem::new(Rsi, SOSD6_STAGE_Y20 + 8 * k as i32),
                &format!("y20[{k}]"),
            );
        }
        for (k, s) in scratch.into_iter().enumerate() {
            m.store(SOSD6F.y20.limb(k), s, &format!("y20[{k}]"));
        }
        m.mov(Rax, Rsi, "");
        m.add_imm(
            Rax,
            SOSD6_STAGE_Y,
            "y pair blocks start where the x limbs end",
        );
        m.store(SOSD6F.yb.mem(), Rax, "y rewind value = outer loop bound");
        m.add_imm(Rax, 320, "past the five rolled pair blocks");
        m.store(SOSD6F.yend.mem(), Rax, "inner walk bound");
        m.comment("both lanes start at zero (the first round adds into zeros)");
        for (k, t) in SOSD6_L0.into_iter().enumerate() {
            m.xor_clear(t, &format!("lane0 w{k} = 0"));
        }
        for (k, u) in SOSD6_L1.into_iter().enumerate() {
            m.xor_clear(u, &format!("lane1 w{k} = 0"));
        }

        m.comment("");
        m.comment("rounds: rsi walks the transposed x limbs, 48 bytes per round");
        m.stride_loop(
            Rsi,
            8,
            LoopEnd::Mem(SOSD6F.yb.mem()),
            ".Lsosd6_round",
            &mut |m| {
                m.load(SOSD6_TOP, SOSD6F.yb.mem(), "y pair-block cursor rewinds");
                m.comment("five rolled pairs: adjacent lane rows share each multiplicand");
                m.stride_loop(
                    SOSD6_TOP,
                    64,
                    LoopEnd::Mem(SOSD6F.yend.mem()),
                    ".Lsosd6_pair",
                    &mut |m| {
                        m.load(MULTIPLIER, Mem::new(Rsi, 0), "x_i[j], the pair's multiplicand");
                        m.xor_clear(LO, "re-seed CF = OF = 0 (back edge clobbered flags)");
                        sosd6_row5(m, SOSD6_L0, SOSD6_TOP, 0, "x_i[j]*row0");
                        sosd6_row5(m, SOSD6_L1, SOSD6_TOP, 32, "x_i[j]*row1");
                        m.add_imm(Rsi, 8, "next x limb (clobbers CF/OF; chains are closed)");
                    },
                );
                m.comment("pair 5: the only rows that can overflow word 4; the top word serves one lane at a time");
                m.xor_clear(
                    SOSD6_TOP,
                    "top word = 0; re-seeds CF = OF = 0 after the back edge",
                );
                m.load(MULTIPLIER, Mem::new(Rsi, 0), "x21[j]");
                sosd6_row6(m, SOSD6_L0, SOSD6F.ny21, "x21[j]*ny21");
                sosd6_cancel_shift(m, SOSD6_L0, "lane0");
                m.load(MULTIPLIER, Mem::new(Rsi, 0), "x21[j] again (the cancel row owned rdx)");
                sosd6_row6(m, SOSD6_L1, SOSD6F.y20, "x21[j]*y20");
                sosd6_cancel_shift(m, SOSD6_L1, "lane1");
            },
        );

        m.comment("");
        m.claim_zero(
            SOSD6_L0[4],
            "lane0 final value < 2.135p < 2^256 fits four words",
        );
        m.claim_zero(
            SOSD6_L1[4],
            "lane1 final value < 2.135p < 2^256 fits four words",
        );
        m.load(
            Rdi,
            SOSD6F.z_ptr.mem(),
            "reload z into lane1's freed word 4",
        );
        m.comment("final reduction per lane: value < 2.135p, subtract p at most twice");
        let keep = [Rax, Rbx, Rcx, MULTIPLIER];
        let lanes = [(lane_result(SOSD6_L0), 0), (lane_result(SOSD6_L1), 32)];
        for (lane, (value, out_off)) in lanes.into_iter().enumerate() {
            for pass in 0..2 {
                csub_pass(
                    m,
                    value,
                    keep,
                    |k| CONSTS_MIRROR.p.limb(k),
                    |k| format!("lane{lane} pass {pass}: keep-copy of word {k}"),
                    |k| format!("lane{lane}: word {k} -= p{k}"),
                    |k| format!("borrow: lane{lane} < p, keep word {k}"),
                );
            }
            for (k, v) in value.iter().enumerate() {
                m.store(
                    Mem::new(Rdi, out_off + 8 * k as i32),
                    *v,
                    &format!("z[{}]", lane * 4 + k),
                );
            }
        }
    });
}
