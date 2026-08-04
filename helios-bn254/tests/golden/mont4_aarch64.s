/* @generated at build time by the helios-bn254 build script.
   Source of truth: crates/helios-bn254/build/a64/schedule.rs (ADR 0001).
   Inspect a copy: HELIOS_DUMP_ASM=<absolute dir> cargo build.
   Verified by: tests/kernelgen_verify.rs (interpreter + determinism).

   _helios_mont4: schedule bn254-mont4-cios-rolled, 68 instructions, 272 bytes

   AAPCS64 (Apple), leaf; the counted loop is one CIOS round.
   Arguments: (z: *mut u64x4, x: *const u64x4, y: *const u64x4,
               consts: *const { p: [u64; 4], neg_p_inv: u64 })
   Contract and safety boundary live beside the only caller in
   src/fp/aarch64.rs; carry bounds live in build/a64/schedule.rs. */

/* _helios_mont4 register map:
   x0   z: result pointer (live throughout)
   x1   x pointer on entry; then per-round scratch: b_i, then m
   x2   y pointer, walked one limb per round by post-index
   x3   consts pointer on entry; then (as w3) the round counter
   x4   accumulator t0 (shifts down one word per reduction row)
   x5   accumulator t1
   x6   accumulator t2
   x7   accumulator t3
   x8   accumulator t4 (carry word)
   x9   a0 (x limb 0, loaded once); result scratch in the epilogue
   x10  a1; result scratch
   x11  a2; result scratch
   x12  a3; result scratch
   x13  p0
   x14  p1
   x15  p2
   x16  p3
   x17  -p^-1 mod 2^64; borrow scratch in the epilogue
   x19  column word 0 of the current row (callee-saved, spilled)
   x20  column word 1
   x21  column word 2
   x22  column word 3
   x23  column word 4
*/
    .text
    .align 3
    .globl _helios_mont4
_helios_mont4:
    stp x19, x20, [sp, #-48]!
    stp x21, x22, [sp, #16]
    str x23, [sp, #32]

    ldp x9, x10, [x1]                  /* a0, a1 */
    ldp x11, x12, [x1, #16]            /* a2, a3 */
    ldp x13, x14, [x3]                 /* p0, p1 */
    ldp x15, x16, [x3, #16]            /* p2, p3 */
    ldr x17, [x3, #32]                 /* -p^-1 mod 2^64 */
    mov x4, xzr                        /* t0 = 0 */
    mov x5, xzr                        /* t1 = 0 */
    mov x6, xzr                        /* t2 = 0 */
    mov x7, xzr                        /* t3 = 0 */
    mov x8, xzr                        /* t4 = 0 */

    mov w3, #4                         /* loop counter */
L_round:
    /* product row: t += a * b_i, one column chain via S */
    ldr x1, [x2], #8                   /* b_i (y walks one limb per round) */
    mul x19, x9, x1                    /* lo(a0*b_i) */
    umulh x20, x9, x1                  /* hi(a0*b_i) */
    mul x21, x10, x1                   /* lo(a1*b_i) */
    adds x20, x20, x21                 /* S1 += lo1 (opens the chain) */
    umulh x21, x10, x1                 /* hi(a1*b_i) */
    mul x22, x11, x1                   /* lo(a2*b_i) */
    adcs x21, x21, x22                 /* S2 = hi1 + lo2 */
    umulh x22, x11, x1                 /* hi(a2*b_i) */
    mul x23, x12, x1                   /* lo(a3*b_i) */
    adcs x22, x22, x23                 /* S3 = hi2 + lo3 */
    umulh x23, x12, x1                 /* hi(a3*b_i) */
    cinc x23, x23, hs                  /* S4 = hi3 + chain carry (cannot wrap) */
    adds x4, x4, x19                   /* t0 += S0 (opens the accumulate chain) */
    adcs x5, x5, x20                   /* t1 += S1 */
    adcs x6, x6, x21                   /* t2 += S2 */
    adcs x7, x7, x22                   /* t3 += S3 */
    adc x8, x8, x23                    /* t4 += S4; t < 2^64 * 2^256, no carry out */
    /* reduction row: m cancels t0; dropping that zero word */
    /* and shifting down one word is the division by 2^64 */
    mul x1, x17, x4                    /* m = t0 * -p^-1 mod 2^64 */
    mul x19, x13, x1                   /* lo(p0*m) */
    umulh x20, x13, x1                 /* hi(p0*m) */
    mul x21, x14, x1                   /* lo(p1*m) */
    adds x20, x20, x21                 /* S1 += lo1 (opens the chain) */
    umulh x21, x14, x1                 /* hi(p1*m) */
    mul x22, x15, x1                   /* lo(p2*m) */
    adcs x21, x21, x22                 /* S2 = hi1 + lo2 */
    umulh x22, x15, x1                 /* hi(p2*m) */
    mul x23, x16, x1                   /* lo(p3*m) */
    adcs x22, x22, x23                 /* S3 = hi2 + lo3 */
    umulh x23, x16, x1                 /* hi(p3*m) */
    cinc x23, x23, hs                  /* S4 = hi3 + chain carry (cannot wrap) */
    cmn x4, x19                        /* t0 + S0 = 0 mod 2^64; keep only its carry */
    adcs x4, x5, x20                   /* t0 = t1 + S1 (shift down) */
    adcs x5, x6, x21                   /* t1 = t2 + S2 */
    adcs x6, x7, x22                   /* t2 = t3 + S3 */
    adcs x7, x8, x23                   /* t3 = t4 + S4 */
    cset x8, hs                        /* t4 = chain carry */
    subs w3, w3, #1
    b.ne L_round

    /* four CIOS rounds leave t < 2p: one branch-free conditional */
    /* subtraction produces the unique canonical residue */
    subs x9, x4, x13                   /* word 0 of t - p */
    sbcs x10, x5, x14                  /* word 1 */
    sbcs x11, x6, x15                  /* word 2 */
    sbcs x12, x7, x16                  /* word 3 */
    sbcs x17, x8, xzr                  /* consume t4; C = (t >= p) */
    csel x4, x9, x4, hs                /* no borrow: keep t - p */
    csel x5, x10, x5, hs
    csel x6, x11, x6, hs
    csel x7, x12, x7, hs
    stp x4, x5, [x0]                   /* z0, z1 */
    stp x6, x7, [x0, #16]              /* z2, z3 */

    ldr x23, [sp, #32]
    ldp x21, x22, [sp, #16]
    ldp x19, x20, [sp], #48
    ret
