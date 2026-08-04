/* @generated at build time by the helius-bn254 build script.
   Source of truth: crates/helius-bn254/build/schedule.rs (ADR 0001).
   Inspect a copy: HELIUS_DUMP_ASM=<absolute dir> cargo build.
   Verified by: tests/kernelgen_verify.rs (interpreter + determinism).

   helius_mont4_mul_x86: schedule bn254-mont4-mul-cios-dual-chain, 153 instructions, 763 bytes
   helius_mont4_sqr_x86: schedule bn254-mont4-sqr-cross-double, 150 instructions, 683 bytes
   helius_sos_x86: schedule bn254-sos-rolled-dual-chain, 128 instructions, 540 bytes
   helius_sosd2_small_x86: schedule bn254-sosd2-dual-lane-rolled, 193 instructions, 909 bytes
   helius_fp6_mul_x86: schedule bn254-fp6-mul-rolled-dual-lane-t6, 335 instructions, 1415 bytes
   helius_fp12_034_x86: schedule bn254-fp12-034-rolled-dual-lane-t6, 413 instructions, 1750 bytes
   helius_fp12_sqr_x86: schedule bn254-fp12-sqr-lazy-karatsuba-dblwidth, 700 instructions, 3071 bytes, 2072 rodata bytes
   helius_fp12_mul_x86: schedule bn254-fp12-mul-lazy-karatsuba-dblwidth, 650 instructions, 2860 bytes, 2256 rodata bytes
   helius_cyc_sqr_x86: schedule bn254-cyc-sqr-lazy-fp4-dblwidth, 479 instructions, 2098 bytes, 2928 rodata bytes
   helius_sosd6_x86: schedule bn254-sosd6-dual-lane-rolled-t6, 263 instructions, 1287 bytes

   System V AMD64; requires BMI2 (mulx) and ADX (adox/adcx).
   mont4 arguments: (z: *mut u64x4, x: *const u64x4, y: *const u64x4,
                     consts: *const { p: [u64; 4], neg_p_inv: u64 })
   sos arguments:   (z: *mut u64x4, pairs: *const *const u64,
                     t: u64 even pair count in 2..=10, consts as above);
   pairs holds 2t pointers a_0, b_0, ..., operands below or at p.
   sosd2_small arguments: (z: *mut u64x8 lane0 then lane1, x0, x1,
                     y0, y1: *const u64x4 at most p, consts as above);
   lane0 = (x0*y0 + x1*(p - y1))/R, lane1 = (x0*y1 + x1*y0)/R mod p,
   rolled rounds (op-cache-compact).
   fp6_mul arguments: (z: *mut u64x24, a, b: *const u64x24 in repr(C)
                       Fp6 order c0.re, c0.im, .., c2.im, all Fp < p;
                       consts: *const { p: [u64; 4], neg_p_inv: u64,
                       mu: u64 = floor(2^310/p) });
   z = a*b in Fp6 = Fp2[v]/(v^3 - (9+u)), all outputs canonical.
   fp12_034 arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)
                        Fp12 order (c0 then c1, each Fp6 as above),
                        z == f allowed; c: *const u64x24 = the sparse
                        coefficients c0, c3, c4 as contiguous Fp2s;
                        consts as fp6_mul);
   z = f * (c0 + c3*w + c4*v*w) in Fp12 = Fp6[w]/(w^2 - v), all Fp
   inputs canonical, outputs canonical (arkworks mul_by_034).
   fp12_sqr arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)
                        Fp12 order, z == f allowed; consts as
                        fp6_mul);
   z = f^2 via mcl's lazy double-width shape: 36 raw 4x4 products
   and 12 Montgomery reductions, cross terms held as 512-bit values
   mod p*2^256 (needs p < 2^254; BN254: yes), outputs canonical.
   fp12_mul arguments: (z: *mut u64x48, a, b: *const u64x48 in
                        repr(C) Fp12 order, z may alias a and/or b;
                        consts as fp6_mul);
   z = a*b via the same lazy shape: 54 raw 4x4 products and 12
   Montgomery reductions (3 Fp6Dbl mulPre + double-width mulVadd
   and Karatsuba assembly mod p*2^256), outputs canonical.
   cyc_sqr arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)
                       Fp12 order, z == f allowed; consts as
                       fp6_mul);
   z = the Granger-Scott cyclotomic square of f via three lazy Fp4
   squares (Fp2Dbl sqrPre complex method): 18 raw 4x4 products and
   12 Montgomery reductions, single-width z-combines; equals f^2
   exactly on the cyclotomic subgroup, and the composed formula
   bit for bit on any canonical input.
   sosd6 arguments: (z: *mut u64x8 lane0 then lane1, stage: *mut
                     u64x64 wrapper-built scratch, consts as mont4);
   stage: +0 the 24 x limbs transposed (x_i[j] at 8*(6j+i), operand
   order x00 x01 x10 x11 x20 x21), +192 five 64-byte y pair blocks
   [y00,y01] [y01,y00] [y10,y11] [y11,y10] [y20,y21]; the kernel
   overwrites the low vectors of blocks 1 and 3 with p - y01 and
   p - y11 in place. lane0 = (sum x_i0*y_i0 + x_i1*(p - y_i1))/R,
   lane1 = (sum x_i0*y_i1 + x_i1*y_i0)/R mod p, operands at most p,
   both lanes canonical.
   Valid for any 4x64 modulus with p < 2^62 * 2^192 (BN254: yes);
   carry-bound proofs live in build/schedule.rs. */

    .text
    .intel_syntax noprefix

/* helius_mont4_mul_x86 register map:
   rdi  z: result pointer (argument 1, live throughout)
   rsi  x pointer on entry; repointed at y after the operand load
   rdx  y pointer on entry; then the implicit mulx multiplicand
   rcx  consts pointer: p at +0..+24, -p^-1 at +32
   r8   a0 (x limb 0, loaded once)
   r9   a1
   r10  a2
   r11  a3
   r12  CIOS accumulator (rotates: t_k of round r is ACC[(r+k) % 5])
   r13  CIOS accumulator
   r14  CIOS accumulator
   r15  CIOS accumulator
   rbp  CIOS accumulator
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product
*/
    .p2align 4
    .globl helius_mont4_mul_x86
    .type helius_mont4_mul_x86, @function
helius_mont4_mul_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r8, [rsi]                      /* a0 */
    mov r9, [rsi + 8]                  /* a1 */
    mov r10, [rsi + 16]                /* a2 */
    mov r11, [rsi + 24]                /* a3 */
    mov rsi, rdx                       /* y pointer moves; rdx becomes the mulx multiplicand */

    /* round 0: t = a*b0, then cancel t0 */
    mov rdx, [rsi]                     /* b0 */
    mulx r13, r12, r8                  /* a0*b0 -> (t0, t1) */
    mulx r14, rax, r9                  /* a1*b0 -> (lo, t2) */
    add r13, rax                       /* t1 += lo(a1*b0) */
    mulx r15, rax, r10                 /* a2*b0 -> (lo, t3) */
    adc r14, rax                       /* t2 += lo(a2*b0) */
    mulx rbp, rax, r11                 /* a3*b0 -> (lo, t4) */
    adc r15, rax                       /* t3 += lo(a3*b0) */
    adc rbp, 0                         /* t4 += chain carry; hi(a3*b0) <= 2^64-2 so CF = 0 */
    xor rax, rax                       /* clear OF (adc left it undefined) before the dual chains */
    mov rdx, r12                       /* m0 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m0 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rcx]     /* m0*p0 -> (lo, hi) */
    adox r12, rax                      /* t0 += lo(m0*p0)   [value chain] */
    adcx r13, rbx                      /* t1 += hi(m0*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* m0*p1 -> (lo, hi) */
    adox r13, rax                      /* t1 += lo(m0*p1)   [value chain] */
    adcx r14, rbx                      /* t2 += hi(m0*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* m0*p2 -> (lo, hi) */
    adox r14, rax                      /* t2 += lo(m0*p2)   [value chain] */
    adcx r15, rbx                      /* t3 += hi(m0*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* m0*p3 -> (lo, hi) */
    adox r15, rax                      /* t3 += lo(m0*p3)   [value chain] */
    adcx rbp, rbx                      /* t4 += hi(m0*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rbp, rax                      /* close the value chain into t4 */

    /* round 1: t += a*b1, then cancel t0 */
    /* invariant: CF = OF = 0 (previous round closed both chains under the 2^320 bound) */
    mov rdx, [rsi + 8]                 /* b1 */
    mulx rbx, rax, r8                  /* a0*b1 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(a0*b1)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(a0*b1)   [carry chain] */
    mulx rbx, rax, r9                  /* a1*b1 -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(a1*b1)   [value chain] */
    adcx r15, rbx                      /* t2 += hi(a1*b1)   [carry chain] */
    mulx rbx, rax, r10                 /* a2*b1 -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(a2*b1)   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(a2*b1)   [carry chain] */
    mulx rbx, rax, r11                 /* a3*b1 -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(a3*b1)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(a3*b1)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    mov rdx, r13                       /* m1 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m1 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rcx]     /* m1*p0 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(m1*p0)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(m1*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* m1*p1 -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(m1*p1)   [value chain] */
    adcx r15, rbx                      /* t2 += hi(m1*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* m1*p2 -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(m1*p2)   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(m1*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* m1*p3 -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(m1*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m1*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */

    /* round 2: t += a*b2, then cancel t0 */
    /* invariant: CF = OF = 0 (previous round closed both chains under the 2^320 bound) */
    mov rdx, [rsi + 16]                /* b2 */
    mulx rbx, rax, r8                  /* a0*b2 -> (lo, hi) */
    adox r14, rax                      /* t0 += lo(a0*b2)   [value chain] */
    adcx r15, rbx                      /* t1 += hi(a0*b2)   [carry chain] */
    mulx rbx, rax, r9                  /* a1*b2 -> (lo, hi) */
    adox r15, rax                      /* t1 += lo(a1*b2)   [value chain] */
    adcx rbp, rbx                      /* t2 += hi(a1*b2)   [carry chain] */
    mulx rbx, rax, r10                 /* a2*b2 -> (lo, hi) */
    adox rbp, rax                      /* t2 += lo(a2*b2)   [value chain] */
    adcx r12, rbx                      /* t3 += hi(a2*b2)   [carry chain] */
    mulx rbx, rax, r11                 /* a3*b2 -> (lo, hi) */
    adox r12, rax                      /* t3 += lo(a3*b2)   [value chain] */
    adcx r13, rbx                      /* t4 += hi(a3*b2)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r13, rax                      /* close the value chain into t4 */
    mov rdx, r14                       /* m2 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m2 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rcx]     /* m2*p0 -> (lo, hi) */
    adox r14, rax                      /* t0 += lo(m2*p0)   [value chain] */
    adcx r15, rbx                      /* t1 += hi(m2*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* m2*p1 -> (lo, hi) */
    adox r15, rax                      /* t1 += lo(m2*p1)   [value chain] */
    adcx rbp, rbx                      /* t2 += hi(m2*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* m2*p2 -> (lo, hi) */
    adox rbp, rax                      /* t2 += lo(m2*p2)   [value chain] */
    adcx r12, rbx                      /* t3 += hi(m2*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* m2*p3 -> (lo, hi) */
    adox r12, rax                      /* t3 += lo(m2*p3)   [value chain] */
    adcx r13, rbx                      /* t4 += hi(m2*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r13, rax                      /* close the value chain into t4 */

    /* round 3: t += a*b3, then cancel t0 */
    /* invariant: CF = OF = 0 (previous round closed both chains under the 2^320 bound) */
    mov rdx, [rsi + 24]                /* b3 */
    mulx rbx, rax, r8                  /* a0*b3 -> (lo, hi) */
    adox r15, rax                      /* t0 += lo(a0*b3)   [value chain] */
    adcx rbp, rbx                      /* t1 += hi(a0*b3)   [carry chain] */
    mulx rbx, rax, r9                  /* a1*b3 -> (lo, hi) */
    adox rbp, rax                      /* t1 += lo(a1*b3)   [value chain] */
    adcx r12, rbx                      /* t2 += hi(a1*b3)   [carry chain] */
    mulx rbx, rax, r10                 /* a2*b3 -> (lo, hi) */
    adox r12, rax                      /* t2 += lo(a2*b3)   [value chain] */
    adcx r13, rbx                      /* t3 += hi(a2*b3)   [carry chain] */
    mulx rbx, rax, r11                 /* a3*b3 -> (lo, hi) */
    adox r13, rax                      /* t3 += lo(a3*b3)   [value chain] */
    adcx r14, rbx                      /* t4 += hi(a3*b3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r14, rax                      /* close the value chain into t4 */
    mov rdx, r15                       /* m3 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m3 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rcx]     /* m3*p0 -> (lo, hi) */
    adox r15, rax                      /* t0 += lo(m3*p0)   [value chain] */
    adcx rbp, rbx                      /* t1 += hi(m3*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* m3*p1 -> (lo, hi) */
    adox rbp, rax                      /* t1 += lo(m3*p1)   [value chain] */
    adcx r12, rbx                      /* t2 += hi(m3*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* m3*p2 -> (lo, hi) */
    adox r12, rax                      /* t2 += lo(m3*p2)   [value chain] */
    adcx r13, rbx                      /* t3 += hi(m3*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* m3*p3 -> (lo, hi) */
    adox r13, rax                      /* t3 += lo(m3*p3)   [value chain] */
    adcx r14, rbx                      /* t4 += hi(m3*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r14, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (final round closed both chains under the 2^320 bound) */

    /* final reduction: value < 2p, subtract p once if value >= p */
    mov r8, rbp                        /* keep-copy of word 0 */
    mov r9, r12                        /* keep-copy of word 1 */
    mov r10, r13                       /* keep-copy of word 2 */
    mov r11, r14                       /* keep-copy of word 3 */
    sub rbp, [rcx]                     /* word 0 -= p0 */
    sbb r12, [rcx + 8]                 /* word 1 -= p1 */
    sbb r13, [rcx + 16]                /* word 2 -= p2 */
    sbb r14, [rcx + 24]                /* word 3 -= p3 */
    cmovc rbp, r8                      /* borrow: value < p, keep word 0 */
    cmovc r12, r9                      /* borrow: value < p, keep word 1 */
    cmovc r13, r10                     /* borrow: value < p, keep word 2 */
    cmovc r14, r11                     /* borrow: value < p, keep word 3 */
    mov [rdi], rbp                     /* z0 */
    mov [rdi + 8], r12                 /* z1 */
    mov [rdi + 16], r13                /* z2 */
    mov [rdi + 24], r14                /* z3 */
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_mont4_mul_x86, . - helius_mont4_mul_x86

/* helius_mont4_sqr_x86 register map:
   rdi  z: result pointer (argument 1, live throughout)
   rsi  x pointer on entry; then cross-product word C6 / T6
   rdx  unused argument on entry; the implicit mulx multiplicand
   rcx  consts pointer: p at +0..+24, -p^-1 at +32
   r8   x0; then T0 (dies as round 0 cancels it)
   r9   x1; then high-half scratch of the reduction rows
   r10  x2; freed by the diagonal row
   r11  x3; freed by the diagonal row
   r12  cross-product word C1; then T1
   r13  cross-product word C2; then T2
   r14  cross-product word C3; then T3
   r15  cross-product word C4; then T4
   rbp  cross-product word C5; then T5
   rbx  doubling carry H; then T7
   rax  low half of the current product; zero for chain closes
*/
    .p2align 4
    .globl helius_mont4_sqr_x86
    .type helius_mont4_sqr_x86, @function
helius_mont4_sqr_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r8, [rsi]                      /* x0 */
    mov r9, [rsi + 8]                  /* x1 */
    mov r10, [rsi + 16]                /* x2 */
    mov r11, [rsi + 24]                /* x3 */

    /* cross products: C = sum of x_i*x_j (i < j), words C1..C6 */
    mov rdx, r8                        /* multiplicand <- x0 */
    mulx r15, r14, r11                 /* x0*x3 -> (C3, C4) */
    mulx rax, r13, r10                 /* x0*x2 -> (C2, hi) */
    add r14, rax                       /* C3 += hi(x0*x2) */
    mov rdx, r9                        /* multiplicand <- x1 */
    mulx rbp, rax, r11                 /* x1*x3 -> (lo, C5) */
    adc r15, rax                       /* C4 += lo(x1*x3) */
    adc rbp, 0                         /* C5 += chain carry; hi(x1*x3) <= 2^64-2 so CF = 0 */
    mulx rax, r12, r8                  /* x0*x1 -> (C1, hi) */
    add r13, rax                       /* C2 += hi(x0*x1)   [new chain] */
    mulx rbx, rax, r10                 /* x1*x2 -> (lo, hi) */
    adc r14, rax                       /* C3 += lo(x1*x2) */
    adc r15, rbx                       /* C4 += hi(x1*x2) */
    mov rdx, r11                       /* multiplicand <- x3 */
    mulx rsi, rax, r10                 /* x2*x3 -> (lo, C6) */
    adc rbp, rax                       /* C5 += lo(x2*x3) */
    adc rsi, 0                         /* C6 += chain carry; hi(x2*x3) <= 2^64-2 so CF = 0 */

    /* double the cross words: T channel = 2C, carry bit lands in H */
    xor rbx, rbx                       /* H = 0; also clears CF for the doubling chain */
    add r12, r12                       /* C1 *= 2 */
    adc r13, r13                       /* C2 *= 2 */
    adc r14, r14                       /* C3 *= 2 */
    adc r15, r15                       /* C4 *= 2 */
    adc rbp, rbp                       /* C5 *= 2 */
    adc rsi, rsi                       /* C6 *= 2 */
    adc rbx, rbx                       /* H = carry shifted out of 2*C6 */

    /* fold the diagonal squares: T = 2C + sum of x_i^2 * 2^(128i) */
    mov rdx, r8                        /* multiplicand <- x0 (r8 freed for T0) */
    mulx rax, r8, rdx                  /* x0^2 -> (T0, hi) */
    add r12, rax                       /* T1 = 2C1 + hi(x0^2) */
    mov rdx, r9                        /* multiplicand <- x1 (register freed) */
    mulx r9, rax, rdx                  /* x1^2 -> (lo, hi) */
    adc r13, rax                       /* T2 += lo(x1^2) */
    adc r14, r9                        /* T3 += hi(x1^2) */
    mov rdx, r10                       /* multiplicand <- x2 (register freed) */
    mulx r10, rax, rdx                 /* x2^2 -> (lo, hi) */
    adc r15, rax                       /* T4 += lo(x2^2) */
    adc rbp, r10                       /* T5 += hi(x2^2) */
    mov rdx, r11                       /* multiplicand <- x3 (register freed) */
    mulx r11, rax, rdx                 /* x3^2 -> (lo, hi) */
    adc rsi, rax                       /* T6 += lo(x3^2) */
    adc rbx, r11                       /* T7 = H + hi(x3^2); x^2 < 2^512 so CF = 0 */

    /* Montgomery reduction: four cancel rows over the 8-word square */
    xor rax, rax                       /* clear OF (adc left it undefined) before the dual chains */
    mov rdx, r8                        /* m0 multiplicand <- t0 */
    mulx r9, rdx, qword ptr [rcx + 32] /* m0 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx r9, rax, qword ptr [rcx]      /* m0*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m0*p0)   [value chain] */
    adcx r12, r9                       /* t1 += hi(m0*p0)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 8]  /* m0*p1 -> (lo, hi) */
    adox r12, rax                      /* t1 += lo(m0*p1)   [value chain] */
    adcx r13, r9                       /* t2 += hi(m0*p1)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 16] /* m0*p2 -> (lo, hi) */
    adox r13, rax                      /* t2 += lo(m0*p2)   [value chain] */
    adcx r14, r9                       /* t3 += hi(m0*p2)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 24] /* m0*p3 -> (lo, hi) */
    adox r14, rax                      /* t3 += lo(m0*p3)   [value chain] */
    adcx r15, r9                       /* t4 += hi(m0*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r15, rax                      /* close the value chain into t4 */
    adcx rbp, rax                      /* T5 += carry-chain ripple */
    adox rbp, rax                      /* T5 += value-chain ripple */
    adcx rsi, rax                      /* T6 += carry-chain ripple */
    adox rsi, rax                      /* T6 += value-chain ripple */
    adcx rbx, rax                      /* T7 += carry-chain ripple */
    adox rbx, rax                      /* T7 += value-chain ripple */

    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2^511 bound) */
    mov rdx, r12                       /* m1 multiplicand <- t0 */
    mulx r9, rdx, qword ptr [rcx + 32] /* m1 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx r9, rax, qword ptr [rcx]      /* m1*p0 -> (lo, hi) */
    adox r12, rax                      /* t0 += lo(m1*p0)   [value chain] */
    adcx r13, r9                       /* t1 += hi(m1*p0)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 8]  /* m1*p1 -> (lo, hi) */
    adox r13, rax                      /* t1 += lo(m1*p1)   [value chain] */
    adcx r14, r9                       /* t2 += hi(m1*p1)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 16] /* m1*p2 -> (lo, hi) */
    adox r14, rax                      /* t2 += lo(m1*p2)   [value chain] */
    adcx r15, r9                       /* t3 += hi(m1*p2)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 24] /* m1*p3 -> (lo, hi) */
    adox r15, rax                      /* t3 += lo(m1*p3)   [value chain] */
    adcx rbp, r9                       /* t4 += hi(m1*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rbp, rax                      /* close the value chain into t4 */
    adcx rsi, rax                      /* T6 += carry-chain ripple */
    adox rsi, rax                      /* T6 += value-chain ripple */
    adcx rbx, rax                      /* T7 += carry-chain ripple */
    adox rbx, rax                      /* T7 += value-chain ripple */

    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2^511 bound) */
    mov rdx, r13                       /* m2 multiplicand <- t0 */
    mulx r9, rdx, qword ptr [rcx + 32] /* m2 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx r9, rax, qword ptr [rcx]      /* m2*p0 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(m2*p0)   [value chain] */
    adcx r14, r9                       /* t1 += hi(m2*p0)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 8]  /* m2*p1 -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(m2*p1)   [value chain] */
    adcx r15, r9                       /* t2 += hi(m2*p1)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 16] /* m2*p2 -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(m2*p2)   [value chain] */
    adcx rbp, r9                       /* t3 += hi(m2*p2)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 24] /* m2*p3 -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(m2*p3)   [value chain] */
    adcx rsi, r9                       /* t4 += hi(m2*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rsi, rax                      /* close the value chain into t4 */
    adcx rbx, rax                      /* T7 += carry-chain ripple */
    adox rbx, rax                      /* T7 += value-chain ripple */

    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2^511 bound) */
    mov rdx, r14                       /* m3 multiplicand <- t0 */
    mulx r9, rdx, qword ptr [rcx + 32] /* m3 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx r9, rax, qword ptr [rcx]      /* m3*p0 -> (lo, hi) */
    adox r14, rax                      /* t0 += lo(m3*p0)   [value chain] */
    adcx r15, r9                       /* t1 += hi(m3*p0)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 8]  /* m3*p1 -> (lo, hi) */
    adox r15, rax                      /* t1 += lo(m3*p1)   [value chain] */
    adcx rbp, r9                       /* t2 += hi(m3*p1)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 16] /* m3*p2 -> (lo, hi) */
    adox rbp, rax                      /* t2 += lo(m3*p2)   [value chain] */
    adcx rsi, r9                       /* t3 += hi(m3*p2)   [carry chain] */
    mulx r9, rax, qword ptr [rcx + 24] /* m3*p3 -> (lo, hi) */
    adox rsi, rax                      /* t3 += lo(m3*p3)   [value chain] */
    adcx rbx, r9                       /* t4 += hi(m3*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rbx, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (last row closed at T7 under the 2^511 bound) */

    /* final reduction: value < 2p, subtract p once if value >= p */
    mov r8, r15                        /* keep-copy of word 0 */
    mov r9, rbp                        /* keep-copy of word 1 */
    mov r10, rsi                       /* keep-copy of word 2 */
    mov r11, rbx                       /* keep-copy of word 3 */
    sub r15, [rcx]                     /* word 0 -= p0 */
    sbb rbp, [rcx + 8]                 /* word 1 -= p1 */
    sbb rsi, [rcx + 16]                /* word 2 -= p2 */
    sbb rbx, [rcx + 24]                /* word 3 -= p3 */
    cmovc r15, r8                      /* borrow: value < p, keep word 0 */
    cmovc rbp, r9                      /* borrow: value < p, keep word 1 */
    cmovc rsi, r10                     /* borrow: value < p, keep word 2 */
    cmovc rbx, r11                     /* borrow: value < p, keep word 3 */
    mov [rdi], r15                     /* z0 */
    mov [rdi + 8], rbp                 /* z1 */
    mov [rdi + 16], rsi                /* z2 */
    mov [rdi + 24], rbx                /* z3 */
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_mont4_sqr_x86, . - helius_mont4_sqr_x86

/* helius_sos_x86 register map:
   rdi  z on entry (spilled); then the current b_i pointer inside a row
   rsi  pair-table base (argument 2, live throughout)
   rdx  T (pair count) on entry; then the implicit mulx multiplicand
   rcx  consts pointer: p at +0..+24, -p^-1 at +32
   r8   accumulator t0
   r9   accumulator t1
   r10  accumulator t2
   r11  accumulator t3
   r12  accumulator t4
   r13  accumulator t5 (top carry word)
   r14  byte offset 8j of the round's source limb; epilogue scratch
   r15  pair-table cursor; epilogue scratch
   rbp  pair-table end (rsi + 16T)
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product
*/
    .p2align 4
    .globl helius_sos_x86
    .type helius_sos_x86, @function
helius_sos_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    /* table end = pairs + 16T; T arrives in rdx (2 pointers/pair) */
    mov rbp, rdx                       /* T */
    add rbp, rbp                       /* 2T */
    add rbp, rbp                       /* 4T */
    add rbp, rbp                       /* 8T */
    add rbp, rbp                       /* 16T */
    add rbp, rsi                       /* pair-table end */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    xor r14, r14                       /* byte offset of the round's source limb: 8j = 0 */

.Lsos_round:
    /* product rows: t += a_i[j] * b_i, two pairs per iteration */
    mov r15, rsi                       /* rewind the pair-table cursor */
.Lsos_pair:
    mov rdi, [r15]                     /* a_i pointer */
    mov rdx, [rdi + r14]               /* a_i[j], the row multiplicand */
    mov rdi, [r15 + 8]                 /* b_i pointer */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rdi]     /* a_i[j]*b_i[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(a_i[j]*b_i[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(a_i[j]*b_i[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* a_i[j]*b_i[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(a_i[j]*b_i[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(a_i[j]*b_i[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* a_i[j]*b_i[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(a_i[j]*b_i[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(a_i[j]*b_i[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* a_i[j]*b_i[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(a_i[j]*b_i[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(a_i[j]*b_i[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    /* second pair of the iteration */
    mov rdi, [r15 + 16]                /* a_{i+1} pointer */
    mov rdx, [rdi + r14]               /* a_{i+1}[j] */
    mov rdi, [r15 + 24]                /* b_{i+1} pointer */
    xor rax, rax                       /* flag-cutting re-seed: without it the row serializes on the previous row's closes */
    mulx rbx, rax, qword ptr [rdi]     /* a_{i+1}[j]*b_{i+1}[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(a_{i+1}[j]*b_{i+1}[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(a_{i+1}[j]*b_{i+1}[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* a_{i+1}[j]*b_{i+1}[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(a_{i+1}[j]*b_{i+1}[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(a_{i+1}[j]*b_{i+1}[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* a_{i+1}[j]*b_{i+1}[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(a_{i+1}[j]*b_{i+1}[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(a_{i+1}[j]*b_{i+1}[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* a_{i+1}[j]*b_{i+1}[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(a_{i+1}[j]*b_{i+1}[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(a_{i+1}[j]*b_{i+1}[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    add r15, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, rbp                       /* back-edge test */
    jne .Lsos_pair
    /* cancel row: m = t0 * -p^-1, then t += m*p zeroes t0 */
    mov rdx, r8                        /* m multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m = t0 * -p^-1 mod 2^64 (hi half discarded) */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rcx]     /* m*p[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m*p[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m*p[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* m*p[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m*p[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m*p[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* m*p[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m*p[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m*p[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* m*p[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m*p[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m*p[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    /* invariant: r8 = 0 (the Montgomery factor cancels the low word) */
    /* shift down one word: the canceled zero word drops */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lsos_round

    /* invariant: r12 = 0 (final value < 3p < 2^256 fits four words) */
    pop rdi
    /* final reduction: value < 3p, subtract p at most twice */
    mov rdx, r8                        /* pass 0: keep-copy of word 0 */
    mov rbx, r9                        /* pass 0: keep-copy of word 1 */
    mov r14, r10                       /* pass 0: keep-copy of word 2 */
    mov r15, r11                       /* pass 0: keep-copy of word 3 */
    sub r8, [rcx]                      /* word 0 -= p0 */
    sbb r9, [rcx + 8]                  /* word 1 -= p1 */
    sbb r10, [rcx + 16]                /* word 2 -= p2 */
    sbb r11, [rcx + 24]                /* word 3 -= p3 */
    cmovc r8, rdx                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, r14                     /* borrow: value < p, keep word 2 */
    cmovc r11, r15                     /* borrow: value < p, keep word 3 */
    mov rdx, r8                        /* pass 1: keep-copy of word 0 */
    mov rbx, r9                        /* pass 1: keep-copy of word 1 */
    mov r14, r10                       /* pass 1: keep-copy of word 2 */
    mov r15, r11                       /* pass 1: keep-copy of word 3 */
    sub r8, [rcx]                      /* word 0 -= p0 */
    sbb r9, [rcx + 8]                  /* word 1 -= p1 */
    sbb r10, [rcx + 16]                /* word 2 -= p2 */
    sbb r11, [rcx + 24]                /* word 3 -= p3 */
    cmovc r8, rdx                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, r14                     /* borrow: value < p, keep word 2 */
    cmovc r11, r15                     /* borrow: value < p, keep word 3 */
    mov [rdi], r8                      /* z0 */
    mov [rdi + 8], r9                  /* z1 */
    mov [rdi + 16], r10                /* z2 */
    mov [rdi + 24], r11                /* z3 */
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_sos_x86, . - helius_sos_x86

/* helius_sosd2_small_x86 register map:
   rdi  z on entry (spilled); lane1 top accumulator; z again at the end
   rsi  x0 pointer on entry; then reloaded pointer scratch
   rdx  x1 pointer on entry (spilled); the implicit mulx multiplicand
   rcx  y0 pointer on entry; then the round cursor (byte offset 8j)
   r8   y1 pointer on entry (spilled); then lane0 accumulator t0
   r9   consts pointer on entry (spilled); then lane0 accumulator t1
   r10  lane0 accumulator t2
   r11  lane0 accumulator t3
   r12  lane0 accumulator t4 (top word)
   r13  lane1 accumulator u0
   r14  lane1 accumulator u1
   r15  lane1 accumulator u2
   rbp  lane1 accumulator u3
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product; prologue scratch
*/
    .p2align 4
    .globl helius_sosd2_small_x86
    .type helius_sosd2_small_x86, @function
helius_sosd2_small_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104
    /* frame: ny1 +0..24, y0 copy +32..56, x0/x1/y1/z/consts pointers +64..96 */
    mov [rsp + 88], rdi                /* spill z */
    mov [rsp + 72], rdx                /* spill the x1 pointer */
    mov [rsp + 80], r8                 /* spill the y1 pointer */
    mov [rsp + 64], rsi                /* spill the x0 pointer */
    mov [rsp + 96], r9                 /* spill the consts pointer */
    /* copy y0 into the frame: two rows per round read it via rsp */
    mov rax, [rcx]                     /* y0[0] */
    mov rbx, [rcx + 8]                 /* y0[1] */
    mov r10, [rcx + 16]                /* y0[2] */
    mov r11, [rcx + 24]                /* y0[3] */
    mov [rsp + 32], rax                /* y0[0] */
    mov [rsp + 40], rbx                /* y0[1] */
    mov [rsp + 48], r10                /* y0[2] */
    mov [rsp + 56], r11                /* y0[3] */
    /* ny1 = p - y1: lane0's subtracted term enters as the negp image */
    mov rax, [r9]                      /* p0 */
    mov rbx, [r9 + 8]                  /* p1 */
    mov r10, [r9 + 16]                 /* p2 */
    mov r11, [r9 + 24]                 /* p3 */
    sub rax, [r8]                      /* p0 - y1[0] */
    sbb rbx, [r8 + 8]                  /* p1 - y1[1] */
    sbb r10, [r8 + 16]                 /* p2 - y1[2] */
    sbb r11, [r8 + 24]                 /* p3 - y1[3] */
    mov [rsp], rax                     /* ny1[0] */
    mov [rsp + 8], rbx                 /* ny1[1] */
    mov [rsp + 16], r10                /* ny1[2] */
    mov [rsp + 24], r11                /* ny1[3] */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* u0 = 0 */
    xor r14, r14                       /* u1 = 0 */
    xor r15, r15                       /* u2 = 0 */
    xor rbp, rbp                       /* u3 = 0 */
    xor rdi, rdi                       /* u4 = 0 */
    xor rcx, rcx                       /* byte offset of the round's source limb: 8j = 0 */

.Lsosd2_round:
    /* product rows: both lanes, sharing each multiplicand load */
    mov rsi, [rsp + 64]                /* x0 pointer */
    mov rdx, [rsi + rcx]               /* x0[j], the row multiplicand */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rsp + 32] /* x0[j]*y0[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x0[j]*y0[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x0[j]*y0[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 40] /* x0[j]*y0[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x0[j]*y0[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x0[j]*y0[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 48] /* x0[j]*y0[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x0[j]*y0[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x0[j]*y0[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 56] /* x0[j]*y0[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x0[j]*y0[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x0[j]*y0[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into the top word */
    /* invariant: CF = OF = 0 (in-round peak < 3p*2^64 < 2^320 keeps the top word from wrapping) */
    mov rsi, [rsp + 80]                /* y1 pointer */
    mulx rbx, rax, qword ptr [rsi]     /* x0[j]*y1[0] -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(x0[j]*y1[0])   [value chain] */
    adcx r14, rbx                      /* t1 += hi(x0[j]*y1[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 8] /* x0[j]*y1[1] -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(x0[j]*y1[1])   [value chain] */
    adcx r15, rbx                      /* t2 += hi(x0[j]*y1[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 16] /* x0[j]*y1[2] -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(x0[j]*y1[2])   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(x0[j]*y1[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 24] /* x0[j]*y1[3] -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(x0[j]*y1[3])   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(x0[j]*y1[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into the top word */
    /* invariant: CF = OF = 0 (in-round peak < 3p*2^64 < 2^320 keeps the top word from wrapping) */
    mov rsi, [rsp + 72]                /* x1 pointer */
    mov rdx, [rsi + rcx]               /* x1[j] */
    mulx rbx, rax, qword ptr [rsp]     /* x1[j]*ny1[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x1[j]*ny1[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x1[j]*ny1[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* x1[j]*ny1[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x1[j]*ny1[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x1[j]*ny1[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* x1[j]*ny1[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x1[j]*ny1[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x1[j]*ny1[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* x1[j]*ny1[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x1[j]*ny1[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x1[j]*ny1[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into the top word */
    /* invariant: CF = OF = 0 (in-round peak < 3p*2^64 < 2^320 keeps the top word from wrapping) */
    mulx rbx, rax, qword ptr [rsp + 32] /* x1[j]*y0[0] -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(x1[j]*y0[0])   [value chain] */
    adcx r14, rbx                      /* t1 += hi(x1[j]*y0[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 40] /* x1[j]*y0[1] -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(x1[j]*y0[1])   [value chain] */
    adcx r15, rbx                      /* t2 += hi(x1[j]*y0[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 48] /* x1[j]*y0[2] -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(x1[j]*y0[2])   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(x1[j]*y0[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 56] /* x1[j]*y0[3] -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(x1[j]*y0[3])   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(x1[j]*y0[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into the top word */
    /* invariant: CF = OF = 0 (in-round peak < 3p*2^64 < 2^320 keeps the top word from wrapping) */
    mov rsi, [rsp + 96]                /* consts pointer */
    /* lane0 cancel row */
    mov rdx, r8                        /* m multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsi + 32] /* m = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsi]     /* m*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m*p0)   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 8] /* m*p1 -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m*p1)   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 16] /* m*p2 -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m*p2)   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 24] /* m*p3 -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (cancel row closed both chains under the 2^320 bound) */
    /* lane1 cancel row */
    mov rdx, r13                       /* m multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsi + 32] /* m = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsi]     /* m*p0 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(m*p0)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(m*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 8] /* m*p1 -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(m*p1)   [value chain] */
    adcx r15, rbx                      /* t2 += hi(m*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 16] /* m*p2 -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(m*p2)   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(m*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsi + 24] /* m*p3 -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(m*p3)   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(m*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (cancel row closed both chains under the 2^320 bound) */
    /* invariant: r8 = 0 (the Montgomery factor cancels lane0's low word) */
    /* invariant: r13 = 0 (the Montgomery factor cancels lane1's low word) */
    /* shift both lanes down one word: the canceled zero drops */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    xor r12, r12                       /* t4 = 0 (CF/OF stay clear) */
    mov r13, r14                       /* u0 = u1 */
    mov r14, r15                       /* u1 = u2 */
    mov r15, rbp                       /* u2 = u3 */
    mov rbp, rdi                       /* u3 = u4 */
    xor rdi, rdi                       /* u4 = 0 (CF/OF stay clear) */
    add rcx, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 32                        /* back-edge test */
    jne .Lsosd2_round

    mov rcx, [rsp + 96]                /* consts pointer back in rcx */
    mov rdi, [rsp + 88]                /* reload z (lane1's zeroed top word) */
    /* final reduction per lane: value < 2p, subtract p once if >= p */
    mov rax, r8                        /* lane0: keep-copy of word 0 */
    mov rbx, r9                        /* lane0: keep-copy of word 1 */
    mov rsi, r10                       /* lane0: keep-copy of word 2 */
    mov rdx, r11                       /* lane0: keep-copy of word 3 */
    sub r8, [rcx]                      /* lane0: word 0 -= p0 */
    sbb r9, [rcx + 8]                  /* lane0: word 1 -= p1 */
    sbb r10, [rcx + 16]                /* lane0: word 2 -= p2 */
    sbb r11, [rcx + 24]                /* lane0: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: lane0 < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: lane0 < p, keep word 1 */
    cmovc r10, rsi                     /* borrow: lane0 < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: lane0 < p, keep word 3 */
    mov [rdi], r8                      /* z[0] */
    mov [rdi + 8], r9                  /* z[1] */
    mov [rdi + 16], r10                /* z[2] */
    mov [rdi + 24], r11                /* z[3] */
    mov rax, r13                       /* lane1: keep-copy of word 0 */
    mov rbx, r14                       /* lane1: keep-copy of word 1 */
    mov rsi, r15                       /* lane1: keep-copy of word 2 */
    mov rdx, rbp                       /* lane1: keep-copy of word 3 */
    sub r13, [rcx]                     /* lane1: word 0 -= p0 */
    sbb r14, [rcx + 8]                 /* lane1: word 1 -= p1 */
    sbb r15, [rcx + 16]                /* lane1: word 2 -= p2 */
    sbb rbp, [rcx + 24]                /* lane1: word 3 -= p3 */
    cmovc r13, rax                     /* borrow: lane1 < p, keep word 0 */
    cmovc r14, rbx                     /* borrow: lane1 < p, keep word 1 */
    cmovc r15, rsi                     /* borrow: lane1 < p, keep word 2 */
    cmovc rbp, rdx                     /* borrow: lane1 < p, keep word 3 */
    mov [rdi + 32], r13                /* z[4] */
    mov [rdi + 40], r14                /* z[5] */
    mov [rdi + 48], r15                /* z[6] */
    mov [rdi + 56], rbp                /* z[7] */
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_sosd2_small_x86, . - helius_sosd2_small_x86

/* helius_fp6_mul_x86 register map:
   rdi  z on entry (spilled as a z+128 cursor); row-base cursor PY in the main loops; z again per component
   rsi  a pointer on entry (spilled); prologue pointer scratch; then PA, the multiplicand cursor a + 8j + 64i
   rdx  b pointer on entry (prologue cursor); the implicit mulx multiplicand
   rcx  consts pointer on entry (prologue only); then the product-walk bound PY + 288
   r8   active-lane accumulator t0 (xi prologue: value limb 0)
   r9   active-lane accumulator t1
   r10  active-lane accumulator t2
   r11  active-lane accumulator t3
   r12  active-lane accumulator t4 (xi prologue: value top limb)
   r13  shared top word t5: only the active lane's in-round carries live there
   r14  xi outer cursor; then round cursor (byte offset 8j of the source limb)
   r15  xi inner cursor; then component cursor (y-window byte offset 0/96/192)
   rbp  lane cursor: y-row byte offset 0 (real lane) / 32 (imag lane)
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product; prologue scratch
*/
    .p2align 4
    .globl helius_fp6_mul_x86
    .type helius_fp6_mul_x86, @function
helius_fp6_mul_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 584
    /* frame: p +0, -p^-1 +32, mu +40, a +48, z cursor +56, dormant lane +64, y window +104 */
    mov [rsp + 48], rsi                /* spill the a pointer */
    mov rax, rdi                       /* z */
    add rax, 128                       /* z + 128: components are produced c2 first, cursor walks down */
    mov [rsp + 56], rax                /* z component cursor */
    mov r8, [rcx]                      /* p0 (kept live through the b copy) */
    mov r9, [rcx + 8]                  /* p1 (kept live through the b copy) */
    mov r10, [rcx + 16]                /* p2 (kept live through the b copy) */
    mov r11, [rcx + 24]                /* p3 (kept live through the b copy) */
    mov [rsp], r8                      /* p0: cancel rows address the frame as a consts table */
    mov [rsp + 8], r9                  /* p1: cancel rows address the frame as a consts table */
    mov [rsp + 16], r10                /* p2: cancel rows address the frame as a consts table */
    mov [rsp + 24], r11                /* p3: cancel rows address the frame as a consts table */
    mov rax, [rcx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    mov rax, [rcx + 40]                /* mu = floor(2^310/p) */
    mov [rsp + 40], rax                /* mu */

    /* copy b into the y window: source walks b0 b1 b2, blocks walk B0 B1 B2 down */
    mov rsi, rdx
    add rsi, 192                       /* source end (three Fp2 components) */
    mov rdi, rsp
    add rdi, 296                       /* first destination block */
.Lfp6_bcopy:
    mov rax, [rdx]                     /* b_i.re[0] */
    mov rbx, [rdx + 8]                 /* b_i.re[1] */
    mov r12, [rdx + 16]                /* b_i.re[2] */
    mov r13, [rdx + 24]                /* b_i.re[3] */
    mov [rdi + 32], rax                /* block re[0] */
    mov [rdi + 40], rbx                /* block re[1] */
    mov [rdi + 48], r12                /* block re[2] */
    mov [rdi + 56], r13                /* block re[3] */
    mov rax, [rdx + 32]                /* b_i.im[0] */
    mov rbx, [rdx + 40]                /* b_i.im[1] */
    mov r12, [rdx + 48]                /* b_i.im[2] */
    mov r13, [rdx + 56]                /* b_i.im[3] */
    mov [rdi + 64], rax                /* block im[0] */
    mov [rdi + 72], rbx                /* block im[1] */
    mov [rdi + 80], r12                /* block im[2] */
    mov [rdi + 88], r13                /* block im[3] */
    /* negp row: the subtracted imag term enters as p - im */
    mov rax, r8                        /* p0 */
    mov rbx, r9                        /* p1 */
    mov r12, r10                       /* p2 */
    mov r13, r11                       /* p3 */
    sub rax, [rdx + 32]                /* p0 - b_i.im[0] */
    sbb rbx, [rdx + 40]                /* p1 - b_i.im[1] */
    sbb r12, [rdx + 48]                /* p2 - b_i.im[2] */
    sbb r13, [rdx + 56]                /* p3 - b_i.im[3] */
    mov [rdi], rax                     /* block negp[0] */
    mov [rdi + 8], rbx                 /* block negp[1] */
    mov [rdi + 16], r12                /* block negp[2] */
    mov [rdi + 24], r13                /* block negp[3] */
    add rdi, -96                       /* next block */
    add rdx, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rdx, rsi                       /* back-edge test */
    jne .Lfp6_bcopy

    /* xi scaling: X2 = xi*b2 from B2, then X1 = xi*b1 from B1 */
    xor r14, r14                       /* outer cursor: first source block (+0) then second (+96) */
.Lfp6_xi:
    xor r15, r15                       /* inner cursor: real output (+0) then imag (+32) */
.Lfp6_xi_val:
    /* C row = [PC]: negp(im) for re = 9re - im, re for im = 9im + re; A row = [PC + 32] */
    mov rsi, rsp
    add rsi, r14                       /* + source block */
    add rsi, r15                       /* + pass */
    add rsi, 104                       /* PC */
    mov rdi, rsi
    add rdi, 320                       /* output row: each X row sits 320 bytes above its C row */
    mov r8, [rsi + 32]                 /* A[0] */
    mov r9, [rsi + 40]                 /* A[1] */
    mov r10, [rsi + 48]                /* A[2] */
    mov r11, [rsi + 56]                /* A[3] */
    xor r12, r12                       /* top limb; also clears CF/OF for the doubling chains */
    add r8, r8                         /* 2A[0] */
    adc r9, r9                         /* 2A[1] */
    adc r10, r10                       /* 2A[2] */
    adc r11, r11                       /* 2A[3] */
    adc r12, r12                       /* 2A[4] */
    add r8, r8                         /* 4A[0] */
    adc r9, r9                         /* 4A[1] */
    adc r10, r10                       /* 4A[2] */
    adc r11, r11                       /* 4A[3] */
    adc r12, r12                       /* 4A[4] */
    add r8, r8                         /* 8A[0] */
    adc r9, r9                         /* 8A[1] */
    adc r10, r10                       /* 8A[2] */
    adc r11, r11                       /* 8A[3] */
    adc r12, r12                       /* 8A[4] */
    /* 9A = 8A + A, then + C: value = 9A + C < 10p < 2^257 */
    add r8, [rsi + 32]                 /* += A[0] */
    adc r9, [rsi + 40]                 /* += A[1] */
    adc r10, [rsi + 48]                /* += A[2] */
    adc r11, [rsi + 56]                /* += A[3] */
    adc r12, 0                         /* 9A < 9p keeps the top limb below 2^61 */
    add r8, [rsi]                      /* += C[0] */
    adc r9, [rsi + 8]                  /* += C[1] */
    adc r10, [rsi + 16]                /* += C[2] */
    adc r11, [rsi + 24]                /* += C[3] */
    adc r12, 0                         /* value < 10p < 2^257: top limb is 0 or 1 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov rbx, r12                       /* E builds from the top limbs */
    shld rbx, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx rcx, rax, rbx                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx rbx, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r13, rcx, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add rcx, rbx                       /* l1 += h0 */
    mulx rbx, rbp, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbp, r13                       /* l2 += h1 */
    mulx r13, rdx, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rdx, rbx                       /* l3 += h2 */
    adc r13, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, rcx                        /* limb 1 */
    sbb r10, rbp                       /* limb 2 */
    sbb r11, rdx                       /* limb 3 */
    sbb r12, r13                       /* limb 4 */
    /* invariant: r12 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction reaches canonical (< 1.33p < 2p) */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rbx, r9                        /* keep-copy of limb 1 */
    mov rcx, r10                       /* keep-copy of limb 2 */
    mov rbp, r11                       /* keep-copy of limb 3 */
    sub r8, [rsp]                      /* limb 0 -= p0 */
    sbb r9, [rsp + 8]                  /* limb 1 -= p1 */
    sbb r10, [rsp + 16]                /* limb 2 -= p2 */
    sbb r11, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep limb 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep limb 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep limb 2 */
    cmovc r11, rbp                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r8                      /* X row limb 0 */
    mov [rdi + 8], r9                  /* X row limb 1 */
    mov [rdi + 16], r10                /* X row limb 2 */
    mov [rdi + 24], r11                /* X row limb 3 */
    add r15, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 64                        /* back-edge test */
    jne .Lfp6_xi_val
    /* negp row of the X block just written: p - x.im (x canonical) */
    mov rsi, rsp
    add rsi, r14                       /* + source block offset */
    add rsi, 392                       /* X block of this pass's source */
    mov r8, [rsp]                      /* p0 */
    mov r9, [rsp + 8]                  /* p1 */
    mov r10, [rsp + 16]                /* p2 */
    mov r11, [rsp + 24]                /* p3 */
    sub r8, [rsi + 64]                 /* p0 - x.im[0] */
    sbb r9, [rsi + 72]                 /* p1 - x.im[1] */
    sbb r10, [rsi + 80]                /* p2 - x.im[2] */
    sbb r11, [rsi + 88]                /* p3 - x.im[3] */
    mov [rsi], r8                      /* X negp[0] */
    mov [rsi + 8], r9                  /* X negp[1] */
    mov [rsi + 16], r10                /* X negp[2] */
    mov [rsi + 24], r11                /* X negp[3] */
    add r14, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp r14, 192                       /* back-edge test */
    jne .Lfp6_xi

    /* components c2, c1, c0 = consecutive 3-block windows of [B2, B1, B0, X2, X1] */
    xor r15, r15                       /* component cursor: window byte offset */
.Lfp6_comp:
    /* both lanes start at zero: registers (imag) and dormant frame (real) */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    mov [rsp + 64], r8                 /* dormant word 0 = 0 */
    mov [rsp + 72], r9                 /* dormant word 1 = 0 */
    mov [rsp + 80], r10                /* dormant word 2 = 0 */
    mov [rsp + 88], r11                /* dormant word 3 = 0 */
    mov [rsp + 96], r12                /* dormant word 4 = 0 */
    xor r14, r14                       /* round cursor: byte offset 8j of the source limb */
.Lfp6_round:
    xor rbp, rbp                       /* lane cursor: real rows (+0) first, then imag (+32) */
.Lfp6_lane:
    /* invariant: r13 = 0 (the shared top word is clear between lane blocks) */
    /* swap the active and dormant lanes through rbx */
    mov rbx, [rsp + 64]                /* dormant word */
    mov [rsp + 64], r8                 /* spill the active word */
    mov r8, rbx                        /* activate */
    mov rbx, [rsp + 72]                /* dormant word */
    mov [rsp + 72], r9                 /* spill the active word */
    mov r9, rbx                        /* activate */
    mov rbx, [rsp + 80]                /* dormant word */
    mov [rsp + 80], r10                /* spill the active word */
    mov r10, rbx                       /* activate */
    mov rbx, [rsp + 88]                /* dormant word */
    mov [rsp + 88], r11                /* spill the active word */
    mov r11, rbx                       /* activate */
    mov rbx, [rsp + 96]                /* dormant word */
    mov [rsp + 96], r12                /* spill the active word */
    mov r12, rbx                       /* activate */
    mov rsi, [rsp + 48]                /* a */
    add rsi, r14                       /* PA = a + 8j */
    mov rdi, rsp
    add rdi, r15                       /* + window */
    add rdi, rbp                       /* + lane row offset */
    add rdi, 104                       /* PY: the first product's block, lane-adjusted */
    mov rcx, rdi
    add rcx, 288                       /* window end: three products */
.Lfp6_prod:
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mov rdx, [rsi]                     /* a_i.re[j] */
    mulx rbx, rax, qword ptr [rdi + 32] /* a_i.re[j]*row0[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(a_i.re[j]*row0[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(a_i.re[j]*row0[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 40] /* a_i.re[j]*row0[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(a_i.re[j]*row0[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(a_i.re[j]*row0[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 48] /* a_i.re[j]*row0[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(a_i.re[j]*row0[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(a_i.re[j]*row0[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 56] /* a_i.re[j]*row0[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(a_i.re[j]*row0[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(a_i.re[j]*row0[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    mov rdx, [rsi + 32]                /* a_i.im[j] */
    mulx rbx, rax, qword ptr [rdi]     /* a_i.im[j]*row1[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(a_i.im[j]*row1[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(a_i.im[j]*row1[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* a_i.im[j]*row1[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(a_i.im[j]*row1[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(a_i.im[j]*row1[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* a_i.im[j]*row1[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(a_i.im[j]*row1[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(a_i.im[j]*row1[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* a_i.im[j]*row1[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(a_i.im[j]*row1[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(a_i.im[j]*row1[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    add rsi, 64                        /* next a component */
    add rdi, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp rdi, rcx                       /* back-edge test */
    jne .Lfp6_prod
    /* cancel row: m = t0 * -p^-1, then t += m*p zeroes t0 */
    mov rdx, r8                        /* m multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m = t0 * -p^-1 mod 2^64 (hi half discarded) */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rsp]     /* m*p[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m*p[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m*p[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m*p[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m*p[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m*p[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m*p[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m*p[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m*p[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m*p[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m*p[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m*p[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    /* invariant: r8 = 0 (the Montgomery factor cancels the low word) */
    /* shift down one word: the canceled zero word drops */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add rbp, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, 64                        /* back-edge test */
    jne .Lfp6_lane
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lfp6_round
    /* component epilogue: imag lane in registers, real lane dormant */
    mov rdi, [rsp + 56]                /* z component cursor */
    /* invariant: r12 = 0 (imag final value < 2.135p < 2^256 fits four words) */
    /* final reduction: value < 2.135p, subtract p at most twice */
    mov rax, r8                        /* imag pass 0: keep-copy of word 0 */
    mov rbx, r9                        /* imag pass 0: keep-copy of word 1 */
    mov rcx, r10                       /* imag pass 0: keep-copy of word 2 */
    mov rdx, r11                       /* imag pass 0: keep-copy of word 3 */
    sub r8, [rsp]                      /* imag: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* imag: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* imag: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* imag: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov rax, r8                        /* imag pass 1: keep-copy of word 0 */
    mov rbx, r9                        /* imag pass 1: keep-copy of word 1 */
    mov rcx, r10                       /* imag pass 1: keep-copy of word 2 */
    mov rdx, r11                       /* imag pass 1: keep-copy of word 3 */
    sub r8, [rsp]                      /* imag: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* imag: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* imag: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* imag: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov [rdi + 32], r8                 /* z component imag limb 0 */
    mov [rdi + 40], r9                 /* z component imag limb 1 */
    mov [rdi + 48], r10                /* z component imag limb 2 */
    mov [rdi + 56], r11                /* z component imag limb 3 */
    mov r8, [rsp + 64]                 /* real lane word 0 */
    mov r9, [rsp + 72]                 /* real lane word 1 */
    mov r10, [rsp + 80]                /* real lane word 2 */
    mov r11, [rsp + 88]                /* real lane word 3 */
    mov r12, [rsp + 96]                /* real lane word 4 */
    /* invariant: r12 = 0 (real final value < 2.135p < 2^256 fits four words) */
    /* final reduction: value < 2.135p, subtract p at most twice */
    mov rax, r8                        /* real pass 0: keep-copy of word 0 */
    mov rbx, r9                        /* real pass 0: keep-copy of word 1 */
    mov rcx, r10                       /* real pass 0: keep-copy of word 2 */
    mov rdx, r11                       /* real pass 0: keep-copy of word 3 */
    sub r8, [rsp]                      /* real: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* real: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* real: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* real: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov rax, r8                        /* real pass 1: keep-copy of word 0 */
    mov rbx, r9                        /* real pass 1: keep-copy of word 1 */
    mov rcx, r10                       /* real pass 1: keep-copy of word 2 */
    mov rdx, r11                       /* real pass 1: keep-copy of word 3 */
    sub r8, [rsp]                      /* real: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* real: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* real: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* real: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov [rdi], r8                      /* z component real limb 0 */
    mov [rdi + 8], r9                  /* z component real limb 1 */
    mov [rdi + 16], r10                /* z component real limb 2 */
    mov [rdi + 24], r11                /* z component real limb 3 */
    add rdi, -64
    mov [rsp + 56], rdi                /* z cursor steps down to the next component */
    add r15, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 288                       /* back-edge test */
    jne .Lfp6_comp
    add rsp, 584
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_fp6_mul_x86, . - helius_fp6_mul_x86

/* helius_fp12_034_x86 register map:
   rdi  z on entry (spilled); staging cursor; PY per product; z component pointer in the epilogue
   rsi  f pointer on entry (g staging cursor); then PA, the g multiplicand base rsp + G + 8*limb
   rdx  coefficient pointer on entry (staging cursor); the implicit mulx multiplicand
   rcx  consts pointer on entry (prologue only); then the product-walk cursor over the table
   r8   active-lane accumulator t0 (xi prologue: value limb 0)
   r9   active-lane accumulator t1
   r10  active-lane accumulator t2
   r11  active-lane accumulator t3
   r12  active-lane accumulator t4 (xi prologue: value top limb)
   r13  shared top word t5: only the active lane's in-round carries live there
   r14  xi outer cursor; then round cursor (byte offset 8j of the source limb)
   r15  component cursor 64*j over the six W-power outputs
   rbp  duplicate-slot cursor in the prologue; then lane cursor: 0 (real) / 32 (imag)
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product; g-offset and prologue scratch
*/
    .p2align 4
    .globl helius_fp12_034_x86
    .type helius_fp12_034_x86, @function
helius_fp12_034_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1400
    /* frame: p +0, -p^-1 +32, mu +40, z +48, walk bound +56, dormant lane +64, product table +104, y blocks +152, g array +632 */
    mov [rsp + 48], rdi                /* spill z */
    mov r8, [rcx]                      /* p0 (kept live through the coefficient copy) */
    mov r9, [rcx + 8]                  /* p1 (kept live through the coefficient copy) */
    mov r10, [rcx + 16]                /* p2 (kept live through the coefficient copy) */
    mov r11, [rcx + 24]                /* p3 (kept live through the coefficient copy) */
    mov [rsp], r8                      /* p0: cancel rows address the frame as a consts table */
    mov [rsp + 8], r9                  /* p1: cancel rows address the frame as a consts table */
    mov [rsp + 16], r10                /* p2: cancel rows address the frame as a consts table */
    mov [rsp + 24], r11                /* p3: cancel rows address the frame as a consts table */
    mov rax, [rcx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    mov rax, [rcx + 40]                /* mu = floor(2^310/p) */
    mov [rsp + 40], rax                /* mu */

    /* product-walk table: g fields and the C0 entry are fixed, the */
    /* two wrap y fields (e1, e2) are rewritten per component */
    xor rax, rax
    mov [rsp + 104], rax               /* e0.y: the C0 block (+0) */
    mov [rsp + 112], rax               /* e0.g: g_j (+0) */
    add rax, 192
    mov [rsp + 128], rax               /* e1.g: g_{j+3} (+192) */
    add rax, 128
    mov [rsp + 144], rax               /* e2.g: g_{j+5} (+320) */
    mov rax, rsp
    add rax, 152
    mov [rsp + 56], rax                /* product-walk bound: the table end address */

    /* g array: f in W-power order g = a0, b0, a1, b1, a2, b2, slots */
    /* duplicated so the wrap products index without mod; f is fully */
    /* staged before any z store, which is what makes z == f safe */
    mov rax, rsi
    add rax, 192                       /* a-half end */
    mov r14, rsi
    add r14, 192                       /* b-half source cursor */
    mov rdi, rsp
    add rdi, 632                       /* g slot cursor (one a/b slot pair per iteration) */
    mov rbp, rdi
    add rbp, 384                       /* duplicate cursor: slot k + 6 */
.Lf034_g:
    mov rbx, [rsi]                     /* a_t[0] */
    mov rcx, [rsi + 8]                 /* a_t[1] */
    mov r12, [rsi + 16]                /* a_t[2] */
    mov r13, [rsi + 24]                /* a_t[3] */
    mov [rdi], rbx                     /* g slot limb 0 */
    mov [rdi + 8], rcx                 /* g slot limb 1 */
    mov [rdi + 16], r12                /* g slot limb 2 */
    mov [rdi + 24], r13                /* g slot limb 3 */
    mov [rbp], rbx                     /* duplicate slot */
    mov [rbp + 8], rcx                 /* duplicate slot */
    mov [rbp + 16], r12                /* duplicate slot */
    mov [rbp + 24], r13                /* duplicate slot */
    mov rbx, [rsi + 32]                /* a_t[4] */
    mov rcx, [rsi + 40]                /* a_t[5] */
    mov r12, [rsi + 48]                /* a_t[6] */
    mov r13, [rsi + 56]                /* a_t[7] */
    mov [rdi + 32], rbx                /* g slot limb 4 */
    mov [rdi + 40], rcx                /* g slot limb 5 */
    mov [rdi + 48], r12                /* g slot limb 6 */
    mov [rdi + 56], r13                /* g slot limb 7 */
    mov [rbp + 32], rbx                /* duplicate slot */
    mov [rbp + 40], rcx                /* duplicate slot */
    mov [rbp + 48], r12                /* duplicate slot */
    mov [rbp + 56], r13                /* duplicate slot */
    mov rbx, [r14]                     /* b_t[0] */
    mov rcx, [r14 + 8]                 /* b_t[1] */
    mov r12, [r14 + 16]                /* b_t[2] */
    mov r13, [r14 + 24]                /* b_t[3] */
    mov [rdi + 64], rbx                /* g slot limb 0 */
    mov [rdi + 72], rcx                /* g slot limb 1 */
    mov [rdi + 80], r12                /* g slot limb 2 */
    mov [rdi + 88], r13                /* g slot limb 3 */
    mov [rbp + 64], rbx                /* duplicate slot */
    mov [rbp + 72], rcx                /* duplicate slot */
    mov [rbp + 80], r12                /* duplicate slot */
    mov [rbp + 88], r13                /* duplicate slot */
    mov rbx, [r14 + 32]                /* b_t[4] */
    mov rcx, [r14 + 40]                /* b_t[5] */
    mov r12, [r14 + 48]                /* b_t[6] */
    mov r13, [r14 + 56]                /* b_t[7] */
    mov [rdi + 96], rbx                /* g slot limb 4 */
    mov [rdi + 104], rcx               /* g slot limb 5 */
    mov [rdi + 112], r12               /* g slot limb 6 */
    mov [rdi + 120], r13               /* g slot limb 7 */
    mov [rbp + 96], rbx                /* duplicate slot */
    mov [rbp + 104], rcx               /* duplicate slot */
    mov [rbp + 112], r12               /* duplicate slot */
    mov [rbp + 120], r13               /* duplicate slot */
    add r14, 64
    add rdi, 128                       /* next slot pair */
    add rbp, 128
    add rsi, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rsi, rax                       /* back-edge test */
    jne .Lf034_g

    /* stage the coefficient blocks: c0 -> C0, c3 -> C3, c4 -> C4 */
    mov rsi, rdx
    add rsi, 192                       /* source end (three Fp2 components) */
    mov rdi, rsp
    add rdi, 152                       /* first destination block */
.Lf034_c:
    mov rax, [rdx]                     /* c_i.re[0] */
    mov rbx, [rdx + 8]                 /* c_i.re[1] */
    mov r12, [rdx + 16]                /* c_i.re[2] */
    mov r13, [rdx + 24]                /* c_i.re[3] */
    mov [rdi + 32], rax                /* block re[0] */
    mov [rdi + 40], rbx                /* block re[1] */
    mov [rdi + 48], r12                /* block re[2] */
    mov [rdi + 56], r13                /* block re[3] */
    mov rax, [rdx + 32]                /* c_i.im[0] */
    mov rbx, [rdx + 40]                /* c_i.im[1] */
    mov r12, [rdx + 48]                /* c_i.im[2] */
    mov r13, [rdx + 56]                /* c_i.im[3] */
    mov [rdi + 64], rax                /* block im[0] */
    mov [rdi + 72], rbx                /* block im[1] */
    mov [rdi + 80], r12                /* block im[2] */
    mov [rdi + 88], r13                /* block im[3] */
    /* negp row: the subtracted imag term enters as p - im */
    mov rax, r8                        /* p0 */
    mov rbx, r9                        /* p1 */
    mov r12, r10                       /* p2 */
    mov r13, r11                       /* p3 */
    sub rax, [rdx + 32]                /* p0 - c_i.im[0] */
    sbb rbx, [rdx + 40]                /* p1 - c_i.im[1] */
    sbb r12, [rdx + 48]                /* p2 - c_i.im[2] */
    sbb r13, [rdx + 56]                /* p3 - c_i.im[3] */
    mov [rdi], rax                     /* block negp[0] */
    mov [rdi + 8], rbx                 /* block negp[1] */
    mov [rdi + 16], r12                /* block negp[2] */
    mov [rdi + 24], r13                /* block negp[3] */
    add rdi, 96                        /* next block */
    add rdx, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rdx, rsi                       /* back-edge test */
    jne .Lf034_c

    /* xi scaling: X3 = xi*c3 from C3, then X4 = xi*c4 from C4 */
    xor r14, r14                       /* outer cursor: first source block (+0) then second (+96) */
.Lf034_xi:
    xor r15, r15                       /* inner cursor: real output (+0) then imag (+32) */
.Lf034_xi_val:
    /* C row = [PC]: negp(im) for re = 9re - im, re for im = 9im + re; A row = [PC + 32] */
    mov rsi, rsp
    add rsi, r14                       /* + source block */
    add rsi, r15                       /* + pass */
    add rsi, 248                       /* PC */
    mov rdi, rsi
    add rdi, 224                       /* output row: each X row sits 224 bytes above its C row */
    mov r8, [rsi + 32]                 /* A[0] */
    mov r9, [rsi + 40]                 /* A[1] */
    mov r10, [rsi + 48]                /* A[2] */
    mov r11, [rsi + 56]                /* A[3] */
    xor r12, r12                       /* top limb; also clears CF/OF for the doubling chains */
    add r8, r8                         /* 2A[0] */
    adc r9, r9                         /* 2A[1] */
    adc r10, r10                       /* 2A[2] */
    adc r11, r11                       /* 2A[3] */
    adc r12, r12                       /* 2A[4] */
    add r8, r8                         /* 4A[0] */
    adc r9, r9                         /* 4A[1] */
    adc r10, r10                       /* 4A[2] */
    adc r11, r11                       /* 4A[3] */
    adc r12, r12                       /* 4A[4] */
    add r8, r8                         /* 8A[0] */
    adc r9, r9                         /* 8A[1] */
    adc r10, r10                       /* 8A[2] */
    adc r11, r11                       /* 8A[3] */
    adc r12, r12                       /* 8A[4] */
    /* 9A = 8A + A, then + C: value = 9A + C < 10p < 2^257 */
    add r8, [rsi + 32]                 /* += A[0] */
    adc r9, [rsi + 40]                 /* += A[1] */
    adc r10, [rsi + 48]                /* += A[2] */
    adc r11, [rsi + 56]                /* += A[3] */
    adc r12, 0                         /* 9A < 9p keeps the top limb below 2^61 */
    add r8, [rsi]                      /* += C[0] */
    adc r9, [rsi + 8]                  /* += C[1] */
    adc r10, [rsi + 16]                /* += C[2] */
    adc r11, [rsi + 24]                /* += C[3] */
    adc r12, 0                         /* value < 10p < 2^257: top limb is 0 or 1 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov rbx, r12                       /* E builds from the top limbs */
    shld rbx, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx rcx, rax, rbx                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx rbx, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r13, rcx, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add rcx, rbx                       /* l1 += h0 */
    mulx rbx, rbp, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbp, r13                       /* l2 += h1 */
    mulx r13, rdx, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rdx, rbx                       /* l3 += h2 */
    adc r13, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, rcx                        /* limb 1 */
    sbb r10, rbp                       /* limb 2 */
    sbb r11, rdx                       /* limb 3 */
    sbb r12, r13                       /* limb 4 */
    /* invariant: r12 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction reaches canonical (< 1.33p < 2p) */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rbx, r9                        /* keep-copy of limb 1 */
    mov rcx, r10                       /* keep-copy of limb 2 */
    mov rbp, r11                       /* keep-copy of limb 3 */
    sub r8, [rsp]                      /* limb 0 -= p0 */
    sbb r9, [rsp + 8]                  /* limb 1 -= p1 */
    sbb r10, [rsp + 16]                /* limb 2 -= p2 */
    sbb r11, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep limb 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep limb 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep limb 2 */
    cmovc r11, rbp                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r8                      /* X row limb 0 */
    mov [rdi + 8], r9                  /* X row limb 1 */
    mov [rdi + 16], r10                /* X row limb 2 */
    mov [rdi + 24], r11                /* X row limb 3 */
    add r15, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 64                        /* back-edge test */
    jne .Lf034_xi_val
    /* negp row of the X block just written: p - x.im (x canonical) */
    mov rsi, rsp
    add rsi, r14                       /* + source block offset */
    add rsi, 440                       /* X block of this pass's source */
    mov r8, [rsp]                      /* p0 */
    mov r9, [rsp + 8]                  /* p1 */
    mov r10, [rsp + 16]                /* p2 */
    mov r11, [rsp + 24]                /* p3 */
    sub r8, [rsi + 64]                 /* p0 - x.im[0] */
    sbb r9, [rsi + 72]                 /* p1 - x.im[1] */
    sbb r10, [rsi + 80]                /* p2 - x.im[2] */
    sbb r11, [rsi + 88]                /* p3 - x.im[3] */
    mov [rsi], r8                      /* X negp[0] */
    mov [rsi + 8], r9                  /* X negp[1] */
    mov [rsi + 16], r10                /* X negp[2] */
    mov [rsi + 24], r11                /* X negp[3] */
    add r14, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp r14, 192                       /* back-edge test */
    jne .Lf034_xi

    /* components h_j, j = 0..5 in the W-power basis: */
    /* h_j = g_j*C0 + g_{j+5}*C3' + g_{j+3}*C4' (wrap xi via X blocks) */
    xor r15, r15                       /* component cursor: 64*j */
.Lf034_comp:
    /* wrap selection: e1.y = X4 exactly for j < 3, e2.y = X3 exactly at j = 0 */
    xor rax, rax
    add rax, 192                       /* the C4 block offset, also the C -> X block delta */
    mov rbx, rax
    add rbx, rax                       /* X4 block offset (+384) */
    mov rcx, r15
    add rcx, -192                      /* CF set exactly when 64j >= 192, i.e. j >= 3 */
    cmovc rbx, rax                     /* j >= 3: plain C4 */
    mov [rsp + 120], rbx               /* e1.y */
    xor rbx, rbx
    add rbx, 96                        /* C3 block offset */
    mov rcx, rbx
    add rcx, rax                       /* X3 block offset (+288) */
    xor rax, rax
    sub rax, r15                       /* CF set exactly when j > 0 */
    cmovc rcx, rbx                     /* j > 0: plain C3 */
    mov [rsp + 136], rcx               /* e2.y */
    /* both lanes start at zero: registers (imag) and dormant frame (real) */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    mov [rsp + 64], r8                 /* dormant word 0 = 0 */
    mov [rsp + 72], r9                 /* dormant word 1 = 0 */
    mov [rsp + 80], r10                /* dormant word 2 = 0 */
    mov [rsp + 88], r11                /* dormant word 3 = 0 */
    mov [rsp + 96], r12                /* dormant word 4 = 0 */
    xor r14, r14                       /* round cursor: byte offset 8j of the source limb */
.Lf034_round:
    xor rbp, rbp                       /* lane cursor: real rows (+0) first, then imag (+32) */
.Lf034_lane:
    /* invariant: r13 = 0 (the shared top word is clear between lane blocks) */
    /* swap the active and dormant lanes through rbx */
    mov rbx, [rsp + 64]                /* dormant word */
    mov [rsp + 64], r8                 /* spill the active word */
    mov r8, rbx                        /* activate */
    mov rbx, [rsp + 72]                /* dormant word */
    mov [rsp + 72], r9                 /* spill the active word */
    mov r9, rbx                        /* activate */
    mov rbx, [rsp + 80]                /* dormant word */
    mov [rsp + 80], r10                /* spill the active word */
    mov r10, rbx                       /* activate */
    mov rbx, [rsp + 88]                /* dormant word */
    mov [rsp + 88], r11                /* spill the active word */
    mov r11, rbx                       /* activate */
    mov rbx, [rsp + 96]                /* dormant word */
    mov [rsp + 96], r12                /* spill the active word */
    mov r12, rbx                       /* activate */
    mov rsi, rsp
    add rsi, r15                       /* + 64j: the g_j slot */
    add rsi, r14                       /* + 8*limb */
    add rsi, 632                       /* PA: the g multiplicand base */
    mov rcx, rsp
    add rcx, 104                       /* product-walk cursor */
.Lf034_prod:
    mov rdi, rsp
    add rdi, rbp                       /* + lane row offset */
    add rdi, 152
    add rdi, [rcx]                     /* PY: this product's y block */
    mov rbx, [rcx + 8]                 /* g offset of this product */
    mov rdx, [rsi + rbx]               /* g.re[limb] */
    xor rax, rax                       /* re-seed CF = OF = 0 (pointer math clobbered flags) */
    mulx rbx, rax, qword ptr [rdi + 32] /* g.re*row0[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(g.re*row0[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(g.re*row0[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 40] /* g.re*row0[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(g.re*row0[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(g.re*row0[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 48] /* g.re*row0[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(g.re*row0[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(g.re*row0[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 56] /* g.re*row0[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(g.re*row0[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(g.re*row0[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    mov rbx, [rcx + 8]                 /* g offset again (rbx was the row's hi scratch) */
    add rbx, 32                        /* the imag limbs sit 32 bytes up */
    mov rdx, [rsi + rbx]               /* g.im[limb] */
    xor rax, rax                       /* re-seed CF = OF = 0 (add clobbered flags) */
    mulx rbx, rax, qword ptr [rdi]     /* g.im*row1[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(g.im*row1[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(g.im*row1[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* g.im*row1[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(g.im*row1[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(g.im*row1[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* g.im*row1[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(g.im*row1[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(g.im*row1[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* g.im*row1[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(g.im*row1[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(g.im*row1[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    add rcx, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, [rsp + 56]                /* back-edge test */
    jne .Lf034_prod
    /* cancel row: m = t0 * -p^-1, then t += m*p zeroes t0 */
    mov rdx, r8                        /* m multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m = t0 * -p^-1 mod 2^64 (hi half discarded) */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rsp]     /* m*p[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m*p[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m*p[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m*p[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m*p[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m*p[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m*p[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m*p[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m*p[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m*p[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m*p[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m*p[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (in-round peak < (T+1)*p*2^64 < 2^325 keeps t5 from wrapping) */
    /* invariant: r8 = 0 (the Montgomery factor cancels the low word) */
    /* shift down one word: the canceled zero word drops */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add rbp, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, 64                        /* back-edge test */
    jne .Lf034_lane
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lf034_round
    /* component epilogue: W order back to repr(C), z + 192*(j&1) + 64*(j>>1) */
    xor rcx, rcx                       /* zero source for the shift */
    mov rax, r15
    shr rax, 7                         /* j >> 1 */
    shld rax, rcx, 6                   /* A = 64*(j >> 1) */
    mov rbx, r15
    sub rbx, rax
    sub rbx, rax                       /* 64j - 128*(j >> 1) = 64*(j&1) */
    mov rcx, rbx
    add rbx, rbx
    add rbx, rcx                       /* 192*(j&1) */
    add rbx, rax                       /* the component's z offset */
    mov rdi, [rsp + 48]                /* z */
    add rdi, rbx                       /* z component pointer */
    add rdi, 32                        /* imag half first: the store cursor walks down */
    /* imag lane from the registers, then the dormant real lane */
    xor rbp, rbp                       /* output-lane counter */
.Lf034_out:
    /* invariant: r12 = 0 (final value < 2.135p < 2^256 fits four words) */
    /* final reduction: value < 2.135p, subtract p at most twice */
    mov rax, r8                        /* lane pass 0: keep-copy of word 0 */
    mov rbx, r9                        /* lane pass 0: keep-copy of word 1 */
    mov rcx, r10                       /* lane pass 0: keep-copy of word 2 */
    mov rdx, r11                       /* lane pass 0: keep-copy of word 3 */
    sub r8, [rsp]                      /* lane: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* lane: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* lane: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* lane: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov rax, r8                        /* lane pass 1: keep-copy of word 0 */
    mov rbx, r9                        /* lane pass 1: keep-copy of word 1 */
    mov rcx, r10                       /* lane pass 1: keep-copy of word 2 */
    mov rdx, r11                       /* lane pass 1: keep-copy of word 3 */
    sub r8, [rsp]                      /* lane: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* lane: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* lane: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* lane: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: value < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: value < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: value < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: value < p, keep word 3 */
    mov [rdi], r8                      /* z component lane limb 0 */
    mov [rdi + 8], r9                  /* z component lane limb 1 */
    mov [rdi + 16], r10                /* z component lane limb 2 */
    mov [rdi + 24], r11                /* z component lane limb 3 */
    /* reload the dormant (real) lane; the last pass reloads dead words */
    mov r8, [rsp + 64]                 /* real lane word 0 */
    mov r9, [rsp + 72]                 /* real lane word 1 */
    mov r10, [rsp + 80]                /* real lane word 2 */
    mov r11, [rsp + 88]                /* real lane word 3 */
    mov r12, [rsp + 96]                /* real lane word 4 */
    add rdi, -32                       /* step down to the real half */
    add rbp, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, 64                        /* back-edge test */
    jne .Lf034_out
    add r15, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 384                       /* back-edge test */
    jne .Lf034_comp
    add rsp, 1400
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_fp12_034_x86, . - helius_fp12_034_x86

/* helius_fp12_sqr_x86 register map:
   rdi  z on entry (spilled); walk destination pointer in every table-driven pass
   rsi  f pointer on entry (staging source); walk source-1 pointer; mask scratch
   rdx  consts pointer on entry; the implicit mulx multiplicand; walk scratch
   rcx  walk source-2 pointer; product m-walk cursor; staging cursor
   r8   accumulator/value word 0
   r9   accumulator/value word 1
   r10  accumulator/value word 2
   r11  accumulator/value word 3
   r12  accumulator/value word 4
   r13  accumulator/value word 5; mu-reduction scratch
   r14  product round cursor (byte offset 8j); 8-limb value word 6
   r15  product block cursor 96k; 8-limb value word 7
   rbp  outer iteration cursor (ctx row address, spilled per phase); every walk's row cursor
   rax  low half of the current product; zero for chain closes; borrow mask
   rbx  high half of the current product; walk bound and half cursors
*/
    .p2align 4
    .globl helius_fp12_sqr_x86
    .type helius_fp12_sqr_x86, @function
helius_fp12_sqr_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 4544
    /* frame: p +0, -p^-1 +32, mu +40, z +48, loop bounds +56..96, ctx slots +104..152, xi scratch +152..320, t0/t1/V/U/y +320..1472, staged f +1472, operand sides +1856, products +3008, xi/neg scratch +4160 */
    mov [rsp + 48], rdi                /* spill z */
    mov rax, [rdx]                     /* p0 */
    mov [rsp], rax                     /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 8]                 /* p1 */
    mov [rsp + 8], rax                 /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 16]                /* p2 */
    mov [rsp + 16], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 24]                /* p3 */
    mov [rsp + 24], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    mov rax, [rdx + 40]                /* mu = floor(2^310/p) */
    mov [rsp + 40], rax                /* mu */
    lea rax, [rip + .Lfsq_tab]         /* walk tables */
    mov [rsp + 88], rax                /* table base */
    mov rbx, rax
    add rbx, 2000                      /* product m-walk end */
    mov [rsp + 96], rbx
    mov rbx, rax
    add rbx, 128                       /* ctx table end (two 64-byte rows) */
    mov [rsp + 56], rbx
    xor rax, rax
    mov [rsp + 192], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 200], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 208], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 216], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 224], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 232], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 240], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 248], rax               /* zero word (negation rows subtract from it) */

    /* stage f: all later reads are frame-relative, which is what */
    /* makes z == f safe (no f read after any z store) */
    mov rdi, rsp
    add rdi, 1472                      /* staging cursor */
    xor rcx, rcx                       /* 48 limbs, 4 per iteration */
.Lfsq_fst:
    mov r8, [rsi]                      /* f limb 0 */
    mov r9, [rsi + 8]                  /* f limb 1 */
    mov r10, [rsi + 16]                /* f limb 2 */
    mov r11, [rsi + 24]                /* f limb 3 */
    mov [rdi], r8                      /* staged */
    mov [rdi + 8], r9                  /* staged */
    mov [rdi + 16], r10                /* staged */
    mov [rdi + 24], r11                /* staged */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lfsq_fst

    /* outer loop: iteration 0 computes V = a*b (and prebuilds t0, t1), */
    /* iteration 1 computes U = t0*t1 (and prebuilds W = V*v + V, 2V) */
    mov rbp, [rsp + 88]                /* ctx cursor = first ctx row */
.Lfsq_iter:
    mov [rsp + 80], rbp                /* spill the outer cursor */
    mov rax, [rbp]                     /* ctx: xi site source */
    mov [rsp + 104], rax
    mov rax, [rbp + 8]                 /* ctx: xi site destination */
    mov [rsp + 112], rax
    mov rax, [rbp + 16]                /* ctx: x-side source */
    mov [rsp + 120], rax
    mov rax, [rbp + 24]                /* ctx: y-side source */
    mov [rsp + 128], rax
    mov rax, [rbp + 32]                /* ctx: reduction destination */
    mov [rsp + 136], rax
    mov rax, [rbp + 40]                /* ctx: modadd segment */
    mov [rsp + 144], rax
    /* xi site: (9*re - im, 9*im + re), subtraction via p - im */
    mov rsi, rsp
    add rsi, [rsp + 104]               /* site source Fp2 */
    mov rdi, rsp
    add rdi, [rsp + 112]               /* site destination Fp2 */
    mov r8, [rsp]                      /* p0 */
    mov r9, [rsp + 8]                  /* p1 */
    mov r10, [rsp + 16]                /* p2 */
    mov r11, [rsp + 24]                /* p3 */
    sub r8, [rsi + 32]                 /* p0 - im[0] */
    sbb r9, [rsi + 40]                 /* p1 - im[1] */
    sbb r10, [rsi + 48]                /* p2 - im[2] */
    sbb r11, [rsi + 56]                /* p3 - im[3] */
    /* invariant: CF = OF = 0 (im < p (canonical site): p - im cannot borrow) */
    mov [rsp + 152], r8                /* negp(im) */
    mov [rsp + 160], r9                /* negp(im) */
    mov [rsp + 168], r10               /* negp(im) */
    mov [rsp + 176], r11               /* negp(im) */
    xor rbx, rbx                       /* half cursor: re output (+0) then im (+32) */
.Lfsq_muxi:
    /* value = 9*X + Y: X = site half, Y = negp(im) for re, re for im */
    mov rcx, rsi
    add rcx, rbx                       /* X = site + half */
    mov rbp, rsp
    add rbp, 152                       /* Y candidate: negp(im) */
    xor rax, rax
    sub rax, rbx                       /* CF set exactly on the im half */
    cmovc rbp, rsi                     /* im half: Y = site.re */
    xor rdx, rdx
    add rdx, 9                         /* xi = 9 + u: the scale is one mulx row */
    mulx r13, r8, qword ptr [rcx]      /* 9*X[0] -> (v0, hi) */
    mulx r14, r9, qword ptr [rcx + 8]  /* 9*X[1] -> (v1, hi) */
    add r9, r13                        /* v1 += hi(9*X[0]) */
    mulx r13, r10, qword ptr [rcx + 16] /* 9*X[2] -> (v2, hi) */
    adc r10, r14                       /* v2 += hi(9*X[1]) */
    mulx r12, r11, qword ptr [rcx + 24] /* 9*X[3] -> (v3, v4) */
    adc r11, r13                       /* v3 += hi(9*X[2]) */
    adc r12, 0                         /* 9X < 9p: the chain closes into the top limb */
    add r8, [rbp]                      /* += Y[0] */
    adc r9, [rbp + 8]                  /* += Y[1] */
    adc r10, [rbp + 16]                /* += Y[2] */
    adc r11, [rbp + 24]                /* += Y[3] */
    adc r12, 0                         /* value < 10p < 2^257: top limb is at most 2 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov r13, r12                       /* E builds from the top limbs */
    shld r13, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx r14, rax, r13                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx r13, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r15, r14, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add r14, r13                       /* l1 += h0 */
    mulx r13, rbp, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbp, r15                       /* l2 += h1 */
    mulx r15, rcx, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rcx, r13                       /* l3 += h2 */
    adc r15, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, r14                        /* limb 1 */
    sbb r10, rbp                       /* limb 2 */
    sbb r11, rcx                       /* limb 3 */
    sbb r12, r15                       /* limb 4 */
    /* invariant: r12 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction reaches canonical (< 1.33p) */
    mov r13, rdi
    add r13, rbx                       /* output half */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rcx, r9                        /* keep-copy of limb 1 */
    mov rbp, r10                       /* keep-copy of limb 2 */
    mov rdx, r11                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rcx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rbp, [rsp + 16]                /* limb 2 -= p2 */
    sbb rdx, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r8                      /* borrow: value < p, keep limb 0 */
    cmovc rcx, r9                      /* borrow: value < p, keep limb 1 */
    cmovc rbp, r10                     /* borrow: value < p, keep limb 2 */
    cmovc rdx, r11                     /* borrow: value < p, keep limb 3 */
    mov [r13], rax                     /* out limb 0 */
    mov [r13 + 8], rcx                 /* out limb 1 */
    mov [r13 + 16], rbp                /* out limb 2 */
    mov [r13 + 24], rdx                /* out limb 3 */
    add rbx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbx, 64                        /* back-edge test */
    jne .Lfsq_muxi
    /* modular add walk: t0/t1 build (iteration 0), W and 2V (iteration 1) */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, [rsp + 144]               /* + this iteration's segment */
    mov rbx, rbp
    add rbx, 288                       /* segment end */
    mov [rsp + 64], rbx                /* walk bound */
.Lfsq_madd:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    add r8, [rcx]                      /* += s2 limb 0 */
    adc r9, [rcx + 8]                  /* += s2 limb 1 */
    adc r10, [rcx + 16]                /* += s2 limb 2 */
    adc r11, [rcx + 24]                /* += s2 limb 3 */
    /* invariant: CF = OF = 0 (s1 + s2 < 2p < 2^256: no carry out) */
    mov r12, r8                        /* keep-copy of limb 0 */
    mov r13, r9                        /* keep-copy of limb 1 */
    mov r14, r10                       /* keep-copy of limb 2 */
    mov r15, r11                       /* keep-copy of limb 3 */
    sub r12, [rsp]                     /* limb 0 -= p0 */
    sbb r13, [rsp + 8]                 /* limb 1 -= p1 */
    sbb r14, [rsp + 16]                /* limb 2 -= p2 */
    sbb r15, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r12, r8                      /* borrow: value < p, keep limb 0 */
    cmovc r13, r9                      /* borrow: value < p, keep limb 1 */
    cmovc r14, r10                     /* borrow: value < p, keep limb 2 */
    cmovc r15, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r12                     /* out limb 0 */
    mov [rdi + 8], r13                 /* out limb 1 */
    mov [rdi + 16], r14                /* out limb 2 */
    mov [rdi + 24], r15                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_madd
    /* stage the two operand sides (six blocks each: singles + sums) */
    xor rax, rax
    add rax, 1856
    mov [rsp + 184], rax               /* destination: x side first */
    mov rbx, rsp
    add rbx, 120                       /* side cursor walks the two source slots */
    mov rax, rbx
    add rax, 16
    mov [rsp + 64], rax                /* side bound */
.Lfsq_side:
    mov rsi, rsp
    add rsi, [rbx]                     /* side source (one Fp6) */
    mov rdi, rsp
    add rdi, [rsp + 184]               /* side destination */
    /* singles: copy each Fp2 and add its in-block s = re + im */
    xor rcx, rcx
.Lfsq_single:
    mov r8, [rsi]                      /* re[0] */
    mov r9, [rsi + 8]                  /* re[1] */
    mov r10, [rsi + 16]                /* re[2] */
    mov r11, [rsi + 24]                /* re[3] */
    mov r12, [rsi + 32]                /* im[0] */
    mov r13, [rsi + 40]                /* im[1] */
    mov r14, [rsi + 48]                /* im[2] */
    mov r15, [rsi + 56]                /* im[3] */
    mov [rdi], r8                      /* block re[0] */
    mov [rdi + 8], r9                  /* block re[1] */
    mov [rdi + 16], r10                /* block re[2] */
    mov [rdi + 24], r11                /* block re[3] */
    mov [rdi + 32], r12                /* block im[0] */
    mov [rdi + 40], r13                /* block im[1] */
    mov [rdi + 48], r14                /* block im[2] */
    mov [rdi + 56], r15                /* block im[3] */
    add r8, r12                        /* s = re + im, limb 0 */
    adc r9, r13                        /* limb 1 */
    adc r10, r14                       /* limb 2 */
    adc r11, r15                       /* limb 3 */
    /* invariant: CF = OF = 0 (re + im < 2p < 2^256: s fits four limbs) */
    mov [rdi + 64], r8                 /* block s[0] */
    mov [rdi + 72], r9                 /* block s[1] */
    mov [rdi + 80], r10                /* block s[2] */
    mov [rdi + 88], r11                /* block s[3] */
    add rsi, 64                        /* next source Fp2 */
    add rdi, 96                        /* next block */
    add rcx, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 192                       /* back-edge test */
    jne .Lfsq_single
    /* sums: whole-block adds (s-lanes add to the sums' s) */
    mov rdx, [rsp + 88]                /* table base */
    add rdx, 2000                      /* walk start */
    mov rax, rdx
    add rax, 72                        /* walk end */
    mov [rsp + 72], rax                /* walk bound */
.Lfsq_sums:
    mov rbp, rsp
    add rbp, [rsp + 184]               /* side base */
    mov rdi, rbp
    add rdi, [rdx]                     /* sum block */
    mov rsi, rbp
    add rsi, [rdx + 8]                 /* addend block A */
    mov rcx, rbp
    add rcx, [rdx + 16]                /* addend block B */
    xor rbp, rbp                       /* row cursor: re, im, s */
.Lfsq_sumrow:
    mov r8, [rsi]                      /* A limb 0 */
    mov r9, [rsi + 8]                  /* A limb 1 */
    mov r10, [rsi + 16]                /* A limb 2 */
    mov r11, [rsi + 24]                /* A limb 3 */
    add r8, [rcx]                      /* += B limb 0 */
    adc r9, [rcx + 8]                  /* += B limb 1 */
    adc r10, [rcx + 16]                /* += B limb 2 */
    adc r11, [rcx + 24]                /* += B limb 3 */
    mov [rdi], r8                      /* sum limb */
    mov [rdi + 8], r9                  /* sum limb */
    mov [rdi + 16], r10                /* sum limb */
    mov [rdi + 24], r11                /* sum limb */
    add rsi, 32
    add rcx, 32
    add rdi, 32
    add rbp, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, 96                        /* back-edge test */
    jne .Lfsq_sumrow
    add rdx, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rdx, [rsp + 72]                /* back-edge test */
    jne .Lfsq_sums
    mov rax, [rsp + 184]
    add rax, 576
    mov [rsp + 184], rax               /* destination: y side next */
    add rbx, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp rbx, [rsp + 64]                /* back-edge test */
    jne .Lfsq_side
    /* products: 6 blocks x 3 sub-products, rolled 4x4 mulpre rounds */
    xor r15, r15                       /* block cursor 96k */
.Lfsq_prod_k:
    mov rcx, [rsp + 88]
    add rcx, 1952                      /* sub-product walk */
.Lfsq_prod_m:
    mov rax, [rcx]                     /* operand sub-offset */
    mov rbx, [rcx + 8]                 /* destination sub-offset */
    mov rsi, rsp
    add rsi, r15
    add rsi, rax
    add rsi, 1856                      /* PA: x sub-row (the multiplicand) */
    mov rdi, rsp
    add rdi, r15
    add rdi, rax
    add rdi, 2432                      /* PY: y sub-row */
    mov rbp, rsp
    add rbp, r15
    add rbp, r15                       /* product regions stride 192 = 2*96k */
    add rbp, rbx
    add rbp, 3008                      /* PZ */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    xor r14, r14                       /* round cursor: byte offset 8j of the x limb */
.Lfsq_prod_j:
    mov rdx, [rsi + r14]               /* x[j], the row multiplicand */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rdi]     /* x[j]*y[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x[j]*y[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x[j]*y[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* x[j]*y[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x[j]*y[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x[j]*y[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* x[j]*y[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x[j]*y[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x[j]*y[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* x[j]*y[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x[j]*y[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x[j]*y[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (row peak < 2^257 window + 2^320 product < 2^321, far below the six-word 2^384) */
    mov [rbp], r8                      /* product limb j is final */
    add rbp, 8                         /* next output limb */
    /* shift down one word */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lfsq_prod_j
    mov [rbp], r8                      /* product limb 4 */
    mov [rbp + 8], r9                  /* product limb 5 */
    mov [rbp + 16], r10                /* product limb 6 */
    mov [rbp + 24], r11                /* product limb 7 */
    add rcx, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, [rsp + 96]                /* back-edge test */
    jne .Lfsq_prod_m
    add r15, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 576                       /* back-edge test */
    jne .Lfsq_prod_k
    /* double-width sub walk: Karatsuba assembly, cross terms, negations */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 848                       /* walk start */
    mov rax, rbp
    add rax, 768                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfsq_gsub:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* word 0 -= s2 */
    sbb r9, [rcx + 8]                  /* word 1 -= s2 */
    sbb r10, [rcx + 16]                /* word 2 -= s2 */
    sbb r11, [rcx + 24]                /* word 3 -= s2 */
    sbb r12, [rcx + 32]                /* word 4 -= s2 */
    sbb r13, [rcx + 40]                /* word 5 -= s2 */
    sbb r14, [rcx + 48]                /* word 6 -= s2 */
    sbb r15, [rcx + 56]                /* word 7 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r12, rbx                       /* borrow: high half += p, word 4 */
    adc r13, rdx                       /* word 5 */
    adc r14, rsi                       /* word 6 */
    adc r15, rax                       /* word 7 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], r12                /* dst word 4 */
    mov [rdi + 40], r13                /* dst word 5 */
    mov [rdi + 48], r14                /* dst word 6 */
    mov [rdi + 56], r15                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_gsub
    /* nine-fold walk: xi = 9 + u on 512-bit values, mu-canonical high */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 1616                      /* walk start */
    mov rax, rbp
    add rax, 96                        /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfsq_nine:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    xor rdx, rdx
    add rdx, 9                         /* 9 is the mulx multiplicand */
    /* low half: l = 9*xL + yL, carry limb l4 <= 10 */
    mulx r13, r8, qword ptr [rsi]      /* 9*x0 -> (l0, hi) */
    mulx r14, r9, qword ptr [rsi + 8]  /* 9*x1 -> (l1, hi) */
    add r9, r13                        /* l1 += hi(9*x0) */
    mulx r13, r10, qword ptr [rsi + 16] /* 9*x2 -> (l2, hi) */
    adc r10, r14                       /* l2 += hi(9*x1) */
    mulx r12, r11, qword ptr [rsi + 24] /* 9*x3 -> (l3, l4) */
    adc r11, r13                       /* l3 += hi(9*x2) */
    adc r12, 0                         /* 9*xL < 9*2^256: l4 closes the chain */
    add r8, [rcx]                      /* += y0 */
    adc r9, [rcx + 8]                  /* += y1 */
    adc r10, [rcx + 16]                /* += y2 */
    adc r11, [rcx + 24]                /* += y3 */
    adc r12, 0                         /* l4 <= 10 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    /* high half: v = 9*xH + yH + l4 < 10p (xH, yH < p) */
    mulx r13, r8, qword ptr [rsi + 32] /* 9*x4 -> (v0, hi) */
    mulx r14, r9, qword ptr [rsi + 40] /* 9*x5 -> (v1, hi) */
    add r9, r13                        /* v1 += hi(9*x4) */
    mulx r13, r10, qword ptr [rsi + 48] /* 9*x6 -> (v2, hi) */
    adc r10, r14                       /* v2 += hi(9*x5) */
    mulx r15, r11, qword ptr [rsi + 56] /* 9*x7 -> (v3, v4) */
    adc r11, r13                       /* v3 += hi(9*x6) */
    adc r15, 0                         /* 9*xH < 9p closes into v4 */
    add r8, r12                        /* += l4 */
    adc r9, 0                          /* ripple the l4 carry */
    adc r10, 0                         /* ripple the l4 carry */
    adc r11, 0                         /* ripple the l4 carry */
    adc r15, 0                         /* ripple the l4 carry */
    add r8, [rcx + 32]                 /* += y4 */
    adc r9, [rcx + 40]                 /* += y5 */
    adc r10, [rcx + 48]                /* += y6 */
    adc r11, [rcx + 56]                /* += y7 */
    adc r15, 0                         /* v < 10p < 2^257 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov r13, r15                       /* E builds from the top limbs */
    shld r13, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx r14, rax, r13                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx r13, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r12, r14, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add r14, r13                       /* l1 += h0 */
    mulx r13, rbx, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbx, r12                       /* l2 += h1 */
    mulx r12, rsi, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rsi, r13                       /* l3 += h2 */
    adc r12, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, r14                        /* limb 1 */
    sbb r10, rbx                       /* limb 2 */
    sbb r11, rsi                       /* limb 3 */
    sbb r15, r12                       /* limb 4 */
    /* invariant: r15 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction: the stored high half is canonical */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rbx, r9                        /* keep-copy of limb 1 */
    mov rcx, r10                       /* keep-copy of limb 2 */
    mov rsi, r11                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rcx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r8                      /* borrow: value < p, keep limb 0 */
    cmovc rbx, r9                      /* borrow: value < p, keep limb 1 */
    cmovc rcx, r10                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi + 32], rax                /* out limb 0 */
    mov [rdi + 40], rbx                /* out limb 1 */
    mov [rdi + 48], rcx                /* out limb 2 */
    mov [rdi + 56], rsi                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_nine
    /* double-width add walk: xi'd cross terms into the output lanes */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 1712                      /* walk start */
    mov rax, rbp
    add rax, 144                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfsq_gadd:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    add r8, [rcx]                      /* word 0 += s2 */
    adc r9, [rcx + 8]                  /* word 1 += s2 */
    adc r10, [rcx + 16]                /* word 2 += s2 */
    adc r11, [rcx + 24]                /* word 3 += s2 */
    adc r12, [rcx + 32]                /* word 4 += s2 */
    adc r13, [rcx + 40]                /* word 5 += s2 */
    adc r14, [rcx + 48]                /* word 6 += s2 */
    adc r15, [rcx + 56]                /* word 7 += s2 */
    /* invariant: CF = OF = 0 (sum of two sub-2^510 values < 2^511: no carry out) */
    /* high half >= p: subtract p once (sum < 2p*2^256) */
    mov rax, r12
    mov rbx, r13
    mov rdx, r14
    mov rcx, r15
    sub rax, [rsp]                     /* high word 0 - p0 */
    sbb rbx, [rsp + 8]                 /* high word 1 - p1 */
    sbb rdx, [rsp + 16]                /* high word 2 - p2 */
    sbb rcx, [rsp + 24]                /* high word 3 - p3 */
    cmovc rax, r12                     /* borrow: high < p, keep */
    cmovc rbx, r13
    cmovc rdx, r14
    cmovc rcx, r15
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], rax                /* dst word 4 */
    mov [rdi + 40], rbx                /* dst word 5 */
    mov [rdi + 48], rdx                /* dst word 6 */
    mov [rdi + 56], rcx                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_gadd
    /* Montgomery reduction walk: 6 coefficients, 4 cancel rows each */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 1856                      /* walk start */
    mov rax, rbp
    add rax, 96                        /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfsq_mod:
    mov rsi, rsp
    add rsi, [rbp]                     /* source T */
    mov rdi, rsp
    add rdi, [rsp + 136]               /* V or U base */
    add rdi, [rbp + 8]                 /* + coefficient offset */
    mov r8, [rsi]                      /* T0 */
    mov r9, [rsi + 8]                  /* T1 */
    mov r10, [rsi + 16]                /* T2 */
    mov r11, [rsi + 24]                /* T3 */
    mov r12, [rsi + 32]                /* T4 */
    mov r13, [rsi + 40]                /* T5 */
    mov r14, [rsi + 48]                /* T6 */
    mov r15, [rsi + 56]                /* T7 */
    xor rax, rax                       /* clear CF = OF before the dual chains */
    mov rdx, r8                        /* m0 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m0 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m0*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m0*p0)   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m0*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m0*p1 -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m0*p1)   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m0*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m0*p2 -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m0*p2)   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m0*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m0*p3 -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m0*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m0*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adcx r13, rax                      /* T5 += carry-chain ripple */
    adox r13, rax                      /* T5 += value-chain ripple */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r9                        /* m1 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m1 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m1*p0 -> (lo, hi) */
    adox r9, rax                       /* t0 += lo(m1*p0)   [value chain] */
    adcx r10, rbx                      /* t1 += hi(m1*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m1*p1 -> (lo, hi) */
    adox r10, rax                      /* t1 += lo(m1*p1)   [value chain] */
    adcx r11, rbx                      /* t2 += hi(m1*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m1*p2 -> (lo, hi) */
    adox r11, rax                      /* t2 += lo(m1*p2)   [value chain] */
    adcx r12, rbx                      /* t3 += hi(m1*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m1*p3 -> (lo, hi) */
    adox r12, rax                      /* t3 += lo(m1*p3)   [value chain] */
    adcx r13, rbx                      /* t4 += hi(m1*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r13, rax                      /* close the value chain into t4 */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r10                       /* m2 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m2 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m2*p0 -> (lo, hi) */
    adox r10, rax                      /* t0 += lo(m2*p0)   [value chain] */
    adcx r11, rbx                      /* t1 += hi(m2*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m2*p1 -> (lo, hi) */
    adox r11, rax                      /* t1 += lo(m2*p1)   [value chain] */
    adcx r12, rbx                      /* t2 += hi(m2*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m2*p2 -> (lo, hi) */
    adox r12, rax                      /* t2 += lo(m2*p2)   [value chain] */
    adcx r13, rbx                      /* t3 += hi(m2*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m2*p3 -> (lo, hi) */
    adox r13, rax                      /* t3 += lo(m2*p3)   [value chain] */
    adcx r14, rbx                      /* t4 += hi(m2*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r14, rax                      /* close the value chain into t4 */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r11                       /* m3 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m3 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m3*p0 -> (lo, hi) */
    adox r11, rax                      /* t0 += lo(m3*p0)   [value chain] */
    adcx r12, rbx                      /* t1 += hi(m3*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m3*p1 -> (lo, hi) */
    adox r12, rax                      /* t1 += lo(m3*p1)   [value chain] */
    adcx r13, rbx                      /* t2 += hi(m3*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m3*p2 -> (lo, hi) */
    adox r13, rax                      /* t2 += lo(m3*p2)   [value chain] */
    adcx r14, rbx                      /* t3 += hi(m3*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m3*p3 -> (lo, hi) */
    adox r14, rax                      /* t3 += lo(m3*p3)   [value chain] */
    adcx r15, rbx                      /* t4 += hi(m3*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r15, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (T < p*2^256 keeps the total below 2p*2^256: no word beyond T7) */
    /* result T4..T7 < 2p: one conditional subtraction */
    mov rax, r12                       /* keep-copy of limb 0 */
    mov rbx, r13                       /* keep-copy of limb 1 */
    mov rdx, r14                       /* keep-copy of limb 2 */
    mov rsi, r15                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rdx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r12                     /* borrow: value < p, keep limb 0 */
    cmovc rbx, r13                     /* borrow: value < p, keep limb 1 */
    cmovc rdx, r14                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r15                     /* borrow: value < p, keep limb 3 */
    mov [rdi], rax                     /* out limb 0 */
    mov [rdi + 8], rbx                 /* out limb 1 */
    mov [rdi + 16], rdx                /* out limb 2 */
    mov [rdi + 24], rsi                /* out limb 3 */
    add rbp, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_mod
    mov rbp, [rsp + 80]                /* reload the outer cursor */
    add rbp, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 56]                /* back-edge test */
    jne .Lfsq_iter

    /* epilogue: y.a = U - W (modular, in place over the W area) */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 704                       /* walk start */
    mov rax, rbp
    add rax, 144                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfsq_msub:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* limb 0 -= s2 */
    sbb r9, [rcx + 8]                  /* limb 1 -= s2 */
    sbb r10, [rcx + 16]                /* limb 2 -= s2 */
    sbb r11, [rcx + 24]                /* limb 3 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r8, rbx                        /* borrow: += p, limb 0 */
    adc r9, rdx                        /* limb 1 */
    adc r10, rsi                       /* limb 2 */
    adc r11, rax                       /* limb 3 */
    mov [rdi], r8                      /* y.a limb 0 */
    mov [rdi + 8], r9                  /* y.a limb 1 */
    mov [rdi + 16], r10                /* y.a limb 2 */
    mov [rdi + 24], r11                /* y.a limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfsq_msub

    /* copy out: y.a then y.b are contiguous, 48 limbs to z */
    mov rdi, [rsp + 48]                /* z */
    mov rsi, rsp
    add rsi, 1088                      /* y.a base */
    xor rcx, rcx
.Lfsq_out:
    mov r8, [rsi]                      /* y limb 0 */
    mov r9, [rsi + 8]                  /* y limb 1 */
    mov r10, [rsi + 16]                /* y limb 2 */
    mov r11, [rsi + 24]                /* y limb 3 */
    mov [rdi], r8                      /* z */
    mov [rdi + 8], r9                  /* z */
    mov [rdi + 16], r10                /* z */
    mov [rdi + 24], r11                /* z */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lfsq_out
    add rsp, 4544
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_fp12_sqr_x86, . - helius_fp12_sqr_x86

/* helius_fp12_mul_x86 register map:
   rdi  z on entry (spilled); walk destination pointer in every table-driven pass
   rsi  a pointer on entry (staging source); walk source-1 pointer; mask scratch
   rdx  b pointer on entry (staging source); the implicit mulx multiplicand; walk scratch
   rcx  consts pointer on entry; walk source-2 pointer; product m-walk cursor; staging cursor
   r8   accumulator/value word 0
   r9   accumulator/value word 1
   r10  accumulator/value word 2
   r11  accumulator/value word 3
   r12  accumulator/value word 4
   r13  accumulator/value word 5; mu-reduction scratch
   r14  product round cursor (byte offset 8j); 8-limb value word 6
   r15  product block cursor 96k; 8-limb value word 7
   rbp  outer iteration cursor (ctx row address, spilled per phase); every walk's row cursor
   rax  low half of the current product; zero for chain closes; borrow mask
   rbx  high half of the current product; walk bound and half cursors
*/
    .p2align 4
    .globl helius_fp12_mul_x86
    .type helius_fp12_mul_x86, @function
helius_fp12_mul_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 6080
    /* frame: p +0, -p^-1 +32, mu +40, z +48, loop bounds +56..96, ctx slots +104..160, NB2 +256, staged a/b +320..1088, t1/t2 +1088..1472, outputs +1472, operand sides +1856, products +3008, xi/neg scratch +4160, AC/BD/CR/TA parks +4544..6080 */
    mov [rsp + 48], rdi                /* spill z */
    mov rax, [rcx]                     /* p0 */
    mov [rsp], rax                     /* cancel rows address the frame as a consts table */
    mov rax, [rcx + 8]                 /* p1 */
    mov [rsp + 8], rax                 /* cancel rows address the frame as a consts table */
    mov rax, [rcx + 16]                /* p2 */
    mov [rsp + 16], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rcx + 24]                /* p3 */
    mov [rsp + 24], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rcx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    mov rax, [rcx + 40]                /* mu = floor(2^310/p) */
    mov [rsp + 40], rax                /* mu */
    lea rax, [rip + .Lfmu_tab]         /* walk tables */
    mov [rsp + 88], rax                /* table base */
    mov rbx, rax
    add rbx, 2184                      /* product m-walk end */
    mov [rsp + 96], rbx
    mov rbx, rax
    add rbx, 144                       /* ctx table end (three 48-byte rows) */
    mov [rsp + 56], rbx
    xor rax, rax
    mov [rsp + 192], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 200], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 208], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 216], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 224], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 232], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 240], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 248], rax               /* zero word (negation rows subtract from it) */
    mov [rsp + 136], rax               /* mod rows carry absolute destination offsets */

    /* stage a then b: all later reads are frame-relative, which is */
    /* what makes z == a, z == b and a == b safe (no operand read */
    /* after any z store) */
    mov rdi, rsp
    add rdi, 320                       /* staging cursor (b's area follows a's) */
    xor rcx, rcx                       /* 48 limbs, 4 per iteration */
.Lfmu_sta:
    mov r8, [rsi]                      /* a limb 0 */
    mov r9, [rsi + 8]                  /* a limb 1 */
    mov r10, [rsi + 16]                /* a limb 2 */
    mov r11, [rsi + 24]                /* a limb 3 */
    mov [rdi], r8                      /* staged */
    mov [rdi + 8], r9                  /* staged */
    mov [rdi + 16], r10                /* staged */
    mov [rdi + 24], r11                /* staged */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lfmu_sta
    mov rsi, rdx                       /* b pointer (rdi has walked to b's area) */
    xor rcx, rcx
.Lfmu_stb:
    mov r8, [rsi]                      /* b limb 0 */
    mov r9, [rsi + 8]                  /* b limb 1 */
    mov r10, [rsi + 16]                /* b limb 2 */
    mov r11, [rsi + 24]                /* b limb 3 */
    mov [rdi], r8                      /* staged */
    mov [rdi + 8], r9                  /* staged */
    mov [rdi + 16], r10                /* staged */
    mov [rdi + 24], r11                /* staged */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lfmu_stb

    /* t1 = a0 + a1, t2 = b0 + b1 (modular, canonical) */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 144                       /* walk start */
    mov rax, rbp
    add rax, 288                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfmu_madd:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    add r8, [rcx]                      /* += s2 limb 0 */
    adc r9, [rcx + 8]                  /* += s2 limb 1 */
    adc r10, [rcx + 16]                /* += s2 limb 2 */
    adc r11, [rcx + 24]                /* += s2 limb 3 */
    /* invariant: CF = OF = 0 (s1 + s2 < 2p < 2^256: no carry out) */
    mov r12, r8                        /* keep-copy of limb 0 */
    mov r13, r9                        /* keep-copy of limb 1 */
    mov r14, r10                       /* keep-copy of limb 2 */
    mov r15, r11                       /* keep-copy of limb 3 */
    sub r12, [rsp]                     /* limb 0 -= p0 */
    sbb r13, [rsp + 8]                 /* limb 1 -= p1 */
    sbb r14, [rsp + 16]                /* limb 2 -= p2 */
    sbb r15, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r12, r8                      /* borrow: value < p, keep limb 0 */
    cmovc r13, r9                      /* borrow: value < p, keep limb 1 */
    cmovc r14, r10                     /* borrow: value < p, keep limb 2 */
    cmovc r15, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r12                     /* out limb 0 */
    mov [rdi + 8], r13                 /* out limb 1 */
    mov [rdi + 16], r14                /* out limb 2 */
    mov [rdi + 24], r15                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_madd

    /* outer loop: iteration 0 parks AC = a0*b0, 1 parks BD = a1*b1, */
    /* 2 parks CR = t1*t2 and rides the mulVadd rows for z.a */
    mov rbp, [rsp + 88]                /* ctx cursor = first ctx row */
.Lfmu_iter:
    mov [rsp + 80], rbp                /* spill the outer cursor */
    mov rax, [rbp]                     /* ctx: x-side source */
    mov [rsp + 120], rax
    mov rax, [rbp + 8]                 /* ctx: y-side source */
    mov [rsp + 128], rax
    mov rax, [rbp + 16]                /* ctx: Fp6Dbl park base */
    mov [rsp + 104], rax
    mov rax, [rbp + 24]                /* ctx: gsub walk end */
    mov [rsp + 112], rax
    mov rax, [rbp + 32]                /* ctx: nine walk end */
    mov [rsp + 144], rax
    mov rax, [rbp + 40]                /* ctx: gadd walk end */
    mov [rsp + 152], rax
    /* stage the two operand sides (six blocks each: singles + sums) */
    xor rax, rax
    add rax, 1856
    mov [rsp + 184], rax               /* destination: x side first */
    mov rbx, rsp
    add rbx, 120                       /* side cursor walks the two source slots */
    mov rax, rbx
    add rax, 16
    mov [rsp + 64], rax                /* side bound */
.Lfmu_side:
    mov rsi, rsp
    add rsi, [rbx]                     /* side source (one Fp6) */
    mov rdi, rsp
    add rdi, [rsp + 184]               /* side destination */
    /* singles: copy each Fp2 and add its in-block s = re + im */
    xor rcx, rcx
.Lfmu_single:
    mov r8, [rsi]                      /* re[0] */
    mov r9, [rsi + 8]                  /* re[1] */
    mov r10, [rsi + 16]                /* re[2] */
    mov r11, [rsi + 24]                /* re[3] */
    mov r12, [rsi + 32]                /* im[0] */
    mov r13, [rsi + 40]                /* im[1] */
    mov r14, [rsi + 48]                /* im[2] */
    mov r15, [rsi + 56]                /* im[3] */
    mov [rdi], r8                      /* block re[0] */
    mov [rdi + 8], r9                  /* block re[1] */
    mov [rdi + 16], r10                /* block re[2] */
    mov [rdi + 24], r11                /* block re[3] */
    mov [rdi + 32], r12                /* block im[0] */
    mov [rdi + 40], r13                /* block im[1] */
    mov [rdi + 48], r14                /* block im[2] */
    mov [rdi + 56], r15                /* block im[3] */
    add r8, r12                        /* s = re + im, limb 0 */
    adc r9, r13                        /* limb 1 */
    adc r10, r14                       /* limb 2 */
    adc r11, r15                       /* limb 3 */
    /* invariant: CF = OF = 0 (re + im < 2p < 2^256: s fits four limbs) */
    mov [rdi + 64], r8                 /* block s[0] */
    mov [rdi + 72], r9                 /* block s[1] */
    mov [rdi + 80], r10                /* block s[2] */
    mov [rdi + 88], r11                /* block s[3] */
    add rsi, 64                        /* next source Fp2 */
    add rdi, 96                        /* next block */
    add rcx, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 192                       /* back-edge test */
    jne .Lfmu_single
    /* sums: whole-block adds (s-lanes add to the sums' s) */
    mov rdx, [rsp + 88]                /* table base */
    add rdx, 2184                      /* walk start */
    mov rax, rdx
    add rax, 72                        /* walk end */
    mov [rsp + 72], rax                /* walk bound */
.Lfmu_sums:
    mov rbp, rsp
    add rbp, [rsp + 184]               /* side base */
    mov rdi, rbp
    add rdi, [rdx]                     /* sum block */
    mov rsi, rbp
    add rsi, [rdx + 8]                 /* addend block A */
    mov rcx, rbp
    add rcx, [rdx + 16]                /* addend block B */
    xor rbp, rbp                       /* row cursor: re, im, s */
.Lfmu_sumrow:
    mov r8, [rsi]                      /* A limb 0 */
    mov r9, [rsi + 8]                  /* A limb 1 */
    mov r10, [rsi + 16]                /* A limb 2 */
    mov r11, [rsi + 24]                /* A limb 3 */
    add r8, [rcx]                      /* += B limb 0 */
    adc r9, [rcx + 8]                  /* += B limb 1 */
    adc r10, [rcx + 16]                /* += B limb 2 */
    adc r11, [rcx + 24]                /* += B limb 3 */
    mov [rdi], r8                      /* sum limb */
    mov [rdi + 8], r9                  /* sum limb */
    mov [rdi + 16], r10                /* sum limb */
    mov [rdi + 24], r11                /* sum limb */
    add rsi, 32
    add rcx, 32
    add rdi, 32
    add rbp, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, 96                        /* back-edge test */
    jne .Lfmu_sumrow
    add rdx, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rdx, [rsp + 72]                /* back-edge test */
    jne .Lfmu_sums
    mov rax, [rsp + 184]
    add rax, 576
    mov [rsp + 184], rax               /* destination: y side next */
    add rbx, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp rbx, [rsp + 64]                /* back-edge test */
    jne .Lfmu_side
    /* products: 6 blocks x 3 sub-products, rolled 4x4 mulpre rounds */
    xor r15, r15                       /* block cursor 96k */
.Lfmu_prod_k:
    mov rcx, [rsp + 88]
    add rcx, 2136                      /* sub-product walk */
.Lfmu_prod_m:
    mov rax, [rcx]                     /* operand sub-offset */
    mov rbx, [rcx + 8]                 /* destination sub-offset */
    mov rsi, rsp
    add rsi, r15
    add rsi, rax
    add rsi, 1856                      /* PA: x sub-row (the multiplicand) */
    mov rdi, rsp
    add rdi, r15
    add rdi, rax
    add rdi, 2432                      /* PY: y sub-row */
    mov rbp, rsp
    add rbp, r15
    add rbp, r15                       /* product regions stride 192 = 2*96k */
    add rbp, rbx
    add rbp, 3008                      /* PZ */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    xor r14, r14                       /* round cursor: byte offset 8j of the x limb */
.Lfmu_prod_j:
    mov rdx, [rsi + r14]               /* x[j], the row multiplicand */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rdi]     /* x[j]*y[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x[j]*y[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x[j]*y[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* x[j]*y[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x[j]*y[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x[j]*y[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* x[j]*y[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x[j]*y[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x[j]*y[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* x[j]*y[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x[j]*y[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x[j]*y[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (row peak < 2^257 window + 2^320 product < 2^321, far below the six-word 2^384) */
    mov [rbp], r8                      /* product limb j is final */
    add rbp, 8                         /* next output limb */
    /* shift down one word */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lfmu_prod_j
    mov [rbp], r8                      /* product limb 4 */
    mov [rbp + 8], r9                  /* product limb 5 */
    mov [rbp + 16], r10                /* product limb 6 */
    mov [rbp + 24], r11                /* product limb 7 */
    add rcx, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, [rsp + 96]                /* back-edge test */
    jne .Lfmu_prod_m
    add r15, 96                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 576                       /* back-edge test */
    jne .Lfmu_prod_k
    /* double-width sub walk: Karatsuba assembly, cross terms, negations */
    mov rbp, [rsp + 88]                /* table base */
    mov rax, rbp
    add rax, [rsp + 112]               /* + ctx walk end offset */
    mov [rsp + 64], rax                /* walk bound */
    add rbp, 432                       /* walk start */
.Lfmu_gsub:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* word 0 -= s2 */
    sbb r9, [rcx + 8]                  /* word 1 -= s2 */
    sbb r10, [rcx + 16]                /* word 2 -= s2 */
    sbb r11, [rcx + 24]                /* word 3 -= s2 */
    sbb r12, [rcx + 32]                /* word 4 -= s2 */
    sbb r13, [rcx + 40]                /* word 5 -= s2 */
    sbb r14, [rcx + 48]                /* word 6 -= s2 */
    sbb r15, [rcx + 56]                /* word 7 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r12, rbx                       /* borrow: high half += p, word 4 */
    adc r13, rdx                       /* word 5 */
    adc r14, rsi                       /* word 6 */
    adc r15, rax                       /* word 7 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], r12                /* dst word 4 */
    mov [rdi + 40], r13                /* dst word 5 */
    mov [rdi + 48], r14                /* dst word 6 */
    mov [rdi + 56], r15                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_gsub
    /* nine-fold walk: xi = 9 + u on 512-bit values, mu-canonical high */
    mov rbp, [rsp + 88]                /* table base */
    mov rax, rbp
    add rax, [rsp + 144]               /* + ctx walk end offset */
    mov [rsp + 64], rax                /* walk bound */
    add rbp, 1224                      /* walk start */
.Lfmu_nine:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    xor rdx, rdx
    add rdx, 9                         /* 9 is the mulx multiplicand */
    /* low half: l = 9*xL + yL, carry limb l4 <= 10 */
    mulx r13, r8, qword ptr [rsi]      /* 9*x0 -> (l0, hi) */
    mulx r14, r9, qword ptr [rsi + 8]  /* 9*x1 -> (l1, hi) */
    add r9, r13                        /* l1 += hi(9*x0) */
    mulx r13, r10, qword ptr [rsi + 16] /* 9*x2 -> (l2, hi) */
    adc r10, r14                       /* l2 += hi(9*x1) */
    mulx r12, r11, qword ptr [rsi + 24] /* 9*x3 -> (l3, l4) */
    adc r11, r13                       /* l3 += hi(9*x2) */
    adc r12, 0                         /* 9*xL < 9*2^256: l4 closes the chain */
    add r8, [rcx]                      /* += y0 */
    adc r9, [rcx + 8]                  /* += y1 */
    adc r10, [rcx + 16]                /* += y2 */
    adc r11, [rcx + 24]                /* += y3 */
    adc r12, 0                         /* l4 <= 10 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    /* high half: v = 9*xH + yH + l4 < 10p (xH, yH < p) */
    mulx r13, r8, qword ptr [rsi + 32] /* 9*x4 -> (v0, hi) */
    mulx r14, r9, qword ptr [rsi + 40] /* 9*x5 -> (v1, hi) */
    add r9, r13                        /* v1 += hi(9*x4) */
    mulx r13, r10, qword ptr [rsi + 48] /* 9*x6 -> (v2, hi) */
    adc r10, r14                       /* v2 += hi(9*x5) */
    mulx r15, r11, qword ptr [rsi + 56] /* 9*x7 -> (v3, v4) */
    adc r11, r13                       /* v3 += hi(9*x6) */
    adc r15, 0                         /* 9*xH < 9p closes into v4 */
    add r8, r12                        /* += l4 */
    adc r9, 0                          /* ripple the l4 carry */
    adc r10, 0                         /* ripple the l4 carry */
    adc r11, 0                         /* ripple the l4 carry */
    adc r15, 0                         /* ripple the l4 carry */
    add r8, [rcx + 32]                 /* += y4 */
    adc r9, [rcx + 40]                 /* += y5 */
    adc r10, [rcx + 48]                /* += y6 */
    adc r11, [rcx + 56]                /* += y7 */
    adc r15, 0                         /* v < 10p < 2^257 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov r13, r15                       /* E builds from the top limbs */
    shld r13, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx r14, rax, r13                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx r13, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r12, r14, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add r14, r13                       /* l1 += h0 */
    mulx r13, rbx, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbx, r12                       /* l2 += h1 */
    mulx r12, rsi, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rsi, r13                       /* l3 += h2 */
    adc r12, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, r14                        /* limb 1 */
    sbb r10, rbx                       /* limb 2 */
    sbb r11, rsi                       /* limb 3 */
    sbb r15, r12                       /* limb 4 */
    /* invariant: r15 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction: the stored high half is canonical */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rbx, r9                        /* keep-copy of limb 1 */
    mov rcx, r10                       /* keep-copy of limb 2 */
    mov rsi, r11                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rcx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r8                      /* borrow: value < p, keep limb 0 */
    cmovc rbx, r9                      /* borrow: value < p, keep limb 1 */
    cmovc rcx, r10                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi + 32], rax                /* out limb 0 */
    mov [rdi + 40], rbx                /* out limb 1 */
    mov [rdi + 48], rcx                /* out limb 2 */
    mov [rdi + 56], rsi                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_nine
    /* double-width add walk: assemble and park the Fp6Dbl (+ z.a rows) */
    mov rbp, [rsp + 88]                /* table base */
    mov rax, rbp
    add rax, [rsp + 152]               /* + ctx walk end offset */
    mov [rsp + 64], rax                /* walk bound */
    add rbp, 1368                      /* walk start */
.Lfmu_gadd:
    mov rdi, rsp
    add rdi, [rsp + 104]               /* + ctx destination base */
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    add r8, [rcx]                      /* word 0 += s2 */
    adc r9, [rcx + 8]                  /* word 1 += s2 */
    adc r10, [rcx + 16]                /* word 2 += s2 */
    adc r11, [rcx + 24]                /* word 3 += s2 */
    adc r12, [rcx + 32]                /* word 4 += s2 */
    adc r13, [rcx + 40]                /* word 5 += s2 */
    adc r14, [rcx + 48]                /* word 6 += s2 */
    adc r15, [rcx + 56]                /* word 7 += s2 */
    /* invariant: CF = OF = 0 (sum of two sub-2^510 values < 2^511: no carry out) */
    /* high half >= p: subtract p once (sum < 2p*2^256) */
    mov rax, r12
    mov rbx, r13
    mov rdx, r14
    mov rcx, r15
    sub rax, [rsp]                     /* high word 0 - p0 */
    sbb rbx, [rsp + 8]                 /* high word 1 - p1 */
    sbb rdx, [rsp + 16]                /* high word 2 - p2 */
    sbb rcx, [rsp + 24]                /* high word 3 - p3 */
    cmovc rax, r12                     /* borrow: high < p, keep */
    cmovc rbx, r13
    cmovc rdx, r14
    cmovc rcx, r15
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], rax                /* dst word 4 */
    mov [rdi + 40], rbx                /* dst word 5 */
    mov [rdi + 48], rdx                /* dst word 6 */
    mov [rdi + 56], rcx                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_gadd
    mov rbp, [rsp + 80]                /* reload the outer cursor */
    add rbp, 48                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 56]                /* back-edge test */
    jne .Lfmu_iter

    /* z.b assembly: CR -= AC, CR -= BD (all lanes guarded mod p*2^256) */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 1656                      /* walk start */
    mov rax, rbp
    add rax, 288                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfmu_gsub2:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* word 0 -= s2 */
    sbb r9, [rcx + 8]                  /* word 1 -= s2 */
    sbb r10, [rcx + 16]                /* word 2 -= s2 */
    sbb r11, [rcx + 24]                /* word 3 -= s2 */
    sbb r12, [rcx + 32]                /* word 4 -= s2 */
    sbb r13, [rcx + 40]                /* word 5 -= s2 */
    sbb r14, [rcx + 48]                /* word 6 -= s2 */
    sbb r15, [rcx + 56]                /* word 7 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r12, rbx                       /* borrow: high half += p, word 4 */
    adc r13, rdx                       /* word 5 */
    adc r14, rsi                       /* word 6 */
    adc r15, rax                       /* word 7 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], r12                /* dst word 4 */
    mov [rdi + 40], r13                /* dst word 5 */
    mov [rdi + 48], r14                /* dst word 6 */
    mov [rdi + 56], r15                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_gsub2
    /* Montgomery reduction walk: 12 output coefficients into YOUT */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 1944                      /* walk start */
    mov rax, rbp
    add rax, 192                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lfmu_mod:
    mov rsi, rsp
    add rsi, [rbp]                     /* source T */
    mov rdi, rsp
    add rdi, [rsp + 136]               /* V or U base */
    add rdi, [rbp + 8]                 /* + coefficient offset */
    mov r8, [rsi]                      /* T0 */
    mov r9, [rsi + 8]                  /* T1 */
    mov r10, [rsi + 16]                /* T2 */
    mov r11, [rsi + 24]                /* T3 */
    mov r12, [rsi + 32]                /* T4 */
    mov r13, [rsi + 40]                /* T5 */
    mov r14, [rsi + 48]                /* T6 */
    mov r15, [rsi + 56]                /* T7 */
    xor rax, rax                       /* clear CF = OF before the dual chains */
    mov rdx, r8                        /* m0 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m0 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m0*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m0*p0)   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m0*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m0*p1 -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m0*p1)   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m0*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m0*p2 -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m0*p2)   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m0*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m0*p3 -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m0*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m0*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adcx r13, rax                      /* T5 += carry-chain ripple */
    adox r13, rax                      /* T5 += value-chain ripple */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r9                        /* m1 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m1 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m1*p0 -> (lo, hi) */
    adox r9, rax                       /* t0 += lo(m1*p0)   [value chain] */
    adcx r10, rbx                      /* t1 += hi(m1*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m1*p1 -> (lo, hi) */
    adox r10, rax                      /* t1 += lo(m1*p1)   [value chain] */
    adcx r11, rbx                      /* t2 += hi(m1*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m1*p2 -> (lo, hi) */
    adox r11, rax                      /* t2 += lo(m1*p2)   [value chain] */
    adcx r12, rbx                      /* t3 += hi(m1*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m1*p3 -> (lo, hi) */
    adox r12, rax                      /* t3 += lo(m1*p3)   [value chain] */
    adcx r13, rbx                      /* t4 += hi(m1*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r13, rax                      /* close the value chain into t4 */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r10                       /* m2 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m2 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m2*p0 -> (lo, hi) */
    adox r10, rax                      /* t0 += lo(m2*p0)   [value chain] */
    adcx r11, rbx                      /* t1 += hi(m2*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m2*p1 -> (lo, hi) */
    adox r11, rax                      /* t1 += lo(m2*p1)   [value chain] */
    adcx r12, rbx                      /* t2 += hi(m2*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m2*p2 -> (lo, hi) */
    adox r12, rax                      /* t2 += lo(m2*p2)   [value chain] */
    adcx r13, rbx                      /* t3 += hi(m2*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m2*p3 -> (lo, hi) */
    adox r13, rax                      /* t3 += lo(m2*p3)   [value chain] */
    adcx r14, rbx                      /* t4 += hi(m2*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r14, rax                      /* close the value chain into t4 */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r11                       /* m3 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m3 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m3*p0 -> (lo, hi) */
    adox r11, rax                      /* t0 += lo(m3*p0)   [value chain] */
    adcx r12, rbx                      /* t1 += hi(m3*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m3*p1 -> (lo, hi) */
    adox r12, rax                      /* t1 += lo(m3*p1)   [value chain] */
    adcx r13, rbx                      /* t2 += hi(m3*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m3*p2 -> (lo, hi) */
    adox r13, rax                      /* t2 += lo(m3*p2)   [value chain] */
    adcx r14, rbx                      /* t3 += hi(m3*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m3*p3 -> (lo, hi) */
    adox r14, rax                      /* t3 += lo(m3*p3)   [value chain] */
    adcx r15, rbx                      /* t4 += hi(m3*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r15, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (T < p*2^256 keeps the total below 2p*2^256: no word beyond T7) */
    /* result T4..T7 < 2p: one conditional subtraction */
    mov rax, r12                       /* keep-copy of limb 0 */
    mov rbx, r13                       /* keep-copy of limb 1 */
    mov rdx, r14                       /* keep-copy of limb 2 */
    mov rsi, r15                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rdx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r12                     /* borrow: value < p, keep limb 0 */
    cmovc rbx, r13                     /* borrow: value < p, keep limb 1 */
    cmovc rdx, r14                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r15                     /* borrow: value < p, keep limb 3 */
    mov [rdi], rax                     /* out limb 0 */
    mov [rdi + 8], rbx                 /* out limb 1 */
    mov [rdi + 16], rdx                /* out limb 2 */
    mov [rdi + 24], rsi                /* out limb 3 */
    add rbp, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lfmu_mod

    /* copy out: z.a then z.b are contiguous, 48 limbs to z */
    mov rdi, [rsp + 48]                /* z */
    mov rsi, rsp
    add rsi, 1472                      /* output base */
    xor rcx, rcx
.Lfmu_out:
    mov r8, [rsi]                      /* z limb 0 */
    mov r9, [rsi + 8]                  /* z limb 1 */
    mov r10, [rsi + 16]                /* z limb 2 */
    mov r11, [rsi + 24]                /* z limb 3 */
    mov [rdi], r8                      /* z */
    mov [rdi + 8], r9                  /* z */
    mov [rdi + 16], r10                /* z */
    mov [rdi + 24], r11                /* z */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lfmu_out
    add rsp, 6080
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_fp12_mul_x86, . - helius_fp12_mul_x86

/* helius_cyc_sqr_x86 register map:
   rdi  z on entry (spilled); walk destination pointer in every table-driven pass
   rsi  f pointer on entry (staging source); walk source-1 pointer; mask scratch
   rdx  consts pointer on entry; the implicit mulx multiplicand; walk scratch
   rcx  walk source-2 pointer; staging cursor; the product output cursor
   r8   accumulator/value word 0
   r9   accumulator/value word 1
   r10  accumulator/value word 2
   r11  accumulator/value word 3
   r12  accumulator/value word 4
   r13  accumulator/value word 5; mu-reduction scratch
   r14  product round cursor (byte offset 8j); 8-limb value word 6
   r15  product cursor (64-byte operand-pair steps); 8-limb value word 7
   rbp  the walk row cursor, marching once through the whole table
   rax  low half of the current product; zero for chain closes; borrow mask
   rbx  high half of the current product; prologue scratch
*/
    .p2align 4
    .globl helius_cyc_sqr_x86
    .type helius_cyc_sqr_x86, @function
helius_cyc_sqr_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 5200
    /* frame: p +0, -p^-1 +32, mu +40, z +48, walk bound +64, table base +88, zero8 +96 (spans mod dst +136), staged f +208, s sums +592, negp images +784, square blocks +976, products +2128, negations +3280, nine-fold y +3536, xi scratch +3920, t values +4432, z combines +4816 */
    mov [rsp + 48], rdi                /* spill z */
    mov rax, [rdx]                     /* p0 */
    mov [rsp], rax                     /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 8]                 /* p1 */
    mov [rsp + 8], rax                 /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 16]                /* p2 */
    mov [rsp + 16], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 24]                /* p3 */
    mov [rsp + 24], rax                /* cancel rows address the frame as a consts table */
    mov rax, [rdx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    mov rax, [rdx + 40]                /* mu = floor(2^310/p) */
    mov [rsp + 40], rax                /* mu */
    lea rax, [rip + .Lcyc_tab]         /* walk tables */
    mov [rsp + 88], rax                /* table base */
    xor rax, rax
    mov [rsp + 96], rax                /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 104], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 112], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 120], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 128], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 136], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 144], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */
    mov [rsp + 152], rax               /* zero word (negation/copy rows and the spanned MOD_DST slot) */

    /* stage f: all later reads are frame-relative, which is what */
    /* makes z == f safe (no f read after any z store) */
    mov rdi, rsp
    add rdi, 208                       /* staging cursor */
    xor rcx, rcx                       /* 48 limbs, 4 per iteration */
.Lcyc_fst:
    mov r8, [rsi]                      /* f limb 0 */
    mov r9, [rsi + 8]                  /* f limb 1 */
    mov r10, [rsi + 16]                /* f limb 2 */
    mov r11, [rsi + 24]                /* f limb 3 */
    mov [rdi], r8                      /* staged */
    mov [rdi + 8], r9                  /* staged */
    mov [rdi + 16], r10                /* staged */
    mov [rdi + 24], r11                /* staged */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lcyc_fst

    /* modular add walk 1: the s_k = x0_k + x1_k cross operands, then */
    /* the additive block rows a + b, 2b and the a copy, all canonical */
    mov rbp, [rsp + 88]                /* table base */
    add rbp, 0                         /* walk start */
    mov rax, rbp
    add rax, 792                       /* walk end */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_madd1:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    add r8, [rcx]                      /* += s2 limb 0 */
    adc r9, [rcx + 8]                  /* += s2 limb 1 */
    adc r10, [rcx + 16]                /* += s2 limb 2 */
    adc r11, [rcx + 24]                /* += s2 limb 3 */
    /* invariant: CF = OF = 0 (s1 + s2 < 2p < 2^256: no carry out) */
    mov r12, r8                        /* keep-copy of limb 0 */
    mov r13, r9                        /* keep-copy of limb 1 */
    mov r14, r10                       /* keep-copy of limb 2 */
    mov r15, r11                       /* keep-copy of limb 3 */
    sub r12, [rsp]                     /* limb 0 -= p0 */
    sbb r13, [rsp + 8]                 /* limb 1 -= p1 */
    sbb r14, [rsp + 16]                /* limb 2 -= p2 */
    sbb r15, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r12, r8                      /* borrow: value < p, keep limb 0 */
    cmovc r13, r9                      /* borrow: value < p, keep limb 1 */
    cmovc r14, r10                     /* borrow: value < p, keep limb 2 */
    cmovc r15, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r12                     /* out limb 0 */
    mov [rdi + 8], r13                 /* out limb 1 */
    mov [rdi + 16], r14                /* out limb 2 */
    mov [rdi + 24], r15                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_madd1

    /* modular sub walk: the a - b block rows, then the negp images */
    /* p - r of the subtractive z-combine operands */
    mov rax, [rsp + 88]                /* table base */
    add rax, 1152                      /* next walk's bound */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_msub:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* limb 0 -= s2 */
    sbb r9, [rcx + 8]                  /* limb 1 -= s2 */
    sbb r10, [rcx + 16]                /* limb 2 -= s2 */
    sbb r11, [rcx + 24]                /* limb 3 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r8, rbx                        /* borrow: += p, limb 0 */
    adc r9, rdx                        /* limb 1 */
    adc r10, rsi                       /* limb 2 */
    adc r11, rax                       /* limb 3 */
    mov [rdi], r8                      /* dst limb 0 */
    mov [rdi + 8], r9                  /* dst limb 1 */
    mov [rdi + 16], r10                /* dst limb 2 */
    mov [rdi + 24], r11                /* dst limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_msub

    /* products: 18 raw 4x4 mulpre, two per square (the complex method: */
    /* a-lane (a-b)(a+b), b-lane 2b*a); the 64-byte operand-pair stride */
    /* maps 1:1 onto the 64-byte output lanes */
    xor r15, r15                       /* product cursor: 64-byte operand-pair steps */
.Lcyc_prod:
    mov rsi, rsp
    add rsi, r15
    add rsi, 976                       /* PA: the multiplicand row */
    mov rdi, rsi
    add rdi, 32                        /* PY: the y row */
    mov rcx, rsi
    add rcx, 1152                      /* PZ: the 512-bit product lane */
    xor r8, r8                         /* t0 = 0 */
    xor r9, r9                         /* t1 = 0 */
    xor r10, r10                       /* t2 = 0 */
    xor r11, r11                       /* t3 = 0 */
    xor r12, r12                       /* t4 = 0 */
    xor r13, r13                       /* t5 = 0 */
    xor r14, r14                       /* round cursor: byte offset 8j of the multiplicand limb */
.Lcyc_prod_j:
    mov rdx, [rsi + r14]               /* x[j], the row multiplicand */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rdi]     /* x[j]*y[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x[j]*y[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x[j]*y[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 8] /* x[j]*y[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x[j]*y[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x[j]*y[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 16] /* x[j]*y[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x[j]*y[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x[j]*y[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rdi + 24] /* x[j]*y[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x[j]*y[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x[j]*y[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adox r13, rax                      /* ripple the t4 close into t5 */
    adcx r13, rax                      /* close the carry chain into t5 */
    /* invariant: CF = OF = 0 (row peak < 2^257 window + 2^320 product < 2^321, far below the six-word 2^384) */
    mov [rcx], r8                      /* product limb j is final */
    add rcx, 8                         /* next output limb */
    /* shift down one word */
    mov r8, r9                         /* t0 = t1 */
    mov r9, r10                        /* t1 = t2 */
    mov r10, r11                       /* t2 = t3 */
    mov r11, r12                       /* t3 = t4 */
    mov r12, r13                       /* t4 = t5 */
    xor r13, r13                       /* t5 = 0 (CF/OF stay clear) */
    add r14, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp r14, 32                        /* back-edge test */
    jne .Lcyc_prod_j
    mov [rcx], r8                      /* product limb 4 */
    mov [rcx + 8], r9                  /* product limb 5 */
    mov [rcx + 16], r10                /* product limb 6 */
    mov [rcx + 24], r11                /* product limb 7 */
    add r15, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp r15, 1152                      /* back-edge test */
    jne .Lcyc_prod

    /* double-width sub walk: the nine-fold y operands ya = T0.a - T1.b */
    /* and yb = T1.a + T0.b (via nbb = 0 - T0.b), U = TS - T0 - T1, then */
    /* the xi*t5 negation (its operand U_2.b is final only after the U rows) */
    mov rax, [rsp + 88]                /* table base */
    add rax, 1680                      /* next walk's bound */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_gsub:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 word 0 */
    mov r9, [rsi + 8]                  /* s1 word 1 */
    mov r10, [rsi + 16]                /* s1 word 2 */
    mov r11, [rsi + 24]                /* s1 word 3 */
    mov r12, [rsi + 32]                /* s1 word 4 */
    mov r13, [rsi + 40]                /* s1 word 5 */
    mov r14, [rsi + 48]                /* s1 word 6 */
    mov r15, [rsi + 56]                /* s1 word 7 */
    xor rax, rax                       /* mask seed; also clears flags for the chain */
    sub r8, [rcx]                      /* word 0 -= s2 */
    sbb r9, [rcx + 8]                  /* word 1 -= s2 */
    sbb r10, [rcx + 16]                /* word 2 -= s2 */
    sbb r11, [rcx + 24]                /* word 3 -= s2 */
    sbb r12, [rcx + 32]                /* word 4 -= s2 */
    sbb r13, [rcx + 40]                /* word 5 -= s2 */
    sbb r14, [rcx + 48]                /* word 6 -= s2 */
    sbb r15, [rcx + 56]                /* word 7 -= s2 */
    sbb rax, rax                       /* mask = -borrow */
    mov rbx, rax
    and rbx, [rsp]                     /* p0 & borrow mask */
    mov rdx, rax
    and rdx, [rsp + 8]                 /* p1 & borrow mask */
    mov rsi, rax
    and rsi, [rsp + 16]                /* p2 & borrow mask */
    and rax, [rsp + 24]                /* p3 & borrow mask */
    add r12, rbx                       /* borrow: high half += p, word 4 */
    adc r13, rdx                       /* word 5 */
    adc r14, rsi                       /* word 6 */
    adc r15, rax                       /* word 7 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    mov [rdi + 32], r12                /* dst word 4 */
    mov [rdi + 40], r13                /* dst word 5 */
    mov [rdi + 48], r14                /* dst word 6 */
    mov [rdi + 56], r15                /* dst word 7 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_gsub

    /* nine-fold walk: each T2 = xi*T1 + T0 completes as 9x + y, then */
    /* XT = xi*U_2 (the t5 site), mu-canonical high halves */
    mov rax, [rsp + 88]                /* table base */
    add rax, 1872                      /* next walk's bound */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_nine:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    xor rdx, rdx
    add rdx, 9                         /* 9 is the mulx multiplicand */
    /* low half: l = 9*xL + yL, carry limb l4 <= 10 */
    mulx r13, r8, qword ptr [rsi]      /* 9*x0 -> (l0, hi) */
    mulx r14, r9, qword ptr [rsi + 8]  /* 9*x1 -> (l1, hi) */
    add r9, r13                        /* l1 += hi(9*x0) */
    mulx r13, r10, qword ptr [rsi + 16] /* 9*x2 -> (l2, hi) */
    adc r10, r14                       /* l2 += hi(9*x1) */
    mulx r12, r11, qword ptr [rsi + 24] /* 9*x3 -> (l3, l4) */
    adc r11, r13                       /* l3 += hi(9*x2) */
    adc r12, 0                         /* 9*xL < 9*2^256: l4 closes the chain */
    add r8, [rcx]                      /* += y0 */
    adc r9, [rcx + 8]                  /* += y1 */
    adc r10, [rcx + 16]                /* += y2 */
    adc r11, [rcx + 24]                /* += y3 */
    adc r12, 0                         /* l4 <= 10 */
    mov [rdi], r8                      /* dst word 0 */
    mov [rdi + 8], r9                  /* dst word 1 */
    mov [rdi + 16], r10                /* dst word 2 */
    mov [rdi + 24], r11                /* dst word 3 */
    /* high half: v = 9*xH + yH + l4 < 10p (xH, yH < p) */
    mulx r13, r8, qword ptr [rsi + 32] /* 9*x4 -> (v0, hi) */
    mulx r14, r9, qword ptr [rsi + 40] /* 9*x5 -> (v1, hi) */
    add r9, r13                        /* v1 += hi(9*x4) */
    mulx r13, r10, qword ptr [rsi + 48] /* 9*x6 -> (v2, hi) */
    adc r10, r14                       /* v2 += hi(9*x5) */
    mulx r15, r11, qword ptr [rsi + 56] /* 9*x7 -> (v3, v4) */
    adc r11, r13                       /* v3 += hi(9*x6) */
    adc r15, 0                         /* 9*xH < 9p closes into v4 */
    add r8, r12                        /* += l4 */
    adc r9, 0                          /* ripple the l4 carry */
    adc r10, 0                         /* ripple the l4 carry */
    adc r11, 0                         /* ripple the l4 carry */
    adc r15, 0                         /* ripple the l4 carry */
    add r8, [rcx + 32]                 /* += y4 */
    adc r9, [rcx + 40]                 /* += y5 */
    adc r10, [rcx + 48]                /* += y6 */
    adc r11, [rcx + 56]                /* += y7 */
    adc r15, 0                         /* v < 10p < 2^257 */
    /* estimated quotient: E = floor(value/2^252), q = floor(E*mu/2^58) <= 10 */
    mov r13, r15                       /* E builds from the top limbs */
    shld r13, r11, 4                   /* E = top five bits of the value */
    mov rdx, [rsp + 40]                /* mu */
    mulx r14, rax, r13                 /* E*mu (high half zero: E < 2^5, mu < 2^57) */
    shr rax, 58                        /* q */
    mov rdx, rax                       /* q is the multiplicand */
    mulx r13, rax, qword ptr [rsp]     /* q*p0 -> (l0, h0) */
    mulx r12, r14, qword ptr [rsp + 8] /* q*p1 -> (l1, h1) */
    add r14, r13                       /* l1 += h0 */
    mulx r13, rbx, qword ptr [rsp + 16] /* q*p2 -> (l2, h2) */
    adc rbx, r12                       /* l2 += h1 */
    mulx r12, rsi, qword ptr [rsp + 24] /* q*p3 -> (l3, h3); rdx freed */
    adc rsi, r13                       /* l3 += h2 */
    adc r12, 0                         /* h3 += carry; q*p < 11p < 2^260 */
    sub r8, rax                        /* value -= q*p, limb 0 */
    sbb r9, r14                        /* limb 1 */
    sbb r10, rbx                       /* limb 2 */
    sbb r11, rsi                       /* limb 3 */
    sbb r15, r12                       /* limb 4 */
    /* invariant: r15 = 0 (value - q*p < 1.33p < 2^255 fits four limbs) */
    /* one conditional subtraction: the stored high half is canonical */
    mov rax, r8                        /* keep-copy of limb 0 */
    mov rbx, r9                        /* keep-copy of limb 1 */
    mov rcx, r10                       /* keep-copy of limb 2 */
    mov rsi, r11                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rcx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r8                      /* borrow: value < p, keep limb 0 */
    cmovc rbx, r9                      /* borrow: value < p, keep limb 1 */
    cmovc rcx, r10                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi + 32], rax                /* out limb 0 */
    mov [rdi + 40], rbx                /* out limb 1 */
    mov [rdi + 48], rcx                /* out limb 2 */
    mov [rdi + 56], rsi                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_nine

    /* Montgomery reduction walk: t0, t1, t2, t3, t4, xi*t5 */
    mov rax, [rsp + 88]                /* table base */
    add rax, 2064                      /* next walk's bound */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_mod:
    mov rsi, rsp
    add rsi, [rbp]                     /* source T */
    mov rdi, rsp
    add rdi, [rsp + 136]               /* V or U base */
    add rdi, [rbp + 8]                 /* + coefficient offset */
    mov r8, [rsi]                      /* T0 */
    mov r9, [rsi + 8]                  /* T1 */
    mov r10, [rsi + 16]                /* T2 */
    mov r11, [rsi + 24]                /* T3 */
    mov r12, [rsi + 32]                /* T4 */
    mov r13, [rsi + 40]                /* T5 */
    mov r14, [rsi + 48]                /* T6 */
    mov r15, [rsi + 56]                /* T7 */
    xor rax, rax                       /* clear CF = OF before the dual chains */
    mov rdx, r8                        /* m0 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m0 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m0*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m0*p0)   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m0*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m0*p1 -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m0*p1)   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m0*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m0*p2 -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m0*p2)   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m0*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m0*p3 -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m0*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m0*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into t4 */
    adcx r13, rax                      /* T5 += carry-chain ripple */
    adox r13, rax                      /* T5 += value-chain ripple */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r9                        /* m1 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m1 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m1*p0 -> (lo, hi) */
    adox r9, rax                       /* t0 += lo(m1*p0)   [value chain] */
    adcx r10, rbx                      /* t1 += hi(m1*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m1*p1 -> (lo, hi) */
    adox r10, rax                      /* t1 += lo(m1*p1)   [value chain] */
    adcx r11, rbx                      /* t2 += hi(m1*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m1*p2 -> (lo, hi) */
    adox r11, rax                      /* t2 += lo(m1*p2)   [value chain] */
    adcx r12, rbx                      /* t3 += hi(m1*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m1*p3 -> (lo, hi) */
    adox r12, rax                      /* t3 += lo(m1*p3)   [value chain] */
    adcx r13, rbx                      /* t4 += hi(m1*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r13, rax                      /* close the value chain into t4 */
    adcx r14, rax                      /* T6 += carry-chain ripple */
    adox r14, rax                      /* T6 += value-chain ripple */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r10                       /* m2 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m2 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m2*p0 -> (lo, hi) */
    adox r10, rax                      /* t0 += lo(m2*p0)   [value chain] */
    adcx r11, rbx                      /* t1 += hi(m2*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m2*p1 -> (lo, hi) */
    adox r11, rax                      /* t1 += lo(m2*p1)   [value chain] */
    adcx r12, rbx                      /* t2 += hi(m2*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m2*p2 -> (lo, hi) */
    adox r12, rax                      /* t2 += lo(m2*p2)   [value chain] */
    adcx r13, rbx                      /* t3 += hi(m2*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m2*p3 -> (lo, hi) */
    adox r13, rax                      /* t3 += lo(m2*p3)   [value chain] */
    adcx r14, rbx                      /* t4 += hi(m2*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r14, rax                      /* close the value chain into t4 */
    adcx r15, rax                      /* T7 += carry-chain ripple */
    adox r15, rax                      /* T7 += value-chain ripple */
    /* invariant: CF = OF = 0 (previous row rippled both chains out under the 2pK bound) */
    mov rdx, r11                       /* m3 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m3 = t0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m3*p0 -> (lo, hi) */
    adox r11, rax                      /* t0 += lo(m3*p0)   [value chain] */
    adcx r12, rbx                      /* t1 += hi(m3*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m3*p1 -> (lo, hi) */
    adox r12, rax                      /* t1 += lo(m3*p1)   [value chain] */
    adcx r13, rbx                      /* t2 += hi(m3*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m3*p2 -> (lo, hi) */
    adox r13, rax                      /* t2 += lo(m3*p2)   [value chain] */
    adcx r14, rbx                      /* t3 += hi(m3*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m3*p3 -> (lo, hi) */
    adox r14, rax                      /* t3 += lo(m3*p3)   [value chain] */
    adcx r15, rbx                      /* t4 += hi(m3*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r15, rax                      /* close the value chain into t4 */
    /* invariant: CF = OF = 0 (T < p*2^256 keeps the total below 2p*2^256: no word beyond T7) */
    /* result T4..T7 < 2p: one conditional subtraction */
    mov rax, r12                       /* keep-copy of limb 0 */
    mov rbx, r13                       /* keep-copy of limb 1 */
    mov rdx, r14                       /* keep-copy of limb 2 */
    mov rsi, r15                       /* keep-copy of limb 3 */
    sub rax, [rsp]                     /* limb 0 -= p0 */
    sbb rbx, [rsp + 8]                 /* limb 1 -= p1 */
    sbb rdx, [rsp + 16]                /* limb 2 -= p2 */
    sbb rsi, [rsp + 24]                /* limb 3 -= p3 */
    cmovc rax, r12                     /* borrow: value < p, keep limb 0 */
    cmovc rbx, r13                     /* borrow: value < p, keep limb 1 */
    cmovc rdx, r14                     /* borrow: value < p, keep limb 2 */
    cmovc rsi, r15                     /* borrow: value < p, keep limb 3 */
    mov [rdi], rax                     /* out limb 0 */
    mov [rdi + 8], rbx                 /* out limb 1 */
    mov [rdi + 16], rdx                /* out limb 2 */
    mov [rdi + 24], rsi                /* out limb 3 */
    add rbp, 16                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_mod

    /* modular add walk 2: the z-combines -- openers (subtractions as */
    /* adds of the negp images), six in-place doublings, final += t */
    mov rax, [rsp + 88]                /* table base */
    add rax, 2928                      /* next walk's bound */
    mov [rsp + 64], rax                /* walk bound */
.Lcyc_madd2:
    mov rdi, rsp
    add rdi, [rbp]                     /* dst = rsp + row.dst */
    mov rsi, rsp
    add rsi, [rbp + 8]                 /* s1 = rsp + row.s1 */
    mov rcx, rsp
    add rcx, [rbp + 16]                /* s2 = rsp + row.s2 */
    mov r8, [rsi]                      /* s1 limb 0 */
    mov r9, [rsi + 8]                  /* s1 limb 1 */
    mov r10, [rsi + 16]                /* s1 limb 2 */
    mov r11, [rsi + 24]                /* s1 limb 3 */
    add r8, [rcx]                      /* += s2 limb 0 */
    adc r9, [rcx + 8]                  /* += s2 limb 1 */
    adc r10, [rcx + 16]                /* += s2 limb 2 */
    adc r11, [rcx + 24]                /* += s2 limb 3 */
    /* invariant: CF = OF = 0 (s1 + s2 < 2p < 2^256: no carry out) */
    mov r12, r8                        /* keep-copy of limb 0 */
    mov r13, r9                        /* keep-copy of limb 1 */
    mov r14, r10                       /* keep-copy of limb 2 */
    mov r15, r11                       /* keep-copy of limb 3 */
    sub r12, [rsp]                     /* limb 0 -= p0 */
    sbb r13, [rsp + 8]                 /* limb 1 -= p1 */
    sbb r14, [rsp + 16]                /* limb 2 -= p2 */
    sbb r15, [rsp + 24]                /* limb 3 -= p3 */
    cmovc r12, r8                      /* borrow: value < p, keep limb 0 */
    cmovc r13, r9                      /* borrow: value < p, keep limb 1 */
    cmovc r14, r10                     /* borrow: value < p, keep limb 2 */
    cmovc r15, r11                     /* borrow: value < p, keep limb 3 */
    mov [rdi], r12                     /* out limb 0 */
    mov [rdi + 8], r13                 /* out limb 1 */
    mov [rdi + 16], r14                /* out limb 2 */
    mov [rdi + 24], r15                /* out limb 3 */
    add rbp, 24                        /* advance the cursor (clobbers CF/OF) */
    cmp rbp, [rsp + 64]                /* back-edge test */
    jne .Lcyc_madd2

    /* copy out: the z area is already repr(C) Fp12, 48 limbs to z */
    mov rdi, [rsp + 48]                /* z */
    mov rsi, rsp
    add rsi, 4816                      /* z-combine base */
    xor rcx, rcx
.Lcyc_out:
    mov r8, [rsi]                      /* z limb 0 */
    mov r9, [rsi + 8]                  /* z limb 1 */
    mov r10, [rsi + 16]                /* z limb 2 */
    mov r11, [rsi + 24]                /* z limb 3 */
    mov [rdi], r8                      /* z */
    mov [rdi + 8], r9                  /* z */
    mov [rdi + 16], r10                /* z */
    mov [rdi + 24], r11                /* z */
    add rsi, 32
    add rdi, 32
    add rcx, 32                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, 384                       /* back-edge test */
    jne .Lcyc_out
    add rsp, 5200
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_cyc_sqr_x86, . - helius_cyc_sqr_x86

/* helius_sosd6_x86 register map:
   rdi  z on entry (spilled at once); then lane1 word 4
   rsi  stage pointer: walks the 24 transposed x limbs linearly, 8 bytes per pair (also the round cursor)
   rdx  consts pointer on entry (copied to the frame); the implicit mulx multiplicand
   rcx  y pair-block cursor over the five rolled pairs; the shared top word in the round tail
   r8   lane0 word 0 (prologue: p limb 0 for the negp rows)
   r9   lane0 word 1 (prologue: p limb 1)
   r10  lane0 word 2 (prologue: p limb 2)
   r11  lane0 word 3 (prologue: p limb 3)
   r12  lane0 word 4 (prologue: negp scratch)
   r13  lane1 word 0 (prologue: negp scratch)
   r14  lane1 word 1
   r15  lane1 word 2
   rbp  lane1 word 3
   rax  low half of the current product; zero for chain closes
   rbx  high half of the current product; prologue scratch
*/
    .p2align 4
    .globl helius_sosd6_x86
    .type helius_sosd6_x86, @function
helius_sosd6_x86:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 128
    /* frame: p +0, -p^-1 +32, ny21 +40, y20 copy +72, z +104, y base +112, y end +120 */
    mov [rsp + 104], rdi               /* spill z */
    /* consts into the frame: cancel rows and reductions address rsp as a table */
    mov r8, [rdx]                      /* p0 (kept live for the negp rows) */
    mov r9, [rdx + 8]                  /* p1 (kept live for the negp rows) */
    mov r10, [rdx + 16]                /* p2 (kept live for the negp rows) */
    mov r11, [rdx + 24]                /* p3 (kept live for the negp rows) */
    mov [rsp], r8                      /* p0 */
    mov [rsp + 8], r9                  /* p1 */
    mov [rsp + 16], r10                /* p2 */
    mov [rsp + 24], r11                /* p3 */
    mov rax, [rdx + 32]                /* -p^-1 */
    mov [rsp + 32], rax                /* -p^-1 */
    /* ny01 = p - y01: lane0's subtracted term enters as the negp image */
    mov rax, r8                        /* p0 */
    mov rbx, r9                        /* p1 */
    mov r12, r10                       /* p2 */
    mov r13, r11                       /* p3 */
    sub rax, [rsi + 256]               /* p0 - y01[0] */
    sbb rbx, [rsi + 264]               /* p1 - y01[1] */
    sbb r12, [rsi + 272]               /* p2 - y01[2] */
    sbb r13, [rsi + 280]               /* p3 - y01[3] */
    mov [rsi + 256], rax               /* ny01[0] */
    mov [rsi + 264], rbx               /* ny01[1] */
    mov [rsi + 272], r12               /* ny01[2] */
    mov [rsi + 280], r13               /* ny01[3] */
    /* ny11 = p - y11: lane0's subtracted term enters as the negp image */
    mov rax, r8                        /* p0 */
    mov rbx, r9                        /* p1 */
    mov r12, r10                       /* p2 */
    mov r13, r11                       /* p3 */
    sub rax, [rsi + 384]               /* p0 - y11[0] */
    sbb rbx, [rsi + 392]               /* p1 - y11[1] */
    sbb r12, [rsi + 400]               /* p2 - y11[2] */
    sbb r13, [rsi + 408]               /* p3 - y11[3] */
    mov [rsi + 384], rax               /* ny11[0] */
    mov [rsi + 392], rbx               /* ny11[1] */
    mov [rsi + 400], r12               /* ny11[2] */
    mov [rsi + 408], r13               /* ny11[3] */
    /* ny21 = p - y21: lane0's subtracted term enters as the negp image */
    mov rax, r8                        /* p0 */
    mov rbx, r9                        /* p1 */
    mov r12, r10                       /* p2 */
    mov r13, r11                       /* p3 */
    sub rax, [rsi + 480]               /* p0 - y21[0] */
    sbb rbx, [rsi + 488]               /* p1 - y21[1] */
    sbb r12, [rsi + 496]               /* p2 - y21[2] */
    sbb r13, [rsi + 504]               /* p3 - y21[3] */
    mov [rsp + 40], rax                /* ny21[0] */
    mov [rsp + 48], rbx                /* ny21[1] */
    mov [rsp + 56], r12                /* ny21[2] */
    mov [rsp + 64], r13                /* ny21[3] */
    /* copy y20 beside ny21: the tail's lane1 row reads pair 5 off rsp */
    mov rax, [rsi + 448]               /* y20[0] */
    mov rbx, [rsi + 456]               /* y20[1] */
    mov r12, [rsi + 464]               /* y20[2] */
    mov r13, [rsi + 472]               /* y20[3] */
    mov [rsp + 72], rax                /* y20[0] */
    mov [rsp + 80], rbx                /* y20[1] */
    mov [rsp + 88], r12                /* y20[2] */
    mov [rsp + 96], r13                /* y20[3] */
    mov rax, rsi
    add rax, 192                       /* y pair blocks start where the x limbs end */
    mov [rsp + 112], rax               /* y rewind value = outer loop bound */
    add rax, 320                       /* past the five rolled pair blocks */
    mov [rsp + 120], rax               /* inner walk bound */
    /* both lanes start at zero (the first round adds into zeros) */
    xor r8, r8                         /* lane0 w0 = 0 */
    xor r9, r9                         /* lane0 w1 = 0 */
    xor r10, r10                       /* lane0 w2 = 0 */
    xor r11, r11                       /* lane0 w3 = 0 */
    xor r12, r12                       /* lane0 w4 = 0 */
    xor r13, r13                       /* lane1 w0 = 0 */
    xor r14, r14                       /* lane1 w1 = 0 */
    xor r15, r15                       /* lane1 w2 = 0 */
    xor rbp, rbp                       /* lane1 w3 = 0 */
    xor rdi, rdi                       /* lane1 w4 = 0 */

    /* rounds: rsi walks the transposed x limbs, 48 bytes per round */
.Lsosd6_round:
    mov rcx, [rsp + 112]               /* y pair-block cursor rewinds */
    /* five rolled pairs: adjacent lane rows share each multiplicand */
.Lsosd6_pair:
    mov rdx, [rsi]                     /* x_i[j], the pair's multiplicand */
    xor rax, rax                       /* re-seed CF = OF = 0 (back edge clobbered flags) */
    mulx rbx, rax, qword ptr [rcx]     /* x_i[j]*row0[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x_i[j]*row0[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x_i[j]*row0[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 8] /* x_i[j]*row0[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x_i[j]*row0[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x_i[j]*row0[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 16] /* x_i[j]*row0[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x_i[j]*row0[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x_i[j]*row0[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 24] /* x_i[j]*row0[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x_i[j]*row0[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x_i[j]*row0[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into word 4 */
    /* invariant: CF = OF = 0 (value through five rows < (5*2^64 + 7)p < 2^320: word 4 cannot wrap) */
    mulx rbx, rax, qword ptr [rcx + 32] /* x_i[j]*row1[0] -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(x_i[j]*row1[0])   [value chain] */
    adcx r14, rbx                      /* t1 += hi(x_i[j]*row1[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 40] /* x_i[j]*row1[1] -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(x_i[j]*row1[1])   [value chain] */
    adcx r15, rbx                      /* t2 += hi(x_i[j]*row1[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 48] /* x_i[j]*row1[2] -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(x_i[j]*row1[2])   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(x_i[j]*row1[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rcx + 56] /* x_i[j]*row1[3] -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(x_i[j]*row1[3])   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(x_i[j]*row1[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into word 4 */
    /* invariant: CF = OF = 0 (value through five rows < (5*2^64 + 7)p < 2^320: word 4 cannot wrap) */
    add rsi, 8                         /* next x limb (clobbers CF/OF; chains are closed) */
    add rcx, 64                        /* advance the cursor (clobbers CF/OF) */
    cmp rcx, [rsp + 120]               /* back-edge test */
    jne .Lsosd6_pair
    /* pair 5: the only rows that can overflow word 4; the top word serves one lane at a time */
    xor rcx, rcx                       /* top word = 0; re-seeds CF = OF = 0 after the back edge */
    mov rdx, [rsi]                     /* x21[j] */
    mulx rbx, rax, qword ptr [rsp + 40] /* x21[j]*ny21[0] -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(x21[j]*ny21[0])   [value chain] */
    adcx r9, rbx                       /* t1 += hi(x21[j]*ny21[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 48] /* x21[j]*ny21[1] -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(x21[j]*ny21[1])   [value chain] */
    adcx r10, rbx                      /* t2 += hi(x21[j]*ny21[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 56] /* x21[j]*ny21[2] -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(x21[j]*ny21[2])   [value chain] */
    adcx r11, rbx                      /* t3 += hi(x21[j]*ny21[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 64] /* x21[j]*ny21[3] -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(x21[j]*ny21[3])   [value chain] */
    adcx r12, rbx                      /* t4 += hi(x21[j]*ny21[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into word 4 */
    adox rcx, rax                      /* ripple the word-4 close into the shared top word */
    adcx rcx, rax                      /* close the carry chain into the shared top word */
    /* invariant: CF = OF = 0 (row-6 peak < 7p + 6p*2^64 < 2^321: the top word cannot wrap) */
    /* lane0 cancel row: m = w0 * -p^-1, then += m*p zeroes w0 */
    mov rdx, r8                        /* m multiplicand <- w0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m = w0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m*p0 -> (lo, hi) */
    adox r8, rax                       /* t0 += lo(m*p0)   [value chain] */
    adcx r9, rbx                       /* t1 += hi(m*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m*p1 -> (lo, hi) */
    adox r9, rax                       /* t1 += lo(m*p1)   [value chain] */
    adcx r10, rbx                      /* t2 += hi(m*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m*p2 -> (lo, hi) */
    adox r10, rax                      /* t2 += lo(m*p2)   [value chain] */
    adcx r11, rbx                      /* t3 += hi(m*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m*p3 -> (lo, hi) */
    adox r11, rax                      /* t3 += lo(m*p3)   [value chain] */
    adcx r12, rbx                      /* t4 += hi(m*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox r12, rax                      /* close the value chain into word 4 */
    adox rcx, rax                      /* ripple the word-4 close into the shared top word */
    adcx rcx, rax                      /* close the carry chain into the shared top word */
    /* invariant: CF = OF = 0 (cancel row closed both chains under the 2^321 bound) */
    /* invariant: r8 = 0 (the Montgomery factor cancels the low word) */
    /* lane0 shift down one word: the canceled zero drops, the top word empties */
    mov r8, r9                         /* w0 = w1 */
    mov r9, r10                        /* w1 = w2 */
    mov r10, r11                       /* w2 = w3 */
    mov r11, r12                       /* w3 = w4 */
    mov r12, rcx                       /* word 4 <- the shared top word */
    xor rcx, rcx                       /* top word frees for the other lane (CF/OF stay clear) */
    mov rdx, [rsi]                     /* x21[j] again (the cancel row owned rdx) */
    mulx rbx, rax, qword ptr [rsp + 72] /* x21[j]*y20[0] -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(x21[j]*y20[0])   [value chain] */
    adcx r14, rbx                      /* t1 += hi(x21[j]*y20[0])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 80] /* x21[j]*y20[1] -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(x21[j]*y20[1])   [value chain] */
    adcx r15, rbx                      /* t2 += hi(x21[j]*y20[1])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 88] /* x21[j]*y20[2] -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(x21[j]*y20[2])   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(x21[j]*y20[2])   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 96] /* x21[j]*y20[3] -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(x21[j]*y20[3])   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(x21[j]*y20[3])   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into word 4 */
    adox rcx, rax                      /* ripple the word-4 close into the shared top word */
    adcx rcx, rax                      /* close the carry chain into the shared top word */
    /* invariant: CF = OF = 0 (row-6 peak < 7p + 6p*2^64 < 2^321: the top word cannot wrap) */
    /* lane1 cancel row: m = w0 * -p^-1, then += m*p zeroes w0 */
    mov rdx, r13                       /* m multiplicand <- w0 */
    mulx rbx, rdx, qword ptr [rsp + 32] /* m = w0 * -p^-1 mod 2^64 (hi half discarded) */
    mulx rbx, rax, qword ptr [rsp]     /* m*p0 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(m*p0)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(m*p0)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 8] /* m*p1 -> (lo, hi) */
    adox r14, rax                      /* t1 += lo(m*p1)   [value chain] */
    adcx r15, rbx                      /* t2 += hi(m*p1)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 16] /* m*p2 -> (lo, hi) */
    adox r15, rax                      /* t2 += lo(m*p2)   [value chain] */
    adcx rbp, rbx                      /* t3 += hi(m*p2)   [carry chain] */
    mulx rbx, rax, qword ptr [rsp + 24] /* m*p3 -> (lo, hi) */
    adox rbp, rax                      /* t3 += lo(m*p3)   [value chain] */
    adcx rdi, rbx                      /* t4 += hi(m*p3)   [carry chain] */
    mov rax, 0                         /* zero for the chain closes (flags preserved) */
    adox rdi, rax                      /* close the value chain into word 4 */
    adox rcx, rax                      /* ripple the word-4 close into the shared top word */
    adcx rcx, rax                      /* close the carry chain into the shared top word */
    /* invariant: CF = OF = 0 (cancel row closed both chains under the 2^321 bound) */
    /* invariant: r13 = 0 (the Montgomery factor cancels the low word) */
    /* lane1 shift down one word: the canceled zero drops, the top word empties */
    mov r13, r14                       /* w0 = w1 */
    mov r14, r15                       /* w1 = w2 */
    mov r15, rbp                       /* w2 = w3 */
    mov rbp, rdi                       /* w3 = w4 */
    mov rdi, rcx                       /* word 4 <- the shared top word */
    xor rcx, rcx                       /* top word frees for the other lane (CF/OF stay clear) */
    add rsi, 8                         /* advance the cursor (clobbers CF/OF) */
    cmp rsi, [rsp + 112]               /* back-edge test */
    jne .Lsosd6_round

    /* invariant: r12 = 0 (lane0 final value < 2.135p < 2^256 fits four words) */
    /* invariant: rdi = 0 (lane1 final value < 2.135p < 2^256 fits four words) */
    mov rdi, [rsp + 104]               /* reload z into lane1's freed word 4 */
    /* final reduction per lane: value < 2.135p, subtract p at most twice */
    mov rax, r8                        /* lane0 pass 0: keep-copy of word 0 */
    mov rbx, r9                        /* lane0 pass 0: keep-copy of word 1 */
    mov rcx, r10                       /* lane0 pass 0: keep-copy of word 2 */
    mov rdx, r11                       /* lane0 pass 0: keep-copy of word 3 */
    sub r8, [rsp]                      /* lane0: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* lane0: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* lane0: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* lane0: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: lane0 < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: lane0 < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: lane0 < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: lane0 < p, keep word 3 */
    mov rax, r8                        /* lane0 pass 1: keep-copy of word 0 */
    mov rbx, r9                        /* lane0 pass 1: keep-copy of word 1 */
    mov rcx, r10                       /* lane0 pass 1: keep-copy of word 2 */
    mov rdx, r11                       /* lane0 pass 1: keep-copy of word 3 */
    sub r8, [rsp]                      /* lane0: word 0 -= p0 */
    sbb r9, [rsp + 8]                  /* lane0: word 1 -= p1 */
    sbb r10, [rsp + 16]                /* lane0: word 2 -= p2 */
    sbb r11, [rsp + 24]                /* lane0: word 3 -= p3 */
    cmovc r8, rax                      /* borrow: lane0 < p, keep word 0 */
    cmovc r9, rbx                      /* borrow: lane0 < p, keep word 1 */
    cmovc r10, rcx                     /* borrow: lane0 < p, keep word 2 */
    cmovc r11, rdx                     /* borrow: lane0 < p, keep word 3 */
    mov [rdi], r8                      /* z[0] */
    mov [rdi + 8], r9                  /* z[1] */
    mov [rdi + 16], r10                /* z[2] */
    mov [rdi + 24], r11                /* z[3] */
    mov rax, r13                       /* lane1 pass 0: keep-copy of word 0 */
    mov rbx, r14                       /* lane1 pass 0: keep-copy of word 1 */
    mov rcx, r15                       /* lane1 pass 0: keep-copy of word 2 */
    mov rdx, rbp                       /* lane1 pass 0: keep-copy of word 3 */
    sub r13, [rsp]                     /* lane1: word 0 -= p0 */
    sbb r14, [rsp + 8]                 /* lane1: word 1 -= p1 */
    sbb r15, [rsp + 16]                /* lane1: word 2 -= p2 */
    sbb rbp, [rsp + 24]                /* lane1: word 3 -= p3 */
    cmovc r13, rax                     /* borrow: lane1 < p, keep word 0 */
    cmovc r14, rbx                     /* borrow: lane1 < p, keep word 1 */
    cmovc r15, rcx                     /* borrow: lane1 < p, keep word 2 */
    cmovc rbp, rdx                     /* borrow: lane1 < p, keep word 3 */
    mov rax, r13                       /* lane1 pass 1: keep-copy of word 0 */
    mov rbx, r14                       /* lane1 pass 1: keep-copy of word 1 */
    mov rcx, r15                       /* lane1 pass 1: keep-copy of word 2 */
    mov rdx, rbp                       /* lane1 pass 1: keep-copy of word 3 */
    sub r13, [rsp]                     /* lane1: word 0 -= p0 */
    sbb r14, [rsp + 8]                 /* lane1: word 1 -= p1 */
    sbb r15, [rsp + 16]                /* lane1: word 2 -= p2 */
    sbb rbp, [rsp + 24]                /* lane1: word 3 -= p3 */
    cmovc r13, rax                     /* borrow: lane1 < p, keep word 0 */
    cmovc r14, rbx                     /* borrow: lane1 < p, keep word 1 */
    cmovc r15, rcx                     /* borrow: lane1 < p, keep word 2 */
    cmovc rbp, rdx                     /* borrow: lane1 < p, keep word 3 */
    mov [rdi + 32], r13                /* z[4] */
    mov [rdi + 40], r14                /* z[5] */
    mov [rdi + 48], r15                /* z[6] */
    mov [rdi + 56], rbp                /* z[7] */
    add rsp, 128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size helius_sosd6_x86, . - helius_sosd6_x86

    .section .rodata
    .p2align 3
.Lfsq_tab:
    .quad 0x700
    .quad 0x100
    .quad 0x5c0
    .quad 0x680
    .quad 0x2c0
    .quad 0x80
    .quad 0x0
    .quad 0x0
    .quad 0x340
    .quad 0x100
    .quad 0x140
    .quad 0x200
    .quad 0x380
    .quad 0x1a0
    .quad 0x0
    .quad 0x0
    .quad 0x140
    .quad 0x5c0
    .quad 0x680
    .quad 0x160
    .quad 0x5e0
    .quad 0x6a0
    .quad 0x180
    .quad 0x600
    .quad 0x6c0
    .quad 0x1a0
    .quad 0x620
    .quad 0x6e0
    .quad 0x1c0
    .quad 0x640
    .quad 0x700
    .quad 0x1e0
    .quad 0x660
    .quad 0x720
    .quad 0x200
    .quad 0x100
    .quad 0x5c0
    .quad 0x220
    .quad 0x120
    .quad 0x5e0
    .quad 0x240
    .quad 0x680
    .quad 0x600
    .quad 0x260
    .quad 0x6a0
    .quad 0x620
    .quad 0x280
    .quad 0x6c0
    .quad 0x640
    .quad 0x2a0
    .quad 0x6e0
    .quad 0x660
    .quad 0x440
    .quad 0x100
    .quad 0x2c0
    .quad 0x460
    .quad 0x120
    .quad 0x2e0
    .quad 0x480
    .quad 0x2c0
    .quad 0x300
    .quad 0x4a0
    .quad 0x2e0
    .quad 0x320
    .quad 0x4c0
    .quad 0x300
    .quad 0x340
    .quad 0x4e0
    .quad 0x320
    .quad 0x360
    .quad 0x500
    .quad 0x2c0
    .quad 0x2c0
    .quad 0x520
    .quad 0x2e0
    .quad 0x2e0
    .quad 0x540
    .quad 0x300
    .quad 0x300
    .quad 0x560
    .quad 0x320
    .quad 0x320
    .quad 0x580
    .quad 0x340
    .quad 0x340
    .quad 0x5a0
    .quad 0x360
    .quad 0x360
    .quad 0x440
    .quad 0x380
    .quad 0x440
    .quad 0x460
    .quad 0x3a0
    .quad 0x460
    .quad 0x480
    .quad 0x3c0
    .quad 0x480
    .quad 0x4a0
    .quad 0x3e0
    .quad 0x4a0
    .quad 0x4c0
    .quad 0x400
    .quad 0x4c0
    .quad 0x4e0
    .quad 0x420
    .quad 0x4e0
    .quad 0xc00
    .quad 0xc00
    .quad 0xbc0
    .quad 0xc00
    .quad 0xc00
    .quad 0xc40
    .quad 0xbc0
    .quad 0xbc0
    .quad 0xc40
    .quad 0xcc0
    .quad 0xcc0
    .quad 0xc80
    .quad 0xcc0
    .quad 0xcc0
    .quad 0xd00
    .quad 0xc80
    .quad 0xc80
    .quad 0xd00
    .quad 0xd80
    .quad 0xd80
    .quad 0xd40
    .quad 0xd80
    .quad 0xd80
    .quad 0xdc0
    .quad 0xd40
    .quad 0xd40
    .quad 0xdc0
    .quad 0xe40
    .quad 0xe40
    .quad 0xe00
    .quad 0xe40
    .quad 0xe40
    .quad 0xe80
    .quad 0xe00
    .quad 0xe00
    .quad 0xe80
    .quad 0xf00
    .quad 0xf00
    .quad 0xec0
    .quad 0xf00
    .quad 0xf00
    .quad 0xf40
    .quad 0xec0
    .quad 0xec0
    .quad 0xf40
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xf80
    .quad 0xfc0
    .quad 0xfc0
    .quad 0x1000
    .quad 0xf80
    .quad 0xf80
    .quad 0x1000
    .quad 0xe00
    .quad 0xe00
    .quad 0xc80
    .quad 0xe40
    .quad 0xe40
    .quad 0xcc0
    .quad 0xe00
    .quad 0xe00
    .quad 0xd40
    .quad 0xe40
    .quad 0xe40
    .quad 0xd80
    .quad 0xec0
    .quad 0xec0
    .quad 0xbc0
    .quad 0xf00
    .quad 0xf00
    .quad 0xc00
    .quad 0xec0
    .quad 0xec0
    .quad 0xc80
    .quad 0xf00
    .quad 0xf00
    .quad 0xcc0
    .quad 0xf80
    .quad 0xf80
    .quad 0xbc0
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xc00
    .quad 0xf80
    .quad 0xf80
    .quad 0xd40
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xd80
    .quad 0x1140
    .quad 0xc0
    .quad 0xe40
    .quad 0x1180
    .quad 0xc0
    .quad 0xd80
    .quad 0x1040
    .quad 0xe00
    .quad 0x1140
    .quad 0x1080
    .quad 0xe40
    .quad 0xe00
    .quad 0x10c0
    .quad 0xd40
    .quad 0x1180
    .quad 0x1100
    .quad 0xd80
    .quad 0xd40
    .quad 0x1040
    .quad 0x1040
    .quad 0xbc0
    .quad 0x1080
    .quad 0x1080
    .quad 0xc00
    .quad 0xec0
    .quad 0xec0
    .quad 0x10c0
    .quad 0xf00
    .quad 0xf00
    .quad 0x1100
    .quad 0xf80
    .quad 0xf80
    .quad 0xc80
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xcc0
    .quad 0x1040
    .quad 0x0
    .quad 0x1080
    .quad 0x20
    .quad 0xec0
    .quad 0x40
    .quad 0xf00
    .quad 0x60
    .quad 0xf80
    .quad 0x80
    .quad 0xfc0
    .quad 0xa0
    .quad 0x40
    .quad 0x40
    .quad 0x0
    .quad 0x0
    .quad 0x20
    .quad 0x80
    .quad 0x120
    .quad 0x60
    .quad 0xc0
    .quad 0x180
    .quad 0x0
    .quad 0x60
    .quad 0x1e0
    .quad 0x0
    .quad 0xc0
.Lfmu_tab:
    .quad 0x140
    .quad 0x2c0
    .quad 0x11c0
    .quad 0x4b0
    .quad 0x528
    .quad 0x5e8
    .quad 0x200
    .quad 0x380
    .quad 0x1340
    .quad 0x4b0
    .quad 0x528
    .quad 0x5e8
    .quad 0x440
    .quad 0x500
    .quad 0x14c0
    .quad 0x4c8
    .quad 0x558
    .quad 0x678
    .quad 0x440
    .quad 0x140
    .quad 0x200
    .quad 0x460
    .quad 0x160
    .quad 0x220
    .quad 0x480
    .quad 0x180
    .quad 0x240
    .quad 0x4a0
    .quad 0x1a0
    .quad 0x260
    .quad 0x4c0
    .quad 0x1c0
    .quad 0x280
    .quad 0x4e0
    .quad 0x1e0
    .quad 0x2a0
    .quad 0x500
    .quad 0x2c0
    .quad 0x380
    .quad 0x520
    .quad 0x2e0
    .quad 0x3a0
    .quad 0x540
    .quad 0x300
    .quad 0x3c0
    .quad 0x560
    .quad 0x320
    .quad 0x3e0
    .quad 0x580
    .quad 0x340
    .quad 0x400
    .quad 0x5a0
    .quad 0x360
    .quad 0x420
    .quad 0xc00
    .quad 0xc00
    .quad 0xbc0
    .quad 0xc00
    .quad 0xc00
    .quad 0xc40
    .quad 0xbc0
    .quad 0xbc0
    .quad 0xc40
    .quad 0xcc0
    .quad 0xcc0
    .quad 0xc80
    .quad 0xcc0
    .quad 0xcc0
    .quad 0xd00
    .quad 0xc80
    .quad 0xc80
    .quad 0xd00
    .quad 0xd80
    .quad 0xd80
    .quad 0xd40
    .quad 0xd80
    .quad 0xd80
    .quad 0xdc0
    .quad 0xd40
    .quad 0xd40
    .quad 0xdc0
    .quad 0xe40
    .quad 0xe40
    .quad 0xe00
    .quad 0xe40
    .quad 0xe40
    .quad 0xe80
    .quad 0xe00
    .quad 0xe00
    .quad 0xe80
    .quad 0xf00
    .quad 0xf00
    .quad 0xec0
    .quad 0xf00
    .quad 0xf00
    .quad 0xf40
    .quad 0xec0
    .quad 0xec0
    .quad 0xf40
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xf80
    .quad 0xfc0
    .quad 0xfc0
    .quad 0x1000
    .quad 0xf80
    .quad 0xf80
    .quad 0x1000
    .quad 0xe00
    .quad 0xe00
    .quad 0xc80
    .quad 0xe40
    .quad 0xe40
    .quad 0xcc0
    .quad 0xe00
    .quad 0xe00
    .quad 0xd40
    .quad 0xe40
    .quad 0xe40
    .quad 0xd80
    .quad 0xec0
    .quad 0xec0
    .quad 0xbc0
    .quad 0xf00
    .quad 0xf00
    .quad 0xc00
    .quad 0xec0
    .quad 0xec0
    .quad 0xc80
    .quad 0xf00
    .quad 0xf00
    .quad 0xcc0
    .quad 0xf80
    .quad 0xf80
    .quad 0xbc0
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xc00
    .quad 0xf80
    .quad 0xf80
    .quad 0xd40
    .quad 0xfc0
    .quad 0xfc0
    .quad 0xd80
    .quad 0x1140
    .quad 0xc0
    .quad 0xe40
    .quad 0x1180
    .quad 0xc0
    .quad 0xd80
    .quad 0x100
    .quad 0xc0
    .quad 0x1480
    .quad 0x1040
    .quad 0xe00
    .quad 0x1140
    .quad 0x1080
    .quad 0xe40
    .quad 0xe00
    .quad 0x10c0
    .quad 0xd40
    .quad 0x1180
    .quad 0x1100
    .quad 0xd80
    .quad 0xd40
    .quad 0x1640
    .quad 0x1440
    .quad 0x100
    .quad 0x1680
    .quad 0x1480
    .quad 0x1440
    .quad 0x0
    .quad 0x1040
    .quad 0xbc0
    .quad 0x40
    .quad 0x1080
    .quad 0xc00
    .quad 0x80
    .quad 0xec0
    .quad 0x10c0
    .quad 0xc0
    .quad 0xf00
    .quad 0x1100
    .quad 0x100
    .quad 0xf80
    .quad 0xc80
    .quad 0x140
    .quad 0xfc0
    .quad 0xcc0
    .quad 0x180
    .quad 0x1640
    .quad 0x11c0
    .quad 0x1c0
    .quad 0x1680
    .quad 0x1200
    .quad 0x200
    .quad 0x1340
    .quad 0x1240
    .quad 0x240
    .quad 0x1380
    .quad 0x1280
    .quad 0x280
    .quad 0x13c0
    .quad 0x12c0
    .quad 0x2c0
    .quad 0x1400
    .quad 0x1300
    .quad 0x14c0
    .quad 0x14c0
    .quad 0x11c0
    .quad 0x14c0
    .quad 0x14c0
    .quad 0x1340
    .quad 0x1500
    .quad 0x1500
    .quad 0x1200
    .quad 0x1500
    .quad 0x1500
    .quad 0x1380
    .quad 0x1540
    .quad 0x1540
    .quad 0x1240
    .quad 0x1540
    .quad 0x1540
    .quad 0x13c0
    .quad 0x1580
    .quad 0x1580
    .quad 0x1280
    .quad 0x1580
    .quad 0x1580
    .quad 0x1400
    .quad 0x15c0
    .quad 0x15c0
    .quad 0x12c0
    .quad 0x15c0
    .quad 0x15c0
    .quad 0x1440
    .quad 0x1600
    .quad 0x1600
    .quad 0x1300
    .quad 0x1600
    .quad 0x1600
    .quad 0x1480
    .quad 0x1640
    .quad 0x5c0
    .quad 0x1680
    .quad 0x5e0
    .quad 0x16c0
    .quad 0x600
    .quad 0x1700
    .quad 0x620
    .quad 0x1740
    .quad 0x640
    .quad 0x1780
    .quad 0x660
    .quad 0x14c0
    .quad 0x680
    .quad 0x1500
    .quad 0x6a0
    .quad 0x1540
    .quad 0x6c0
    .quad 0x1580
    .quad 0x6e0
    .quad 0x15c0
    .quad 0x700
    .quad 0x1600
    .quad 0x720
    .quad 0x40
    .quad 0x40
    .quad 0x0
    .quad 0x0
    .quad 0x20
    .quad 0x80
    .quad 0x120
    .quad 0x60
    .quad 0xc0
    .quad 0x180
    .quad 0x0
    .quad 0x60
    .quad 0x1e0
    .quad 0x0
    .quad 0xc0
.Lcyc_tab:
    .quad 0x250
    .quad 0xd0
    .quad 0x1d0
    .quad 0x270
    .quad 0xf0
    .quad 0x1f0
    .quad 0x290
    .quad 0x190
    .quad 0x150
    .quad 0x2b0
    .quad 0x1b0
    .quad 0x170
    .quad 0x2d0
    .quad 0x110
    .quad 0x210
    .quad 0x2f0
    .quad 0x130
    .quad 0x230
    .quad 0x3f0
    .quad 0xd0
    .quad 0xf0
    .quad 0x410
    .quad 0xf0
    .quad 0xf0
    .quad 0x430
    .quad 0xd0
    .quad 0x60
    .quad 0x470
    .quad 0x1d0
    .quad 0x1f0
    .quad 0x490
    .quad 0x1f0
    .quad 0x1f0
    .quad 0x4b0
    .quad 0x1d0
    .quad 0x60
    .quad 0x4f0
    .quad 0x250
    .quad 0x270
    .quad 0x510
    .quad 0x270
    .quad 0x270
    .quad 0x530
    .quad 0x250
    .quad 0x60
    .quad 0x570
    .quad 0x190
    .quad 0x1b0
    .quad 0x590
    .quad 0x1b0
    .quad 0x1b0
    .quad 0x5b0
    .quad 0x190
    .quad 0x60
    .quad 0x5f0
    .quad 0x150
    .quad 0x170
    .quad 0x610
    .quad 0x170
    .quad 0x170
    .quad 0x630
    .quad 0x150
    .quad 0x60
    .quad 0x670
    .quad 0x290
    .quad 0x2b0
    .quad 0x690
    .quad 0x2b0
    .quad 0x2b0
    .quad 0x6b0
    .quad 0x290
    .quad 0x60
    .quad 0x6f0
    .quad 0x110
    .quad 0x130
    .quad 0x710
    .quad 0x130
    .quad 0x130
    .quad 0x730
    .quad 0x110
    .quad 0x60
    .quad 0x770
    .quad 0x210
    .quad 0x230
    .quad 0x790
    .quad 0x230
    .quad 0x230
    .quad 0x7b0
    .quad 0x210
    .quad 0x60
    .quad 0x7f0
    .quad 0x2d0
    .quad 0x2f0
    .quad 0x810
    .quad 0x2f0
    .quad 0x2f0
    .quad 0x830
    .quad 0x2d0
    .quad 0x60
    .quad 0x3d0
    .quad 0xd0
    .quad 0xf0
    .quad 0x450
    .quad 0x1d0
    .quad 0x1f0
    .quad 0x4d0
    .quad 0x250
    .quad 0x270
    .quad 0x550
    .quad 0x190
    .quad 0x1b0
    .quad 0x5d0
    .quad 0x150
    .quad 0x170
    .quad 0x650
    .quad 0x290
    .quad 0x2b0
    .quad 0x6d0
    .quad 0x110
    .quad 0x130
    .quad 0x750
    .quad 0x210
    .quad 0x230
    .quad 0x7d0
    .quad 0x2d0
    .quad 0x2f0
    .quad 0x310
    .quad 0x60
    .quad 0xd0
    .quad 0x330
    .quad 0x60
    .quad 0xf0
    .quad 0x350
    .quad 0x60
    .quad 0x110
    .quad 0x370
    .quad 0x60
    .quad 0x130
    .quad 0x390
    .quad 0x60
    .quad 0x150
    .quad 0x3b0
    .quad 0x60
    .quad 0x170
    .quad 0xdd0
    .quad 0x850
    .quad 0x910
    .quad 0xcd0
    .quad 0x60
    .quad 0x890
    .quad 0xe10
    .quad 0x8d0
    .quad 0xcd0
    .quad 0xe50
    .quad 0x9d0
    .quad 0xa90
    .quad 0xd10
    .quad 0x60
    .quad 0xa10
    .quad 0xe90
    .quad 0xa50
    .quad 0xd10
    .quad 0xed0
    .quad 0xb50
    .quad 0xc10
    .quad 0xd50
    .quad 0x60
    .quad 0xb90
    .quad 0xf10
    .quad 0xbd0
    .quad 0xd50
    .quad 0x950
    .quad 0x950
    .quad 0x850
    .quad 0x950
    .quad 0x950
    .quad 0x8d0
    .quad 0x990
    .quad 0x990
    .quad 0x890
    .quad 0x990
    .quad 0x990
    .quad 0x910
    .quad 0xad0
    .quad 0xad0
    .quad 0x9d0
    .quad 0xad0
    .quad 0xad0
    .quad 0xa50
    .quad 0xb10
    .quad 0xb10
    .quad 0xa10
    .quad 0xb10
    .quad 0xb10
    .quad 0xa90
    .quad 0xc50
    .quad 0xc50
    .quad 0xb50
    .quad 0xc50
    .quad 0xc50
    .quad 0xbd0
    .quad 0xc90
    .quad 0xc90
    .quad 0xb90
    .quad 0xc90
    .quad 0xc90
    .quad 0xc10
    .quad 0xd90
    .quad 0x60
    .quad 0xc90
    .quad 0xf50
    .quad 0x8d0
    .quad 0xdd0
    .quad 0xf90
    .quad 0x910
    .quad 0xe10
    .quad 0xfd0
    .quad 0xa50
    .quad 0xe50
    .quad 0x1010
    .quad 0xa90
    .quad 0xe90
    .quad 0x1050
    .quad 0xbd0
    .quad 0xed0
    .quad 0x1090
    .quad 0xc10
    .quad 0xf10
    .quad 0x10d0
    .quad 0xc50
    .quad 0xd90
    .quad 0x1110
    .quad 0xc90
    .quad 0xc50
    .quad 0xf50
    .quad 0x1150
    .quad 0xf90
    .quad 0x1170
    .quad 0x950
    .quad 0x1190
    .quad 0x990
    .quad 0x11b0
    .quad 0xfd0
    .quad 0x11d0
    .quad 0x1010
    .quad 0x11f0
    .quad 0xad0
    .quad 0x1210
    .quad 0xb10
    .quad 0x1230
    .quad 0x1050
    .quad 0x1250
    .quad 0x1090
    .quad 0x1270
    .quad 0x10d0
    .quad 0x1290
    .quad 0x1110
    .quad 0x12b0
    .quad 0x12d0
    .quad 0x1150
    .quad 0x310
    .quad 0x12f0
    .quad 0x1170
    .quad 0x330
    .quad 0x1310
    .quad 0x11d0
    .quad 0x350
    .quad 0x1330
    .quad 0x11f0
    .quad 0x370
    .quad 0x1350
    .quad 0x1250
    .quad 0x390
    .quad 0x1370
    .quad 0x1270
    .quad 0x3b0
    .quad 0x1390
    .quad 0x1290
    .quad 0x190
    .quad 0x13b0
    .quad 0x12b0
    .quad 0x1b0
    .quad 0x13d0
    .quad 0x1190
    .quad 0x1d0
    .quad 0x13f0
    .quad 0x11b0
    .quad 0x1f0
    .quad 0x1410
    .quad 0x210
    .quad 0x1210
    .quad 0x1430
    .quad 0x230
    .quad 0x1230
    .quad 0x12d0
    .quad 0x12d0
    .quad 0x12d0
    .quad 0x12f0
    .quad 0x12f0
    .quad 0x12f0
    .quad 0x1310
    .quad 0x1310
    .quad 0x1310
    .quad 0x1330
    .quad 0x1330
    .quad 0x1330
    .quad 0x1350
    .quad 0x1350
    .quad 0x1350
    .quad 0x1370
    .quad 0x1370
    .quad 0x1370
    .quad 0x1390
    .quad 0x1390
    .quad 0x1390
    .quad 0x13b0
    .quad 0x13b0
    .quad 0x13b0
    .quad 0x13d0
    .quad 0x13d0
    .quad 0x13d0
    .quad 0x13f0
    .quad 0x13f0
    .quad 0x13f0
    .quad 0x1410
    .quad 0x1410
    .quad 0x1410
    .quad 0x1430
    .quad 0x1430
    .quad 0x1430
    .quad 0x12d0
    .quad 0x12d0
    .quad 0x1150
    .quad 0x12f0
    .quad 0x12f0
    .quad 0x1170
    .quad 0x1310
    .quad 0x1310
    .quad 0x11d0
    .quad 0x1330
    .quad 0x1330
    .quad 0x11f0
    .quad 0x1350
    .quad 0x1350
    .quad 0x1250
    .quad 0x1370
    .quad 0x1370
    .quad 0x1270
    .quad 0x1390
    .quad 0x1390
    .quad 0x1290
    .quad 0x13b0
    .quad 0x13b0
    .quad 0x12b0
    .quad 0x13d0
    .quad 0x13d0
    .quad 0x1190
    .quad 0x13f0
    .quad 0x13f0
    .quad 0x11b0
    .quad 0x1410
    .quad 0x1410
    .quad 0x1210
    .quad 0x1430
    .quad 0x1430
    .quad 0x1230

    .section .note.GNU-stack, "", @progbits
