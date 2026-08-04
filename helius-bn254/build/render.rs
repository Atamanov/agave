//! Render the complete x86-64 `.s` text: provenance header, per-kernel
//! register maps, and the emitted schedules. The build script writes this
//! text to OUT_DIR and assembles it; no copy is a build input. The only
//! checked-in `.s` files are the golden snapshots under `tests/golden/`,
//! diffed against this render by `tests/kernel_golden.rs`.

use super::emit::Emitter;
use super::machine::Reg;
use super::schedule::{
    CYC_SQR_REGISTER_MAP, FP6_REGISTER_MAP, FP12_034_REGISTER_MAP, FP12_MUL_REGISTER_MAP,
    FP12_SQR_REGISTER_MAP, MUL_REGISTER_MAP, SOS_REGISTER_MAP, SOSD2_SMALL_REGISTER_MAP,
    SOSD6_REGISTER_MAP, SQR_REGISTER_MAP, cyc_sqr_x86, fp6_mul_x86, fp12_034_x86, fp12_mul_x86,
    fp12_sqr_x86, mont4_mul, mont4_sqr, sos_rolled, sosd2_small_x86, sosd6_x86,
};

pub const MUL_SYMBOL: &str = "helius_mont4_mul_x86";
pub const SQR_SYMBOL: &str = "helius_mont4_sqr_x86";
pub const SOS_SYMBOL: &str = "helius_sos_x86";
pub const SOSD2_SMALL_SYMBOL: &str = "helius_sosd2_small_x86";
pub const FP6_SYMBOL: &str = "helius_fp6_mul_x86";
pub const FP12_034_SYMBOL: &str = "helius_fp12_034_x86";
pub const FP12_SQR_SYMBOL: &str = "helius_fp12_sqr_x86";
pub const FP12_MUL_SYMBOL: &str = "helius_fp12_mul_x86";
pub const CYC_SQR_SYMBOL: &str = "helius_cyc_sqr_x86";
pub const SOSD6_SYMBOL: &str = "helius_sosd6_x86";

/// One registered kernel: everything the renderer, the provenance header,
/// and the verification suite need, in emission order. The single source of
/// truth for the kernel roster -- `kernelgen_verify` asserts against this
/// table instead of parallel lists.
pub struct KernelSpec {
    pub symbol: &'static str,
    pub schedule_name: &'static str,
    pub register_map: &'static [(Reg, &'static str)],
    pub schedule: fn(&mut Emitter),
    /// Counted back edges (`jne`) the kernel body must contain, exactly.
    pub back_edges: usize,
    /// Op-cache byte budget (inclusive), where the frontend thesis sets one.
    pub max_bytes: Option<usize>,
}

pub const KERNELS: [KernelSpec; 10] = [
    KernelSpec {
        symbol: MUL_SYMBOL,
        schedule_name: "bn254-mont4-mul-cios-dual-chain",
        register_map: MUL_REGISTER_MAP,
        schedule: mont4_mul::<Emitter>,
        back_edges: 0,
        max_bytes: None,
    },
    KernelSpec {
        symbol: SQR_SYMBOL,
        schedule_name: "bn254-mont4-sqr-cross-double",
        register_map: SQR_REGISTER_MAP,
        schedule: mont4_sqr::<Emitter>,
        back_edges: 0,
        max_bytes: None,
    },
    KernelSpec {
        symbol: SOS_SYMBOL,
        schedule_name: "bn254-sos-rolled-dual-chain",
        register_map: SOS_REGISTER_MAP,
        schedule: sos_rolled::<Emitter>,
        // Round and pair loops.
        back_edges: 2,
        max_bytes: Some(767),
    },
    KernelSpec {
        symbol: SOSD2_SMALL_SYMBOL,
        schedule_name: "bn254-sosd2-dual-lane-rolled",
        register_map: SOSD2_SMALL_REGISTER_MAP,
        schedule: sosd2_small_x86::<Emitter>,
        // The rolled round loop.
        back_edges: 1,
        max_bytes: Some(1023),
    },
    KernelSpec {
        symbol: FP6_SYMBOL,
        schedule_name: "bn254-fp6-mul-rolled-dual-lane-t6",
        register_map: FP6_REGISTER_MAP,
        schedule: fp6_mul_x86::<Emitter>,
        // b copy, xi outer/inner, component/round/lane/product.
        back_edges: 7,
        max_bytes: Some(1536),
    },
    KernelSpec {
        symbol: FP12_034_SYMBOL,
        schedule_name: "bn254-fp12-034-rolled-dual-lane-t6",
        register_map: FP12_034_REGISTER_MAP,
        schedule: fp12_034_x86::<Emitter>,
        // g copy, coefficient copy, xi outer/inner,
        // component/round/lane/product/output.
        back_edges: 9,
        max_bytes: Some(1792),
    },
    KernelSpec {
        symbol: FP12_SQR_SYMBOL,
        schedule_name: "bn254-fp12-sqr-lazy-karatsuba-dblwidth",
        register_map: FP12_SQR_REGISTER_MAP,
        schedule: fp12_sqr_x86::<Emitter>,
        // f stage, outer, muxi halves, modadd walk, side/single/sums/sum-row
        // staging, product k/m/j, gsub/nine/gadd/mod walks, modsub walk,
        // copy out.
        back_edges: 17,
        max_bytes: Some(3072),
    },
    KernelSpec {
        symbol: FP12_MUL_SYMBOL,
        schedule_name: "bn254-fp12-mul-lazy-karatsuba-dblwidth",
        register_map: FP12_MUL_REGISTER_MAP,
        schedule: fp12_mul_x86::<Emitter>,
        // a/b staging, modadd walk, outer, side/single/sums/sum-row staging,
        // product k/m/j, gsub/nine/gadd walks, epilogue gsub and mod walks,
        // copy out.
        back_edges: 17,
        max_bytes: Some(3072),
    },
    KernelSpec {
        symbol: CYC_SQR_SYMBOL,
        schedule_name: "bn254-cyc-sqr-lazy-fp4-dblwidth",
        register_map: CYC_SQR_REGISTER_MAP,
        schedule: cyc_sqr_x86::<Emitter>,
        // f stage, madd1/msub walks, product outer/round, gsub/nine/mod/madd2
        // walks, copy out.
        back_edges: 10,
        max_bytes: Some(2112),
    },
    KernelSpec {
        symbol: SOSD6_SYMBOL,
        schedule_name: "bn254-sosd6-dual-lane-rolled-t6",
        register_map: SOSD6_REGISTER_MAP,
        schedule: sosd6_x86::<Emitter>,
        // Round and pair loops.
        back_edges: 2,
        max_bytes: Some(1535),
    },
];

struct Kernel {
    symbol: &'static str,
    schedule_name: &'static str,
    register_map: &'static [(Reg, &'static str)],
    body: Vec<String>,
    instructions: usize,
    bytes: usize,
    rodata: Vec<(String, Vec<u64>)>,
    rodata_bytes: usize,
}

fn emit_kernel(spec: &KernelSpec) -> Kernel {
    let mut emitter = Emitter::new();
    (spec.schedule)(&mut emitter);
    let instructions = emitter.instructions();
    let bytes = emitter.bytes();
    let rodata_bytes = emitter.rodata_bytes();
    let (body, rodata) = emitter.into_parts();
    assert_eq!(
        body.iter().filter(|line| line.contains("jne")).count(),
        spec.back_edges,
        "{} back-edge count changed",
        spec.symbol,
    );
    if let Some(max_bytes) = spec.max_bytes {
        assert!(
            bytes <= max_bytes,
            "{} exceeds its {}-byte limit",
            spec.symbol,
            max_bytes,
        );
    }
    Kernel {
        symbol: spec.symbol,
        schedule_name: spec.schedule_name,
        register_map: spec.register_map,
        instructions,
        bytes,
        body,
        rodata,
        rodata_bytes,
    }
}

fn kernels() -> [Kernel; 10] {
    core::array::from_fn(|i| emit_kernel(&KERNELS[i]))
}

/// Render the full x86-64 kernel file. Byte-for-byte deterministic (no
/// timestamps, paths, or host data); tests assert generate-twice identity.
pub fn render_mont4_x86_64() -> String {
    let kernels = kernels();
    let mut out = String::new();
    let mut line = |text: &str| {
        out.push_str(text);
        out.push('\n');
    };

    line("/* @generated at build time by the helius-bn254 build script.");
    line("   Source of truth: crates/helius-bn254/build/schedule.rs (ADR 0001).");
    line("   Inspect a copy: HELIUS_DUMP_ASM=<absolute dir> cargo build.");
    line("   Verified by: tests/kernelgen_verify.rs (interpreter + determinism).");
    line("");
    for kernel in &kernels {
        if kernel.rodata_bytes == 0 {
            line(&format!(
                "   {}: schedule {}, {} instructions, {} bytes",
                kernel.symbol, kernel.schedule_name, kernel.instructions, kernel.bytes,
            ));
        } else {
            line(&format!(
                "   {}: schedule {}, {} instructions, {} bytes, {} rodata bytes",
                kernel.symbol,
                kernel.schedule_name,
                kernel.instructions,
                kernel.bytes,
                kernel.rodata_bytes,
            ));
        }
    }
    line("");
    line("   System V AMD64; requires BMI2 (mulx) and ADX (adox/adcx).");
    line("   mont4 arguments: (z: *mut u64x4, x: *const u64x4, y: *const u64x4,");
    line("                     consts: *const { p: [u64; 4], neg_p_inv: u64 })");
    line("   sos arguments:   (z: *mut u64x4, pairs: *const *const u64,");
    line("                     t: u64 even pair count in 2..=10, consts as above);");
    line("   pairs holds 2t pointers a_0, b_0, ..., operands below or at p.");
    line("   sosd2_small arguments: (z: *mut u64x8 lane0 then lane1, x0, x1,");
    line("                     y0, y1: *const u64x4 at most p, consts as above);");
    line("   lane0 = (x0*y0 + x1*(p - y1))/R, lane1 = (x0*y1 + x1*y0)/R mod p,");
    line("   rolled rounds (op-cache-compact).");
    line("   fp6_mul arguments: (z: *mut u64x24, a, b: *const u64x24 in repr(C)");
    line("                       Fp6 order c0.re, c0.im, .., c2.im, all Fp < p;");
    line("                       consts: *const { p: [u64; 4], neg_p_inv: u64,");
    line("                       mu: u64 = floor(2^310/p) });");
    line("   z = a*b in Fp6 = Fp2[v]/(v^3 - (9+u)), all outputs canonical.");
    line("   fp12_034 arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)");
    line("                        Fp12 order (c0 then c1, each Fp6 as above),");
    line("                        z == f allowed; c: *const u64x24 = the sparse");
    line("                        coefficients c0, c3, c4 as contiguous Fp2s;");
    line("                        consts as fp6_mul);");
    line("   z = f * (c0 + c3*w + c4*v*w) in Fp12 = Fp6[w]/(w^2 - v), all Fp");
    line("   inputs canonical, outputs canonical (arkworks mul_by_034).");
    line("   fp12_sqr arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)");
    line("                        Fp12 order, z == f allowed; consts as");
    line("                        fp6_mul);");
    line("   z = f^2 via mcl's lazy double-width shape: 36 raw 4x4 products");
    line("   and 12 Montgomery reductions, cross terms held as 512-bit values");
    line("   mod p*2^256 (needs p < 2^254; BN254: yes), outputs canonical.");
    line("   fp12_mul arguments: (z: *mut u64x48, a, b: *const u64x48 in");
    line("                        repr(C) Fp12 order, z may alias a and/or b;");
    line("                        consts as fp6_mul);");
    line("   z = a*b via the same lazy shape: 54 raw 4x4 products and 12");
    line("   Montgomery reductions (3 Fp6Dbl mulPre + double-width mulVadd");
    line("   and Karatsuba assembly mod p*2^256), outputs canonical.");
    line("   cyc_sqr arguments: (z: *mut u64x48, f: *const u64x48 in repr(C)");
    line("                       Fp12 order, z == f allowed; consts as");
    line("                       fp6_mul);");
    line("   z = the Granger-Scott cyclotomic square of f via three lazy Fp4");
    line("   squares (Fp2Dbl sqrPre complex method): 18 raw 4x4 products and");
    line("   12 Montgomery reductions, single-width z-combines; equals f^2");
    line("   exactly on the cyclotomic subgroup, and the composed formula");
    line("   bit for bit on any canonical input.");
    line("   sosd6 arguments: (z: *mut u64x8 lane0 then lane1, stage: *mut");
    line("                     u64x64 wrapper-built scratch, consts as mont4);");
    line("   stage: +0 the 24 x limbs transposed (x_i[j] at 8*(6j+i), operand");
    line("   order x00 x01 x10 x11 x20 x21), +192 five 64-byte y pair blocks");
    line("   [y00,y01] [y01,y00] [y10,y11] [y11,y10] [y20,y21]; the kernel");
    line("   overwrites the low vectors of blocks 1 and 3 with p - y01 and");
    line("   p - y11 in place. lane0 = (sum x_i0*y_i0 + x_i1*(p - y_i1))/R,");
    line("   lane1 = (sum x_i0*y_i1 + x_i1*y_i0)/R mod p, operands at most p,");
    line("   both lanes canonical.");
    line("   Valid for any 4x64 modulus with p < 2^62 * 2^192 (BN254: yes);");
    line("   carry-bound proofs live in build/schedule.rs. */");
    line("");
    line("    .text");
    line("    .intel_syntax noprefix");

    for kernel in &kernels {
        line("");
        line(&format!("/* {} register map:", kernel.symbol));
        for (reg, role) in kernel.register_map {
            line(&format!("   {:<4} {}", reg.name(), role));
        }
        line("*/");
        line("    .p2align 4");
        line(&format!("    .globl {}", kernel.symbol));
        line(&format!("    .type {}, @function", kernel.symbol));
        line(&format!("{}:", kernel.symbol));
        for body_line in &kernel.body {
            line(body_line);
        }
        line(&format!("    .size {0}, . - {0}", kernel.symbol));
    }

    // Walk tables live in .rodata: data-cache traffic, not op-cache mass.
    if kernels.iter().any(|kernel| !kernel.rodata.is_empty()) {
        line("");
        line("    .section .rodata");
        line("    .p2align 3");
        for kernel in &kernels {
            for (label, values) in &kernel.rodata {
                line(&format!("{label}:"));
                for value in values {
                    line(&format!("    .quad {value:#x}"));
                }
            }
        }
    }

    line("");
    line("    .section .note.GNU-stack, \"\", @progbits");
    out
}

/// (instructions, bytes) per kernel, in `[mul, sqr, sos, sosd2_small,
/// fp6_mul, fp12_034, fp12_sqr, fp12_mul, cyc_sqr, sosd6]` order.
#[cfg(test)]
pub fn kernel_sizes() -> [(usize, usize); 10] {
    kernels().map(|kernel| (kernel.instructions, kernel.bytes))
}
