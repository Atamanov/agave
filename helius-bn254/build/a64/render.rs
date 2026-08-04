//! Render the complete AArch64 `.s` text: provenance header, register map,
//! and the emitted schedule. The build script writes this text to OUT_DIR
//! and assembles it for aarch64-apple targets; no copy is checked in.

use super::emit::EmitterA64;
use super::schedule::{MONT4_REGISTER_MAP, mont4};

/// Apple Mach-O symbol (underscore-prefixed at the assembly level; the Rust
/// FFI declaration in `src/fp/aarch64.rs` names it `helius_mont4`).
pub const MONT4_SYMBOL: &str = "_helius_mont4";
pub const MONT4_SCHEDULE_NAME: &str = "bn254-mont4-cios-rolled";

/// Render the full AArch64 kernel file. Byte-for-byte deterministic (no
/// timestamps, paths, or host data); tests assert generate-twice identity.
pub fn render_mont4_aarch64() -> String {
    let mut emitter = EmitterA64::new();
    mont4(&mut emitter);
    let instructions = emitter.instructions();
    let bytes = emitter.bytes();
    let body = emitter.into_lines();

    let mut out = String::new();
    let mut line = |text: &str| {
        out.push_str(text);
        out.push('\n');
    };

    line("/* @generated at build time by the helius-bn254 build script.");
    line("   Source of truth: crates/helius-bn254/build/a64/schedule.rs (ADR 0001).");
    line("   Inspect a copy: HELIUS_DUMP_ASM=<absolute dir> cargo build.");
    line("   Verified by: tests/kernelgen_verify.rs (interpreter + determinism).");
    line("");
    line(&format!(
        "   {MONT4_SYMBOL}: schedule {MONT4_SCHEDULE_NAME}, {instructions} instructions, {bytes} bytes",
    ));
    line("");
    line("   AAPCS64 (Apple), leaf; the counted loop is one CIOS round.");
    line("   Arguments: (z: *mut u64x4, x: *const u64x4, y: *const u64x4,");
    line("               consts: *const { p: [u64; 4], neg_p_inv: u64 })");
    line("   Contract and safety boundary live beside the only caller in");
    line("   src/fp/aarch64.rs; carry bounds live in build/a64/schedule.rs. */");
    line("");
    line(&format!("/* {MONT4_SYMBOL} register map:"));
    for (reg, role) in MONT4_REGISTER_MAP {
        line(&format!("   {:<4} {}", reg.name(), role));
    }
    line("*/");
    line("    .text");
    line("    .align 3");
    line(&format!("    .globl {MONT4_SYMBOL}"));
    line(&format!("{MONT4_SYMBOL}:"));
    for body_line in &body {
        line(body_line);
    }
    out
}

/// (instructions, bytes) for the kernel.
#[cfg(test)]
pub fn kernel_size() -> (usize, usize) {
    let mut emitter = EmitterA64::new();
    mont4(&mut emitter);
    (emitter.instructions(), emitter.bytes())
}
