//! Generates the assembly kernels from the schedule DSL at build time
//! (ADR 0001, build-time amendment). No `.s` file is a build input: the text
//! is rendered in-memory from `build/`, written to OUT_DIR, and assembled
//! there. The only checked-in `.s` files are the golden snapshots under
//! `tests/golden/` (reviewed, regenerated with `HELIOS_BLESS=1`, diffed by
//! `tests/kernel_golden.rs`); the build never reads them.
//! `tests/kernelgen_verify.rs` includes the same modules and verifies the
//! schedules with a bit-accurate interpreter plus a determinism gate.

#[path = "build/mod.rs"]
mod kernelgen;

use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
};

/// The generated kernels, rendered on every build (host-independent and
/// deterministic). `[(file name, text)]`.
fn generated_kernels() -> [(&'static str, String); 2] {
    [
        (
            "mont4_aarch64.s",
            kernelgen::a64::render::render_mont4_aarch64(),
        ),
        ("mont4_x86_64.s", kernelgen::render::render_mont4_x86_64()),
    ]
}

fn write_kernel(directory: &Path, name: &str, text: &str) -> io::Result<PathBuf> {
    let path = directory.join(name);
    std::fs::write(&path, text).map_err(|error| {
        io::Error::new(error.kind(), format!("write {}: {error}", path.display()))
    })?;
    Ok(path)
}

/// Whether the CPU this build targets is Intel: an explicit Intel
/// `-C target-cpu` name, or `native` on a GenuineIntel build host (native
/// means host-targeted, so reading the host vendor is exact). AMD (`znver*`),
/// generic tuning levels, and anything unrecognized answer no.
fn target_cpu_is_intel() -> bool {
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let cpu = flags
        .split('\x1f')
        .filter_map(|f| {
            f.strip_prefix("-Ctarget-cpu=")
                .or_else(|| f.strip_prefix("target-cpu="))
        })
        .next_back()
        .unwrap_or("")
        .to_string();
    if cpu.starts_with("znver") || cpu.is_empty() || cpu.starts_with("x86-64") {
        return false;
    }
    if cpu == "native" {
        return std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.contains("GenuineIntel"))
            .unwrap_or(false);
    }
    const INTEL: &[&str] = &[
        "icelake",
        "sapphirerapids",
        "graniterapids",
        "emeraldrapids",
        "skylake",
        "cascadelake",
        "cooperlake",
        "tigerlake",
        "rocketlake",
        "alderlake",
        "raptorlake",
        "meteorlake",
    ];
    INTEL.iter().any(|p| cpu.starts_with(p))
}

/// Whether the CPU this build targets is AMD: an explicit `znver*`
/// `-C target-cpu`, or `native` on an AuthenticAMD build host. Generic
/// tuning levels and anything unrecognized answer no (same discipline as
/// [`target_cpu_is_intel`]: an unknown target gets neither vendor default).
fn target_cpu_is_amd() -> bool {
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let cpu = flags
        .split('\x1f')
        .filter_map(|f| {
            f.strip_prefix("-Ctarget-cpu=")
                .or_else(|| f.strip_prefix("target-cpu="))
        })
        .next_back()
        .unwrap_or("");
    if cpu.starts_with("znver") {
        return true;
    }
    if cpu == "native" {
        return std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.contains("AuthenticAMD"))
            .unwrap_or(false);
    }
    false
}

/// What an unset leaf toggle resolves to.
enum ToggleDefault {
    Off,
    On,
    /// Follows the target CPU: on exactly when the vendor probe answers yes.
    Vendor(fn() -> bool),
}

/// One HELIOS_*_ASM leaf toggle: env override, emitted activation cfg,
/// default policy, and the accepted-values text for the rejection message
/// (it also states the default). The cfg is the full dispatch decision --
/// emitted only when the toggle resolves on AND the target is the ADX tier
/// AND the force-portable feature is off -- so every dispatch site is a
/// plain two-arm `#[cfg(helios_*_active)]` / `#[cfg(not(...))]`. The
/// comment above each row is the measured verdict that set its default.
struct Toggle {
    env: &'static str,
    cfg: &'static str,
    default: ToggleDefault,
    values: &'static str,
}

const LEAF_TOGGLES: &[Toggle] = &[
    // The sosd2 leaf is always assembled and interpreter-verified; the
    // toggle only selects what the production dispatch links to. Measured on
    // Zen 4 the asm leaf beats the portable body in isolation (-13% latency)
    // but is neutral through the full pairing; on Granite Rapids it loses at
    // both levels. Portable is therefore the default on every target, and
    // HELIOS_SOSD2_ASM=1 opts a build into the asm leaf (AMD deployments).
    Toggle {
        env: "HELIOS_SOSD2_ASM",
        cfg: "helios_sosd2_active",
        default: ToggleDefault::Off,
        values: "0 (portable, default) or 1 (asm leaf)",
    },
    // Dedicated dual-lane T = 6 leaf: one call replaces the composed sosd6
    // route's two serial helios_sos_x86 walks (whose single-lane carry
    // chains cannot overlap), 24 pointer-table stores, and three Rust negp
    // temporaries, with both lanes' chains interleaved like the sosd2 leaf.
    // Measured: Miller -3.8% on Zen 4, flipping the full pairing past mcl
    // (409-410 vs 414 us on-box); no effect on Intel, whose dispatch sites
    // the vendor-default leaves already own. Default follows the target CPU:
    // on for AMD, off elsewhere; HELIOS_SOSD6_ASM overrides.
    Toggle {
        env: "HELIOS_SOSD6_ASM",
        cfg: "helios_sosd6_active",
        default: ToggleDefault::Vendor(target_cpu_is_amd),
        values: "0 (composed) or 1 (leaf); unset follows the target CPU",
    },
    // Whole-Fp6 multiply leaf: one call replaces three sosd6 dispatches
    // (six helios_sos_x86 calls, 72 pointer-table stores, nine negp temps, or
    // three sosd6-leaf calls on the AMD default) and both Rust xi scalings.
    // Measured through the full pairing it wins
    // on Zen 4 (-1.3%) and Granite Rapids (-0.5%), so it defaults on;
    // HELIOS_FP6_ASM=0 restores the composed path.
    Toggle {
        env: "HELIOS_FP6_ASM",
        cfg: "helios_fp6_active",
        default: ToggleDefault::On,
        values: "1 (leaf, default) or 0 (composed)",
    },
    // Whole sparse Fp12 multiply leaf (the Miller loop's per-line update):
    // one call replaces six sosd6 dispatches (twelve helios_sos_x86 calls,
    // 144 pointer-table stores, eighteen negp temps, or six sosd6-leaf calls
    // on the AMD default) and both Rust xi scalings. Microarch-split result:
    // -4% Miller loop on Granite Rapids,
    // +3% on Zen 4, whose store ports hide the composed path's marshalling
    // while the leaf's 48-limb aliasing stage costs it. Default follows the
    // target CPU: on for Intel, off for AMD and for targets whose vendor is
    // unknown; HELIOS_FP12_034_ASM overrides either way.
    Toggle {
        env: "HELIOS_FP12_034_ASM",
        cfg: "helios_fp12_034_active",
        default: ToggleDefault::Vendor(target_cpu_is_intel),
        values: "0 (composed) or 1 (leaf); unset follows the target CPU",
    },
    // Whole Fp12 square leaf (63 calls per Miller loop): mcl's lazy
    // double-width shape, 36 raw products + 12 reductions where the composed
    // SoS path pays 72 + 12 (flattened to six sosd6 rows; the -6% Miller
    // verdict below was measured against the earlier 84-product body).
    // Measured: Miller -6% on Granite Rapids, neutral on Zen 4 (its excess is
    // scheduling, not mass). Default follows the target CPU like the 034 leaf;
    // HELIOS_FP12_SQR_ASM overrides.
    Toggle {
        env: "HELIOS_FP12_SQR_ASM",
        cfg: "helios_fp12_sqr_active",
        default: ToggleDefault::Vendor(target_cpu_is_intel),
        values: "0 (composed) or 1 (leaf); unset follows the target CPU",
    },
    // Whole Fp12 multiply leaf (60 calls per final exponentiation plus the
    // Miller loop's terminal product): mcl's lazy double-width shape, 54 raw
    // products + 12 reductions where the composed Fp6-Karatsuba path pays
    // 108 + 18. Measured: part of the winning Intel combination (final exp
    // to mcl parity); +9% final exp on Zen 4, whose latency chain dislikes
    // the serial staging. Default follows the target CPU;
    // HELIOS_FP12_MUL_ASM overrides.
    Toggle {
        env: "HELIOS_FP12_MUL_ASM",
        cfg: "helios_fp12_mul_active",
        default: ToggleDefault::Vendor(target_cpu_is_intel),
        values: "0 (composed) or 1 (leaf); unset follows the target CPU",
    },
    // Granger-Scott cyclotomic square leaf (192 calls per final
    // exponentiation, the pow_x dependent chain): mcl's lazy double-width
    // shape at 18 raw products + 12 reductions with a critical path one
    // phase shorter than the composed form. The only lazy leaf that wins on
    // BOTH microarchs (pairing -4.6% Zen 4, final exp -10% both), so it
    // defaults on; HELIOS_CYC_SQR_ASM=0 restores the composed path.
    Toggle {
        env: "HELIOS_CYC_SQR_ASM",
        cfg: "helios_cyc_sqr_active",
        default: ToggleDefault::On,
        values: "1 (leaf, default) or 0 (composed)",
    },
];

impl Toggle {
    fn resolves_on(&self) -> Result<bool, String> {
        let enabled = match std::env::var(self.env).ok().as_deref() {
            Some("1") => true,
            Some("0") => false,
            None => match self.default {
                ToggleDefault::Off => false,
                ToggleDefault::On => true,
                ToggleDefault::Vendor(probe) => probe(),
            },
            Some(other) => {
                return Err(format!(
                    "{}={other:?} is not recognized. Use {}",
                    self.env, self.values
                ));
            }
        };
        Ok(enabled)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rustc-check-cfg=cfg(helios_mont4_x86_64_adx)");
    println!("cargo::rustc-check-cfg=cfg(helios_x86_intel)");
    println!("cargo::rustc-check-cfg=cfg(helios_avx512_ifma)");
    for toggle in LEAF_TOGGLES {
        println!("cargo::rustc-check-cfg=cfg({})", toggle.cfg);
        println!("cargo:rerun-if-env-changed={}", toggle.env);
    }
    println!("cargo:rerun-if-env-changed=HELIOS_AVX512_IFMA");
    println!("cargo:rerun-if-env-changed=HELIOS_DUMP_ASM");
    println!("cargo:rerun-if-changed=build");

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has = |feature: &str| features.split(',').any(|entry| entry == feature);
    let adx_tier = arch == "x86_64" && os == "linux" && has("bmi2") && has("adx");
    let force_portable = std::env::var_os("CARGO_FEATURE_FORCE_PORTABLE").is_some();
    let deny_ifma = std::env::var_os("CARGO_FEATURE_DENY_IFMA").is_some();
    let force_ifma = std::env::var_os("CARGO_FEATURE_FORCE_IFMA").is_some();
    if deny_ifma && force_ifma {
        return Err("deny-ifma and force-ifma cannot be enabled together".into());
    }
    if force_portable && force_ifma {
        return Err("force-portable and force-ifma cannot be enabled together".into());
    }

    // A leaf requires its toggle, the ADX tier, and non-portable mode.
    // Validate explicit values on every target.
    for toggle in LEAF_TOGGLES {
        let on = toggle.resolves_on().map_err(io::Error::other)?;
        if on && adx_tier && !force_portable {
            println!("cargo:rustc-cfg={}", toggle.cfg);
        }
    }

    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").ok_or("Cargo did not set OUT_DIR for the build script")?,
    );
    let kernels = generated_kernels();

    // The inspection path writes all kernels, independent of target gates.
    if let Some(dump) = std::env::var_os("HELIOS_DUMP_ASM") {
        let dump = PathBuf::from(dump);
        if !dump.is_absolute() {
            return Err("HELIOS_DUMP_ASM must be an absolute directory path".into());
        }
        std::fs::create_dir_all(&dump).map_err(|error| {
            io::Error::new(error.kind(), format!("create {}: {error}", dump.display()))
        })?;
        for (name, text) in &kernels {
            write_kernel(&dump, name, text)?;
        }
    }

    let [(aarch64_name, aarch64_text), (x86_name, x86_text)] = &kernels;

    if arch == "aarch64" && vendor == "apple" {
        // The generated AArch64 kernel is the verified CIOS schedule.
        let path = write_kernel(&out_dir, aarch64_name, aarch64_text)?;
        cc::Build::new().file(path).compile("helios_mont4_asm");
    }

    // The x86 kernel contains BMI2 and ADX instructions and has no runtime
    // fallback.
    if adx_tier {
        let path = write_kernel(&out_dir, x86_name, x86_text)?;
        cc::Build::new().file(path).compile("helios_mont4_asm");
        println!("cargo:rustc-cfg=helios_mont4_x86_64_adx");
        // This tuning hint does not select a backend or change linking.
        if target_cpu_is_intel() {
            println!("cargo:rustc-cfg=helios_x86_intel");
        }
    }

    // The IFMA tier has no runtime fallback. Value 1 requires IFMA target
    // features. Value 0 forbids IFMA.
    let ifma_env = std::env::var("HELIOS_AVX512_IFMA").ok();
    if let Some(other) = ifma_env
        .as_deref()
        .filter(|value| !matches!(*value, "0" | "1"))
    {
        return Err(format!(
            "HELIOS_AVX512_IFMA={other:?} is not recognized. Use 1 to force or 0 to deny"
        )
        .into());
    }
    let ifma_available = arch == "x86_64" && has("avx512f") && has("avx512ifma");
    match (deny_ifma, force_ifma, ifma_env.as_deref()) {
        (true, _, Some("1")) => return Err("deny-ifma rejects HELIOS_AVX512_IFMA=1".into()),
        (true, _, _) => {}
        (_, true, Some("0")) => return Err("force-ifma rejects HELIOS_AVX512_IFMA=0".into()),
        (_, true, _) if !ifma_available => {
            return Err("force-ifma requires avx512f and avx512ifma target features".into());
        }
        (_, true, _) => println!("cargo:rustc-cfg=helios_avx512_ifma"),
        (_, _, Some("1")) if !ifma_available => {
            return Err(
                "HELIOS_AVX512_IFMA=1 requires avx512f and avx512ifma target features".into(),
            );
        }
        (_, _, Some("0")) => {}
        (_, _, _) if ifma_available => println!("cargo:rustc-cfg=helios_avx512_ifma"),
        _ => {}
    }
    Ok(())
}
