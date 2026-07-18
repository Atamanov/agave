//! Builds the vendored mcl (herumi/mcl @ e107c70e) as a portable no-asm
//! static library for the BN_SNARK1 / alt_bn128 256-bit configuration, or
//! links a prebuilt archive when MCL_LIB_DIR is set.
//!
//! The defines mirror what upstream `make MCL_FP_BIT=256 MCL_FR_BIT=256
//! lib/libmcl.a` passes (common.mk + Makefile at the pin), minus the
//! platform fast paths that need LLVM-IR or assembler objects:
//! - MCL_FP_BIT/MCL_FR_BIT=256, MCL_SIZEOF_UNIT=8 (BIT/8), NDEBUG,
//!   -O3 -fomit-frame-pointer -fno-stack-protector (common.mk CFLAGS_OPT).
//! - MCL_BINT_ASM=0: upstream defaults to 1 and links bint64.ll/asm objects;
//!   0 selects the pure-C++ bint_switch path.
//! - MCL_DONT_USE_XBYAK: upstream auto-enables the xbyak JIT on x86-64;
//!   portable build keeps only the cpuid class.
//! - MCL_MSM=0 explicit (auto-0 for 256-bit, pinned for clarity); MCL_USE_LLVM
//!   left undefined: upstream's default build defines it globally and links
//!   the generated .ll objects, which this cc build does not compile, so
//!   defining it here would fail to link; arithmetic results are identical
//!   either way and the on-box fingerprint run arbitrates parity with the
//!   prebuilt archive.
//! - MCL_DONT_USE_OPENSSL and MCL_USE_VINT are config.hpp defaults already.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=MCL_LIB_DIR");
    println!("cargo:rerun-if-changed=vendor/mcl");
    println!("cargo:rerun-if-changed=build.rs");

    if let Ok(dir) = std::env::var("MCL_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
        println!("cargo:rustc-link-lib=static=mcl");
        link_cpp_runtime();
        return;
    }

    let vendor = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("vendor/mcl");
    cc::Build::new()
        .cpp(true)
        .std("c++11")
        .opt_level(3)
        .include(vendor.join("include"))
        .file(vendor.join("src/fp.cpp"))
        .file(vendor.join("src/bn_c256.cpp"))
        .define("MCL_FP_BIT", "256")
        .define("MCL_FR_BIT", "256")
        .define("MCL_SIZEOF_UNIT", "8")
        .define("MCL_BINT_ASM", "0")
        .define("MCL_MSM", "0")
        .define("MCL_DONT_USE_XBYAK", None)
        .define("NDEBUG", None)
        .flag_if_supported("-fomit-frame-pointer")
        .flag_if_supported("-fno-stack-protector")
        .warnings(false)
        .compile("mcl");
    // cc emits the link-search and link-lib lines for the compiled archive
    link_cpp_runtime();
}

fn link_cpp_runtime() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
