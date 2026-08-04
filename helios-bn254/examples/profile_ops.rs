//! Fine-grained profile harness for Instruments / xctrace / sample.
//!
//! Modes:
//!   profile_ops                  # all phases once (long)
//!   profile_ops --loop g1_add    # spin one op forever (for attach/xctrace)
//!   profile_ops --loop pairing
//!
//! PHASE_BEGIN / PHASE_END markers on stdout for windowing.

use std::hint::black_box;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use helios_bn254::pairing::{final_exponentiation, miller_loop};
use helios_bn254::{Fp, Fr, G1Affine, G1Projective, G2Affine, G2Projective, pairing};

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn cycles() -> u64 {
    let c: u64;
    unsafe {
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) c, options(nomem, nostack, preserves_flags));
    }
    c
}
#[cfg(not(target_arch = "aarch64"))]
fn cycles() -> u64 {
    0
}

fn flush_mark(s: &str) {
    let _ = writeln!(io::stdout(), "{s}");
    let _ = io::stdout().flush();
}

fn phase(name: &str, iters: u64, mut f: impl FnMut()) {
    for _ in 0..(iters / 20).max(1) {
        f();
    }
    flush_mark(&format!("PHASE_BEGIN {name}"));
    // settle so Instruments PMI window lands on compute, not dyld
    std::thread::sleep(Duration::from_millis(50));
    let c0 = cycles();
    let t0 = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = t0.elapsed().as_nanos() as f64;
    let c1 = cycles();
    flush_mark(&format!(
        "PHASE_END {name} total_ns={ns:.0} iters={iters} ns_per_op={:.3} cycles={}",
        ns / iters as f64,
        c1.saturating_sub(c0)
    ));
}

fn run_loop(op: &str) -> ! {
    let p = G1Affine::generator();
    let q = G2Affine::test_generator();
    let s = Fr::from_u64(0xdead_beef_cafe_babe);
    let mut a = Fp::from_u64(0x1234_5678_9abc_def0);
    let b = Fp::from_u64(0xfedc_ba98_7654_3210);
    let mut c = Fp::ZERO;
    let mut p2 = G1Projective::from(p);
    let mut q2 = G2Projective::from(q);
    let mut ml = helios_bn254::Fp12::ONE;
    let mut e = helios_bn254::Fp12::ONE;

    // delay so xctrace --launch is fully attached
    flush_mark(&format!("LOOP_READY {op}"));
    std::thread::sleep(Duration::from_millis(500));
    flush_mark(&format!("PHASE_BEGIN {op}"));

    let t0 = Instant::now();
    let mut n = 0u64;
    loop {
        match op {
            "fp_mul" => {
                c = black_box(a) * black_box(b);
                a = c;
            }
            "fp_sqr" => {
                c = black_box(a).square();
                a = c;
            }
            "g1_add" => p2 = black_box(p2).add_mixed(black_box(p)),
            "g1_dbl" => p2 = black_box(p2).double(),
            "g1_mul" => {
                let _ = black_box(G1Projective::from(p)).mul(black_box(s));
            }
            "g2_add" => q2 = black_box(q2).add_mixed(black_box(q)),
            "g2_dbl" => q2 = black_box(q2).double(),
            "g2_mul" => {
                q2 = black_box(G2Projective::from(q)).mul(black_box(s));
            }
            "miller" => ml = miller_loop(black_box(&p), black_box(&q)),
            "final_exp" => {
                if n == 0 {
                    ml = miller_loop(&p, &q);
                }
                e = final_exponentiation(black_box(&ml));
            }
            "pairing" => e = pairing(black_box(&p), black_box(&q)),
            _ => {
                eprintln!("unknown loop op: {op}");
                std::process::exit(2);
            }
        }
        n += 1;
        // progress every ~200ms wall
        if n & 0xfff == 0 && t0.elapsed() > Duration::from_millis(200) {
            // keep going; Instruments samples continuously
        }
        let _ = (c, p2, q2, ml, e);
    }
}

/// Exactly `iters` runs of one op, no warmup or sleeps: callgrind/cachegrind
/// differential instruction counting (run with two iter counts, divide).
fn run_icount(op: &str, iters: u64) {
    let p = G1Affine::generator();
    let q = G2Affine::test_generator();
    let mut ml = miller_loop(&p, &q);
    let mut e = helios_bn254::Fp12::ONE;
    let t0 = Instant::now();
    for _ in 0..iters {
        match op {
            "miller" => ml = miller_loop(black_box(&p), black_box(&q)),
            "final_exp" => e = final_exponentiation(black_box(&ml)),
            "pairing" => e = pairing(black_box(&p), black_box(&q)),
            _ => {
                eprintln!("unknown icount op: {op}");
                std::process::exit(2);
            }
        }
    }
    let ns = t0.elapsed().as_nanos() as f64;
    let _ = black_box((ml, e));
    flush_mark(&format!(
        "ICOUNT_DONE {op} iters={iters} ns_per_op={:.3}",
        ns / iters as f64
    ));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("--loop") {
        let op = args.get(1).map(|s| s.as_str()).unwrap_or("g1_add");
        run_loop(op);
    }
    if args.first().map(|s| s.as_str()) == Some("--icount") {
        let op = args.get(1).map(|s| s.as_str()).unwrap_or("miller");
        let iters: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
        run_icount(op, iters);
        return;
    }

    let filter: Option<Vec<&str>> = if !args.is_empty() {
        Some(args.iter().map(|s| s.as_str()).collect())
    } else {
        None
    };
    let want = |n: &str| filter.as_ref().map(|f| f.contains(&n)).unwrap_or(true);

    // give Instruments time after launch before heavy work
    flush_mark("HARNESS_START");
    std::thread::sleep(Duration::from_millis(800));

    let p = G1Affine::generator();
    let q = G2Affine::test_generator();
    let s = Fr::from_u64(0xdead_beef_cafe_babe);
    let mut a = Fp::from_u64(0x1234_5678_9abc_def0);
    let b = Fp::from_u64(0xfedc_ba98_7654_3210);
    let mut c = Fp::ZERO;
    let mut p2 = G1Projective::from(p);
    let mut q2 = G2Projective::from(q);
    let mut ml = helios_bn254::Fp12::ONE;
    let mut e = helios_bn254::Fp12::ONE;

    if want("fp_mul") {
        phase("fp_mul", 8_000_000, || {
            c = black_box(a) * black_box(b);
            a = c;
        });
    }
    if want("fp_sqr") {
        phase("fp_sqr", 8_000_000, || {
            c = black_box(a).square();
            a = c;
        });
    }
    if want("g1_add") {
        phase("g1_add", 3_000_000, || {
            p2 = black_box(p2).add_mixed(black_box(p));
        });
    }
    if want("g1_dbl") {
        phase("g1_dbl", 3_000_000, || {
            p2 = black_box(p2).double();
        });
    }
    if want("g1_mul") {
        phase("g1_mul", 80_000, || {
            let _ = black_box(G1Projective::from(p)).mul(black_box(s));
        });
    }
    if want("g2_add") {
        phase("g2_add", 1_200_000, || {
            q2 = black_box(q2).add_mixed(black_box(q));
        });
    }
    if want("g2_dbl") {
        phase("g2_dbl", 1_200_000, || {
            q2 = black_box(q2).double();
        });
    }
    if want("g2_mul") {
        phase("g2_mul", 30_000, || {
            q2 = black_box(G2Projective::from(q)).mul(black_box(s));
        });
    }
    if want("miller") {
        phase("miller", 12_000, || {
            ml = miller_loop(black_box(&p), black_box(&q));
        });
    }
    if want("final_exp") {
        ml = miller_loop(&p, &q);
        phase("final_exp", 12_000, || {
            e = final_exponentiation(black_box(&ml));
        });
    }
    if want("pairing") {
        phase("pairing", 8_000, || {
            e = pairing(black_box(&p), black_box(&q));
        });
    }

    let _ = (c, p2, q2, ml, e);
    flush_mark("PROFILE_DONE");
}
