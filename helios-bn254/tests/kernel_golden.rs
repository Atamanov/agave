//! Golden pin for the generated mont4 kernels: the rendered text must match
//! the checked-in snapshots byte for byte. The interpreter suite
//! (`kernelgen_verify.rs`) proves the schedules correct; this gate makes any
//! change to the emitted text show up as a reviewable diff instead of only
//! inside OUT_DIR.
//!
//! Blessing is deliberate: `HELIOS_BLESS=1 cargo test --test kernel_golden`
//! rewrites the snapshots, and the change then shows in `git diff`.

#[path = "../build/mod.rs"]
pub mod kernelgen;

use std::fs;
use std::path::PathBuf;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn check(name: &str, rendered: &str) {
    let golden = golden_path(name);
    match std::env::var("HELIOS_BLESS").ok().as_deref() {
        Some("1") => {
            fs::create_dir_all(golden.parent().expect("golden dir"))
                .unwrap_or_else(|e| panic!("create tests/golden: {e}"));
            fs::write(&golden, rendered)
                .unwrap_or_else(|e| panic!("write {}: {e}", golden.display()));
            return;
        }
        None => {}
        Some(other) => panic!("HELIOS_BLESS={other:?} is not recognized; use 1 to bless"),
    }
    let expected = fs::read_to_string(&golden).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\n\
             Missing snapshot? Generate it with:\n  \
             HELIOS_BLESS=1 cargo test --release --features std --test kernel_golden",
            golden.display(),
        )
    });
    if rendered != expected {
        let actual = std::env::temp_dir().join(format!("helios-{name}.actual"));
        fs::write(&actual, rendered).unwrap_or_else(|e| panic!("write {}: {e}", actual.display()));
        panic!(
            "generated kernel {name} drifted from its golden snapshot.\n\
             Inspect: diff {} {}\n\
             If the change is intended, bless it and review the git diff:\n  \
             HELIOS_BLESS=1 cargo test --release --features std --test kernel_golden",
            golden.display(),
            actual.display(),
        );
    }
}

#[test]
fn mont4_x86_64_matches_golden() {
    check("mont4_x86_64.s", &kernelgen::render::render_mont4_x86_64());
}

#[test]
fn mont4_aarch64_matches_golden() {
    check(
        "mont4_aarch64.s",
        &kernelgen::a64::render::render_mont4_aarch64(),
    );
}
