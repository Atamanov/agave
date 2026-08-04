//! Every comment, doc line, and string that reaches humans must be
//! keyboard-typeable ASCII. This gate walks both crates and rejects any
//! byte >= 0x80 in source and docs, printing file:line:col for each hit.

use std::fs;
use std::path::{Path, PathBuf};

/// Human-readable source extensions. No exclusions: every tracked source
/// file in both crates must be pure ASCII. Assembly is build-generated, so
/// no `.s` files exist in the tree.
const EXTENSIONS: &[&str] = &["rs", "md", "toml"];

fn is_excluded(_rel: &str) -> bool {
    false
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, files);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e))
        {
            files.push(path);
        }
    }
}

#[test]
fn all_source_is_ascii() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_root = manifest.parent().expect("crates/ root").to_path_buf();
    let mut files = Vec::new();
    walk(&manifest, &mut files);
    walk(&crates_root.join("bn254-batch-syscall"), &mut files);
    files.sort();

    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let rel = path
            .strip_prefix(&crates_root)
            .expect("path under crates/")
            .to_string_lossy()
            .replace('\\', "/");
        if is_excluded(&rel) {
            continue;
        }
        checked += 1;
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let (mut line, mut col) = (1usize, 1usize);
        for &b in &bytes {
            if b >= 0x80 {
                offenders.push(format!("{rel}:{line}:{col}: byte 0x{b:02x}"));
            }
            if b == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
    }
    assert!(
        checked > 30,
        "walk found too few files ({checked}); broken?"
    );
    assert!(
        offenders.is_empty(),
        "non-ASCII bytes found:\n{}",
        offenders.join("\n")
    );
}
