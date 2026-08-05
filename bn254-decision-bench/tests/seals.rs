//! Checks every committed provenance seal against the bytes it names.
//!
//! A seal is only worth its digest if something recomputes it. Each test here
//! reads the named file and hashes it; none of them restates a constant.
//!
//! Two seals were wrong before this file existed. `fixtures-v3/manifest.sha256`
//! still described the pre-rename bytes after the repo-wide helios/helius
//! rename edited the manifest it names. The guest build script kept its own
//! copy of every fixture digest beside the copy in `recursion-v2/manifest.json`,
//! and nothing compared the two.
//!
//! `imported_zolana_manifest_is_the_committed_copy` binds the source digest
//! recorded in `recursion-v2/manifest.json` to the in-repo copy of the Zolana
//! manifest that replaced the original export.

use {
    serde_json::Value,
    std::{
        collections::BTreeSet,
        path::{Path, PathBuf},
    },
};

/// The helios/helius rename edited the committed copy of the imported Zolana
/// manifest after its source digest was recorded. Undoing exactly this
/// substitution must reproduce the recorded digest.
const IMPORTED_SPELLING: (&str, &str) = ("helius", "helios");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn research_dir() -> PathBuf {
    repo_root().join("research/bn254-decision-table-v2-20260804")
}

fn recursion_dir() -> PathBuf {
    research_dir().join("recursion-v2")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|error| panic!("{} must be committed: {error}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(solana_sha256_hasher::hash(bytes).to_bytes())
}

fn sha256_of(path: &Path) -> String {
    sha256(&read(path))
}

fn recursion_manifest() -> Value {
    serde_json::from_slice(&read(&recursion_dir().join("manifest.json")))
        .expect("recursion manifest is JSON")
}

fn entries(value: &Value, key: &str) -> Vec<Value> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("recursion manifest has no {key} array"))
        .clone()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} must be a string, got {}", value[key]))
}

fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Every `*.sha256` under `research/` must describe its sibling file.
///
/// This is `shasum -a 256 -c` run from each seal's own directory, which nothing
/// in the repo did before.
#[test]
fn every_committed_sha256_file_matches_the_bytes_it_names() {
    let seals: Vec<PathBuf> = files_under(&research_dir())
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "sha256")
        })
        .collect();
    assert!(
        seals.len() >= 2,
        "expected the fixture and recursion seals under {}, found {seals:?}",
        research_dir().display()
    );

    for seal in seals {
        let listing = String::from_utf8(read(&seal)).expect("seal file is UTF-8");
        let directory = seal.parent().expect("seal has a directory");
        let sealed: Vec<&str> = listing
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(!sealed.is_empty(), "{} seals nothing", seal.display());
        for line in sealed {
            let (digest, name) = line
                .split_once("  ")
                .unwrap_or_else(|| panic!("{}: not a shasum line: {line:?}", seal.display()));
            let named = directory.join(name.trim());
            assert_eq!(
                sha256_of(&named),
                digest,
                "{} seals {} with a digest that is not its content",
                seal.display(),
                named.display()
            );
        }
    }
}

/// Every artifact the recursion manifest lists must be on disk with the sealed
/// length and digest, and nothing in the bundle may be left unsealed.
#[test]
fn every_recursion_manifest_artifact_matches_disk() {
    let manifest = recursion_manifest();
    let artifacts = entries(&manifest, "artifacts");
    assert!(
        !artifacts.is_empty(),
        "the recursion manifest seals nothing"
    );

    let mut sealed = BTreeSet::new();
    for artifact in &artifacts {
        let relative = text(artifact, "path");
        let path = recursion_dir().join(relative);
        let bytes = read(&path);
        assert_eq!(
            u64::try_from(bytes.len()).expect("artifact length"),
            artifact["bytes"].as_u64().expect("sealed byte count"),
            "{relative} is not the sealed length"
        );
        assert_eq!(
            sha256(&bytes),
            text(artifact, "sha256"),
            "{relative} does not hash to its sealed digest"
        );
        sealed.insert(path);
    }

    // The manifest and its own seal are the root of trust, not sealed entries.
    let root = [
        recursion_dir().join("manifest.json"),
        recursion_dir().join("manifest.sha256"),
    ];
    let unsealed: Vec<_> = files_under(&recursion_dir())
        .into_iter()
        .filter(|path| !sealed.contains(path) && !root.contains(path))
        .collect();
    assert!(
        unsealed.is_empty(),
        "these bundle files are in no seal: {unsealed:?}"
    );
}

/// The per-row digests must name the same bytes as the artifact list. Both live
/// in one file and nothing compared them before.
#[test]
fn every_recursion_row_points_at_the_sealed_artifacts() {
    let manifest = recursion_manifest();
    let rows = entries(&manifest, "rows");
    assert_eq!(
        rows.len(),
        3,
        "the campaign has three Groth16 recursion rows"
    );

    for row in &rows {
        let directory = recursion_dir().join(text(row, "directory"));
        let row_id = text(row, "row_id");
        assert_eq!(
            sha256_of(&directory.join("fixture.bin")),
            text(row, "source_row_sha256"),
            "{row_id} source_row_sha256 is not the digest of fixture.bin"
        );
        assert_eq!(
            sha256_of(&directory.join("vk.bin")),
            text(row, "outer_vk_sha256"),
            "{row_id} outer_vk_sha256 is not the digest of vk.bin"
        );
    }
}

/// `statement_sha256` is the unreduced digest whose residue mod the BN254
/// scalar field is the committed statement commitment. It is deliberately not
/// the digest of `statement_commitment_fr.bin`, and reading it as one is what
/// made the two pinning sites look like they disagreed.
#[test]
fn row_statement_digest_reduces_to_the_committed_field_element() {
    let manifest = recursion_manifest();

    for row in entries(&manifest, "rows") {
        let row_id = text(&row, "row_id");
        let directory = recursion_dir().join(text(&row, "directory"));
        let claimed = text(&row, "statement_sha256");

        let generation: Value = serde_json::from_slice(&read(&directory.join("generation.json")))
            .expect("generation record is JSON");
        assert_eq!(
            text(&generation, "statement_sha256"),
            claimed,
            "{row_id} manifest and generation record disagree on statement_sha256"
        );

        let element = read(&directory.join("statement_commitment_fr.bin"));
        assert_eq!(
            hex::encode(&element),
            text(&generation, "statement_commitment_fr_be"),
            "{row_id} statement_commitment_fr.bin is not the big-endian element the record names"
        );

        let digest = hex::decode(claimed).expect("statement_sha256 is hex");
        assert!(
            reduction_multiple(u256_from_be(&digest), u256_from_be(&element)).is_some(),
            "{row_id} statement_sha256 does not reduce to statement_commitment_fr.bin"
        );

        // Overwriting the row field with the artifact digest would look like it
        // reconciled the two pinning sites and would destroy the preimage.
        let artifact_digest = hex::decode(sha256(&element)).expect("artifact digest is hex");
        assert!(
            reduction_multiple(u256_from_be(&artifact_digest), u256_from_be(&element)).is_none(),
            "{row_id} statement_sha256 must stay the preimage digest, not the artifact digest"
        );
    }
}

/// The guest build script must pin the manifest and nothing else. A second
/// digest here is a second source of truth, which is how the statement pins
/// came to disagree.
#[test]
fn guest_build_script_pins_only_the_recursion_manifest() {
    let build_script = repo_root().join("bn254-decision-bench/sbf/groth-recursion/build.rs");
    let source = String::from_utf8(read(&build_script)).expect("build script is UTF-8");

    assert_eq!(
        sha256_digests_in(&source),
        BTreeSet::from([sha256_of(&recursion_dir().join("manifest.json"))]),
        "{} must pin the recursion manifest and derive every other digest from it",
        build_script.display()
    );
    assert!(
        !source.contains("/Users/"),
        "{} names an absolute path that exists on one machine only",
        build_script.display()
    );
}

/// The Zolana manifest the recursion fixtures were built from is committed at
/// `fixtures-v3/manifest.json`. The repo-wide rename edited that copy after the
/// source digest was recorded, so the recorded digest is reproduced by undoing
/// exactly that substitution. Any other edit to the copy fails here.
#[test]
fn imported_zolana_manifest_is_the_committed_copy() {
    let committed = read(&research_dir().join("fixtures-v3/manifest.json"));
    let text_form = String::from_utf8(committed).expect("Zolana manifest is UTF-8");
    let (current, imported) = IMPORTED_SPELLING;
    assert!(
        !text_form.contains(imported),
        "the committed copy still spells {imported}, so the rename is not the only difference"
    );
    let as_imported = sha256(text_form.replace(current, imported).as_bytes());

    let manifest = recursion_manifest();
    assert_eq!(
        text(&manifest, "source_zolana_manifest_sha256"),
        as_imported,
        "the recursion manifest was built from different Zolana manifest bytes than the committed copy"
    );
    for row in entries(&manifest, "rows") {
        let directory = recursion_dir().join(text(&row, "directory"));
        let generation: Value = serde_json::from_slice(&read(&directory.join("generation.json")))
            .expect("generation record is JSON");
        assert_eq!(
            text(&generation, "source_manifest_sha256"),
            as_imported,
            "{} was generated from different Zolana manifest bytes than the committed copy",
            text(&row, "row_id")
        );
    }
}

/// Every maximal run of exactly 64 lowercase hex characters in `source`.
fn sha256_digests_in(source: &str) -> BTreeSet<String> {
    let is_hex = |c: char| c.is_ascii_digit() || ('a'..='f').contains(&c);
    source
        .split(|c: char| !is_hex(c))
        .filter(|run| run.len() == 64)
        .map(str::to_owned)
        .collect()
}

/// A 256-bit unsigned integer, most significant limb first.
type U256 = [u64; 4];

/// BN254 scalar field modulus. A statement commitment is an element of this
/// field, so the digest it came from differs from it by a multiple of r.
const BN254_FR_MODULUS: U256 = [
    0x3064_4e72_e131_a029,
    0xb850_45b6_8181_585d,
    0x2833_e848_79b9_7091,
    0x43e1_f593_f000_0001,
];

fn u256_from_be(bytes: &[u8]) -> U256 {
    let bytes: [u8; 32] = bytes.try_into().expect("a field element is 32 bytes");
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_be_bytes(chunk.try_into().expect("eight byte limb"));
    }
    limbs
}

fn checked_sub(a: U256, b: U256) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for index in (0..4).rev() {
        let (difference, first) = a[index].overflowing_sub(b[index]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        out[index] = difference;
        borrow = first || second;
    }
    (!borrow).then_some(out)
}

/// How many times the modulus fits in `digest - element`, or `None` when
/// `digest` does not reduce to `element`. The modulus exceeds 2^253 and a
/// digest is below 2^256, so four subtractions exhaust every congruent case.
fn reduction_multiple(digest: U256, element: U256) -> Option<u32> {
    let mut remainder = checked_sub(digest, element)?;
    for multiple in 0..=4 {
        if remainder == [0u64; 4] {
            return Some(multiple);
        }
        remainder = checked_sub(remainder, BN254_FR_MODULUS)?;
    }
    None
}

#[test]
fn reduction_multiple_rejects_a_digest_that_is_not_congruent() {
    let element = [0, 0, 0, 7];
    assert_eq!(reduction_multiple(element, element), Some(0));
    assert_eq!(
        reduction_multiple(
            checked_sub(BN254_FR_MODULUS, [0, 0, 0, 1]).expect("r - 1"),
            element
        ),
        None
    );
}
