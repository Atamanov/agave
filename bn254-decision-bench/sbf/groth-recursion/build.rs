//! Compiles the sealed recursion fixtures into the guest.
//!
//! `COMPACT_MANIFEST_SHA256` is the only digest written here. Every per-artifact
//! digest is read out of the manifest that constant pins, so no fixture digest
//! is pinned in two places where the copies can drift apart. Re-pinning the
//! constant is the single edit that changes which bundle this build trusts.

use std::{collections::BTreeMap, env, path::PathBuf};

use groth16_solana::vk::gnark::generate_bsb22_vk_file;
use sha2::{Digest, Sha256};

const COMPACT_MANIFEST_SHA256: &str =
    "4d2d2e40408e481c543ace25276e42a34b6980d3de4fd622277ca0b0459f5cdd";

struct Fixture {
    directory: &'static str,
    symbol: &'static str,
    vk_digest_environment: &'static str,
    payload_digest_environment: &'static str,
    expected_n: usize,
    expected_public_variables_including_one: usize,
    expected_payload_bytes: usize,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_sealed(path: &std::path::Path, expected: &str) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("read sealed artifact {}: {error}", path.display()));
    assert_eq!(
        sha256(&bytes),
        expected,
        "sealed artifact digest mismatch for {}",
        path.display()
    );
    bytes
}

/// Digest of every artifact the compact manifest seals, keyed by bundle-relative path.
fn sealed_digests(manifest: &serde_json::Value) -> BTreeMap<String, String> {
    manifest["artifacts"]
        .as_array()
        .expect("compact manifest lists artifacts")
        .iter()
        .map(|artifact| {
            let path = artifact["path"].as_str().expect("artifact path").to_owned();
            let digest = artifact["sha256"]
                .as_str()
                .expect("artifact sha256")
                .to_owned();
            (path, digest)
        })
        .collect()
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    println!("cargo:rerun-if-env-changed=HELIUS_GROTH_RECURSION_FIXTURE_ROOT");
    let fixtures = env::var_os("HELIUS_GROTH_RECURSION_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest_dir.join("../../../research/bn254-decision-table-v2-20260804/recursion-v2")
        });
    let output = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let compact_manifest = read_sealed(&fixtures.join("manifest.json"), COMPACT_MANIFEST_SHA256);
    let compact_manifest: serde_json::Value =
        serde_json::from_slice(&compact_manifest).expect("compact recursion manifest is JSON");
    assert_eq!(
        compact_manifest["schema"].as_str(),
        Some("helios.bn254-real-zolana-recursion-runtime-compact.v4"),
        "compact manifest is not the schema this guest reads"
    );
    let digests = sealed_digests(&compact_manifest);
    println!("cargo:rustc-env=HELIUS_GROTH_RECURSION_MANIFEST_SHA256={COMPACT_MANIFEST_SHA256}");

    for fixture in [
        Fixture {
            directory: "n2-distinct",
            symbol: "VK_G2",
            vk_digest_environment: "HELIUS_GROTH_G2_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G2_PAYLOAD_SHA256",
            expected_n: 2,
            expected_public_variables_including_one: 4,
            expected_payload_bytes: 480,
        },
        Fixture {
            directory: "n3-distinct",
            symbol: "VK_G3",
            vk_digest_environment: "HELIUS_GROTH_G3_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G3_PAYLOAD_SHA256",
            expected_n: 3,
            expected_public_variables_including_one: 5,
            expected_payload_bytes: 512,
        },
        Fixture {
            directory: "n5-same",
            symbol: "VK_G5",
            vk_digest_environment: "HELIUS_GROTH_G5_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G5_PAYLOAD_SHA256",
            expected_n: 5,
            expected_public_variables_including_one: 7,
            expected_payload_bytes: 576,
        },
    ] {
        let directory = fixtures.join(fixture.directory);
        let sealed = |name: &str| {
            let key = format!("{}/{name}", fixture.directory);
            digests
                .get(&key)
                .unwrap_or_else(|| panic!("compact manifest does not seal {key}"))
                .as_str()
        };

        let source_row_sha256 = sealed("fixture.bin");
        let generation =
            read_sealed(&directory.join("generation.json"), sealed("generation.json"));
        let generation = std::str::from_utf8(&generation).expect("generation JSON UTF-8");
        assert!(generation.contains(
            "\"schema\": \"helios.gnark-bn254-recursion.secure-os-random.imported-zolana-statement.v4\""
        ));
        assert!(generation.contains(&format!("\"n_inner_proofs\": {}", fixture.expected_n)));
        assert!(generation.contains(&format!(
            "\"outer_public_variables_including_one_wire\": {}",
            fixture.expected_public_variables_including_one
        )));
        assert!(generation.contains("\"exact_inner_proof_equality_constrained\": true"));
        assert!(generation.contains("\"all_inner_proofs_host_verified\": true"));
        assert!(generation.contains("\"outer_proof_host_verified\": true"));
        assert!(generation.contains("\"measurement_ready\": true"));
        assert!(generation.contains("\"secure_os_random_export\": true"));
        assert!(generation.contains("\"publicly_derivable_toxic_waste\": false"));
        assert!(generation.contains(source_row_sha256));

        read_sealed(&directory.join("fixture.bin"), source_row_sha256);
        let statement = read_sealed(
            &directory.join("statement_commitment_fr.bin"),
            sealed("statement_commitment_fr.bin"),
        );
        let payload_sha256 = sealed("payload_unnegated_a.bin");
        let payload = read_sealed(&directory.join("payload_unnegated_a.bin"), payload_sha256);
        assert_eq!(payload.len(), fixture.expected_payload_bytes);
        assert_eq!(
            payload.get(payload.len() - 32..),
            Some(statement.as_slice())
        );
        println!(
            "cargo:rustc-env={}={}",
            fixture.payload_digest_environment, payload_sha256
        );

        let vk_path = directory.join("vk.bin");
        let vk_sha256 = sealed("vk.bin");
        read_sealed(&vk_path, vk_sha256);
        println!(
            "cargo:rustc-env={}={}",
            fixture.vk_digest_environment, vk_sha256
        );
        generate_bsb22_vk_file(
            &vk_path,
            &output,
            &format!("{}.rs", fixture.directory.replace('-', "_")),
            fixture.symbol,
        )
        .unwrap_or_else(|error| {
            panic!(
                "generate {} from {}: {error:?}",
                fixture.symbol,
                vk_path.display()
            )
        });
    }
}
