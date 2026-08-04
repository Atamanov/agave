use std::{env, path::PathBuf};

use groth16_solana::vk::gnark::generate_bsb22_vk_file;
use sha2::{Digest, Sha256};

const COMPACT_MANIFEST_SHA256: &str =
    "4d2d2e40408e481c543ace25276e42a34b6980d3de4fd622277ca0b0459f5cdd";
const SOURCE_ZOLANA_MANIFEST_SHA256: &str =
    "df35081dcc762c81f81b90b91af9849a9815bf3772bf8139b9aa92c0ad055a0c";

struct Fixture {
    directory: &'static str,
    symbol: &'static str,
    vk_digest_environment: &'static str,
    payload_digest_environment: &'static str,
    expected_vk_sha256: &'static str,
    expected_payload_sha256: &'static str,
    expected_generation_sha256: &'static str,
    expected_statement_sha256: &'static str,
    expected_source_row_sha256: &'static str,
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

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    println!("cargo:rerun-if-env-changed=HELIUS_GROTH_RECURSION_FIXTURE_ROOT");
    let fixtures = env::var_os("HELIUS_GROTH_RECURSION_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            manifest.join("../../../research/bn254-decision-table-v2-20260804/recursion-v2")
        });
    let output = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let compact_manifest = read_sealed(&fixtures.join("manifest.json"), COMPACT_MANIFEST_SHA256);
    let compact_manifest =
        std::str::from_utf8(&compact_manifest).expect("compact recursion manifest UTF-8");
    assert!(
        compact_manifest
            .contains("\"schema\": \"helius.bn254-real-zolana-recursion-runtime-compact.v4\"")
    );
    assert!(compact_manifest.contains(SOURCE_ZOLANA_MANIFEST_SHA256));
    println!("cargo:rustc-env=HELIUS_GROTH_RECURSION_MANIFEST_SHA256={COMPACT_MANIFEST_SHA256}");

    for fixture in [
        Fixture {
            directory: "n2-distinct",
            symbol: "VK_G2",
            vk_digest_environment: "HELIUS_GROTH_G2_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G2_PAYLOAD_SHA256",
            expected_vk_sha256: "2a6fda1a4be28af88044e181e59c4ea0cc23ba5f1e35c0958baaa504174ee416",
            expected_payload_sha256: "6901c6d6d4575d24ad987caf3defa82113cbccf36794a9a4d69d02810ee15278",
            expected_generation_sha256: "3bfd41011e55dd5227b0d3f5a65d4c5b51def5c4a887dfb59d0cca9e7a5f0e44",
            expected_statement_sha256: "d941fde012539a9b6b2b97ecb66227da05373f6461513f10de8502097f0af4c8",
            expected_source_row_sha256: "51e5585ca8ac1dd547380b016f3e49f8e8cad60fed596faefd762a5af5ded577",
            expected_n: 2,
            expected_public_variables_including_one: 4,
            expected_payload_bytes: 480,
        },
        Fixture {
            directory: "n3-distinct",
            symbol: "VK_G3",
            vk_digest_environment: "HELIUS_GROTH_G3_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G3_PAYLOAD_SHA256",
            expected_vk_sha256: "ef5786d016d67e10bc5290ff62de65a18b67ca3a1627022a11a4eed557f8cc8a",
            expected_payload_sha256: "58d8db8c9f035386f1419b35c230c3589a62f47e89bf370cc734880f2487c79f",
            expected_generation_sha256: "9b40c2f47d6dec8e3041025f704cf689f2fef669c0601849f4c4ff27113e8020",
            expected_statement_sha256: "89c2a476438c36e43354ee193495977697bbae57ed173b2145724efc638b560e",
            expected_source_row_sha256: "79d55ae5e3fbeaec1db68330554724e4ae3c9f42185029d53476f14799a649a1",
            expected_n: 3,
            expected_public_variables_including_one: 5,
            expected_payload_bytes: 512,
        },
        Fixture {
            directory: "n5-same",
            symbol: "VK_G5",
            vk_digest_environment: "HELIUS_GROTH_G5_OUTER_VK_SHA256",
            payload_digest_environment: "HELIUS_GROTH_G5_PAYLOAD_SHA256",
            expected_vk_sha256: "a265ecefc4f5da6c9b9c433b4ab083462908749784692cd74b807fd59621f9f4",
            expected_payload_sha256: "4e949e0ec63f00197ce059a7be6b7a9aaac8fe8be08907f37f86e7c5aeb1dc86",
            expected_generation_sha256: "85889924d9d3f764697d38dadb266c24b5e585797a09b4843a01706aa74e31c2",
            expected_statement_sha256: "1db97b150e3b8cba653b77aa2d8d52a9b2ca2534a0e1057af537a79400dc4057",
            expected_source_row_sha256: "cc6de5ad6f9e70e4c2448ec0c23f9575f61dd17d9aa6c05dc834d2b6c380dfbf",
            expected_n: 5,
            expected_public_variables_including_one: 7,
            expected_payload_bytes: 576,
        },
    ] {
        let directory = fixtures.join(fixture.directory);
        let generation = read_sealed(
            &directory.join("generation.json"),
            fixture.expected_generation_sha256,
        );
        let generation = std::str::from_utf8(&generation).expect("generation JSON UTF-8");
        assert!(generation.contains(
            "\"schema\": \"helius.gnark-bn254-recursion.secure-os-random.imported-zolana-statement.v4\""
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
        assert!(generation.contains(fixture.expected_source_row_sha256));

        read_sealed(
            &directory.join("fixture.bin"),
            fixture.expected_source_row_sha256,
        );
        let statement = read_sealed(
            &directory.join("statement_commitment_fr.bin"),
            fixture.expected_statement_sha256,
        );
        let payload = read_sealed(
            &directory.join("payload_unnegated_a.bin"),
            fixture.expected_payload_sha256,
        );
        assert_eq!(payload.len(), fixture.expected_payload_bytes);
        assert_eq!(
            payload.get(payload.len() - 32..),
            Some(statement.as_slice())
        );
        println!(
            "cargo:rustc-env={}={}",
            fixture.payload_digest_environment, fixture.expected_payload_sha256
        );

        let vk_path = directory.join("vk.bin");
        read_sealed(&vk_path, fixture.expected_vk_sha256);
        println!(
            "cargo:rustc-env={}={}",
            fixture.vk_digest_environment, fixture.expected_vk_sha256
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
